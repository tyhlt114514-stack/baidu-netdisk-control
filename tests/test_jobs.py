"""Asynchronous receipts, failure boundaries, and restart recovery."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from baidu_netdisk.common import NetdiskError, atomic_json
from baidu_netdisk.jobs import JobManager


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = JobManager(Path(self.temp.name), workers=1)

    def tearDown(self):
        self.manager.executor.shutdown(wait=True)
        self.temp.cleanup()

    def finished_job(self, callback, args=None):
        receipt = self.manager.start("test", args or {}, callback)
        self.manager.executor.shutdown(wait=True)
        return self.manager.get(receipt["job_id"])

    def test_success_receipt_is_persisted_and_sanitized(self):
        secret = "NEVER_STORE_SECRET"
        job = self.finished_job(lambda: {"ok": True, "access_token": secret, "url": f"access_token={secret}"},
                                {"password": secret})
        self.assertEqual(job["status"], "succeeded")
        self.assertIn("finished_at", job)
        self.assertNotIn(secret, json.dumps(job))
        self.assertNotIn(secret, (self.manager.path / (job["job_id"] + ".json")).read_text(encoding="utf-8"))

    def test_false_result_is_failure(self):
        job = self.finished_job(lambda: {"ok": False, "error": "denied"})
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["result"]["error"], "denied")

    def test_unexpected_exception_has_no_trace_or_token(self):
        def fail():
            raise RuntimeError("access_token=NEVER_PRINT_SECRET")
        job = self.finished_job(fail)
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["result"]["error"], "RuntimeError")
        self.assertNotIn("NEVER_PRINT_SECRET", json.dumps(job))

    def test_known_exception_redacts_message_and_bearer_credentials(self):
        def fail():
            raise NetdiskError("denied", "Authorization: Bearer NEVER_PRINT_SECRET", {"cookie": "NEVER_PRINT_SECRET"})
        job = self.finished_job(fail)
        self.assertEqual(job["status"], "failed")
        self.assertNotIn("NEVER_PRINT_SECRET", json.dumps(job))
        self.assertNotIn("NEVER_PRINT_SECRET", (self.manager.path / (job["job_id"] + ".json")).read_text(encoding="utf-8"))

    def test_queue_cap_then_completion(self):
        release = threading.Event()
        try:
            for _ in range(20):
                self.manager.start("blocked", {}, lambda: release.wait(15))
            with self.assertRaises(NetdiskError) as caught:
                self.manager.start("over-cap", {}, lambda: None)
            self.assertEqual(caught.exception.code, "queue_full")
        finally:
            release.set()
        self.manager.executor.shutdown(wait=True)
        self.assertEqual(len(self.manager.list(100)), 20)
        self.assertTrue(all(job["status"] == "succeeded" for job in self.manager.list(100)))

    def test_restart_marks_pending_interrupted_and_persists_recovery(self):
        self.manager.executor.shutdown(wait=True)
        a, b, c = "a" * 32, "b" * 32, "c" * 32
        for identifier, status, created in ((a, "running", 1), (b, "queued", 2), (c, "succeeded", 3)):
            atomic_json(self.manager.path / (identifier + ".json"),
                        {"job_id": identifier, "status": status, "created_at": created, "owner_pid": 0})
        restored = JobManager(Path(self.temp.name), workers=1)
        try:
            self.assertEqual(restored.get(a)["status"], "interrupted")
            self.assertEqual(restored.get(b)["status"], "interrupted")
            self.assertEqual(restored.get(c)["status"], "succeeded")
            saved = json.loads((restored.path / (a + ".json")).read_text(encoding="utf-8"))
            self.assertEqual(saved["status"], "interrupted")
            self.assertIn("finished_at", saved)
        finally:
            restored.executor.shutdown(wait=True)

    def test_corrupt_or_wrong_schema_records_give_actionable_error(self):
        self.manager.executor.shutdown(wait=True)
        identifier = "d" * 32
        for value in ([], {}, "value", {"status": "queued"},
                      {"job_id": "e" * 32, "status": "succeeded", "created_at": 1}):
            atomic_json(self.manager.path / (identifier + ".json"), value)
            with self.subTest(value=value), self.assertRaises(NetdiskError) as caught:
                self.manager.get(identifier)
            self.assertEqual(caught.exception.code, "job_state_error")

    def test_multiple_managers_share_records_without_interrupting_live_jobs(self):
        started, release = threading.Event(), threading.Event()
        def callback():
            started.set()
            release.wait(15)
            return {"ok": True, "source": "first"}
        first = self.manager.start("live", {}, callback)
        self.assertTrue(started.wait(5))
        second = JobManager(Path(self.temp.name), workers=1)
        try:
            self.assertEqual(second.get(first["job_id"])["status"], "running")
            other = second.start("other", {}, lambda: {"ok": True, "source": "second"})
            second.executor.shutdown(wait=True)
            release.set()
            self.manager.executor.shutdown(wait=True)
            self.assertEqual(self.manager.get(other["job_id"])["result"]["source"], "second")
            self.assertEqual(second.get(first["job_id"])["result"]["source"], "first")
            self.assertEqual(len(second.list()), 2)
        finally:
            release.set()
            second.executor.shutdown(wait=True)

    def test_live_child_owner_is_preserved_and_exit_is_persisted_interrupted(self):
        script = ("import sys,time,threading\nfrom pathlib import Path\n"
                  "from baidu_netdisk.jobs import JobManager\n"
                  "manager=JobManager(Path(sys.argv[1]),workers=1)\n"
                  "job=manager.start('offline',{},lambda: threading.Event().wait(20))\n"
                  "print(job['job_id'],flush=True)\ntime.sleep(20)\n")
        child = subprocess.Popen([getattr(sys, "_base_executable", sys.executable), "-u", "-c", script, self.temp.name],
                                 cwd=str(Path(__file__).resolve().parents[1]),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            identifier = child.stdout.readline().strip()
            self.assertRegex(identifier, r"^[a-f0-9]{32}$")
            live = self.manager.get(identifier)
            self.assertEqual(live["owner_pid"], child.pid)
            self.assertIn(live["status"], ("queued", "running"))
        finally:
            child.terminate()
            child.communicate(timeout=10)
        recovered = self.manager.get(identifier)
        self.assertEqual(recovered["status"], "interrupted")
        saved = json.loads((self.manager.path / (identifier + ".json")).read_text(encoding="utf-8"))
        self.assertEqual(saved["status"], "interrupted")

    def test_unknown_job_and_invalid_limits(self):
        for identifier in ("f" * 32, "missing", "../config", "/absolute"):
            with self.assertRaises(NetdiskError) as caught:
                self.manager.get(identifier)
            self.assertEqual(caught.exception.code, "unknown_job")
        for limit in (0, 101):
            with self.assertRaises(NetdiskError) as caught:
                self.manager.list(limit)
            self.assertEqual(caught.exception.code, "invalid_limit")


if __name__ == "__main__":
    unittest.main()
