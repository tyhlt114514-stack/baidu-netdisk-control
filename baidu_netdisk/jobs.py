from __future__ import annotations

import concurrent.futures
import json
import os
import re
import threading
import time
import uuid
from pathlib import Path

from .common import NetdiskError, atomic_json, process_alive, redact


class JobManager:
    """Persist each transfer separately so multiple MCP sessions share receipts."""

    def __init__(self, state_dir: Path, workers: int = 2):
        self.path = state_dir / "jobs"
        self.lock = threading.RLock()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="netdisk")
        self.path.mkdir(parents=True, exist_ok=True)

    def _job_path(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(r"[a-f0-9]{32}", identifier):
            raise NetdiskError("unknown_job", "任务编号无效。")
        return self.path / (identifier + ".json")

    def _read(self, identifier):
        path = self._job_path(identifier)
        if not path.exists():
            raise NetdiskError("unknown_job", "任务编号不存在。")
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(job, dict) or job.get("job_id") != identifier or
                    not isinstance(job.get("created_at"), (int, float)) or
                    job.get("status") not in ("queued", "running", "succeeded", "failed", "interrupted")):
                raise ValueError("invalid record")
            if job["status"] in ("queued", "running") and not process_alive(int(job.get("owner_pid", 0))):
                job.update(status="interrupted", finished_at=time.time(),
                           message="上次传输进程已退出，请核对网盘后重新提交。")
                atomic_json(path, job)
            return job
        except (ValueError, TypeError, KeyError, OSError):
            raise NetdiskError("job_state_error", "传输任务记录损坏，请检查 .private/jobs。") from None

    def start(self, operation: str, args: dict, callback) -> dict:
        with self.lock:
            records = [self._read(p.stem) for p in self.path.glob("*.json")]
            if sum(j["status"] in ("queued", "running") for j in records) >= 20:
                raise NetdiskError("queue_full", "已有 20 个未完成任务，请稍后再试。")
            identifier = uuid.uuid4().hex
            record = {"job_id": identifier, "operation": operation, "arguments": redact(args),
                      "status": "queued", "created_at": time.time(), "owner_pid": os.getpid()}
            atomic_json(self._job_path(identifier), record)
            self.executor.submit(self._run, identifier, callback)
            return dict(record)

    def _run(self, identifier, callback):
        with self.lock:
            job = self._read(identifier)
            job.update(status="running", started_at=time.time())
            atomic_json(self._job_path(identifier), job)
        try:
            result = callback()
            outcome = {"status": "succeeded", "result": redact(result)}
            if isinstance(result, dict) and result.get("ok") is False:
                outcome["status"] = "failed"
        except NetdiskError as exc:
            outcome = {"status": "failed", "result": exc.as_dict()}
        except Exception as exc:
            # Stack traces can contain credentials and URLs. Return only the type.
            outcome = {"status": "failed", "result": {"ok": False, "error": type(exc).__name__,
                                                        "message": "传输异常；请核对本地文件和网盘状态。"}}
        with self.lock:
            job.update(**outcome, finished_at=time.time())
            atomic_json(self._job_path(identifier), job)

    def get(self, identifier: str) -> dict:
        with self.lock:
            return redact(self._read(identifier))

    def list(self, limit: int = 20) -> list:
        if not 1 <= limit <= 100:
            raise NetdiskError("invalid_limit", "limit 应在 1 到 100 之间。")
        with self.lock:
            records = [self._read(p.stem) for p in self.path.glob("*.json")]
            return redact(sorted(records, key=lambda j: j["created_at"], reverse=True)[:limit])
