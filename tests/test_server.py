"""Official MCP SDK integration against an actual stdio server process.

No Baidu network requests, login prompts, or cloud mutations are performed.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from baidu_netdisk.common import NetdiskError
from baidu_netdisk.config import Settings
from baidu_netdisk.service import NetdiskService

PROJECT = Path(__file__).resolve().parents[1]


def tool_payload(result):
    if result.structuredContent is not None:
        return result.structuredContent
    texts = [entry.text for entry in result.content if entry.type == "text"]
    return json.loads("".join(texts))


class ServerIntegrationTests(unittest.TestCase):
    def test_stdio_cloud_index_read_resource_images_and_file_transfers_with_local_fake_backend(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / "config.json"
            config.write_text(json.dumps({"backend": "pcs", "state_dir": str(root / "state"),
                "allowed_local_roots": [str(root)], "cache_root": str(root / "cache")}), encoding="utf-8")
            source = root / "original.txt"
            source.write_text("上传下载闭环测试\n", encoding="utf-8")
            tree = root / "source-tree"
            (tree / "empty").mkdir(parents=True)
            (tree / "note.txt").write_text("目录文件测试\n", encoding="utf-8")
            asyncio.run(self._check_fake_stdio(config, source, tree, root))

    async def _check_fake_stdio(self, config, source, tree, root):
        png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42kAAAAASUVORK5CYII="
        script = (
            "import sys,base64\nfrom pathlib import Path\n"
            "project=Path(sys.argv[1]);sys.path.insert(0,str(project));sys.path.insert(0,str(project/'tests'))\n"
            "from test_filesystem import FakeBackend\nfrom baidu_netdisk.service import NetdiskService\nimport server\n"
            "backend=FakeBackend();backend.add_dir('/资料')\n"
            "backend.add_file('/资料/说明.txt','正文第一行\\naccess_token=USER_FILE_LITERAL\\n'.encode())\n"
            f"backend.add_file('/资料/picture.png',base64.b64decode('{png}'),fs_id='556')\n"
            "service=NetdiskService(Path(sys.argv[2]));service._structured=lambda:backend\n"
            "server.NetdiskService=lambda config_path=None:service\n"
            "server.create_server(Path(sys.argv[2])).run(transport='stdio')\n"
        )
        env = dict(os.environ)
        env.pop("BAIDU_ACCESS_TOKEN", None)
        env["PYTHONUTF8"] = "1"
        parameters = StdioServerParameters(command=sys.executable,
            args=["-u", "-c", script, str(PROJECT), str(config)], cwd=str(PROJECT), env=env)
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=20)) as session:
                await session.initialize()
                names = {tool.name for tool in (await session.list_tools()).tools}
                self.assertTrue({"netdisk_stat", "netdisk_start_scan", "netdisk_glob", "netdisk_find",
                    "netdisk_read_file", "netdisk_read_bytes", "netdisk_read_image", "netdisk_prepare_file",
                    "netdisk_put_file", "netdisk_get_file", "netdisk_upload_tree", "netdisk_download_tree"}.issubset(names))
                async def call(name, args):
                    return tool_payload(await session.call_tool(name, args))
                async def finish(job_id):
                    deadline = asyncio.get_running_loop().time() + 10
                    while True:
                        job = await call("netdisk_get_job", {"job_id": job_id})
                        if job["status"] not in ("queued", "running"):
                            self.assertEqual(job["status"], "succeeded", repr(job))
                            return job["result"]
                        if asyncio.get_running_loop().time() > deadline:
                            self.fail("Offline fixture job did not complete")
                        await asyncio.sleep(0.02)
                stat = await call("netdisk_stat", {"path": "/资料/说明.txt"})
                self.assertEqual(stat["entry"]["name"], "说明.txt")
                scan = await call("netdisk_start_scan", {"path": "/", "recursive": True})
                receipt = await finish(scan["job_id"])
                self.assertTrue(receipt["complete"])
                indexed = await call("netdisk_glob", {"path": "/", "pattern": "*.txt", "recursive": True})
                self.assertIn("/资料/说明.txt", [entry["path"] for entry in indexed["entries"]])
                prepared = await call("netdisk_read_file", {"remote_path": "/资料/说明.txt"})
                self.assertEqual(prepared["status"], "preparing")
                await finish(prepared["job_id"])
                text = await call("netdisk_read_file", {"remote_path": "/资料/说明.txt", "start_line": 2, "line_count": 1})
                self.assertEqual(text["text"], "access_token=USER_FILE_LITERAL\n")
                self.assertTrue(text["untrusted_content"])
                raw = await call("netdisk_read_bytes", {"remote_path": "/资料/说明.txt", "offset": 0, "limit": 6})
                self.assertEqual(base64.b64decode(raw["data_base64"]), "正文".encode())
                resource = await session.read_resource("baidu://file/" + quote("/资料/说明.txt", safe=""))
                self.assertIn("USER_FILE_LITERAL", json.loads(resource.contents[0].text)["text"])
                prepared_image = await call("netdisk_prepare_file", {"remote_path": "/资料/picture.png"})
                await finish(prepared_image["job_id"])
                image_result = await session.call_tool("netdisk_read_image", {"remote_path": "/资料/picture.png"})
                images = [item for item in image_result.content if item.type == "image"]
                self.assertEqual(len(images), 1)
                self.assertEqual(base64.b64decode(images[0].data), base64.b64decode(png))
                put = await call("netdisk_put_file", {"local_path": str(source), "remote_path": "/自动创建/renamed.md"})
                uploaded = await finish(put["job_id"])
                self.assertTrue(uploaded["verified"])
                target = root / "downloads" / "new-name.txt"
                get = await call("netdisk_get_file", {"remote_path": "/自动创建/renamed.md", "local_path": str(target)})
                await finish(get["job_id"])
                self.assertEqual(target.read_bytes(), source.read_bytes())
                tree_put = await call("netdisk_upload_tree", {"local_dir": str(tree), "remote_dir": "/tree-copy"})
                await finish(tree_put["job_id"])
                tree_target = root / "tree-downloaded"
                tree_get = await call("netdisk_download_tree", {"remote_dir": "/tree-copy", "local_dir": str(tree_target)})
                await finish(tree_get["job_id"])
                self.assertEqual((tree_target / "note.txt").read_bytes(), (tree / "note.txt").read_bytes())
                self.assertTrue((tree_target / "empty").is_dir())

    def test_private_state_is_blocked_before_upload_or_download_is_queued(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            state = root / ".private"
            state.mkdir()
            credential = state / "oauth.dpapi.json"
            credential.write_text("private-test-data", encoding="utf-8")
            for backend in ("openapi", "pcs"):
                service = NetdiskService()
                service._settings = Settings(backend, state, [root], remote_root="/apps/qa-test")
                try:
                    with self.subTest(backend=backend, operation="upload"), self.assertRaises(NetdiskError):
                        service.start_upload(str(credential), "/apps/qa-test/oauth.dpapi.json")
                    with self.subTest(backend=backend, operation="download"), self.assertRaises(NetdiskError):
                        service.start_download(str(credential if backend == "openapi" else state),
                                               remote_path="/remote.txt", fs_id=1, overwrite=(backend == "openapi"))
                    self.assertIsNone(service._jobs)
                    self.assertEqual(credential.read_text(encoding="utf-8"), "private-test-data")
                finally:
                    if service._jobs is not None:
                        service._jobs.executor.shutdown(wait=True)

    def test_stdio_initialization_discovery_status_and_invalid_calls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            allowed = root / "allowed"
            allowed.mkdir()
            config = root / "config.json"
            config.write_text(json.dumps({
                "backend": "openapi", "state_dir": str(root / "state"),
                "allowed_local_roots": [str(allowed)], "remote_root": "/apps/qa-test",
                "client_id": "offline-client", "timeout": 1,
            }), encoding="utf-8")
            asyncio.run(self._check_stdio(config, allowed))

    async def _check_stdio(self, config, allowed):
        env = dict(os.environ)
        env.pop("BAIDU_ACCESS_TOKEN", None)
        env["PYTHONUTF8"] = "1"
        parameters = StdioServerParameters(command=sys.executable,
            args=[str(PROJECT / "server.py"), "--config", str(config.resolve())],
            cwd=str(PROJECT), env=env)
        async with stdio_client(parameters) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=15)) as session:
                initialized = await session.initialize()
                self.assertEqual(initialized.serverInfo.name, "baidu-netdisk")
                tools = {tool.name: tool for tool in (await session.list_tools()).tools}
                required = {"netdisk_status", "netdisk_list", "netdisk_search", "netdisk_start_upload",
                    "netdisk_start_download", "netdisk_get_job", "netdisk_list_jobs", "netdisk_delete",
                    "netdisk_copy", "netdisk_move", "netdisk_rename", "netdisk_mkdir", "netdisk_share"}
                self.assertTrue(required.issubset(tools))
                self.assertTrue(tools["netdisk_status"].annotations.readOnlyHint)
                self.assertTrue(tools["netdisk_delete"].annotations.destructiveHint)
                status = tool_payload(await session.call_tool("netdisk_status", {}))
                self.assertTrue(status["configured"])
                self.assertEqual(status["backend"], "openapi")
                self.assertFalse(status["connection"]["authorized"])
                cases = (
                    ("netdisk_list", {"path": "/../escape"}, "invalid_path"),
                    ("netdisk_list", {"limit": 0}, "invalid_pagination"),
                    ("netdisk_delete", {"paths": ["/"]}, "invalid_path"),
                    ("netdisk_start_upload", {"local_path": str(allowed / "missing.txt"), "remote_path": "/apps/qa-test/a.txt"}, "local_file_missing"),
                    ("netdisk_start_upload", {"local_path": str(allowed.parent / "outside.txt"), "remote_path": "/apps/qa-test/a.txt"}, "local_path_denied"),
                    ("netdisk_get_job", {"job_id": "no-such-job"}, "unknown_job"),
                    ("netdisk_list_jobs", {"limit": 101}, "invalid_limit"),
                    ("netdisk_quota", {}, "login_required"),
                )
                for name, arguments, code in cases:
                    with self.subTest(tool=name, error=code):
                        result = tool_payload(await session.call_tool(name, arguments))
                        self.assertFalse(result["ok"])
                        self.assertEqual(result["error"], code)
                jobs = tool_payload(await session.call_tool("netdisk_list_jobs", {}))
                self.assertEqual(jobs["jobs"], [])
                # A valid local upload request reaches the real background queue.
                # With credentials explicitly absent, authorization fails before
                # any Baidu HTTP request; a second MCP process sees its receipt.
                source = allowed / "offline.txt"
                source.write_text("offline integration fixture", encoding="utf-8")
                started = tool_payload(await session.call_tool("netdisk_start_upload", {
                    "local_path": str(source), "remote_path": "/apps/qa-test/offline.txt"}))
                self.assertRegex(started["job_id"], r"^[a-f0-9]{32}$")
                async with stdio_client(parameters) as (second_read, second_write):
                    async with ClientSession(second_read, second_write,
                                             read_timeout_seconds=timedelta(seconds=15)) as second:
                        await second.initialize()
                        deadline = asyncio.get_running_loop().time() + 5
                        while True:
                            receipt = tool_payload(await second.call_tool("netdisk_get_job", {"job_id": started["job_id"]}))
                            if receipt["status"] not in ("queued", "running"):
                                break
                            if asyncio.get_running_loop().time() > deadline:
                                self.fail("Offline authorization failure did not produce a final receipt")
                            await asyncio.sleep(0.02)
                        self.assertEqual(receipt["status"], "failed")
                        self.assertEqual(receipt["result"]["error"], "login_required")
                        observed = tool_payload(await second.call_tool("netdisk_list_jobs", {}))
                        self.assertEqual(len(observed["jobs"]), 1)


if __name__ == "__main__":
    unittest.main()
