"""Safety and command-mapping tests; these never contact Baidu or a real account."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from baidu_netdisk.pcs import PcsBackend, _redact


def meta(path: str, *, directory: bool = False, size: int = 3) -> str:
    kind = "目录" if directory else "文件"
    noun = "目录" if directory else "文件"
    return f"[0] - [{path}] --------------\n类型 {kind}\n{noun}路径 {path}\n{noun}名称 {Path(path).name}\n文件大小 {size}, 3B\napp_id 1\nfs_id 123\n"


NOT_FOUND = "获取文件/目录的元信息: 遇到错误, 远端服务器返回错误, 代码: 31066, 消息: 文件不存在\n"


class PcsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.exe = self.root / "BaiduPCS-Go.exe"
        self.exe.touch()
        self.config = self.root / "private-config"
        self.backend = PcsBackend(str(self.exe), self.config, [self.root])
        self.calls: list[tuple[list[str], dict]] = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    def runner(self, responses: list[str | tuple[int, str, str]]):
        def run(args: list[str], **kwargs):
            self.calls.append((args, kwargs))
            response = responses.pop(0)
            code, out, err = (0, response, "") if isinstance(response, str) else response
            kwargs["stdout"].write(out.encode("utf-8"))
            kwargs["stderr"].write(err.encode("utf-8"))
            return subprocess.CompletedProcess(args, code)
        return run

    def test_status_missing_binary_is_usable_without_login(self):
        self.exe.unlink()
        result = self.backend.status()
        self.assertTrue(result["ok"])
        self.assertFalse(result["installed"])
        self.assertFalse(result["logged_in"])

    def test_status_without_logged_in_account_and_isolated_config(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            "当前帐号 uid: 0, 用户名: , 性别: , 年龄: 0.0\n"
        ])):
            result = self.backend.status()
        self.assertTrue(result["ok"])
        self.assertTrue(result["installed"])
        self.assertFalse(result["logged_in"])
        args, kwargs = self.calls[0]
        self.assertEqual(args, [str(self.exe), "who"])
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["cwd"], str(self.config))
        self.assertEqual(kwargs["env"]["BAIDUPCS_GO_CONFIG_DIR"], str(self.config))
        self.assertEqual(kwargs["env"]["BAIDUPCS_GO_VERBOSE"], "0")

    def test_zero_exit_remote_error_is_not_success(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([NOT_FOUND])):
            result = self.backend.file_info("/missing.txt")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "not_found")

    def test_actual_zero_exit_socket_failure_is_network_error(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            '获取文件/目录的元信息: 网络错误, Post "https://pcs.baidu.com/rest/2.0/pcs/file": '
            'dial tcp 36.110.192.115:443: connectex: An attempt was made to access a socket in a way forbidden by its access permissions.\n'
        ])):
            result = self.backend.file_info("/")
        self.assertFalse(result["ok"])
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["error"]["code"], "network_error")

    def test_actual_unauthenticated_baidu_responses_are_authentication_required(self):
        responses = [
            "获取文件/目录的元信息: 遇到错误, 远端服务器返回错误, 代码: 31045, "
            "消息: 操作失败, 可能百度帐号登录状态过期, 请尝试重新登录, 消息: user not exists\n",
            "获取目录下的文件列表: 遇到错误, 远端服务器返回错误, 代码: -6, 消息: 请重新登录",
        ]
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner(responses)):
            for result in (self.backend.file_info("/"), self.backend.list_files("/")):
                self.assertFalse(result["ok"])
                self.assertEqual(result["returncode"], 0)
                self.assertEqual(result["error"]["code"], "authentication_required")

    def test_nonzero_exit_is_not_success_even_with_success_marker(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([(3, "总空间: 1TB, 已用空间: 1GB", "error")])):
            result = self.backend.quota()
        self.assertFalse(result["ok"])
        self.assertEqual(result["returncode"], 3)

    def test_text_that_does_not_confirm_completion_fails_closed(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner(["NAME: BaiduPCS-Go mkdir\nUSAGE: ...\n"])):
            result = self.backend._execute("mkdir", ["mkdir", "/x"], success="创建目录成功:")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "unrecognized_output")

    def test_metadata_must_match_requested_path(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([meta("/other.txt")])):
            result = self.backend.file_info("/requested.txt")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "unrecognized_output")

    def test_metadata_success_is_structured(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([meta("/中文 文档.txt")])):
            result = self.backend.file_info("/中文 文档.txt")
        self.assertTrue(result["ok"])
        self.assertEqual(result["file"], {"path": "/中文 文档.txt", "name": "中文 文档.txt", "fs_id": "123", "is_dir": False, "size": 3})

    def test_wildcards_traversal_and_root_mutations_rejected_before_execution(self):
        for path in ("relative", "/x/../y", "/x/./y", "/x/*", "/x/[a]", "/x\\y", "/x\ny", "//x"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.backend.list_files(path)
        for paths in (["/"], ["/a", "/a"], "/a", []):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                self.backend.delete(paths)
        self.assertFalse(self.calls)

    def test_search_keyword_cannot_be_interpreted_as_flag(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner(["文件总数: 0, 目录总数: 0\n"])):
            result = self.backend.search("-path=/unexpected")
        self.assertTrue(result["ok"])
        self.assertEqual(self.calls[0][0][1:], ["search", "-path=/", "-r", "--", "-path=/unexpected"])

    def test_local_path_must_be_inside_allowlist(self):
        outside = self.root.parent / "outside.txt"
        with self.assertRaises(ValueError):
            self.backend.upload(outside, "/")
        with self.assertRaises(ValueError):
            self.backend.upload(str(self.root / ".." / "something"), "/")

    def test_upload_would_not_include_private_credentials(self):
        self.config.mkdir()
        credential = self.config / "pcs_config.json"
        credential.write_text("sensitive", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.backend.upload(credential, "/")
        with self.assertRaises(ValueError):
            self.backend.upload(self.root, "/")

    def test_upload_sets_skip_and_preserves_exact_argument_paths(self):
        local = self.root / "中文 file.txt"
        local.write_bytes(b"abc")
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            meta("/目标", directory=True), NOT_FOUND, "上传结束, 时间: 1s, 总大小: 3B\n", meta("/目标/中文 file.txt", size=3)
        ])):
            result = self.backend.upload(local, "/目标")
        self.assertTrue(result["ok"])
        self.assertFalse(result["overwrite"])
        self.assertEqual(result["remote_path"], "/目标/中文 file.txt")
        self.assertEqual(self.calls[-2][0][1:], ["upload", "-policy=skip", "-norapid", "-p=1", "-l=1", "-retry=1", str(local), "/目标"])
        self.assertEqual(self.calls[-2][1]["timeout"], 3600)
        self.assertEqual(result["verification"], "remote_metadata_size_matches_unchanged_local_file")

    def test_upload_success_text_with_wrong_remote_size_is_failure(self):
        local = self.root / "file.txt"
        local.write_bytes(b"abc")
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            meta("/目标", directory=True), NOT_FOUND, "上传结束, 时间: 1s, 总大小: 3B\n", meta("/目标/file.txt", size=0)
        ])):
            result = self.backend.upload(local, "/目标")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "verification_failed")

    def test_upload_collision_does_not_launch_transfer(self):
        local = self.root / "file.txt"
        local.write_bytes(b"abc")
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            meta("/目标", directory=True), meta("/目标/file.txt")
        ])):
            result = self.backend.upload(local, "/目标")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "already_exists")
        self.assertEqual(len(self.calls), 2)

    def test_unknown_preflight_error_does_not_launch_mutation(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner(["遇到错误, 代码: 31034, 消息: 用户未登录\n"])):
            result = self.backend.mkdir("/new")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "preflight_failed")
        self.assertEqual(len(self.calls), 1)

    def test_rename_does_not_overwrite_an_existing_target(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([meta("/dir/new.txt")])):
            result = self.backend.rename("/dir/old.txt", "new.txt")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "already_exists")
        self.assertEqual(len(self.calls), 1)

    def test_move_has_directory_and_collision_preflights(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            meta("/dest", directory=True), NOT_FOUND, "操作成功, 以下文件/目录移动成功:\n/a -> /dest/a\n"
        ])):
            result = self.backend.move(["/a"], "/dest")
        self.assertTrue(result["ok"])
        self.assertEqual(self.calls[-1][0][1:], ["mv", "/a", "/dest"])

    def test_move_into_descendant_and_ambiguous_names_rejected(self):
        with self.assertRaises(ValueError):
            self.backend.move(["/a"], "/a/child")
        with self.assertRaises(ValueError):
            self.backend.copy(["/a/f", "/b/f"], "/dest")

    def test_download_directory_and_windows_unsafe_basename_rejected(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([meta("/folder", directory=True)])):
            result = self.backend.download("/folder", self.root / "downloads")
        self.assertEqual(result["error"]["code"], "unsupported")
        for name in ("CON.txt", "a:b", "name.", "name "):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.backend.download("/" + name, self.root / "downloads")

    def test_download_does_not_overwrite_local_file(self):
        local_dir = self.root / "downloads"
        local_dir.mkdir()
        target = local_dir / "file.txt"
        target.write_bytes(b"previous")
        result = self.backend.download("/file.txt", local_dir)
        self.assertEqual(result["error"]["code"], "already_exists")
        self.assertEqual(target.read_bytes(), b"previous")
        self.assertFalse(self.calls)

    def test_download_checks_expected_file_and_size(self):
        local_dir = self.root / "downloads"
        runner = self.runner([meta("/file.txt", size=3), "下载结束, 时间: 1s, 数据总量: 3B\n"])
        def run(args, **kwargs):
            if args[1] == "download":
                (local_dir / "file.txt").write_bytes(b"abc")
            return runner(args, **kwargs)
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=run):
            result = self.backend.download("/file.txt", local_dir)
        self.assertTrue(result["ok"])
        self.assertNotIn("-ow", self.calls[-1][0])
        self.assertIn("-saveto=" + str(local_dir), self.calls[-1][0])

    def test_download_success_text_without_file_does_not_report_success(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            meta("/file.txt"), "下载结束, 时间: 1s, 数据总量: 0B\n"
        ])):
            result = self.backend.download("/file.txt", self.root / "downloads")
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "verification_failed")

    def test_partial_transfer_failure_with_zero_exit_is_not_success(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            "下载结束, 时间: 1s, 数据总量: 0B\n以下文件下载失败:\n/file.txt\n"
        ])):
            result = self.backend._execute("download", ["download", "/file.txt"], success="下载结束,")
        self.assertFalse(result["ok"])

    def test_output_truncation_does_not_hide_a_final_error(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            "文件总数: 10\n" + "long-progress\n" * 3000 + "遇到错误, 远端服务器返回错误, 代码: 1\n"
        ])):
            result = self.backend.list_files("/")
        self.assertFalse(result["ok"])
        self.assertTrue(result["output_truncated"])
        self.assertLessEqual(len(result["stdout"]), 24000)

    def test_timeout_is_structured_and_remote_uncertainty_disclosed(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=subprocess.TimeoutExpired("pcs", 60)):
            result = self.backend.quota()
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "timeout")
        self.assertIn("may have changed", result["error"]["message"])

    def test_share_and_cancel_map_only_to_fixed_commands(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            "shareID: 123, 链接: https://pan.baidu.com/s/abc, 密码: a1B2\n", "取消分享链接成功\n"
        ])):
            result = self.backend.share(["/file.txt"], "a1B2", 7)
            canceled = self.backend.cancel_share([123])
        self.assertTrue(result["ok"])
        self.assertEqual(result["share"]["share_id"], "123")
        self.assertEqual(result["share"]["extraction_code"], "a1B2")
        self.assertEqual(self.calls[0][0][1:], ["share", "set", "-p=a1B2", "-period=7", "/file.txt"])
        self.assertTrue(canceled["ok"])
        self.assertEqual(self.calls[1][0][1:], ["share", "cancel", "123"])

    def test_invalid_share_values_are_rejected(self):
        for value in ("", "公开分享", "abc", "abcde", "--run=x"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.backend.share(["/file.txt"], value)
        for ids in ([0], [-1], [True], ["x"], [2**63], []):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                self.backend.cancel_share(ids)

    def test_credentials_are_redacted_from_output(self):
        raw = ('BDUSS=secret1 STOKEN=secret2 PTOKEN=secret3\nCookie: BDUSS=secret4; BAIDUID=secret5\n'
               'access_token=secret6\n"password": "secret7 secret8"\nAuthorization: Bearer secret9\n'
               "bdstoken='secret10 secret11'\n")
        redacted = _redact(raw)
        for secret in ("secret1", "secret2", "secret3", "secret4", "secret5", "secret6", "secret7", "secret8", "secret9", "secret10", "secret11"):
            self.assertNotIn(secret, redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_nonexistence_code_whitelist_is_specific(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            "获取文件/目录的元信息: 遇到错误, 远端服务器返回错误, 代码: 31064\n"
        ])):
            result = self.backend.mkdir("/new")
        self.assertEqual(result["error"]["code"], "preflight_failed")
        self.assertEqual(len(self.calls), 1)

    def test_filename_containing_failure_word_does_not_change_success(self):
        with patch("baidu_netdisk.pcs.subprocess.run", side_effect=self.runner([
            NOT_FOUND, "创建目录成功: /失败\n"
        ])):
            result = self.backend.mkdir("/失败")
        self.assertTrue(result["ok"])

    def test_linked_upload_path_is_rejected(self):
        local = self.root / "link.txt"
        target = self.root / "target.txt"
        target.write_bytes(b"abc")
        try:
            local.symlink_to(target)
        except OSError:
            self.skipTest("Creating symbolic links requires local privileges.")
        with self.assertRaises(ValueError):
            self.backend.upload(local, "/")

    def test_malformed_timeout_is_rejected(self):
        for timeout in (True, 0, -1, "3600", 86401):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.backend._execute("quota", ["quota"], timeout=timeout)

    def test_shell_script_executable_is_rejected(self):
        for name in ("evil.cmd", "evil.bat", "evil.ps1", "evil.sh"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                PcsBackend(str(self.root / name), self.config, [self.root])


if __name__ == "__main__":
    unittest.main()
