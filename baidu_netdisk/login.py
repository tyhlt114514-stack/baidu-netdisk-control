"""Local session import with diagnostics that never echo credential-bearing output."""
from __future__ import annotations

import re

from .common import NetdiskError


def normalize_cookie(raw: str) -> str:
    value = raw.strip()
    for _ in range(2):
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1].strip()
        value = re.sub(r"(?i)^cookies?\s*:\s*", "", value)
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise NetdiskError("invalid_cookie", "请粘贴 Cookie 请求头的单行值；不要复制整组请求头。")
    fields = {}
    for segment in value.split(";"):
        key, separator, content = segment.strip().partition("=")
        if separator and key:
            fields[key] = content
    if not fields.get("BDUSS"):
        hint = "只包含 BDUSS_BFESS，缺少此客户端需要的 BDUSS。" if fields.get("BDUSS_BFESS") else "缺少 BDUSS 登录字段。"
        raise NetdiskError("cookie_missing_bduss", hint + "请从已登录 pan.baidu.com 的实际请求中复制完整 Cookie。",
                           {"has_bduss": False, "has_bduss_bfess": bool(fields.get("BDUSS_BFESS"))})
    return value


def normalize_login_input(raw: str, kind: str = "cookie") -> str:
    """Keep a copied cookie value distinct from a complete Cookie header."""
    if kind == "cookie":
        return normalize_cookie(raw)
    if kind != "bduss":
        raise NetdiskError("invalid_credential_type", "请选择完整 Cookie 或仅 BDUSS 值。")
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1].strip()
    if value.startswith("BDUSS="):
        value = value[len("BDUSS="):]
    if not value or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value) or ";" in value:
        raise NetdiskError("invalid_bduss", "请粘贴 BDUSS 这一项的完整值；复制了完整 Cookie 时请选择对应选项。")
    if "*" in value or "…" in value or "..." in value:
        raise NetdiskError("invalid_bduss", "请在本地输入完整 BDUSS，不能使用打码或省略后的片段。")
    if "=" in value.rstrip("="):
        raise NetdiskError("invalid_bduss", "这个输入包含 Cookie 字段名，请检查选择的是 BDUSS，并只复制它的值。")
    return normalize_cookie("BDUSS=" + value)


def diagnose_login(stdout: bytes | str, stderr: bytes | str, returncode: int) -> dict:
    # Recognize fixed signals only; arbitrary output may contain credentials.
    def decode(value):
        return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
    text = decode(stdout) + "\n" + decode(stderr)
    codes = sorted(set(re.findall(r"(?i)(?:错误码|错误代码|errno|error_code|代码)\s*[:=]\s*(-?\d{1,9})\b", text)))
    if re.search(r"(?i)permission denied|access is denied|拒绝访问|权限不足", text):
        category = "configuration_permission"
        hint = "本地网盘配置目录无访问权限，请用当前 Windows 用户重新运行 setup.ps1。"
    elif re.search(r"(?i)Incorrect Usage|flag provided but not defined|invalid argument", text):
        category = "command_arguments"
        hint = "命令行参数解析失败，正在使用的网盘程序与插件不匹配。"
    elif re.search(r"(?i)connectex|connection refused|timed? ?out|TLS handshake|certificate|网络错误|no such host", text):
        category = "network"
        hint = "网盘登录请求的网络或 TLS 连接失败，请检查系统网络和代理。"
    elif re.search(r"(?i)captcha|verify|验证码|验证手机|验证邮箱|风控", text):
        category = "baidu_verification"
        hint = "百度要求额外验证，请在百度官网本人完成验证后重新导入登录会话。"
    elif re.search(r"(?i)BDUSS.*(?:不合法|无效|为空)|cookie.*(?:invalid|empty)|重新登录|登录失效|user not exists", text):
        category = "session_invalid"
        hint = "百度没有接受这份登录会话，请从本人当前已登录网盘的请求重新复制完整 Cookie。"
    elif re.search(r"(?i)FATAL ERROR.*config|config file error|配置.*错误|保存.*失败", text):
        category = "configuration_error"
        hint = "网盘配置读取或保存失败；请检查插件的 .private/pcs 目录。"
    else:
        category = "upstream_login_failed"
        hint = "网盘程序未确认登录。可尝试本地 BDUSS/STOKEN 入口；请勿把凭据发到聊天。"
    return {"backend_exit_code": returncode, "category": category, "error_codes": codes,
            "hint": hint, "raw_output_hidden": True}


def masked_cookie_dialog() -> str:
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk()
    root.title("百度网盘 · 本地账号授权")
    root.geometry("650x320")
    root.resizable(False, False)
    result = {"value": None}
    tk.Label(root, text="在本机粘贴本人百度网盘的登录凭据，并选择复制的内容类型。\n凭据仅用于百度网盘授权，不会发送到 Codex 聊天。",
             justify="left", anchor="w").pack(fill="x", padx=18, pady=(18, 12))
    kind = tk.StringVar(value="cookie")
    choices = tk.Frame(root)
    choices.pack(fill="x", padx=18, pady=(0, 10))
    tk.Radiobutton(choices, text="完整 Cookie（BDUSS=值; …）", variable=kind, value="cookie").pack(side="left")
    tk.Radiobutton(choices, text="仅 BDUSS 值（浏览器中 BDUSS 行的值）", variable=kind, value="bduss").pack(side="left", padx=12)
    entry = tk.Entry(root, show="●", width=78)
    entry.pack(padx=18, fill="x")
    entry.focus_set()
    tk.Label(root, text="可以按 Ctrl+V，或点击下方“从剪贴板粘贴”。输入始终隐藏。", anchor="w").pack(fill="x", padx=18, pady=12)

    def paste():
        try:
            entry.delete(0, "end")
            entry.insert(0, root.clipboard_get())
        except tk.TclError:
            messagebox.showerror("无法粘贴", "剪贴板中没有可用的文本。", parent=root)

    def submit():
        try:
            result["value"] = normalize_login_input(entry.get(), kind.get())
            entry.delete(0, "end")
            root.destroy()
        except NetdiskError as exc:
            messagebox.showerror("检查输入", exc.message, parent=root)

    buttons = tk.Frame(root)
    buttons.pack(pady=4)
    tk.Button(buttons, text="从剪贴板粘贴", command=paste, width=20).pack(side="left", padx=8)
    tk.Button(buttons, text="授权", command=submit, width=14).pack(side="left", padx=8)
    tk.Button(buttons, text="取消", command=root.destroy, width=14).pack(side="left", padx=8)
    root.mainloop()
    if result["value"] is None:
        raise NetdiskError("login_cancelled", "本地授权已取消。")
    return result["value"]
