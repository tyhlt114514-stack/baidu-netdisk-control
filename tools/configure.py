from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from baidu_netdisk.common import atomic_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=["pcs", "openapi"])
    parser.add_argument("--client-id")
    parser.add_argument("--app-name")
    args = parser.parse_args()
    path = ROOT / "config.json"
    if path.exists():
        config = json.loads(path.read_text(encoding="utf-8-sig"))
        if args.backend:
            config["backend"] = args.backend
        if args.client_id is not None:
            config["client_id"] = args.client_id
        if args.app_name is not None:
            config["remote_root"] = "/apps/" + args.app_name
        atomic_json(path, config)
    else:
        atomic_json(path, {"backend": args.backend or "pcs", "state_dir": str(ROOT / ".private"),
                           "allowed_local_roots": [str(ROOT.parent)],
                           "pcs_executable": str(ROOT / "bin" / "BaiduPCS-Go.exe"),
                           "client_id": args.client_id or "", "remote_root": "/apps/" + (args.app_name or "baidu-netdisk"),
                           "redirect_uri": "oob", "timeout": 60})
    server = {"command": sys.executable,
              "args": ["-X", "utf8", str(ROOT / "server.py"), "--config", str(path)],
              "cwd": str(ROOT), "startup_timeout_sec": 20, "tool_timeout_sec": 120}
    atomic_json(ROOT / ".mcp.json", {"mcpServers": {"baidu_netdisk": server}})
    atomic_json(ROOT / "mcp.json", {"$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
                                    "mcpServers": {"baidu_netdisk": {"type": "stdio", **server}}})
    atomic_json(ROOT / "runtime.json", {"python": sys.executable})
    # Publish only tool wiring and instructions. Never cache local credentials or binaries as plugin source.
    package = ROOT / "plugin"
    (package / ".codex-plugin").mkdir(parents=True, exist_ok=True)
    (package / "skills" / "baidu-netdisk").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / ".codex-plugin" / "plugin.json", package / ".codex-plugin" / "plugin.json")
    shutil.copyfile(ROOT / ".mcp.json", package / ".mcp.json")
    shutil.copyfile(ROOT / "skills" / "baidu-netdisk" / "SKILL.md", package / "skills" / "baidu-netdisk" / "SKILL.md")
    # Resolve the runtime docs/CLI references from a cached copy of the skill.
    skill = package / "skills" / "baidu-netdisk" / "SKILL.md"
    skill.write_text(skill.read_text(encoding="utf-8") + "\nRuntime directory: `" + str(ROOT) + "`. Its runtime.json, cli.py, README.md and login scripts remain there.\n", encoding="utf-8")
    print("Configured " + str(path))


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    main()
