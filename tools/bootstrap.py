"""Download the pinned upstream Windows binary and verify GitHub asset digests."""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = "v4.0.2"
HASHES = {
    "x64": "ce72b3155a710b7c4a2b15611c3aebd11a057d7cccf0529e7703bdde04f0aa30",
    "arm64": "576f7a7ab6df05996089edf766793c6bd083f19dc109fd9cf2d29b70c943191d",
    "x86": "cd9eae3d3251a211382a199b0ad98855fe749a987558a6e7650bd7c536c9ee42",
}


def main():
    if os.name != "nt":
        raise SystemExit("This bootstrap installs the Windows BaiduPCS-Go build only.")
    architecture = platform.machine().lower()
    arch = "arm64" if architecture in ("arm64", "aarch64") else "x64" if architecture in ("amd64", "x86_64") else "x86"
    url = f"https://github.com/qjfoidnh/BaiduPCS-Go/releases/download/{VERSION}/BaiduPCS-Go-{VERSION}-windows-{arch}.zip"
    print(f"Downloading official upstream {VERSION} ({arch})...", flush=True)
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "baidu-netdisk-plugin/0.1"}), timeout=60) as response:
        payload = response.read(16 * 1024 * 1024 + 1)
    if len(payload) > 16 * 1024 * 1024:
        raise SystemExit("Release archive is unexpectedly large.")
    digest = hashlib.sha256(payload).hexdigest()
    if digest != HASHES[arch]:
        raise SystemExit("SHA-256 mismatch; nothing was installed.")
    binary_dir = ROOT / "bin"
    binary_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        binaries = [info for info in archive.infolist() if Path(info.filename).name.lower() == "baidupcs-go.exe"]
        if len(binaries) != 1 or binaries[0].file_size > 64 * 1024 * 1024:
            raise SystemExit("Release archive has an unexpected executable layout.")
        # Extract only the exact binary; archive paths are never used as local paths.
        executable = archive.read(binaries[0])
    target = binary_dir / "BaiduPCS-Go.exe"
    temporary = binary_dir / "BaiduPCS-Go.exe.tmp"
    temporary.write_bytes(executable)
    os.replace(temporary, target)
    (binary_dir / "provenance.json").write_text(json.dumps({
        "version": VERSION, "source": url, "archive_sha256": digest,
        "executable_sha256": hashlib.sha256(executable).hexdigest(),
        "upstream": "https://github.com/qjfoidnh/BaiduPCS-Go",
    }, indent=2), encoding="utf-8")
    print("Installed and verified: " + str(target))


if __name__ == "__main__":
    main()
