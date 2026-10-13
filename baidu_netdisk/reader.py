"""Bounded, offline reading of files materialized by the Netdisk service.

File content is data, never instructions. No external relationships, macros,
embedded executables or network resources are executed or fetched by this module.
"""
from __future__ import annotations

import base64
import codecs
import hashlib
import json
import os
import posixpath
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Callable, Iterator
from xml.etree import ElementTree as ET

from .common import NetdiskError, atomic_json, checked_local, file_lock, normalize_remote

_EXTRACT_VERSION = 1
_CHUNK = 16 * 1024
_XML_LIMIT = 64 * 1024 * 1024
_ARCHIVE_LIMIT = 128 * 1024 * 1024
_EXTRACT_LIMIT = 128 * 1024 * 1024
_TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl", ".xml",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".log", ".sql",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".css", ".html", ".htm", ".tex",
    ".c", ".cpp", ".h", ".hpp", ".java", ".cs", ".go", ".rs", ".sh",
    ".ps1", ".bat", ".lps", ".srt", ".vtt", ".rtf", ".svg",
}
_BINARY_EXTENSIONS = {".exe", ".dll", ".bin", ".so", ".dylib", ".mp3", ".mp4",
                      ".avi", ".mov", ".wav", ".7z", ".rar", ".gz", ".doc", ".xls", ".ppt"}


def _tag(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class _SafeXmlStream:
    """Reject DTD/entities before ElementTree can expand document-provided data."""
    def __init__(self, stream):
        self.stream, self.tail = stream, b""

    def read(self, size=-1):
        data = self.stream.read(_CHUNK if size < 0 else min(size, _CHUNK))
        probe = (self.tail + data).replace(b"\x00", b"").upper()
        if b"<!DOCTYPE" in probe or b"<!ENTITY" in probe:
            raise NetdiskError("unsafe_document_xml", "文档 XML 含 DTD 或实体声明，已停止解析。")
        self.tail = data[-64:]
        return data


def _elements(archive: zipfile.ZipFile, member: str):
    try:
        info = archive.getinfo(member)
    except KeyError:
        raise NetdiskError("invalid_document", "文档缺少必需的内部文件。", {"member": member}) from None
    if info.file_size > _XML_LIMIT:
        raise NetdiskError("extraction_limit", "文档内部 XML 超过安全读取上限。")
    with archive.open(info) as source:
        parents = []
        for event, element in ET.iterparse(_SafeXmlStream(source), events=("start", "end")):
            if event == "start":
                parents.append(element)
                continue
            yield event, element
            if len(parents) > 1:
                parents[-2].remove(element)
            parents.pop()


def _check_archive(archive):
    if sum(item.file_size for item in archive.infolist()) > _ARCHIVE_LIMIT:
        raise NetdiskError("extraction_limit", "文档解压大小超过 128 MiB 读取上限。")
    if len(archive.infolist()) > 20000:
        raise NetdiskError("extraction_limit", "文档内部文件数量过多。")


def _text_fragment_is_safe(text: str) -> bool:
    # NUL and C0/C1 controls are strong binary signals. Whitespace used by text
    # documents is allowed, including form feed between printed pages.
    return not any((ord(character) < 32 and character not in "\t\n\r\f") or
                   127 <= ord(character) <= 159 for character in text)


def _detect_encoding(sample: bytes) -> str | None:
    if sample.startswith(codecs.BOM_UTF32_LE) or sample.startswith(codecs.BOM_UTF32_BE):
        return None
    if sample.startswith(codecs.BOM_UTF8):
        candidates = ["utf-8-sig"]
    elif sample.startswith(codecs.BOM_UTF16_LE) or sample.startswith(codecs.BOM_UTF16_BE):
        candidates = ["utf-16"]
    else:
        if b"\x00" in sample:
            return None
        candidates = ["utf-8", "gb18030"]
    for encoding in candidates:
        try:
            decoded = codecs.getincrementaldecoder(encoding)(errors="strict").decode(sample, final=False)
        except UnicodeError:
            continue
        if _text_fragment_is_safe(decoded):
            return encoding
    return None


class FileReader:
    def __init__(self, cache_root: Path,
                 resolve_local_callback: Callable[[str], dict], *,
                 max_page_lines: int = 200, max_page_bytes: int = 65536):
        self.cache_root = Path(cache_root).resolve()
        self.resolve_local = resolve_local_callback
        if (isinstance(max_page_lines, bool) or not isinstance(max_page_lines, int) or max_page_lines < 1 or
                isinstance(max_page_bytes, bool) or not isinstance(max_page_bytes, int) or max_page_bytes < 1):
            raise ValueError("Reader page limits must be positive integers")
        self.max_page_lines, self.max_page_bytes = max_page_lines, max_page_bytes

    def _materialized(self, remote_path):
        remote_path = normalize_remote(remote_path, allow_root=False)
        result = self.resolve_local(remote_path)
        if not isinstance(result, dict) or result.get("ok") is False or not result.get("local_path"):
            raise NetdiskError("materialize_failed", "网盘文件尚未成功下载到读取缓存。")
        local = checked_local(result["local_path"], [self.cache_root], must_exist=True)
        base = {"ok": True, "remote_path": remote_path, "local_path": str(local),
                "size": local.stat().st_size, "untrusted_content": True}
        if isinstance(result.get("entry"), dict):
            base["entry"] = result["entry"]
        return local, base

    def _page_arguments(self, start_line, line_count, max_bytes):
        max_bytes = self.max_page_bytes if max_bytes is None else max_bytes
        for name, value, lower, upper in (("start_line", start_line, 1, 2 ** 63 - 1),
                                         ("line_count", line_count, 1, self.max_page_lines),
                                         ("max_bytes", max_bytes, 1, self.max_page_bytes)):
            if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                raise NetdiskError("invalid_read_range", f"{name} 应为 {lower}..{upper} 的整数。")
        return max_bytes

    @staticmethod
    def _kind(local: Path):
        with local.open("rb") as source:
            sample = source.read(65536)
        suffix = local.suffix.lower()
        if sample.startswith(b"\x89PNG\r\n\x1a\n"):
            return "image", "png", "image/png", None
        if sample.startswith(b"\xff\xd8\xff"):
            return "image", "jpeg", "image/jpeg", None
        if sample.startswith((b"GIF87a", b"GIF89a")):
            return "image", "gif", "image/gif", None
        if sample.startswith(b"BM") and len(sample) >= 26 and sample[6:10] == b"\x00" * 4:
            return "image", "bmp", "image/bmp", None
        if sample.startswith((b"II*\x00", b"MM\x00*")):
            return "image", "tiff", "image/tiff", None
        if sample[:4] == b"RIFF" and sample[8:12] == b"WEBP":
            return "image", "webp", "image/webp", None
        if b"%PDF-" in sample[:1024]:
            return "document", "pdf", "application/pdf", None
        if sample.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
            try:
                with zipfile.ZipFile(local) as archive:
                    names = set(archive.namelist())
                    if "word/document.xml" in names:
                        return "document", "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", None
                    if "xl/workbook.xml" in names:
                        return "document", "xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", None
                    if "ppt/presentation.xml" in names:
                        return "document", "pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation", None
            except (zipfile.BadZipFile, OSError):
                pass
            return "binary", "zip", "application/zip", None
        if sample.startswith((b"MZ", b"\x7fELF", b"\xd0\xcf\x11\xe0", b"\x1f\x8b")) or suffix in _BINARY_EXTENSIONS:
            return "binary", suffix.lstrip(".") or "binary", "application/octet-stream", None
        if suffix in {".pdf", ".docx", ".xlsx", ".pptx"}:
            return "binary", "invalid_" + suffix[1:], "application/octet-stream", None
        encoding = _detect_encoding(sample)
        if encoding is not None and (sample or suffix in _TEXT_EXTENSIONS):
            return "text", suffix.lstrip(".") if suffix in _TEXT_EXTENSIONS else "text", "text/plain", encoding
        return "binary", "binary", "application/octet-stream", None

    def read(self, remote_path: str, start_line: int = 1, line_count: int = 200,
             max_bytes: int | None = None) -> dict:
        max_bytes = self._page_arguments(start_line, line_count, max_bytes)
        local, base = self._materialized(remote_path)
        kind, format_name, mime, encoding = self._kind(local)
        base.update(content_kind=kind, format=format_name, mime=mime)
        if kind == "image":
            return {**base, "status": "ready", "message": "图片已自动下载；可用本地路径显示原图。"}
        if kind == "binary":
            return {**base, "status": "unsupported_with_local_path",
                    "message": "此格式没有可用的文本提取器；文件已下载，可用 read_bytes 分段读取原始字节。"}
        try:
            if kind == "text":
                try:
                    page = self._read_lines(local, encoding, start_line, line_count, max_bytes)
                except UnicodeError:
                    # An ASCII-only sample is compatible with both encodings.
                    # Retry the full strict stream when GB18030 first appears
                    # after the sample, rather than misclassifying valid text.
                    with local.open("rb") as source:
                        bom = source.read(3)
                    if encoding != "utf-8" or bom.startswith(codecs.BOM_UTF8):
                        raise
                    encoding = "gb18030"
                    page = self._read_lines(local, encoding, start_line, line_count, max_bytes)
                return {**base, **page,
                        "encoding": encoding, "metadata": {"extraction_method": "strict-streaming-text"}}
            return self._read_document(local, base, format_name, start_line, line_count, max_bytes)
        except (UnicodeError, NetdiskError) as exc:
            if isinstance(exc, NetdiskError) and exc.code not in {"binary_content", "library_missing", "encrypted_pdf",
                    "invalid_document", "unsafe_document_xml", "extraction_limit", "extraction_failed"}:
                raise
            reason = exc.code if isinstance(exc, NetdiskError) else "invalid_text_encoding"
            return {**base, "ok": False, "status": "unsupported_with_local_path", "error": reason,
                    "message": exc.message if isinstance(exc, NetdiskError) else "完整文件无法按检测到的文本编码严格解码。"}

    def read_text(self, remote_path: str, start_line: int = 1, line_count: int = 200,
                  max_bytes: int | None = None) -> dict:
        result = self.read(remote_path, start_line, line_count, max_bytes)
        if result.get("content_kind") not in ("text", "document"):
            raise NetdiskError("not_text", "此文件没有可直接读取的文本内容。",
                               {"local_path": result["local_path"], "format": result["format"]})
        return result

    def extract_text(self, remote_path: str, start_line: int = 1, line_count: int = 200,
                     max_bytes: int | None = None) -> dict:
        return self.read_text(remote_path, start_line, line_count, max_bytes)

    def read_bytes(self, remote_path: str, offset: int = 0, limit: int = 65536) -> dict:
        if (isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or
                isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= self.max_page_bytes):
            raise NetdiskError("invalid_read_range", f"offset 应为非负整数，limit 应为 1..{self.max_page_bytes}。")
        local, base = self._materialized(remote_path)
        with local.open("rb") as source:
            source.seek(offset)
            data = source.read(limit)
        return {**base, "content_kind": "bytes", "encoding": "base64", "offset": offset,
                "bytes_returned": len(data), "next_offset": offset + len(data),
                "eof": offset + len(data) >= base["size"], "data_base64": base64.b64encode(data).decode("ascii")}

    @staticmethod
    def _read_lines(local, encoding, start_line, line_count, max_bytes):
        fragments, bytes_returned, current_line = [], 0, 1
        selected_lines, truncated_lines = set(), set()
        current_has_text, total_lines = False, 0
        requested_end = start_line + line_count - 1
        with local.open("r", encoding=encoding, errors="strict", newline=None) as source:
            while chunk := source.read(_CHUNK):
                if not _text_fragment_is_safe(chunk):
                    raise NetdiskError("binary_content", "文件正文含二进制控制字符，未当作文本返回。")
                # splitlines would treat form feed as a new line; only LF is the
                # pagination delimiter, so split explicitly after normalization.
                pieces = chunk.split("\n")
                for index, piece in enumerate(pieces):
                    ended = index < len(pieces) - 1
                    fragment = piece + ("\n" if ended else "")
                    if not fragment:
                        continue
                    current_has_text = True
                    if start_line <= current_line <= requested_end:
                        encoded = fragment.encode("utf-8")
                        room = max_bytes - bytes_returned
                        if room > 0:
                            accepted = encoded[:room].decode("utf-8", errors="ignore")
                            if accepted:
                                fragments.append(accepted)
                                bytes_returned += len(accepted.encode("utf-8"))
                                selected_lines.add(current_line)
                        else:
                            accepted = ""
                        if len(accepted.encode("utf-8")) != len(encoded):
                            truncated_lines.add(current_line)
                    if ended:
                        total_lines = current_line
                        current_line += 1
                        current_has_text = False
        if current_has_text:
            total_lines = current_line
        first = min(selected_lines) if selected_lines else None
        last = max(selected_lines) if selected_lines else None
        next_line = (last + 1) if last is not None and last < total_lines else None
        if last is None and start_line <= total_lines:
            next_line = start_line
        limitations = []
        if truncated_lines:
            limitations.append("超长行在页字节上限处截断；未返回该行剩余部分。需要完整原文时用 read_bytes 分段读取。")
        return {"text": "".join(fragments), "line_start": first, "line_end": last,
                "requested_start_line": start_line, "lines_returned": len(selected_lines),
                "total_lines": total_lines, "bytes_returned": bytes_returned,
                "has_more": next_line is not None or bool(truncated_lines), "next_start_line": next_line,
                "text_complete": start_line == 1 and total_lines == len(selected_lines) and not truncated_lines,
                "truncated_lines": sorted(truncated_lines), "max_page_bytes": max_bytes,
                "extraction_limitations": limitations, "status": "text_read"}

    def _read_document(self, local, base, format_name, start_line, line_count, max_bytes):
        stat = local.stat()
        identity = f"{_EXTRACT_VERSION}\0{local}\0{stat.st_size}\0{stat.st_mtime_ns}"
        key = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        directory = self.cache_root / ".reader"
        directory.mkdir(parents=True, exist_ok=True)
        text_path, meta_path = directory / (key + ".txt"), directory / (key + ".json")
        with file_lock(directory / (key + ".lock"), timeout=30):
            metadata = None
            if text_path.is_file() and meta_path.is_file():
                try:
                    candidate = json.loads(meta_path.read_text(encoding="utf-8"))
                    if isinstance(candidate, dict) and candidate.get("version") == _EXTRACT_VERSION:
                        metadata = candidate
                except (OSError, ValueError):
                    pass
            if metadata is None:
                metadata = {"version": _EXTRACT_VERSION, "format": format_name}
                fd, temporary_name = tempfile.mkstemp(prefix=key + ".", suffix=".tmp", dir=directory)
                temporary = Path(temporary_name)
                try:
                    written = 0
                    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as output:
                        for fragment in self._document_fragments(local, format_name, metadata):
                            written += len(fragment.encode("utf-8"))
                            if written > _EXTRACT_LIMIT:
                                raise NetdiskError("extraction_limit", "提取文本超过 128 MiB 上限。")
                            output.write(fragment)
                        output.flush()
                        os.fsync(output.fileno())
                    if (local.stat().st_size, local.stat().st_mtime_ns) != (stat.st_size, stat.st_mtime_ns):
                        raise NetdiskError("source_changed", "读取缓存文件在提取期间发生变化，请重试。")
                    os.replace(temporary, text_path)
                    atomic_json(meta_path, metadata)
                finally:
                    temporary.unlink(missing_ok=True)
        result = self._read_lines(text_path, "utf-8", start_line, line_count, max_bytes)
        result["extraction_limitations"] = metadata.get("limitations", []) + result["extraction_limitations"]
        if metadata.get("no_extractable_text"):
            result["status"] = "no_extractable_text"
        return {**base, **result, "content_kind": "document", "metadata": metadata}

    @staticmethod
    def _document_fragments(local, format_name, metadata) -> Iterator[str]:
        try:
            if format_name == "pdf":
                yield from FileReader._pdf(local, metadata)
                return
            with zipfile.ZipFile(local) as archive:
                _check_archive(archive)
                if format_name == "docx":
                    metadata.update(extraction_method="streaming-ooxml",
                        limitations=["仅提取正文段落与表格文字；图片、版式、批注、脚注和页眉页脚未提取。"])
                    meaningful = False
                    for _, element in _elements(archive, "word/document.xml"):
                        tag = _tag(element.tag)
                        if tag == "t" and element.text:
                            meaningful = meaningful or bool(element.text.strip())
                            yield element.text
                        elif tag in ("p", "br", "cr"):
                            yield "\n"
                        elif tag == "tab":
                            yield "\t"
                        element.clear()
                    metadata["no_extractable_text"] = not meaningful
                elif format_name == "pptx":
                    slides = sorted((name for name in archive.namelist() if re.fullmatch(r"ppt/slides/slide[0-9]+\.xml", name)),
                                    key=lambda name: int(re.search(r"slide([0-9]+)", name)[1]))
                    if "ppt/_rels/presentation.xml.rels" in archive.namelist():
                        relationships = {}
                        for _, element in _elements(archive, "ppt/_rels/presentation.xml.rels"):
                            if _tag(element.tag) == "Relationship" and element.get("TargetMode") != "External":
                                target = element.get("Target", "")
                                resolved = posixpath.normpath(target.lstrip("/") if target.startswith("/") else posixpath.join("ppt", target))
                                if resolved in slides:
                                    relationships[element.get("Id")] = resolved
                            element.clear()
                        ordered = []
                        for _, element in _elements(archive, "ppt/presentation.xml"):
                            if _tag(element.tag) == "sldId":
                                identifier = next((value for name, value in element.attrib.items() if _tag(name) == "id" and "}" in name), None)
                                if identifier in relationships:
                                    ordered.append(relationships[identifier])
                            element.clear()
                        if ordered:
                            slides = ordered
                    metadata.update(extraction_method="streaming-ooxml", slide_count=len(slides),
                        limitations=["按幻灯片内部文字顺序提取；图片、图表、视觉布局及讲者备注未提取。"])
                    meaningful = False
                    for number, member in enumerate(slides, 1):
                        yield f"【幻灯片 {number}】\n"
                        for _, element in _elements(archive, member):
                            tag = _tag(element.tag)
                            if tag == "t" and element.text:
                                meaningful = meaningful or bool(element.text.strip())
                                yield element.text
                            elif tag in ("p", "br"):
                                yield "\n"
                            element.clear()
                    metadata["no_extractable_text"] = not meaningful
                elif format_name == "xlsx":
                    yield from FileReader._xlsx(archive, metadata)
                else:
                    raise NetdiskError("invalid_document", "没有适用的文档提取器。")
        except NetdiskError:
            raise
        except (zipfile.BadZipFile, ET.ParseError, OSError, KeyError, ValueError, IndexError):
            raise NetdiskError("invalid_document", "文档结构损坏或不符合预期格式。") from None

    @staticmethod
    def _xlsx(archive, metadata):
        metadata.update(extraction_method="streaming-ooxml-cells",
            limitations=["输出单元格坐标、原始值与公式；不计算公式。日期可能呈现为 Excel 序列号；图表、图片和格式未提取。"])
        relations = {}
        for _, element in _elements(archive, "xl/_rels/workbook.xml.rels"):
            if _tag(element.tag) == "Relationship" and element.get("TargetMode") != "External":
                target = element.get("Target", "")
                resolved = posixpath.normpath(target.lstrip("/") if target.startswith("/") else posixpath.join("xl", target))
                if resolved.startswith("xl/") and resolved.endswith(".xml"):
                    relations[element.get("Id")] = resolved
            element.clear()
        sheets = []
        for _, element in _elements(archive, "xl/workbook.xml"):
            if _tag(element.tag) == "sheet":
                identifier = next((value for name, value in element.attrib.items() if _tag(name) == "id"), None)
                if identifier in relations:
                    sheets.append((element.get("name", "Unnamed"), relations[identifier]))
            element.clear()
        shared = []
        if "xl/sharedStrings.xml" in archive.namelist():
            parts, chars = [], 0
            for _, element in _elements(archive, "xl/sharedStrings.xml"):
                tag = _tag(element.tag)
                if tag == "t":
                    parts.append(element.text or "")
                elif tag == "si":
                    value = "".join(parts)
                    chars += len(value)
                    if chars > 16 * 1024 * 1024:
                        raise NetdiskError("extraction_limit", "工作簿共享字符串超过 16 Mi 字符上限。")
                    shared.append(value)
                    parts = []
                element.clear()
        metadata["sheet_count"] = len(sheets)
        meaningful = False
        for name, member in sheets:
            yield f"【工作表：{name}】\n"
            parts, value, formula = [], "", ""
            for _, element in _elements(archive, member):
                tag = _tag(element.tag)
                if tag == "t":
                    parts.append(element.text or "")
                elif tag == "v":
                    value = element.text or ""
                elif tag == "f":
                    formula = element.text or ""
                elif tag == "c":
                    kind = element.get("t")
                    display = "".join(parts) if kind == "inlineStr" else value
                    if kind == "s" and value:
                        display = shared[int(value)]
                    elif kind == "b":
                        display = "TRUE" if value == "1" else "FALSE"
                    if formula:
                        display = "=" + formula + (f" [缓存值: {display}]" if display else "")
                    if display:
                        meaningful = True
                        yield f"{element.get('r', '?')}\t{display}\n"
                    parts, value, formula = [], "", ""
                element.clear()
        metadata["no_extractable_text"] = not meaningful

    @staticmethod
    def _pdf(local, metadata):
        try:
            from pypdf import PdfReader
        except ImportError:
            raise NetdiskError("library_missing", "PDF 文本读取需要可选 pypdf 库；原始文件已下载。") from None
        try:
            reader = PdfReader(str(local))
            if reader.is_encrypted and not reader.decrypt(""):
                raise NetdiskError("encrypted_pdf", "PDF 受密码保护，无法自动提取文字。")
            metadata.update(extraction_method="pypdf-per-page", page_count=len(reader.pages),
                limitations=["仅提取已有 PDF 文字层；不执行 OCR。阅读顺序与视觉版式可能不同，图片和扫描正文不会转成文字。"])
            no_text_pages, count = [], 0
            for number, page in enumerate(reader.pages, 1):
                text = page.extract_text() or ""
                yield f"【第 {number} 页】\n"
                if text.strip():
                    yield text + ("" if text.endswith("\n") else "\n")
                else:
                    count += 1
                    if len(no_text_pages) < 100:
                        no_text_pages.append(number)
                    yield "[该页没有可提取文字；可能是扫描或空白页]\n"
            metadata.update(no_text_page_count=count, no_text_pages=no_text_pages,
                no_text_pages_truncated=count > len(no_text_pages),
                no_extractable_text=count == len(reader.pages),
                scanned_or_no_text=count == len(reader.pages))
        except NetdiskError:
            raise
        except Exception:
            raise NetdiskError("extraction_failed", "PDF 无法解析或提取文字；原始文件已下载。") from None
