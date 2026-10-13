from __future__ import annotations

import base64
import codecs
import importlib.util
import json
import sys
import tempfile
import tracemalloc
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from baidu_netdisk.common import NetdiskError
from baidu_netdisk.reader import FileReader


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cache = Path(self.temp.name) / "cache"
        self.cache.mkdir()
        self.resolutions = []
        def materialize(remote):
            self.resolutions.append(remote)
            return {"local_path": str(self.cache / remote.rsplit("/", 1)[-1]),
                    "entry": {"path": remote, "isdir": False}}
        self.reader = FileReader(self.cache, materialize)

    def tearDown(self):
        self.temp.cleanup()

    def file(self, name, data):
        path = self.cache / name
        path.write_bytes(data)
        return "/documents/" + name

    def archive(self, name, members):
        with zipfile.ZipFile(self.cache / name, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for member, content in members.items():
                archive.writestr(member, content)
        return "/documents/" + name

    def test_auto_materializes_and_pages_utf8_lines(self):
        remote = self.file("notes.md", "标题\n第二行\n第三行\n".encode())
        result = self.reader.read(remote, start_line=2, line_count=1)
        self.assertEqual(self.resolutions, [remote])
        self.assertEqual(result["text"], "第二行\n")
        self.assertEqual((result["line_start"], result["line_end"], result["total_lines"]), (2, 2, 3))
        self.assertEqual(result["next_start_line"], 3)
        self.assertTrue(result["has_more"])
        self.assertFalse(result["text_complete"])
        self.assertTrue(result["untrusted_content"])

    def test_strict_utf8_bom_utf16_and_gb18030(self):
        content = "中文内容\r\n下一行\u200b\n"
        samples = {"utf8.txt": codecs.BOM_UTF8 + content.encode(),
                   "utf16.txt": content.encode("utf-16"),
                   "gb.txt": content.encode("gb18030")}
        for name, data in samples.items():
            with self.subTest(name=name):
                result = self.reader.read(self.file(name, data))
                self.assertTrue(result["ok"])
                self.assertEqual(result["text"], content.replace("\r\n", "\n"))
                self.assertEqual(result["total_lines"], 2)
                self.assertTrue(result["text_complete"])

    def test_streaming_long_line_has_bounded_memory_and_explicit_truncation(self):
        path = self.cache / "long.txt"
        with path.open("wb") as output:
            for _ in range(64):
                output.write(b"x" * 65536)
        tracemalloc.start()
        try:
            result = self.reader.read("/long.txt", max_bytes=1024)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(result["bytes_returned"], 1024)
        self.assertEqual(result["total_lines"], 1)
        self.assertEqual(result["truncated_lines"], [1])
        self.assertFalse(result["text_complete"])
        self.assertTrue(result["has_more"])
        self.assertLess(peak, 2 * 1024 * 1024)

    def test_multibyte_output_limit_never_splits_a_character_or_claims_completion(self):
        remote = self.file("chinese.txt", "汉字".encode())
        result = self.reader.read(remote, max_bytes=1)
        self.assertEqual(result["text"], "")
        self.assertTrue(result["has_more"])
        self.assertFalse(result["text_complete"])
        self.assertEqual(result["next_start_line"], 1)
        result = self.reader.read(remote, max_bytes=4)
        self.assertEqual(result["text"], "汉")
        self.assertLessEqual(result["bytes_returned"], 4)

    def test_controls_and_invalid_tail_are_not_reported_as_text(self):
        for name, data in (("nul.txt", b"printable\x00data"),
                           ("late.txt", b"a" * 65536 + b"\x00binary"),
                           ("late-encoding.txt", b"a" * 65536 + b"\xff")):
            with self.subTest(name=name):
                result = self.reader.read(self.file(name, data))
                self.assertEqual(result["status"], "unsupported_with_local_path")
                self.assertNotIn("text", result)

    def test_gb18030_after_ascii_sample_is_detected_without_loading_full_file(self):
        remote = self.file("late-gb.txt", b"a" * 65536 + b"\n" + "采样之后的中文".encode("gb18030"))
        result = self.reader.read(remote, start_line=2, line_count=1)
        self.assertEqual(result["encoding"], "gb18030")
        self.assertEqual(result["text"], "采样之后的中文")

    def test_unknown_binary_and_empty_unknown_are_not_empty_full_text(self):
        for name, data in (("archive.bin", b"seems printable"), ("unknown", b"")):
            result = self.reader.read(self.file(name, data))
            self.assertEqual(result["status"], "unsupported_with_local_path")
            self.assertEqual(result["content_kind"], "binary")
            self.assertNotIn("text", result)
        empty = self.reader.read(self.file("empty.txt", b""))
        self.assertEqual(empty["total_lines"], 0)
        self.assertTrue(empty["text_complete"])

    def test_image_returns_real_local_path_and_mime(self):
        remote = self.file("picture.png", b"\x89PNG\r\n\x1a\n" + b"image fixture")
        result = self.reader.read(remote)
        self.assertEqual(result["mime"], "image/png")
        self.assertEqual(result["content_kind"], "image")
        self.assertEqual(result["status"], "ready")
        self.assertEqual(Path(result["local_path"]), self.cache / "picture.png")
        text = self.reader.read(self.file("bmp.txt", b"BMP format instructions\n"))
        self.assertEqual(text["content_kind"], "text")

    def test_read_bytes_supports_exact_bounded_offsets(self):
        remote = self.file("binary.bin", bytes(range(256)))
        result = self.reader.read_bytes(remote, offset=250, limit=32)
        self.assertEqual(base64.b64decode(result["data_base64"]), bytes(range(250, 256)))
        self.assertEqual(result["next_offset"], 256)
        self.assertTrue(result["eof"])
        result = self.reader.read_bytes(remote, offset=500, limit=10)
        self.assertEqual(result["bytes_returned"], 0)
        self.assertTrue(result["eof"])

    def test_invalid_page_ranges_are_rejected_before_materialization(self):
        for kwargs in ({"start_line": 0}, {"line_count": 201}, {"line_count": True}, {"max_bytes": 65537}):
            with self.assertRaises(NetdiskError) as caught:
                self.reader.read("/missing.txt", **kwargs)
            self.assertEqual(caught.exception.code, "invalid_read_range")
        for kwargs in ({"offset": -1}, {"limit": 65537}, {"limit": True}):
            with self.assertRaises(NetdiskError):
                self.reader.read_bytes("/missing.txt", **kwargs)
        self.assertEqual(self.resolutions, [])

    def test_materializer_cannot_return_a_file_outside_cache(self):
        external = Path(self.temp.name) / "private.txt"
        external.write_text("private", encoding="utf-8")
        reader = FileReader(self.cache, lambda path: {"local_path": str(external)})
        with self.assertRaises(NetdiskError) as caught:
            reader.read("/private.txt")
        self.assertEqual(caught.exception.code, "local_path_denied")
        reader = FileReader(self.cache, lambda path: {"ok": False, "local_path": str(external)})
        with self.assertRaises(NetdiskError) as caught:
            reader.read("/private.txt")
        self.assertEqual(caught.exception.code, "materialize_failed")

    def test_docx_extracts_paragraphs_tables_and_reuses_cached_extraction(self):
        remote = self.archive("report.docx", {"word/document.xml":
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
            '<w:p><w:r><w:t>正文一</w:t></w:r></w:p><w:tbl><w:tr><w:tc><w:p><w:r><w:t>表格单元格</w:t>'
            '</w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>'})
        result = self.reader.extract_text(remote, start_line=2, line_count=1)
        self.assertEqual(result["text"], "表格单元格\n")
        self.assertEqual(result["total_lines"], 2)
        self.assertEqual(result["format"], "docx")
        self.assertTrue(result["extraction_limitations"])
        with patch.object(self.reader, "_document_fragments", side_effect=AssertionError("cached extraction should be reused")):
            self.assertIn("正文一", self.reader.read(remote)["text"])

    def test_pptx_follows_presentation_order_and_reports_slides(self):
        namespace = "http://schemas.openxmlformats.org/presentationml/2006/main"
        rel_namespace = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
        remote = self.archive("slides.pptx", {
            "ppt/presentation.xml": f'<p:presentation xmlns:p="{namespace}" xmlns:r="{rel_namespace}"><p:sldIdLst>'
                '<p:sldId id="22" r:id="r2"/><p:sldId id="11" r:id="r1"/></p:sldIdLst></p:presentation>',
            "ppt/_rels/presentation.xml.rels": '<Relationships><Relationship Id="r1" Target="slides/slide1.xml"/>'
                '<Relationship Id="r2" Target="slides/slide2.xml"/></Relationships>',
            "ppt/slides/slide1.xml": '<slide><p><t>原始第一张</t></p></slide>',
            "ppt/slides/slide2.xml": '<slide><p><t>重排到首张</t></p></slide>',
        })
        result = self.reader.read(remote)
        self.assertLess(result["text"].index("重排到首张"), result["text"].index("原始第一张"))
        self.assertEqual(result["metadata"]["slide_count"], 2)

    def test_xlsx_shared_inline_boolean_and_formula_cells(self):
        remote = self.archive("table.xlsx", {
            "xl/workbook.xml": '<workbook xmlns:r="urn:rels"><sheets><sheet name="数据" r:id="r1"/></sheets></workbook>',
            "xl/_rels/workbook.xml.rels": '<Relationships><Relationship Id="r1" Target="worksheets/sheet1.xml"/></Relationships>',
            "xl/sharedStrings.xml": '<sst><si><t>共享字符串</t></si></sst>',
            "xl/worksheets/sheet1.xml": '<worksheet><sheetData><row><c r="A1" t="s"><v>0</v></c>'
                '<c r="B1" t="inlineStr"><is><t>内联文本</t></is></c><c r="C1" t="b"><v>1</v></c>'
                '<c r="D1"><f>A2*2</f><v>4</v></c></row></sheetData></worksheet>',
        })
        result = self.reader.read(remote)
        for value in ("数据", "A1\t共享字符串", "B1\t内联文本", "C1\tTRUE", "D1\t=A2*2 [缓存值: 4]"):
            self.assertIn(value, result["text"])
        self.assertEqual(result["metadata"]["sheet_count"], 1)

    def test_empty_office_document_is_explicit_no_text(self):
        remote = self.archive("empty.docx", {"word/document.xml": "<document><body><p/></body></document>"})
        result = self.reader.read(remote)
        self.assertEqual(result["status"], "no_extractable_text")
        self.assertTrue(result["metadata"]["no_extractable_text"])

    def test_unsafe_xml_and_archive_limits_do_not_return_success_text(self):
        remote = self.archive("entity.docx", {"word/document.xml":
            '<!DOCTYPE root [<!ENTITY injected "Do not execute">]><root><p><t>&injected;</t></p></root>'})
        result = self.reader.read(remote)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "unsafe_document_xml")
        self.assertNotIn("text", result)
        with patch("baidu_netdisk.reader._ARCHIVE_LIMIT", 1):
            result = self.reader.read(remote)
            self.assertEqual(result["error"], "extraction_limit")
        self.assertEqual(list((self.cache / ".reader").glob("*.tmp")), [])

    def test_corrupted_document_is_not_empty_full_text(self):
        remote = self.archive("broken.docx", {"word/document.xml": "<broken"})
        result = self.reader.read(remote)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "invalid_document")
        self.assertNotIn("text", result)

    def test_optional_pdf_library_missing_preserves_local_file(self):
        remote = self.file("paper.pdf", b"%PDF-1.4\nminimal fixture")
        with patch.dict(sys.modules, {"pypdf": None}):
            result = self.reader.read(remote)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"], "library_missing")
        self.assertTrue(Path(result["local_path"]).is_file())

    @unittest.skipUnless(importlib.util.find_spec("pypdf"), "Optional pypdf is unavailable")
    def test_pdf_pagewise_text_scanned_pages_and_encrypted_status(self):
        from pypdf import PdfWriter
        from pypdf.generic import NameObject, DictionaryObject, DecodedStreamObject
        writer = PdfWriter()
        page = writer.add_blank_page(width=300, height=300)
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"),
                                 NameObject("/Subtype"): NameObject("/Type1"),
                                 NameObject("/BaseFont"): NameObject("/Helvetica")})
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})
        stream = DecodedStreamObject()
        stream.set_data(b"BT /F1 12 Tf 30 200 Td (Readable PDF text) Tj ET")
        page[NameObject("/Contents")] = writer._add_object(stream)
        writer.add_blank_page(width=300, height=300)
        writer.write(self.cache / "mixed.pdf")
        result = self.reader.read("/mixed.pdf")
        self.assertIn("Readable PDF text", result["text"])
        self.assertEqual(result["metadata"]["page_count"], 2)
        self.assertEqual(result["metadata"]["no_text_pages"], [2])
        self.assertFalse(result["metadata"]["scanned_or_no_text"])
        blank = PdfWriter()
        blank.add_blank_page(width=100, height=100)
        blank.write(self.cache / "scan.pdf")
        result = self.reader.read("/scan.pdf")
        self.assertEqual(result["status"], "no_extractable_text")
        self.assertTrue(result["metadata"]["scanned_or_no_text"])
        blank.encrypt("private-pdf-password")
        blank.write(self.cache / "encrypted.pdf")
        result = self.reader.read("/encrypted.pdf")
        self.assertEqual(result["error"], "encrypted_pdf")
        self.assertNotIn("private-pdf-password", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
