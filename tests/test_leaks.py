from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from core.leaks.detect import detect_delimiter, split_rows, suggest_fields
from core.leaks.encoding import ascii_fold, try_fix_mojibake
from core.leaks.importer import import_dataset, build_record, normalize_oib
from core.leaks.profiles import save_profile, load_profile, list_profiles, delete_profile
from core.leaks.readers import iter_text_lines, sample_lines
from core.leaks.search import search_records
from core.leaks import db as leaks_db

FB_PROFILE_COLUMNS = [
    "phone", "fb_id", "first_name", "last_name", "gender",
    "city", "hometown", "relationship", "employer",
    "source_date", "email", "birthday",
]

SAMPLE_LINES = [
    "385953444270:100000069095026:Mihael:Sraga:male:Varazdin:Varazdin:Married:Orbico:2/24/2018 12:00:00 AM::",
    "385953444267:1724063819:Mate:Jukic:male:Zagreb, Croatia::::4/24/2019 12:00:00 AM::",
    "385953444235:1029144819:Ante:Cvjetanovic:male:Split, Croatia:Dubrovnik, Croatia:::5/20/2018 12:00:00 AM::",
]


def _write(tmp: str, name: str, lines: list[str], encoding: str = "utf-8") -> Path:
    path = Path(tmp) / name
    path.write_text("\n".join(lines) + "\n", encoding=encoding)
    return path


class EncodingTests(unittest.TestCase):
    def test_ascii_fold_croatian(self):
        self.assertEqual(ascii_fold("Čačić Žužić Šđ"), "cacic zuzic sd")

    def test_try_fix_mojibake_returns_clean_text_unchanged(self):
        self.assertEqual(try_fix_mojibake("Mihael Sraga"), "Mihael Sraga")


class DetectTests(unittest.TestCase):
    def test_detect_colon_delimiter(self):
        self.assertEqual(detect_delimiter(SAMPLE_LINES), ":")

    def test_suggest_fields_identifies_phone_and_fbid(self):
        rows = split_rows(SAMPLE_LINES, ":")
        suggestions = suggest_fields(rows)
        self.assertEqual(suggestions[0], "phone")
        self.assertEqual(suggestions[1], "fb_id")
        self.assertEqual(suggestions[2], "first_name")
        self.assertEqual(suggestions[3], "last_name")
        self.assertEqual(suggestions[4], "gender")

    def test_normalize_oib(self):
        self.assertEqual(normalize_oib("12345678901"), "12345678901")
        self.assertEqual(normalize_oib("123-456"), "123-456")


class BuildRecordTests(unittest.TestCase):
    def test_build_record_normalizes_phone_and_name(self):
        fields = SAMPLE_LINES[0].split(":")
        record = build_record(fields, FB_PROFILE_COLUMNS, dataset_id=1, raw_line=SAMPLE_LINES[0], keep_raw=True)
        columns = leaks_db.record_columns()
        row = dict(zip(columns, record))
        self.assertEqual(row["phone"], "+385953444270")
        self.assertEqual(row["fb_id"], "100000069095026")
        self.assertEqual(row["full_name"], "Mihael Sraga")
        self.assertEqual(row["name_ascii"], "mihael sraga")
        self.assertIn("relationship", row["extra"])
        self.assertEqual(row["raw"], SAMPLE_LINES[0])


class ReaderTests(unittest.TestCase):
    def test_iter_text_lines_txt(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = _write(tmp, "leak.txt", SAMPLE_LINES)
            lines = list(iter_text_lines(path))
            self.assertEqual(len(lines), 3)
            self.assertTrue(lines[0].startswith("385953444270"))

    def test_iter_docx_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "leak.docx"
            self._make_docx(path, SAMPLE_LINES)
            lines = [ln for ln in iter_text_lines(path) if ln.strip()]
            self.assertEqual(len(lines), 3)
            self.assertIn("Mihael", lines[0])

    @staticmethod
    def _make_docx(path: Path, lines: list[str]) -> None:
        paras = "".join(
            f"<w:p><w:r><w:t xml:space=\"preserve\">{ln}</w:t></w:r></w:p>" for ln in lines
        )
        document = (
            "<?xml version=\"1.0\"?>"
            "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">"
            f"<w:body>{paras}</w:body></w:document>"
        )
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("word/document.xml", document)


class ImportSearchTests(unittest.TestCase):
    def test_import_and_search_by_phone(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "leaks.db"
            src = _write(tmp, "fb.txt", SAMPLE_LINES)
            summary = import_dataset(
                src,
                name="FB HR test",
                delimiter=":",
                encoding="utf-8",
                columns=FB_PROFILE_COLUMNS,
                keep_raw=True,
                db_path=db_path,
            )
            self.assertEqual(summary["read"], 3)
            self.assertEqual(summary["inserted"], 3)

            rows, total = search_records(text="385953444270", db_path=db_path)
            self.assertEqual(total, 1)
            self.assertEqual(rows[0]["full_name"], "Mihael Sraga")
            self.assertEqual(rows[0]["dataset_name"], "FB HR test")

    def test_search_by_name_diacritic_insensitive(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "leaks.db"
            src = _write(tmp, "fb.txt", SAMPLE_LINES)
            import_dataset(
                src, name="set", delimiter=":", encoding="utf-8",
                columns=FB_PROFILE_COLUMNS, db_path=db_path,
            )
            rows, total = search_records(text="cvjetanovic", db_path=db_path)
            self.assertGreaterEqual(total, 1)
            self.assertTrue(any(r["last_name"] == "Cvjetanovic" for r in rows))

    def test_dedup_skips_duplicate_phone_fbid(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "leaks.db"
            dup_lines = SAMPLE_LINES + [SAMPLE_LINES[0]]
            src = _write(tmp, "fb.txt", dup_lines)
            summary = import_dataset(
                src, name="set", delimiter=":", encoding="utf-8",
                columns=FB_PROFILE_COLUMNS, db_path=db_path,
            )
            self.assertEqual(summary["read"], 4)
            self.assertEqual(summary["inserted"], 3)
            self.assertEqual(summary["duplicates"], 1)

    def test_search_filter_by_dataset(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "leaks.db"
            src = _write(tmp, "fb.txt", SAMPLE_LINES)
            r = import_dataset(
                src, name="set A", delimiter=":", encoding="utf-8",
                columns=FB_PROFILE_COLUMNS, db_path=db_path,
            )
            rows, total = search_records(dataset_id=r["dataset_id"], db_path=db_path)
            self.assertEqual(total, 3)
            rows2, total2 = search_records(dataset_id=99999, db_path=db_path)
            self.assertEqual(total2, 0)


class ProfileTests(unittest.TestCase):
    def test_profile_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            pdir = Path(tmp) / "profiles"
            save_profile(
                {
                    "name": "Facebook 2019 (HR)",
                    "delimiter": ":",
                    "encoding": "cp1250",
                    "has_header": False,
                    "columns": FB_PROFILE_COLUMNS,
                },
                profiles_dir=pdir,
            )
            self.assertIn("Facebook 2019 (HR)", list_profiles(profiles_dir=pdir))
            loaded = load_profile("Facebook 2019 (HR)", profiles_dir=pdir)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["columns"], FB_PROFILE_COLUMNS)
            self.assertEqual(loaded["encoding"], "cp1250")
            self.assertTrue(delete_profile("Facebook 2019 (HR)", profiles_dir=pdir))


if __name__ == "__main__":
    unittest.main()
