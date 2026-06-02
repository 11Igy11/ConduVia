from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Callable

from core.leaks import db as leaks_db
from core.leaks.detect import split_line
from core.leaks.encoding import ascii_fold, try_fix_mojibake
from core.leaks.readers import iter_text_lines
from core.leaks.schema import DEDICATED_FIELDS, FIELD_SKIP
from core.osint.normalize import normalize_email, normalize_msisdn

_TEXT_FIELDS = (
    "first_name",
    "last_name",
    "full_name",
    "username",
    "city",
    "hometown",
    "employer",
    "address",
)
_BATCH_SIZE = 10000

ProgressFn = Callable[[int, int], None]


def normalize_oib(value: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    return digits if len(digits) == 11 else str(value or "").strip()


def build_record(
    fields: list[str],
    columns: list[str],
    *,
    dataset_id: int,
    raw_line: str,
    keep_raw: bool,
) -> tuple:
    dedicated: dict[str, str] = {name: "" for name in DEDICATED_FIELDS}
    extra: dict[str, str] = {}

    for index, field in enumerate(columns):
        if not field or field == FIELD_SKIP:
            continue
        value = fields[index].strip() if index < len(fields) else ""
        if not value:
            continue
        if field in dedicated:
            dedicated[field] = value
        else:
            extra[field] = value

    for name in _TEXT_FIELDS:
        if dedicated[name]:
            dedicated[name] = try_fix_mojibake(dedicated[name])
    for key, value in list(extra.items()):
        extra[key] = try_fix_mojibake(value)

    if dedicated["phone"]:
        dedicated["phone"] = normalize_msisdn(dedicated["phone"]) or dedicated["phone"].strip()
    if dedicated["email"]:
        dedicated["email"] = normalize_email(dedicated["email"]) or dedicated["email"].strip().lower()
    if dedicated["oib"]:
        dedicated["oib"] = normalize_oib(dedicated["oib"])

    full_name = dedicated["full_name"]
    if not full_name:
        full_name = " ".join(p for p in (dedicated["first_name"], dedicated["last_name"]) if p).strip()
        dedicated["full_name"] = full_name
    name_ascii = ascii_fold(full_name or f"{dedicated['first_name']} {dedicated['last_name']}")

    extra_json = json.dumps(extra, ensure_ascii=False) if extra else ""
    raw = raw_line if keep_raw else ""

    return (
        dataset_id,
        dedicated["phone"],
        dedicated["email"],
        dedicated["oib"],
        dedicated["fb_id"],
        dedicated["username"],
        dedicated["first_name"],
        dedicated["last_name"],
        dedicated["full_name"],
        name_ascii,
        dedicated["gender"],
        dedicated["birthday"],
        dedicated["city"],
        dedicated["hometown"],
        dedicated["employer"],
        dedicated["address"],
        dedicated["secret"],
        extra_json,
        raw,
    )


def import_dataset(
    path: str | Path,
    *,
    name: str,
    delimiter: str,
    encoding: str,
    columns: list[str],
    display_columns: list[str] | None = None,
    has_header: bool = False,
    source_note: str = "",
    profile_name: str = "",
    keep_raw: bool = True,
    progress: ProgressFn | None = None,
    cancel: Callable[[], bool] | None = None,
    db_path: Path = leaks_db.LEAKS_DB_PATH,
) -> dict:
    leaks_db.init_leaks_db(db_path)
    dataset_id = leaks_db.create_dataset(
        name,
        source_note=source_note,
        source_path=str(path),
        delimiter=delimiter,
        encoding=encoding,
        profile_name=profile_name,
        columns=list(display_columns) if display_columns
        else [c for c in columns if c and c != "skip"],
        db_path=db_path,
    )

    read = 0
    batch: list[tuple] = []
    cancelled = False
    skipped_header = False

    with leaks_db.import_connection(db_path) as con:
        for line in iter_text_lines(path, encoding):
            if cancel is not None and cancel():
                cancelled = True
                break
            if not line.strip():
                continue
            if has_header and not skipped_header:
                skipped_header = True
                continue
            read += 1
            fields = split_line(line, delimiter)
            batch.append(
                build_record(
                    fields, columns, dataset_id=dataset_id, raw_line=line, keep_raw=keep_raw
                )
            )
            if len(batch) >= _BATCH_SIZE:
                leaks_db.insert_records(con, batch)
                batch.clear()
                if progress is not None:
                    progress(read, 0)
        if batch:
            leaks_db.insert_records(con, batch)
            batch.clear()

    inserted = leaks_db.finalize_dataset(dataset_id, db_path=db_path)
    if cancelled:
        leaks_db.delete_dataset(dataset_id, db_path=db_path)
        return {"dataset_id": 0, "read": read, "inserted": 0, "cancelled": True}

    if progress is not None:
        progress(read, inserted)
    return {
        "dataset_id": dataset_id,
        "read": read,
        "inserted": inserted,
        "duplicates": max(0, read - inserted),
        "cancelled": False,
    }
