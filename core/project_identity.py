from __future__ import annotations

from core.db import Project
from core.osint.imsi import format_identifier_display, format_intercept_imsi, is_imsi_target_type


def _split_identifier_values(value: str) -> list[str]:
    text = str(value or "").replace(";", "\n").replace(",", "\n")
    rows: list[str] = []
    seen: set[str] = set()
    for part in text.splitlines():
        item = part.strip()
        if not item:
            continue
        key = item.casefold()
        if key in seen:
            continue
        seen.add(key)
        rows.append(item)
    return rows


def identifier_values_for_editor(value: str, *, kind: str = "") -> list[str]:
    """Split stored identifier text into separate dialog rows."""
    import re

    from core.osint.imsi import format_intercept_imsi

    rows = _split_identifier_values(value)
    if len(rows) > 1:
        return rows

    raw = str(value or "").strip()
    if not raw:
        return []

    if str(kind or "").casefold() == "imsi":
        digits = re.sub(r"\D", "", raw)
        if len(digits) > 15:
            chunks: list[str] = []
            start = 0
            mcc = "219"
            while start < len(digits):
                next_start = None
                search_from = start + 14
                while search_from < len(digits):
                    if digits.startswith(mcc, search_from):
                        next_start = search_from
                        break
                    search_from += 1
                if next_start is None:
                    chunks.append(digits[start:])
                    break
                chunks.append(digits[start:next_start])
                start = next_start
            if len(chunks) > 1:
                return [format_intercept_imsi(part) for part in chunks if part]

    return [raw]


def subject_full_name(project: Project) -> str:
    parts = [
        (project.subject_first_name or "").strip(),
        (project.subject_last_name or "").strip(),
    ]
    return " ".join(part for part in parts if part)


def subject_display_label(project: Project) -> str:
    name = subject_full_name(project)
    if name:
        return name

    identifiers = project_identifier_rows(project)
    if identifiers:
        first = identifiers[0]
        return f"{first['type']} / {first['value']}"

    if (project.target_identifier or "").strip():
        return target_display_label(project)

    return "-"


def target_display_label(project: Project) -> str:
    identifier = format_identifier_display(project.target_identifier, project.target_type)
    target_type = (project.target_type or "").strip()
    if identifier and target_type:
        return f"{target_type} / {identifier}"
    return identifier or target_type or "-"


def project_identifier_rows(project: Project) -> list[dict[str, str]]:
    rows = []
    for value in _split_identifier_values(project.subject_msisdn):
        rows.append({"type": "MSISDN", "label": "Mobile number", "value": value})
    for value in _split_identifier_values(project.subject_imsi):
        rows.append({"type": "IMSI", "label": "IMSI", "value": format_identifier_display(value, "IMSI")})
    for value in _split_identifier_values(project.subject_imei):
        rows.append({"type": "IMEI", "label": "IMEI", "value": value})
    if (project.subject_ip or "").strip():
        rows.append({"type": "IP", "label": "IP address", "value": project.subject_ip})

    if (project.target_identifier or "").strip():
        legacy_type = (project.target_type or "Target").strip() or "Target"
        legacy_value = format_identifier_display(project.target_identifier, legacy_type)
        rows.append({
            "type": legacy_type,
            "label": "Legacy target",
            "value": legacy_value,
        })

    seen: set[tuple[str, str]] = set()
    result: list[dict[str, str]] = []
    for row in rows:
        value = str(row.get("value") or "").strip()
        kind = str(row.get("type") or "").strip()
        if not value:
            continue
        key = (kind.casefold(), value.casefold())
        if key in seen:
            continue
        seen.add(key)
        result.append({
            "type": kind,
            "label": str(row.get("label") or kind),
            "value": value,
        })

    return result


def project_identifiers_text(project: Project) -> str:
    rows = project_identifier_rows(project)
    if not rows:
        return "-"
    return ", ".join(f"{row['type']}: {row['value']}" for row in rows)


def normalize_identifier_value(value: str, identifier_type: str = "") -> str:
    raw = str(value or "").strip()
    kind = str(identifier_type or "").strip()
    kind_fold = kind.casefold()

    if is_imsi_target_type(kind):
        return format_intercept_imsi(raw)

    if kind_fold in {"msisdn", "imsi", "imei", "oib", "target", "isdndataonly"}:
        compact = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
        if compact.startswith("+"):
            compact = compact[1:]
        return compact

    digits_and_phone_marks = all(ch.isdigit() or ch in "+ -()./" for ch in raw)
    if digits_and_phone_marks:
        compact = "".join(ch for ch in raw if ch.isdigit() or ch == "+")
        if compact.startswith("+"):
            compact = compact[1:]
        return compact

    return raw.casefold()


def normalize_oib(value: str) -> str:
    return "".join(ch for ch in str(value or "") if ch.isdigit())


def is_valid_oib(value: str) -> bool:
    digits = normalize_oib(value)
    if len(digits) != 11:
        return False

    carry = 10
    for ch in digits[:10]:
        carry = (carry + int(ch)) % 10
        if carry == 0:
            carry = 10
        carry = (carry * 2) % 11

    control = (11 - carry) % 10
    return control == int(digits[-1])


def identifier_values_match(
    project_value: str,
    dataset_value: str,
    *,
    project_type: str = "",
    dataset_type: str = "",
) -> bool:
    project_norm = normalize_identifier_value(project_value, project_type)
    dataset_norm = normalize_identifier_value(dataset_value, dataset_type)
    return bool(project_norm and dataset_norm and project_norm == dataset_norm)


def repair_stored_imsi_identifiers(project_id: int, *, db_path=None) -> None:
    """Persist normalized IMSI values for legacy projects with truncated exports."""
    from core.db import DEFAULT_DB_PATH, get_project, set_project_target, _connect

    db_path = db_path or DEFAULT_DB_PATH
    project = get_project(project_id, db_path=db_path)
    if not project:
        return

    target = format_identifier_display(project.target_identifier, project.target_type)
    if target and target != (project.target_identifier or "").strip():
        set_project_target(project_id, target, project.target_type or "", db_path=db_path)

    imsi = format_identifier_display(project.subject_imsi, "IMSI")
    if imsi and imsi != (project.subject_imsi or "").strip():
        with _connect(db_path) as con:
            con.execute(
                "UPDATE projects SET subject_imsi = ?, updated_at = datetime('now') WHERE id = ?;",
                (imsi, project_id),
            )


def looks_like_ip_address(value: str) -> bool:
    from core.osint.normalize import normalize_ip

    return bool(normalize_ip(str(value or "").strip()))


_SUBJECT_NON_IP_FIELDS = frozenset({
    "first_name",
    "last_name",
    "oib",
    "msisdn",
    "imsi",
    "imei",
    "extra_identifiers",
})


def sanitize_subject_fields(**fields: str) -> dict[str, str]:
    """Strip IP-looking values from name/identifier fields; route them to subject_ip."""
    cleaned = {key: str(value or "").strip() for key, value in fields.items()}
    ip_value = cleaned.get("ip", "")
    for key in _SUBJECT_NON_IP_FIELDS:
        value = cleaned.get(key, "")
        if not value or not looks_like_ip_address(value):
            continue
        if not ip_value:
            ip_value = value
        cleaned[key] = ""
    if ip_value:
        cleaned["ip"] = ip_value
    return cleaned


def subject_field_rejects_ip(field_key: str, value: str) -> bool:
    return field_key in _SUBJECT_NON_IP_FIELDS and looks_like_ip_address(value)


def _subject_field_for_target_type(target_type: str) -> str:
    kind = str(target_type or "").strip().casefold()
    if not kind:
        return ""
    if "imsi" in kind:
        return "imsi"
    if "imei" in kind:
        return "imei"
    if kind in {"ip", "ipv4", "ipv6"}:
        return "ip"
    if "msisdn" in kind or kind in {"phone", "mobile", "mobile number", "isdndataonly", "msisdndataonly"}:
        return "msisdn"
    if "isdn" in kind:
        return "msisdn"
    return ""


def _infer_subject_field(target: str, target_type: str) -> str:
    field = _subject_field_for_target_type(target_type)
    if field:
        return field
    if looks_like_ip_address(target):
        return "ip"
    digits = normalize_identifier_value(target, "MSISDN")
    if digits.isdigit() and 8 <= len(digits) <= 15:
        return "msisdn"
    if digits.isdigit() and len(digits) >= 14:
        return "imsi"
    return ""


def sync_project_subject_from_json_meta(
    project_id: int,
    meta: dict,
    *,
    db_path=None,
) -> None:
    """Fill empty project subject fields from JSON dataset metadata."""
    from core.db import DEFAULT_DB_PATH, get_project, set_project_subject, set_project_target

    db_path = db_path or DEFAULT_DB_PATH
    project = get_project(project_id, db_path=db_path)
    if not project:
        return

    target = str(meta.get("target") or "").strip()
    target_type = str(meta.get("targettype") or "").strip()
    if not target:
        return

    if is_imsi_target_type(target_type):
        target = format_intercept_imsi(target)

    field = _infer_subject_field(target, target_type)

    updates: dict[str, str] = {}
    if field == "msisdn" and not _split_identifier_values(project.subject_msisdn):
        updates["msisdn"] = target
    elif field == "imsi" and not _split_identifier_values(project.subject_imsi):
        updates["imsi"] = target
    elif field == "imei" and not _split_identifier_values(project.subject_imei):
        updates["imei"] = target
    elif field == "ip" and not (project.subject_ip or "").strip():
        updates["ip"] = target

    if updates:
        set_project_subject(project_id, **updates, db_path=db_path)

    project = get_project(project_id, db_path=db_path)
    if not project:
        return

    if not (project.target_identifier or "").strip() and not project_identifier_rows(project):
        set_project_target(project_id, target, target_type or field.upper(), db_path=db_path)
