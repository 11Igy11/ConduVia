from __future__ import annotations

from core.db import Project


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
    identifier = (project.target_identifier or "").strip()
    target_type = (project.target_type or "").strip()
    if identifier and target_type:
        return f"{target_type} / {identifier}"
    return identifier or target_type or "-"


def project_identifier_rows(project: Project) -> list[dict[str, str]]:
    rows = [
        {"type": "MSISDN", "label": "Mobile number", "value": project.subject_msisdn},
        {"type": "IMSI", "label": "IMSI", "value": project.subject_imsi},
        {"type": "IMEI", "label": "IMEI", "value": project.subject_imei},
        {"type": "IP", "label": "IP address", "value": project.subject_ip},
    ]

    if (project.target_identifier or "").strip():
        rows.append({
            "type": (project.target_type or "Target").strip() or "Target",
            "label": "Legacy target",
            "value": project.target_identifier,
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
    kind = str(identifier_type or "").strip().casefold()

    if kind in {"msisdn", "imsi", "imei", "oib", "target", "isdndataonly"}:
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
