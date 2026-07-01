from __future__ import annotations

import html
from typing import Any

from core.db import Project
from core.project_identity import project_identifiers_text, subject_display_label


def build_case_context(
    project: Project | None = None,
    *,
    project_name: str = "",
    dataset_meta: dict[str, Any] | None = None,
) -> dict[str, str]:
    meta = dataset_meta or {}
    dataset_target = str(meta.get("target") or "").strip()
    dataset_target_type = str(meta.get("targettype") or "").strip()
    if dataset_target and dataset_target_type:
        dataset_target_label = f"{dataset_target_type} / {dataset_target}"
    else:
        dataset_target_label = dataset_target or dataset_target_type or "-"

    klasa = "-"
    urbroj = "-"
    order_validity = "-"
    if project and getattr(project, "id", None):
        from core.case_metadata import (
            format_active_order_validity,
            format_klasa_summary,
            format_urbroj_summary,
            load_case_metadata,
        )

        case_metadata = load_case_metadata(int(project.id))
        klasa = format_klasa_summary(case_metadata)
        urbroj = format_urbroj_summary(case_metadata)
        order_validity = format_active_order_validity(case_metadata)

    if project:
        return {
            "project": project.name or project_name or "-",
            "subject": subject_display_label(project),
            "identifiers": project_identifiers_text(project),
            "oib": project.subject_oib or "-",
            "known_ip": project.subject_ip or "-",
            "dataset_target": dataset_target_label,
            "klasa": klasa,
            "urbroj": urbroj,
            "order_validity": order_validity,
        }

    return {
        "project": project_name or "-",
        "subject": "-",
        "identifiers": "-",
        "oib": "-",
        "known_ip": "-",
        "dataset_target": dataset_target_label,
        "klasa": klasa,
        "urbroj": urbroj,
        "order_validity": order_validity,
    }


def case_export_metadata_rows(context: dict[str, str]) -> list[tuple[str, str]]:
    rows = [
        ("Project", context.get("project") or "-"),
        ("Case Subject", context.get("subject") or "-"),
        ("Known Identifiers", context.get("identifiers") or "-"),
    ]
    for label, key in (
        ("OIB", "oib"),
        ("Known IP", "known_ip"),
        ("Klasa", "klasa"),
        ("Urbroj", "urbroj"),
        ("Lawful interception dates", "order_validity"),
        ("Dataset Target", "dataset_target"),
    ):
        value = str(context.get(key) or "").strip()
        if value and value != "-":
            rows.append((label, value))
    return rows


def context_cards_html(
    context: dict[str, str],
    *,
    card_class: str,
    label_class: str = "label",
    value_class: str = "value",
    include_dataset_target: bool = True,
) -> str:
    fields = [
        ("Project", context.get("project") or "-"),
        ("Case Subject", context.get("subject") or "-"),
        ("Known Identifiers", context.get("identifiers") or "-"),
    ]

    if context.get("oib") and context.get("oib") != "-":
        fields.append(("OIB", context.get("oib") or "-"))

    if context.get("known_ip") and context.get("known_ip") != "-":
        fields.append(("Known IP", context.get("known_ip") or "-"))

    for label, key in (("Klasa", "klasa"), ("Urbroj", "urbroj"), ("Lawful interception dates", "order_validity")):
        value = str(context.get(key) or "").strip()
        if value and value != "-":
            fields.append((label, value))

    if include_dataset_target:
        fields.append(("Dataset Target", context.get("dataset_target") or "-"))

    return "\n".join(
        f'<div class="{html.escape(card_class)}">'
        f'<div class="{html.escape(label_class)}">{html.escape(label)}</div>'
        f'<div class="{html.escape(value_class)}">{html.escape(str(value))}</div>'
        "</div>"
        for label, value in fields
    )


def case_context_table_html(
    context: dict[str, str],
    *,
    table_class: str = "case-table",
    include_dataset_target: bool = True,
) -> str:
    rows = case_export_metadata_rows(context)
    if include_dataset_target:
        has_target = any(label == "Dataset Target" for label, _ in rows)
        if not has_target:
            rows.append(("Dataset Target", context.get("dataset_target") or "-"))
    elif rows:
        rows = [(label, value) for label, value in rows if label != "Dataset Target"]

    body = "".join(
        "<tr>"
        f"<th scope=\"row\">{html.escape(label)}</th>"
        f"<td>{html.escape(str(value))}</td>"
        "</tr>"
        for label, value in rows
    )
    return f'<table class="{html.escape(table_class)}"><tbody>{body}</tbody></table>'
