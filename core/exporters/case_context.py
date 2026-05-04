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

    if project:
        return {
            "project": project.name or project_name or "-",
            "subject": subject_display_label(project),
            "identifiers": project_identifiers_text(project),
            "oib": project.subject_oib or "-",
            "known_ip": project.subject_ip or "-",
            "dataset_target": dataset_target_label,
        }

    return {
        "project": project_name or "-",
        "subject": "-",
        "identifiers": "-",
        "oib": "-",
        "known_ip": "-",
        "dataset_target": dataset_target_label,
    }


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

    if include_dataset_target:
        fields.append(("Dataset Target", context.get("dataset_target") or "-"))

    return "\n".join(
        f'<div class="{html.escape(card_class)}">'
        f'<div class="{html.escape(label_class)}">{html.escape(label)}</div>'
        f'<div class="{html.escape(value_class)}">{html.escape(str(value))}</div>'
        "</div>"
        for label, value in fields
    )
