from __future__ import annotations

import html
from pathlib import Path
from typing import Any


def load_template(name: str) -> str:
    project_root = Path(__file__).resolve().parents[2]
    return (project_root / "templates" / name).read_text(encoding="utf-8")


def load_export_template(name: str) -> str:
    css = load_template("report.css")
    return load_template(name).replace("{{REPORT_CSS}}", css)


def render_template(template: str, values: dict[str, Any], *, escape_values: bool = True) -> str:
    rendered = template
    for key, value in values.items():
        text = "" if value is None else str(value)
        if escape_values:
            text = html.escape(text)
        rendered = rendered.replace(f"{{{{{key}}}}}", text)
    return rendered
