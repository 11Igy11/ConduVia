from __future__ import annotations

from typing import Any, Callable

from core.db import add_activity, get_finding, update_finding
from core.formatters import human_bytes


def format_finding_detail(row: Any, status_label: Callable[[str], str]) -> str:
    return "\n".join(
        [
            f"Title: {row['title']}",
            "",
            f"Status: {status_label(row['status'])} {row['status']}",
            f"Created: {row['created_at']}",
            f"Tags: {row['tags'] or '-'}",
            "",
            "Flow",
            f"Source: {row['src_ip']}:{row['src_port'] or ''}",
            f"Destination: {row['dst_ip']}:{row['dst_port'] or ''}",
            f"Protocol: {row['protocol']}",
            f"Application: {row['application_name'] or '-'}",
            f"SNI: {row['requested_server_name'] or '-'}",
            f"Bytes: {human_bytes(row['bidirectional_bytes'], precision=2)}",
            f"Packets: {row['bidirectional_packets']}",
            f"Duration (ms): {row['bidirectional_duration_ms']}",
            "",
            "Note",
            row["note"] or "-",
        ]
    )


def update_finding_status(finding_id: int, status: str, project_id: int | None = None) -> bool:
    row = get_finding(finding_id)
    if row is None:
        return False

    update_finding(
        finding_id,
        title=row["title"] or "",
        note=row["note"] or "",
        status=status,
        tags=row["tags"] or "",
    )
    if project_id:
        add_activity(project_id, "finding_status", f"#{finding_id} -> {status}")
    return True
