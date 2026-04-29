from __future__ import annotations

from typing import Any

from core.flow_stats import (
    top_field_by_bytes,
    top_field_values,
    top_flows_by_bytes as _top_flows_by_bytes,
)
from core.formatters import safe_int


def top_src_ips(flows: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    return top_field_values(flows, "src_ip", limit=limit)


def top_dst_ips(flows: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    return top_field_values(flows, "dst_ip", limit=limit)


def top_protocols(flows: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    return top_field_values(flows, "protocol", limit=limit, include_empty=True, empty_label="")


def top_applications(flows: list[dict[str, Any]], limit: int = 10) -> list[tuple[str, int]]:
    return top_field_values(flows, "application_name", limit=limit)


# -------- BYTES-BASED --------
def _as_int(v: Any) -> int:
    return safe_int(v)


def top_src_ips_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[tuple[str, int]]:
    return top_field_by_bytes(flows, "src_ip", limit=limit, bytes_field=bytes_field)


def top_dst_ips_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[tuple[str, int]]:
    return top_field_by_bytes(flows, "dst_ip", limit=limit, bytes_field=bytes_field)


def top_apps_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[tuple[str, int]]:
    return top_field_by_bytes(
        flows,
        "application_name",
        limit=limit,
        bytes_field=bytes_field,
        include_empty=True,
        empty_label="Unknown",
    )


def top_sni_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[tuple[str, int]]:
    """SNI/hostname from requested_server_name."""
    return top_field_by_bytes(flows, "requested_server_name", limit=limit, bytes_field=bytes_field)


def top_flows_by_bytes(
    flows: list[dict[str, Any]],
    limit: int = 10,
    bytes_field: str = "bidirectional_bytes",
) -> list[dict[str, Any]]:
    """Return largest flow records for quick analyst review."""
    return _top_flows_by_bytes(flows, limit=limit, bytes_field=bytes_field)
