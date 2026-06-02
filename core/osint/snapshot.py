from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from core.behavior_profile import _flow_domain
from core.db import DEFAULT_DB_PATH, get_project, get_project_behavior_profile
from core.osint.normalize import (
    normalize_domain,
    normalize_email,
    normalize_ip,
    normalize_msisdn,
    parse_extra_identifiers,
)
from core.project_evidence import saved_pcap_device_ip_counts


def build_osint_snapshot(project_id: int, *, db_path: Path = DEFAULT_DB_PATH) -> dict[str, Any]:
    kwargs = {"db_path": db_path}

    project = get_project(project_id, **kwargs)
    if not project:
        return {
            "project_id": project_id,
            "project_name": "",
            "subject_label": "",
            "identifiers": [],
            "ips": [],
            "domains": [],
            "checklist": [],
            "empty": True,
        }

    subject_label = " ".join(
        part
        for part in (project.subject_first_name or "", project.subject_last_name or "")
        if part.strip()
    ).strip()

    identifiers = _collect_identifiers(project)
    ips = _collect_ips(project_id, project, **kwargs)
    domains = _collect_domains(project_id, project, **kwargs)
    checklist = _build_checklist(identifiers, ips, domains)

    return {
        "project_id": project_id,
        "project_name": project.name,
        "subject_label": subject_label,
        "identifiers": identifiers,
        "ips": ips,
        "domains": domains,
        "checklist": checklist,
        "empty": not (identifiers or ips or domains),
    }


def _collect_identifiers(project) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, *, source: str, label: str = "") -> None:
        text = str(value or "").strip()
        if not text:
            return
        key = (kind.lower(), text.lower())
        if key in seen:
            return
        seen.add(key)
        rows.append(
            {
                "kind": kind,
                "value": text,
                "label": label or kind,
                "source": source,
            }
        )

    if project.subject_oib:
        add("OIB", project.subject_oib, source="project", label="OIB")
    msisdn = normalize_msisdn(project.subject_msisdn)
    if msisdn:
        add("MSISDN", msisdn, source="project", label="Mobile number")
    if project.subject_imsi:
        add("IMSI", project.subject_imsi, source="project", label="IMSI")
    if project.subject_imei:
        add("IMEI", project.subject_imei, source="project", label="IMEI")
    if project.target_identifier:
        add(project.target_type or "Target", project.target_identifier, source="project")
    subject_ip = normalize_ip(project.subject_ip)
    if subject_ip:
        add("IP", subject_ip, source="project", label="Subject IP")

    for item in parse_extra_identifiers(project.subject_extra_identifiers):
        add(item["kind"], item["value"], source="project", label=item.get("label") or item["kind"])

    return rows


def _collect_ips(project_id: int, project, **kwargs) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()

    subject_ip = normalize_ip(project.subject_ip)
    if subject_ip:
        counts[subject_ip] += 1

    for ip, count in saved_pcap_device_ip_counts(project_id, **kwargs).items():
        normalized = normalize_ip(ip)
        if normalized:
            counts[normalized] += int(count or 0)

    rows = []
    for value, count in counts.most_common():
        rows.append(
            {
                "value": value,
                "source": "case",
                "count": count,
            }
        )
    return rows


def _collect_domains(project_id: int, project, **kwargs) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    profile = get_project_behavior_profile(project_id, **kwargs) or {}
    for row in profile.get("domain_rows") or []:
        label = normalize_domain(str(row.get("label") or ""))
        if label:
            counts[label] += int(row.get("count") or 0)

    rows = []
    for value, count in counts.most_common():
        rows.append(
            {
                "value": value,
                "source": "profile",
                "count": count,
            }
        )
    return rows


def _build_checklist(
    identifiers: list[dict[str, Any]],
    ips: list[dict[str, Any]],
    domains: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    if identifiers:
        items.append({"id": "subject_search", "label": "Run name/identifier search links", "done": False})
    if domains:
        items.append({"id": "domain_whois", "label": "Fetch WHOIS/RDAP for top observed domain", "done": False})
        items.append({"id": "domain_dns", "label": "Fetch DNS for top observed domain", "done": False})
    if ips:
        items.append({"id": "ip_reverse", "label": "Reverse DNS for top observed IP", "done": False})
        items.append({"id": "ip_geo", "label": "GeoIP lookup for public IP", "done": False})
    return items


def flow_domain(value: str) -> str:
    return _flow_domain({"requested_server_name": value})
