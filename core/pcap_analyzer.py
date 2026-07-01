from __future__ import annotations

import datetime as _dt
import base64
import gc
import math
import re
import socket
import string
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.analysis_limits import (
    MAX_COMMUNICATION_ROWS,
    MAX_COMMUNICATION_ROWS_HARD_CAP,
    MAX_COMMUNICATION_SCAN_HARD_CAP,
    MAX_INVESTIGATOR_SERVICE_ROWS,
    MAX_PCAP_ARTIFACTS_HARD_CAP,
    MAX_PCAP_ARTIFACTS_PER_KIND,
    MAX_PCAP_COUNTER_HARD_CAP,
    MAX_PCAP_ENDPOINT_ROWS,
    MAX_PCAP_FLOW_MAP_HARD_CAP,
    MAX_PCAP_FLOWS,
    MAX_PCAP_METADATA_COUNTER_HARD_CAP,
    MAX_PCAP_OUTPUT_FLOWS_HARD_CAP,
    MAX_PCAP_PACKET_SLICE_BYTES,
    MAX_PCAP_PORT_ROWS,
    MAX_PCAP_PROTOCOL_ROWS,
    MAX_PCAP_READABLE_SAMPLES,
    MAX_PCAP_READABLE_SAMPLES_HARD_CAP,
    METADATA_TOP_DNS_ROWS,
    METADATA_TOP_HTTP_ROWS,
    METADATA_TOP_TLS_ROWS,
    counter_most_common,
    slice_rows,
)
from core.formatters import format_pcap_datetime, human_bytes
from core.service_classification import (
    classify_communication_service,
    classify_pcap_investigator_service,
)
from core.limit_notices import pcap_flow_cap_notice


PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAP_MAGIC_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}

PROTO_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

APP_PORT_HINTS = {
    (6, 80): "HTTP",
    (6, 443): "TLS/HTTPS",
    (17, 443): "QUIC/HTTP3",
    (17, 53): "DNS",
    (6, 53): "DNS",
    (17, 1900): "SSDP",
    (17, 5353): "mDNS",
    (17, 137): "NetBIOS",
    (6, 5222): "XMPP/Messaging",
}

PRINTABLE_BYTES = set(bytes(string.printable, "ascii")) | {9, 10, 13}

ARTIFACT_LIMIT_PER_KIND = MAX_PCAP_ARTIFACTS_PER_KIND


def _output_flow_limit(max_flows: int) -> int:
    if max_flows > 0:
        return max_flows
    if MAX_PCAP_OUTPUT_FLOWS_HARD_CAP > 0:
        return MAX_PCAP_OUTPUT_FLOWS_HARD_CAP
    return 0


def _parse_flow_map_limit(max_flows: int, *, file_size: int = 0, hard_cap: int | None = None) -> int:
    if max_flows > 0:
        return max_flows
    cap = int(hard_cap or 0)
    if cap > 0:
        return max(1, cap)
    size_cap = _flow_map_hard_cap_for_file_size(file_size)
    return size_cap if size_cap > 0 else 0


def _flow_map_hard_cap_for_file_size(file_size: int) -> int:
    size = max(0, int(file_size or 0))
    if MAX_PCAP_FLOW_MAP_HARD_CAP <= 0:
        return 0
    if size >= 2_000_000_000:
        return 25_000
    if size >= 500_000_000:
        return 50_000
    return MAX_PCAP_FLOW_MAP_HARD_CAP


def _communication_row_limit(limit: int) -> int:
    if limit > 0:
        return limit
    if MAX_COMMUNICATION_ROWS_HARD_CAP > 0:
        return MAX_COMMUNICATION_ROWS_HARD_CAP
    return 0


def _counter_hard_cap() -> int:
    return MAX_PCAP_COUNTER_HARD_CAP


def _increment_counter_limited(counter: Counter, key, *, hard_cap: int) -> None:
    if hard_cap > 0 and key not in counter and len(counter) >= hard_cap:
        return
    counter[key] += 1


def analyze_timeout_for_path(path: str | Path) -> float:
    try:
        size = Path(path).stat().st_size
    except Exception:
        return 3600.0
    # ~90s per 100MB, floor 10 min, ceiling 6 hours
    minutes = max(10.0, min(360.0, (size / (100 * 1024 * 1024)) * 1.5))
    return minutes * 60.0


def _output_sample_limit(max_evidence: int) -> int:
    if max_evidence > 0:
        return max_evidence
    if MAX_PCAP_READABLE_SAMPLES_HARD_CAP > 0:
        return MAX_PCAP_READABLE_SAMPLES_HARD_CAP
    return 0


def _metadata_counter_limit(configured: int) -> int:
    if configured > 0:
        return configured
    if MAX_PCAP_METADATA_COUNTER_HARD_CAP > 0:
        return MAX_PCAP_METADATA_COUNTER_HARD_CAP
    return 0


@dataclass
class PcapSummary:
    file_path: str = ""
    file_name: str = ""
    file_size: int = 0
    source_paths: list[str] = field(default_factory=list)
    format: str = "Unknown"
    packet_count: int = 0
    wire_bytes: int = 0
    truncated_packets: int = 0
    malformed_blocks: int = 0
    first_seen: str = ""
    last_seen: str = ""
    duration_seconds: float = 0.0
    likely_device_ip: str = ""
    protocols: list[dict[str, Any]] = field(default_factory=list)
    top_endpoints: list[dict[str, Any]] = field(default_factory=list)
    top_ports: list[dict[str, Any]] = field(default_factory=list)
    total_dns_names: int = 0
    total_tls_sni_hosts: int = 0
    total_http_hosts: int = 0
    dns_query_counts: dict[str, int] = field(default_factory=dict)
    tls_sni_counts: dict[str, int] = field(default_factory=dict)
    http_host_counts: dict[str, int] = field(default_factory=dict)
    dns_queries: list[dict[str, Any]] = field(default_factory=list)
    tls_sni: list[dict[str, Any]] = field(default_factory=list)
    http_hosts: list[dict[str, Any]] = field(default_factory=list)
    readable_samples: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    communication_rows: list[dict[str, Any]] = field(default_factory=list)
    hourly_activity: list[dict[str, Any]] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    total_flows: int = 0
    total_readable_samples: int = 0
    flows_capped: bool = False
    flow_map_limit: int = 0


@dataclass
class _Interface:
    linktype: int
    snaplen: int
    ts_factor: float = 1e-6


@dataclass
class _Packet:
    ts: float | None
    src_ip: str
    dst_ip: str
    protocol: int
    src_port: int | None = None
    dst_port: int | None = None
    wire_len: int = 0
    payload: bytes = b""


class _PcapAccumulator:
    def __init__(self, *, max_flows: int, max_evidence: int, flow_map_hard_cap: int | None = None):
        self.max_flows = max_flows
        self.max_evidence = max_evidence
        self.flow_map_hard_cap = int(flow_map_hard_cap or 0)
        self.packet_count = 0
        self.wire_bytes = 0
        self.truncated_packets = 0
        self.malformed_blocks = 0
        self.first_ts: float | None = None
        self.last_ts: float | None = None
        self.protocols: Counter[int] = Counter()
        self.endpoints: Counter[str] = Counter()
        self.ports: Counter[tuple[int, int]] = Counter()
        self.dns_queries: Counter[str] = Counter()
        self.tls_sni: Counter[str] = Counter()
        self.http_hosts: Counter[str] = Counter()
        self.hourly_activity: Counter[str] = Counter()
        self.readable_samples: list[dict[str, Any]] = []
        self.total_readable_samples = 0
        self.artifacts: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.flow_map: dict[tuple[Any, ...], dict[str, Any]] = {}
        self.flows_capped = False

    def _flow_map_limit(self) -> int:
        if self.max_flows > 0:
            return self.max_flows
        if self.flow_map_hard_cap > 0:
            return self.flow_map_hard_cap
        return MAX_PCAP_FLOW_MAP_HARD_CAP if MAX_PCAP_FLOW_MAP_HARD_CAP > 0 else 0

    def _artifact_kind_limit(self) -> int:
        if ARTIFACT_LIMIT_PER_KIND > 0:
            return ARTIFACT_LIMIT_PER_KIND
        if MAX_PCAP_ARTIFACTS_HARD_CAP > 0:
            return MAX_PCAP_ARTIFACTS_HARD_CAP
        return 0

    def add_packet(self, packet: _Packet) -> None:
        self.packet_count += 1
        self.wire_bytes += max(0, int(packet.wire_len or 0))

        if packet.ts is not None and math.isfinite(packet.ts):
            self.first_ts = packet.ts if self.first_ts is None else min(self.first_ts, packet.ts)
            self.last_ts = packet.ts if self.last_ts is None else max(self.last_ts, packet.ts)
            try:
                self.hourly_activity[_dt.datetime.fromtimestamp(packet.ts).strftime("%Y-%m-%d %H:00")] += 1
            except (OverflowError, OSError, ValueError):
                pass

        self.protocols[packet.protocol] += 1
        endpoint_cap = _counter_hard_cap()
        _increment_counter_limited(self.endpoints, packet.src_ip, hard_cap=endpoint_cap)
        _increment_counter_limited(self.endpoints, packet.dst_ip, hard_cap=endpoint_cap)

        if packet.src_port is not None:
            _increment_counter_limited(self.ports, (packet.protocol, packet.src_port), hard_cap=endpoint_cap)
        if packet.dst_port is not None:
            _increment_counter_limited(self.ports, (packet.protocol, packet.dst_port), hard_cap=endpoint_cap)

        self._add_flow(packet)
        self._inspect_payload(packet)

    def _add_flow(self, packet: _Packet) -> None:
        key = (
            packet.src_ip,
            packet.src_port or "",
            packet.dst_ip,
            packet.dst_port or "",
            packet.protocol,
        )
        flow = self.flow_map.get(key)
        if not flow:
            limit = self._flow_map_limit()
            if limit > 0 and len(self.flow_map) >= limit:
                self.flows_capped = True
                return
            flow = {
                "src_ip": packet.src_ip,
                "src_port": packet.src_port or "",
                "dst_ip": packet.dst_ip,
                "dst_port": packet.dst_port or "",
                "protocol": packet.protocol,
                "application_name": _application_hint(packet.protocol, packet.src_port, packet.dst_port),
                "requested_server_name": "",
                "bidirectional_bytes": 0,
                "bidirectional_packets": 0,
                "bidirectional_first_seen_ms": _format_ts(packet.ts),
                "bidirectional_last_seen_ms": _format_ts(packet.ts),
                "bidirectional_duration_ms": 0,
                "pcap_payload_preview": "",
            }
            self.flow_map[key] = flow

        flow["bidirectional_bytes"] += max(0, int(packet.wire_len or 0))
        flow["bidirectional_packets"] += 1
        if packet.ts is not None:
            if not flow["bidirectional_first_seen_ms"]:
                flow["bidirectional_first_seen_ms"] = _format_ts(packet.ts)
            flow["bidirectional_last_seen_ms"] = _format_ts(packet.ts)
            first = _parse_ts(flow["bidirectional_first_seen_ms"])
            if first is not None:
                flow["bidirectional_duration_ms"] = int(max(0, packet.ts - first) * 1000)

    def _inspect_payload(self, packet: _Packet) -> None:
        payload = packet.payload or b""
        if not payload:
            return

        evidence_type = ""
        value = ""

        if packet.protocol in (6, 17) and (packet.src_port == 53 or packet.dst_port == 53):
            query = _parse_dns_query(payload)
            if query:
                _increment_counter_limited(self.dns_queries, query, hard_cap=_metadata_counter_limit(METADATA_TOP_DNS_ROWS))
                evidence_type = "DNS query"
                value = query

        if packet.protocol == 6:
            sni = _parse_tls_sni(payload)
            if sni:
                _increment_counter_limited(self.tls_sni, sni, hard_cap=_metadata_counter_limit(METADATA_TOP_TLS_ROWS))
                evidence_type = evidence_type or "TLS SNI"
                value = value or sni

        text = _payload_text(payload)
        if text:
            if _looks_like_http(packet, text):
                host = _extract_http_host(text)
                if host:
                    _increment_counter_limited(self.http_hosts, host, hard_cap=_metadata_counter_limit(METADATA_TOP_HTTP_ROWS))
                evidence_type = "HTTP cleartext"
                value = text
            elif packet.protocol == 17 and (packet.src_port == 1900 or packet.dst_port == 1900):
                evidence_type = "SSDP discovery"
                value = text
            elif not evidence_type:
                evidence_type = "Readable payload"
                value = text

        if evidence_type and value:
            self._store_sample(packet, evidence_type, value)
            self._annotate_flow(packet, evidence_type, value)

        self._inspect_artifacts(packet, text or "")

    def _inspect_artifacts(self, packet: _Packet, text: str) -> None:
        payload = packet.payload or b""

        if packet.protocol in (6, 17) and (packet.src_port == 53 or packet.dst_port == 53):
            query = _parse_dns_query(payload)
            if query:
                self._add_artifact("Web", "DNS query", query, packet, "metadata", "DNS request name visible in plaintext metadata.")

        if packet.protocol == 6:
            sni = _parse_tls_sni(payload)
            if sni:
                self._add_artifact("Web", "TLS SNI", sni, packet, "metadata", "TLS server name indication visible before encrypted content.")

        if packet.protocol == 17 and (packet.src_port in (5353, 5355) or packet.dst_port in (5353, 5355)):
            name = _parse_dns_query(payload)
            if name:
                label = "mDNS query" if packet.src_port == 5353 or packet.dst_port == 5353 else "LLMNR query"
                self._add_artifact("Local Network", label, name, packet, "metadata", "Local name discovery request.")

        if packet.protocol == 17 and (packet.src_port == 1900 or packet.dst_port == 1900) and text:
            self._add_artifact("Local Network", "SSDP discovery", text[:500], packet, "plaintext", "Local UPnP/SSDP discovery payload.")

        if packet.protocol == 17 and (packet.src_port == 137 or packet.dst_port == 137):
            nb_name = _parse_nbns_name(payload)
            if nb_name:
                self._add_artifact("Windows / Enterprise", "NBNS name", nb_name, packet, "metadata", "NetBIOS name service query.")

        if packet.protocol == 17 and (packet.src_port in (67, 68) or packet.dst_port in (67, 68)):
            for artifact_type, value in _parse_dhcp_artifacts(payload):
                self._add_artifact("Local Network", artifact_type, value, packet, "metadata", "DHCP option visible in plaintext.")

        if text:
            for artifact_type, value, sensitive in _parse_http_artifacts(text):
                category = "Credentials" if sensitive else "Web"
                visibility = "plaintext-sensitive" if sensitive else "plaintext"
                explanation = "Sensitive HTTP value visible in plaintext." if sensitive else "HTTP header/request visible in plaintext."
                self._add_artifact(category, artifact_type, value, packet, visibility, explanation, sensitive=sensitive)

            for artifact_type, value, sensitive in _parse_plaintext_credentials(text):
                visibility = "plaintext-sensitive" if sensitive else "plaintext"
                self._add_artifact("Credentials", artifact_type, value, packet, visibility, "Credential-like command visible in plaintext.", sensitive=sensitive)

        for artifact_type, value in _parse_ntlm_strings(payload):
            self._add_artifact("Windows / Enterprise", artifact_type, value, packet, "metadata", "NTLMSSP string visible in captured payload.")

    def _add_artifact(
        self,
        category: str,
        artifact_type: str,
        value: str,
        packet: _Packet,
        visibility: str,
        explanation: str,
        *,
        sensitive: bool = False,
    ) -> None:
        value = (value or "").strip()
        if not value:
            return

        redacted = _redact_value(value) if sensitive else value
        key = (category, artifact_type, redacted.casefold())
        existing = self.artifacts.get(key)
        if existing:
            existing["count"] += 1
            existing["last_seen"] = _format_ts(packet.ts)
            return

        kind_count = sum(
            1
            for item in self.artifacts.values()
            if item.get("category") == category and item.get("type") == artifact_type
        )
        kind_limit = self._artifact_kind_limit()
        if kind_limit > 0 and kind_count >= kind_limit:
            return

        self.artifacts[key] = {
            "category": category,
            "type": artifact_type,
            "value": redacted[:500],
            "raw_value": "" if sensitive else value[:500],
            "sensitive": sensitive,
            "visibility": visibility,
            "source": _endpoint(packet.src_ip, packet.src_port),
            "destination": _endpoint(packet.dst_ip, packet.dst_port),
            "first_seen": _format_ts(packet.ts),
            "last_seen": _format_ts(packet.ts),
            "count": 1,
            "explanation": explanation,
        }

    def _store_sample(self, packet: _Packet, evidence_type: str, value: str) -> None:
        self.total_readable_samples += 1
        sample_limit = _output_sample_limit(self.max_evidence)
        if sample_limit > 0 and len(self.readable_samples) >= sample_limit:
            return

        self.readable_samples.append({
            "time": _format_ts(packet.ts),
            "type": evidence_type,
            "source": _endpoint(packet.src_ip, packet.src_port),
            "destination": _endpoint(packet.dst_ip, packet.dst_port),
            "protocol": PROTO_NAMES.get(packet.protocol, str(packet.protocol)),
            "value": value[:500],
        })

    def _annotate_flow(self, packet: _Packet, evidence_type: str, value: str) -> None:
        key = (
            packet.src_ip,
            packet.src_port or "",
            packet.dst_ip,
            packet.dst_port or "",
            packet.protocol,
        )
        flow = self.flow_map.get(key)
        if not flow:
            return
        if not flow.get("requested_server_name") and evidence_type in ("DNS query", "TLS SNI"):
            flow["requested_server_name"] = value
        if not flow.get("pcap_payload_preview"):
            flow["pcap_payload_preview"] = f"{evidence_type}: {value[:220]}"

    def build_summary(self, path: Path, file_format: str) -> PcapSummary:
        all_flows = sorted(
            self.flow_map.values(),
            key=lambda f: int(f.get("bidirectional_bytes") or 0),
            reverse=True,
        )
        flows = slice_rows(all_flows, _output_flow_limit(self.max_flows))

        likely_device = self.endpoints.most_common(1)[0][0] if self.endpoints else ""
        first_seen = _format_ts(self.first_ts)
        last_seen = _format_ts(self.last_ts)
        duration = 0.0
        if self.first_ts is not None and self.last_ts is not None:
            duration = max(0.0, self.last_ts - self.first_ts)

        notes = [
            "Encrypted traffic payload is not readable; ViaNyquist reports metadata such as endpoints, ports, DNS and TLS SNI.",
        ]
        if self.flows_capped:
            notes.append(
                f"Unique flow tracking capped at {self._flow_map_limit():,} connections to protect memory; "
                "packet and metadata counters still include all traffic."
            )
        if self.max_evidence > 0 and self.total_readable_samples > len(self.readable_samples):
            notes.append(
                f"Readable payload samples: {len(self.readable_samples):,} shown of {self.total_readable_samples:,} observed."
            )

        communication_rows = build_communication_rows(flows)

        return PcapSummary(
            file_path=str(path),
            file_name=path.name,
            file_size=path.stat().st_size if path.exists() else 0,
            format=file_format,
            packet_count=self.packet_count,
            wire_bytes=self.wire_bytes,
            truncated_packets=self.truncated_packets,
            malformed_blocks=self.malformed_blocks,
            first_seen=first_seen,
            last_seen=last_seen,
            duration_seconds=duration,
            likely_device_ip=likely_device,
            protocols=[
                {"protocol": PROTO_NAMES.get(k, str(k)), "number": k, "packets": v}
                for k, v in counter_most_common(self.protocols, MAX_PCAP_PROTOCOL_ROWS)
            ],
            top_endpoints=[
                {"ip": k, "packets": v}
                for k, v in counter_most_common(self.endpoints, MAX_PCAP_ENDPOINT_ROWS)
            ],
            top_ports=[
                {"protocol": PROTO_NAMES.get(k[0], str(k[0])), "port": k[1], "packets": v}
                for k, v in counter_most_common(self.ports, MAX_PCAP_PORT_ROWS)
            ],
            total_dns_names=len(self.dns_queries),
            total_tls_sni_hosts=len(self.tls_sni),
            total_http_hosts=len(self.http_hosts),
            dns_query_counts=dict(counter_most_common(self.dns_queries, _metadata_counter_limit(METADATA_TOP_DNS_ROWS))),
            tls_sni_counts=dict(counter_most_common(self.tls_sni, _metadata_counter_limit(METADATA_TOP_TLS_ROWS))),
            http_host_counts=dict(counter_most_common(self.http_hosts, _metadata_counter_limit(METADATA_TOP_HTTP_ROWS))),
            dns_queries=[
                {"query": k, "count": v}
                for k, v in counter_most_common(self.dns_queries, METADATA_TOP_DNS_ROWS)
            ],
            tls_sni=[
                {"host": k, "count": v}
                for k, v in counter_most_common(self.tls_sni, METADATA_TOP_TLS_ROWS)
            ],
            http_hosts=[
                {"host": k, "count": v}
                for k, v in counter_most_common(self.http_hosts, METADATA_TOP_HTTP_ROWS)
            ],
            readable_samples=self.readable_samples,
            artifacts=sorted(
                self.artifacts.values(),
                key=lambda item: (str(item.get("category", "")), str(item.get("type", "")), -int(item.get("count", 0))),
            ),
            communication_rows=communication_rows,
            hourly_activity=[
                {"hour": k, "packets": v}
                for k, v in sorted(self.hourly_activity.items())
            ],
            flows=flows,
            notes=notes,
            total_flows=len(all_flows),
            total_readable_samples=self.total_readable_samples,
            flows_capped=self.flows_capped,
            flow_map_limit=self._flow_map_limit() if self.flows_capped else 0,
        )


def analyze_pcap(path: str | Path, *, max_flows: int = MAX_PCAP_FLOWS, max_evidence: int = MAX_PCAP_READABLE_SAMPLES) -> PcapSummary:
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"PCAP file not found: {p}")

    acc = _PcapAccumulator(
        max_flows=max_flows,
        max_evidence=max_evidence,
        flow_map_hard_cap=_parse_flow_map_limit(max_flows, file_size=p.stat().st_size),
    )
    with p.open("rb") as f:
        magic = f.read(4)
        f.seek(0)
        if magic == PCAPNG_MAGIC:
            _read_pcapng(f, acc)
            file_format = "PCAPNG"
        elif magic in PCAP_MAGIC_ENDIAN:
            _read_pcap(f, acc)
            file_format = "PCAP"
        else:
            raise ValueError("Unsupported capture format. Expected PCAP or PCAPNG.")

    summary = acc.build_summary(p, file_format)
    summary.source_paths = [str(p)]
    return summary


def analyze_pcap_files(
    paths: list[str | Path],
    *,
    label: str = "",
    max_flows: int = MAX_PCAP_FLOWS,
    max_evidence: int = MAX_PCAP_READABLE_SAMPLES,
) -> PcapSummary:
    clean_paths = [Path(path) for path in paths if str(path or "").strip()]
    if not clean_paths:
        raise FileNotFoundError("No PCAP files were provided.")
    if len(clean_paths) == 1:
        return analyze_pcap(clean_paths[0], max_flows=max_flows, max_evidence=max_evidence)

    aggregate_label = label or f"{len(clean_paths)} PCAP files"
    merged: PcapSummary | None = None
    for path in clean_paths:
        summary = analyze_pcap(path, max_flows=max_flows, max_evidence=max_evidence)
        if merged is None:
            merged = summary
        else:
            merged = merge_pcap_summaries([merged, summary], label=aggregate_label)
            summary = None
        gc.collect()

    return merged or PcapSummary(file_name=aggregate_label)


def _run_isolated_subprocess(args: list[str], *, stdin_payload: bytes | None = None, timeout: float | None = None) -> PcapSummary:
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "core.pcap_isolated", *args],
        input=stdin_payload,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or b"").decode("utf-8", errors="replace").strip()
        raise RuntimeError(detail or f"PCAP child process exited with code {proc.returncode}")
    try:
        import pickle

        return pickle.loads(proc.stdout)
    except Exception as exc:
        raise RuntimeError("PCAP child process returned invalid data.") from exc


def analyze_pcap_files_isolated(
    paths: list[str | Path],
    *,
    label: str = "",
    max_flows: int = MAX_PCAP_FLOWS,
    max_evidence: int = MAX_PCAP_READABLE_SAMPLES,
    timeout: float | None = None,
) -> PcapSummary:
    """Run multi-file PCAP analysis in a child process so native crashes do not kill the UI."""
    import pickle

    clean_paths = [str(path) for path in paths if str(path or "").strip()]
    if not clean_paths:
        raise FileNotFoundError("No PCAP files were provided.")
    if len(clean_paths) == 1:
        return analyze_pcap_isolated(clean_paths[0], max_flows=max_flows, max_evidence=max_evidence, timeout=timeout)

    payload = pickle.dumps(
        {
            "paths": clean_paths,
            "label": label,
            "max_flows": max_flows,
            "max_evidence": max_evidence,
        },
        protocol=pickle.HIGHEST_PROTOCOL,
    )
    try:
        return _run_isolated_subprocess(["--batch"], stdin_payload=payload, timeout=timeout)
    except Exception as exc:
        raise RuntimeError(
            f"PCAP re-analysis crashed or failed for {len(clean_paths):,} files "
            f"({Path(clean_paths[0]).name} …)."
        ) from exc


def analyze_pcap_isolated(
    path: str | Path,
    *,
    max_flows: int = MAX_PCAP_FLOWS,
    max_evidence: int = MAX_PCAP_READABLE_SAMPLES,
    timeout: float | None = None,
) -> PcapSummary:
    """Run single-file PCAP analysis in a child process so native crashes do not kill the UI."""
    target = str(path)
    if timeout is None:
        timeout = analyze_timeout_for_path(target)
    try:
        return _run_isolated_subprocess(
            [target, str(max_flows), str(max_evidence)],
            timeout=timeout,
        )
    except Exception as exc:
        raise RuntimeError(f"PCAP analysis crashed or failed for {Path(target).name}.") from exc


def merge_pcap_summaries_isolated(
    summaries: list[PcapSummary],
    *,
    label: str = "",
    timeout: float | None = 1800.0,
) -> PcapSummary:
    """Merge PCAP summaries in a child process to protect the UI from native crashes."""
    import pickle

    items = [summary for summary in summaries if summary is not None]
    if not items:
        return PcapSummary(file_name=label or "PCAP aggregate")
    if len(items) == 1:
        return items[0]
    payload = pickle.dumps(
        {"summaries": items, "label": label},
        protocol=pickle.HIGHEST_PROTOCOL,
    )
    try:
        return _run_isolated_subprocess(["--merge"], stdin_payload=payload, timeout=timeout)
    except Exception as exc:
        raise RuntimeError(f"PCAP merge crashed or failed for {len(items):,} summaries.") from exc


def merge_pcap_summaries(summaries: list[PcapSummary], *, label: str = "") -> PcapSummary:
    items = [summary for summary in summaries if summary is not None]
    if not items:
        return PcapSummary(file_name=label or "PCAP aggregate")
    if len(items) == 1:
        return items[0]

    protocols: Counter[tuple[str, int]] = Counter()
    endpoints: Counter[str] = Counter()
    ports: Counter[tuple[str, int]] = Counter()
    dns: Counter[str] = Counter()
    tls: Counter[str] = Counter()
    http: Counter[str] = Counter()
    hourly: Counter[str] = Counter()
    device_votes: Counter[str] = Counter()
    flow_map: dict[tuple[Any, ...], dict[str, Any]] = {}
    artifacts: dict[tuple[str, str, str], dict[str, Any]] = {}
    samples: list[dict[str, Any]] = []
    total_readable = 0
    total_flow_candidates = 0
    source_paths: list[str] = []
    flows_capped = False
    sample_limit = _output_sample_limit(MAX_PCAP_READABLE_SAMPLES)
    flow_map_limit = _output_flow_limit(MAX_PCAP_FLOWS)

    packet_count = 0
    wire_bytes = 0
    file_size = 0
    truncated = 0
    malformed = 0
    first_ts: float | None = None
    last_ts: float | None = None
    formats: set[str] = set()

    for summary in items:
        packet_count += int(summary.packet_count or 0)
        wire_bytes += int(summary.wire_bytes or 0)
        file_size += int(summary.file_size or 0)
        truncated += int(summary.truncated_packets or 0)
        malformed += int(summary.malformed_blocks or 0)
        if summary.format:
            formats.add(summary.format)
        paths = summary.source_paths or ([summary.file_path] if summary.file_path else [])
        source_paths.extend(str(path) for path in paths if str(path or "").strip())

        start = _parse_ts(summary.first_seen)
        end = _parse_ts(summary.last_seen)
        if start is not None:
            first_ts = start if first_ts is None else min(first_ts, start)
        if end is not None:
            last_ts = end if last_ts is None else max(last_ts, end)
        if summary.likely_device_ip:
            device_votes[summary.likely_device_ip] += max(1, int(summary.packet_count or 0))

        for row in summary.protocols:
            protocols[(str(row.get("protocol") or ""), _safe_int(row.get("number")))] += _safe_int(row.get("packets"))
        for row in summary.top_endpoints:
            endpoints[str(row.get("ip") or "")] += _safe_int(row.get("packets"))
        for row in summary.top_ports:
            ports[(str(row.get("protocol") or ""), _safe_int(row.get("port")))] += _safe_int(row.get("packets"))
        _merge_metadata_counter(dns, summary.dns_query_counts, summary.dns_queries, key_name="query")
        _merge_metadata_counter(tls, summary.tls_sni_counts, summary.tls_sni, key_name="host")
        _merge_metadata_counter(http, summary.http_host_counts, summary.http_hosts, key_name="host")
        for row in summary.hourly_activity:
            hourly[str(row.get("hour") or "")] += _safe_int(row.get("packets") or row.get("count"))

        total_readable += int(getattr(summary, "total_readable_samples", 0) or len(summary.readable_samples or []))
        total_flow_candidates += int(getattr(summary, "total_flows", 0) or len(summary.flows or []))
        if getattr(summary, "flows_capped", False):
            flows_capped = True
        if sample_limit > 0 and len(samples) < sample_limit:
            samples.extend(
                (summary.readable_samples or [])[: max(0, sample_limit - len(samples))]
            )
        elif sample_limit <= 0:
            samples.extend(summary.readable_samples or [])

        for artifact in summary.artifacts:
            key = (
                str(artifact.get("category") or ""),
                str(artifact.get("type") or ""),
                str(artifact.get("value") or ""),
            )
            existing = artifacts.get(key)
            if not existing:
                artifacts[key] = dict(artifact)
            else:
                existing["count"] = _safe_int(existing.get("count")) + _safe_int(artifact.get("count"))

        for flow in summary.flows:
            key = (
                flow.get("src_ip") or "",
                flow.get("src_port") or "",
                flow.get("dst_ip") or "",
                flow.get("dst_port") or "",
                flow.get("protocol") or "",
            )
            existing = flow_map.get(key)
            if not existing:
                if flow_map_limit > 0 and len(flow_map) >= flow_map_limit:
                    flows_capped = True
                    continue
                flow_map[key] = dict(flow)
                continue
            existing["bidirectional_bytes"] = _safe_int(existing.get("bidirectional_bytes")) + _safe_int(flow.get("bidirectional_bytes"))
            existing["bidirectional_packets"] = _safe_int(existing.get("bidirectional_packets")) + _safe_int(flow.get("bidirectional_packets"))
            existing["bidirectional_duration_ms"] = max(
                _safe_int(existing.get("bidirectional_duration_ms")),
                _safe_int(flow.get("bidirectional_duration_ms")),
            )
            if not existing.get("requested_server_name"):
                existing["requested_server_name"] = flow.get("requested_server_name") or ""
            if not existing.get("pcap_payload_preview"):
                existing["pcap_payload_preview"] = flow.get("pcap_payload_preview") or ""
            existing["bidirectional_first_seen_ms"] = _min_time_text(existing.get("bidirectional_first_seen_ms"), flow.get("bidirectional_first_seen_ms"))
            existing["bidirectional_last_seen_ms"] = _max_time_text(existing.get("bidirectional_last_seen_ms"), flow.get("bidirectional_last_seen_ms"))

    flow_map_values = sorted(flow_map.values(), key=lambda row: _safe_int(row.get("bidirectional_bytes")), reverse=True)
    total_flows = len(flow_map_values)
    flows = slice_rows(flow_map_values, flow_map_limit)
    first_seen = _format_ts(first_ts)
    last_seen = _format_ts(last_ts)
    duration = max(0.0, (last_ts or 0) - (first_ts or 0)) if first_ts is not None and last_ts is not None else 0.0
    file_name = label or f"{len(items)} PCAP files"
    file_path = file_name

    return PcapSummary(
        file_path=file_path,
        file_name=file_name,
        file_size=file_size,
        source_paths=source_paths,
        format="Mixed PCAP" if len(formats) > 1 else next(iter(formats), "PCAP"),
        packet_count=packet_count,
        wire_bytes=wire_bytes,
        truncated_packets=truncated,
        malformed_blocks=malformed,
        first_seen=first_seen,
        last_seen=last_seen,
        duration_seconds=duration,
        likely_device_ip=device_votes.most_common(1)[0][0] if device_votes else "",
        protocols=[
            {"protocol": protocol or PROTO_NAMES.get(number, str(number)), "number": number, "packets": packets}
            for (protocol, number), packets in counter_most_common(protocols, MAX_PCAP_PROTOCOL_ROWS)
        ],
        top_endpoints=[
            {"ip": ip, "packets": packets}
            for ip, packets in counter_most_common(endpoints, MAX_PCAP_ENDPOINT_ROWS)
            if ip
        ],
        top_ports=[
            {"protocol": protocol, "port": port, "packets": packets}
            for (protocol, port), packets in counter_most_common(ports, MAX_PCAP_PORT_ROWS)
        ],
        total_dns_names=len(dns),
        total_tls_sni_hosts=len(tls),
        total_http_hosts=len(http),
        dns_query_counts=dict(dns),
        tls_sni_counts=dict(tls),
        http_host_counts=dict(http),
        dns_queries=[
            {"query": query, "count": count}
            for query, count in counter_most_common(dns, METADATA_TOP_DNS_ROWS)
            if query
        ],
        tls_sni=[
            {"host": host, "count": count}
            for host, count in counter_most_common(tls, METADATA_TOP_TLS_ROWS)
            if host
        ],
        http_hosts=[
            {"host": host, "count": count}
            for host, count in counter_most_common(http, METADATA_TOP_HTTP_ROWS)
            if host
        ],
        readable_samples=slice_rows(samples, sample_limit),
        artifacts=sorted(
            artifacts.values(),
            key=lambda item: (str(item.get("category", "")), str(item.get("type", "")), -_safe_int(item.get("count"))),
        ),
        communication_rows=build_communication_rows(flows),
        hourly_activity=[
            {"hour": hour, "packets": packets}
            for hour, packets in sorted(hourly.items())
            if hour
        ],
        flows=flows,
        total_flows=max(total_flows, total_flow_candidates),
        total_readable_samples=max(total_readable, len(samples)),
        flows_capped=flows_capped,
        flow_map_limit=flow_map_limit if flows_capped else 0,
        notes=[
            f"Aggregated PCAP view built from {len(items):,} files.",
            "Encrypted traffic payload is not readable; ViaNyquist reports metadata such as endpoints, ports, DNS and TLS SNI.",
        ]
        + (
            [
                f"Flow merge capped at {flow_map_limit:,} unique connections to protect memory; "
                "packet and metadata counters still include all traffic."
            ]
            if flows_capped
            else []
        ),
    )


def _min_time_text(left: Any, right: Any) -> str:
    left_ts = _parse_ts(str(left or ""))
    right_ts = _parse_ts(str(right or ""))
    if left_ts is None:
        return str(right or "")
    if right_ts is None:
        return str(left or "")
    return str(left if left_ts <= right_ts else right)


def _max_time_text(left: Any, right: Any) -> str:
    left_ts = _parse_ts(str(left or ""))
    right_ts = _parse_ts(str(right or ""))
    if left_ts is None:
        return str(right or "")
    if right_ts is None:
        return str(left or "")
    return str(left if left_ts >= right_ts else right)


def build_communication_rows(flows: list[dict[str, Any]], *, limit: int = MAX_COMMUNICATION_ROWS) -> list[dict[str, Any]]:
    output_limit = _communication_row_limit(limit)
    if output_limit <= 0:
        scan_source = flows
    elif MAX_COMMUNICATION_SCAN_HARD_CAP > 0:
        scan_limit = max(output_limit, MAX_COMMUNICATION_SCAN_HARD_CAP)
        scan_source = flows[:scan_limit]
    else:
        scan_source = flows
    rows: list[dict[str, Any]] = []
    for flow in scan_source:
        service = _communication_service(flow)
        if not service:
            continue
        activity_type, confidence, evidence = _communication_activity(flow, service)
        rows.append({
            "service": service,
            "activity_type": activity_type,
            "confidence": confidence,
            "evidence": evidence,
            "host": flow.get("requested_server_name") or "",
            "protocol": PROTO_NAMES.get(int(flow.get("protocol") or 0), str(flow.get("protocol") or "")),
            "source": _endpoint(str(flow.get("src_ip") or ""), flow.get("src_port") or None),
            "destination": _endpoint(str(flow.get("dst_ip") or ""), flow.get("dst_port") or None),
            "bytes": int(flow.get("bidirectional_bytes") or 0),
            "packets": int(flow.get("bidirectional_packets") or 0),
            "duration_ms": int(flow.get("bidirectional_duration_ms") or 0),
            "first_seen": flow.get("bidirectional_first_seen_ms") or "",
            "last_seen": flow.get("bidirectional_last_seen_ms") or "",
        })

    confidence_rank = {"high": 0, "medium": 1, "low": 2}
    rows.sort(
        key=lambda row: (
            confidence_rank.get(str(row.get("confidence")), 9),
            -int(row.get("duration_ms") or 0),
            -int(row.get("bytes") or 0),
            str(row.get("service") or ""),
        )
    )
    return rows[:output_limit] if output_limit > 0 else rows


def build_investigator_view(summary: PcapSummary) -> dict[str, Any]:
    service_rows = _build_service_rows(summary)
    protocol_rows = _with_share(summary.protocols, "packets")
    activity_rows = _with_share(summary.hourly_activity, "packets")
    visibility_rows = _build_visibility_rows(summary)

    limitations = [
        "Encrypted HTTPS, QUIC and app traffic content cannot be read from the capture alone.",
        "DNS names, TLS SNI names, endpoints, ports and timing are metadata. They show communication patterns, not message contents.",
        "Plaintext credentials are reported only when visible in unencrypted payload.",
    ]
    cap_note = pcap_flow_cap_notice(
        flows_capped=bool(getattr(summary, "flows_capped", False)),
        flow_map_limit=int(getattr(summary, "flow_map_limit", 0) or 0),
        total_flows=int(getattr(summary, "total_flows", 0) or len(summary.flows or [])),
    )
    if cap_note:
        limitations.insert(0, cap_note)
    for note in summary.notes or []:
        lowered = str(note).lower()
        if note and note not in limitations and ("capped" in lowered or "samples" in lowered):
            limitations.append(str(note))

    return {
        "plain_summary": _plain_summary(summary, service_rows, visibility_rows),
        "key_points": _key_points(summary, service_rows),
        "service_rows": service_rows,
        "protocol_rows": protocol_rows,
        "activity_rows": activity_rows,
        "visibility_rows": visibility_rows,
        "communication_rows": summary.communication_rows,
        "limitations": limitations,
    }


def _communication_service(flow: dict[str, Any]) -> str:
    return classify_communication_service(flow)


def _communication_activity(flow: dict[str, Any], service: str) -> tuple[str, str, str]:
    proto = int(flow.get("protocol") or 0)
    src_port = _safe_int(flow.get("src_port"))
    dst_port = _safe_int(flow.get("dst_port"))
    bytes_count = int(flow.get("bidirectional_bytes") or 0)
    packets = int(flow.get("bidirectional_packets") or 0)
    duration_ms = int(flow.get("bidirectional_duration_ms") or 0)
    host = str(flow.get("requested_server_name") or "")
    host_l = host.lower()
    app = str(flow.get("application_name") or "")
    ports = {src_port, dst_port}

    reasons = [
        f"service indicator: {host or app or service}",
        f"{PROTO_NAMES.get(proto, proto)} {src_port}->{dst_port}",
        f"{packets} packets",
        f"{_duration_label(duration_ms)}",
    ]

    if proto == 17 and (3478 in ports or 5349 in ports) and packets >= 20:
        reasons.append("STUN/TURN/WebRTC-style relay port")
        confidence = "high" if duration_ms >= 20_000 and packets >= 80 else "medium"
        return "Possible call/media signaling", confidence, "; ".join(reasons)

    if proto == 17 and duration_ms >= 30_000 and packets >= 120 and bytes_count >= 250_000:
        reasons.append("sustained UDP media-like stream")
        confidence = "high" if bytes_count >= 2_000_000 and duration_ms >= 60_000 else "medium"
        return "Possible voice/video media session", confidence, "; ".join(reasons)

    if proto == 17 and 443 in ports and duration_ms >= 20_000 and bytes_count >= 500_000:
        reasons.append("sustained QUIC/UDP 443 traffic")
        return "Possible app media or heavy encrypted session", "medium", "; ".join(reasons)

    if _is_push_host(host_l) or 5222 in ports or "applepush" in app.lower():
        reasons.append("known push/messaging transport signal")
        confidence = "medium" if service in {"Apple / iCloud", "Facebook / Meta", "Google / YouTube"} else "low"
        return "Push/background messaging transport", confidence, "; ".join(reasons)

    if service == "Apple / iCloud" and any(token in host_l for token in ("gateway.icloud", "mask-api", "courier", "push")):
        reasons.append("Apple cloud/push infrastructure visible in metadata")
        return "Possible iCloud / device sync or push transport", "medium", "; ".join(reasons)

    if _is_messaging_endpoint(host_l, service):
        reasons.append("messaging endpoint name visible in metadata")
        confidence = "medium" if service in {
            "WhatsApp",
            "Viber",
            "Telegram",
            "Facebook / Meta",
            "Signal",
            "Apple / iCloud",
        } else "low"
        return "Possible messaging endpoint", confidence, "; ".join(reasons)

    if duration_ms >= 120_000 and bytes_count <= 120_000:
        reasons.append("long-lived low-volume encrypted connection")
        return "Background keepalive / sync connection", "low", "; ".join(reasons)

    if duration_ms < 10_000 and packets <= 40:
        reasons.append("short metadata burst")
        return "App contact / metadata burst", "low", "; ".join(reasons)

    if bytes_count >= 1_000_000:
        reasons.append("large encrypted transfer")
        return "Large encrypted app transfer", "low", "; ".join(reasons)

    if service in {"Google / YouTube", "TikTok", "Spotify"}:
        reasons.append("service API/content endpoint without call-specific signal")
        return "App/API or content service connection", "low", "; ".join(reasons)

    return "App service contact observed", "low", "; ".join(reasons)


def _is_push_host(host: str) -> bool:
    return any(
        token in host
        for token in (
            "edge-mqtt",
            "mqtt",
            "push",
            "push.apple",
            "courier",
            "notification",
            "notify",
            "fcm",
            "apns",
        )
    )


def _is_messaging_endpoint(host: str, service: str) -> bool:
    if any(token in host for token in ("chat", "message", "msg", "e2ee", "messenger")):
        return True
    if service in {"WhatsApp", "Viber", "Telegram"} and any(token in host for token in ("mmg", "media", "web", "api")):
        return True
    return False


def _communication_summary_text(summary: PcapSummary) -> str:
    rows = list(summary.communication_rows or [])
    if not rows:
        return "No communication indicators were classified in this view."
    services: list[str] = []
    seen: set[str] = set()
    for row in rows:
        service = str(row.get("service") or "").strip()
        if service and service not in seen:
            seen.add(service)
            services.append(service)
        if len(services) >= 5:
            break
    service_text = ", ".join(services) if services else "mixed services"
    return (
        f"{len(rows):,} communication indicators were identified, mainly involving {service_text}."
    )


def _plain_summary(
    summary: PcapSummary,
    service_rows: list[dict[str, Any]],
    visibility_rows: list[dict[str, Any]],
) -> str:
    duration = _duration_words(summary.duration_seconds)
    source_count = len(getattr(summary, "source_paths", None) or []) or 1
    scope = f"{source_count:,} PCAP files" if source_count > 1 else "one PCAP file"
    comm_text = _communication_summary_text(summary)
    top_services = ", ".join(row["service"] for row in service_rows[:5]) or "no dominant service groups"
    encrypted = next((row for row in visibility_rows if row["label"].startswith("Encrypted")), None)
    encrypted_text = ""
    if encrypted and encrypted.get("count"):
        encrypted_text = (
            f" Most sessions look encrypted or metadata-only "
            f"({encrypted['count']:,} packets on common encrypted service ports)."
        )

    credential_text = "No plaintext credentials were observed in readable samples."
    if any("credential" in str(sample.get("type", "")).lower() for sample in summary.readable_samples):
        credential_text = "Potential credential-like plaintext was observed and should be reviewed carefully."

    return (
        f"This view covers {duration} across {scope}. "
        f"{comm_text} "
        f"Visible metadata groups include {top_services}.{encrypted_text} "
        f"{credential_text} "
        f"Open Communications for classified activity and Evidence for DNS, TLS hosts and payloads."
    )


def _key_points(summary: PcapSummary, service_rows: list[dict[str, Any]]) -> list[str]:
    points = [
        f"Capture window: {_fmt_pcap_dt(summary.first_seen)} to {_fmt_pcap_dt(summary.last_seen)}",
        f"Packets: {summary.packet_count:,}; volume: {human_bytes(summary.wire_bytes, precision=2)}",
        f"Visible DNS names: {_visible_count(summary.total_dns_names, len(summary.dns_queries))}; "
        f"TLS SNI hosts: {_visible_count(summary.total_tls_sni_hosts, len(summary.tls_sni))}; "
        f"HTTP hosts: {_visible_count(summary.total_http_hosts, len(summary.http_hosts))}",
    ]
    comm_count = len(summary.communication_rows or [])
    if comm_count:
        points.append(f"Communication indicators: {comm_count:,}")
    if service_rows:
        points.append("Top service groups: " + ", ".join(row["service"] for row in service_rows[:5]))
    return points


def _visible_count(total: int, shown: int) -> str:
    total = int(total or 0)
    shown = int(shown or 0)
    if total > shown:
        return f"{total:,} ({shown:,} shown)"
    return f"{total:,}" if total else "0"


def _merge_metadata_counter(
    target: Counter[str],
    counts: dict[str, int] | None,
    rows: list[dict[str, Any]] | None,
    *,
    key_name: str,
) -> None:
    if counts:
        for key, value in counts.items():
            name = str(key or "").strip()
            if name:
                target[name] += _safe_int(value)
        return
    for row in rows or []:
        name = str(row.get(key_name) or "").strip()
        if name:
            target[name] += _safe_int(row.get("count"))


def metadata_count_label(total: int, shown: int) -> str:
    return _visible_count(total, shown)


def _fmt_pcap_dt(value: Any) -> str:
    return format_pcap_datetime(value) or "-"


def _build_service_rows(summary: PcapSummary) -> list[dict[str, Any]]:
    counts: Counter[str] = Counter()
    examples: dict[str, str] = {}

    def add_host(host: str, count: int) -> None:
        label = _service_label(host)
        counts[label] += count
        examples.setdefault(label, host)

    for item in summary.dns_queries:
        add_host(str(item.get("query") or ""), int(item.get("count") or 0))
    for item in summary.tls_sni:
        add_host(str(item.get("host") or ""), int(item.get("count") or 0))
    for item in summary.http_hosts:
        add_host(str(item.get("host") or ""), int(item.get("count") or 0))

    rows = [
        {"service": service, "count": count, "example": examples.get(service, "")}
        for service, count in counter_most_common(counts, MAX_INVESTIGATOR_SERVICE_ROWS)
    ]
    return _with_share(rows, "count")


def _service_label(host: str) -> str:
    return classify_pcap_investigator_service(host)


def _build_visibility_rows(summary: PcapSummary) -> list[dict[str, Any]]:
    port_counts = {
        (str(item.get("protocol") or ""), int(item.get("port") or 0)): int(item.get("packets") or 0)
        for item in summary.top_ports
    }
    encrypted_count = (
        port_counts.get(("TCP", 443), 0)
        + port_counts.get(("UDP", 443), 0)
        + port_counts.get(("TCP", 5222), 0)
    )
    dns_count = port_counts.get(("UDP", 53), 0) + port_counts.get(("TCP", 53), 0)
    http_visible = sum(1 for sample in summary.readable_samples if sample.get("type") == "HTTP cleartext")
    readable_other = max(0, len(summary.readable_samples) - http_visible)

    rows = [
        {"label": "Encrypted or metadata-only indicators", "count": encrypted_count},
        {"label": "DNS metadata", "count": dns_count},
        {"label": "HTTP cleartext samples", "count": http_visible},
        {"label": "Other readable samples", "count": readable_other},
    ]
    return _with_share([row for row in rows if row["count"]], "count")


def _with_share(rows: list[dict[str, Any]], count_key: str) -> list[dict[str, Any]]:
    total = sum(int(row.get(count_key) or 0) for row in rows)
    out = []
    for row in rows:
        count = int(row.get(count_key) or 0)
        item = dict(row)
        item["share"] = round((count / total) * 100, 1) if total else 0.0
        item["bar"] = _bar(item["share"])
        out.append(item)
    return out


def _bar(percent: float, width: int = 24) -> str:
    filled = max(0, min(width, int(round((percent / 100) * width))))
    return "#" * filled + "-" * (width - filled)


def _duration_words(seconds: float) -> str:
    seconds = max(0, int(seconds or 0))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"approximately {hours}h {minutes}m"
    if minutes:
        return f"approximately {minutes}m {secs}s"
    return f"{secs}s"


def _duration_label(milliseconds: int) -> str:
    seconds = max(0, int(milliseconds or 0) // 1000)
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except Exception:
        return 0


def _read_pcap(f, acc: _PcapAccumulator) -> None:
    gh = f.read(24)
    endian, ts_div = PCAP_MAGIC_ENDIAN[gh[:4]]
    if len(gh) < 24:
        raise ValueError("Invalid PCAP header.")

    _ver_major, _ver_minor, _thiszone, _sigfigs, _snaplen, linktype = struct.unpack(endian + "HHiiii", gh[4:24])

    while True:
        hdr = f.read(16)
        if not hdr:
            break
        if len(hdr) < 16:
            acc.malformed_blocks += 1
            break
        ts_sec, ts_frac, inc_len, orig_len = struct.unpack(endian + "IIII", hdr)
        safe_len = min(int(inc_len), MAX_PCAP_PACKET_SLICE_BYTES)
        data = f.read(safe_len)
        if len(data) < safe_len:
            acc.malformed_blocks += 1
            break
        if safe_len < int(inc_len):
            acc.malformed_blocks += 1
            remainder = int(inc_len) - safe_len
            if remainder > 0:
                f.read(remainder)
        if safe_len < orig_len:
            acc.truncated_packets += 1
        packet = _parse_packet(data, linktype, ts_sec + (ts_frac / ts_div), orig_len)
        if packet:
            acc.add_packet(packet)


def _read_pcapng(f, acc: _PcapAccumulator) -> None:
    endian = "<"
    interfaces: list[_Interface] = []

    while True:
        head = f.read(8)
        if not head:
            break
        if len(head) < 8:
            acc.malformed_blocks += 1
            break

        block_type, block_len = struct.unpack(endian + "II", head)
        if block_len < 12:
            acc.malformed_blocks += 1
            break

        body = f.read(block_len - 12)
        tail = f.read(4)
        if len(body) != block_len - 12 or len(tail) != 4:
            acc.malformed_blocks += 1
            break

        if block_type == 0x0A0D0D0A:
            if body[:4] == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            elif body[:4] == b"\x4d\x3c\x2b\x1a":
                endian = "<"
        elif block_type == 1 and len(body) >= 8:
            linktype, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
            interfaces.append(_Interface(linktype=linktype, snaplen=snaplen, ts_factor=_pcapng_ts_factor(body[8:], endian)))
        elif block_type == 6 and len(body) >= 20:
            iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(endian + "IIIII", body[:20])
            if iface_id < 0 or iface_id >= len(interfaces):
                iface = _Interface(linktype=1, snaplen=65535)
            else:
                iface = interfaces[iface_id]
            payload_max = max(0, len(body) - 20)
            snap_cap = max(64, min(int(iface.snaplen or 65535), MAX_PCAP_PACKET_SLICE_BYTES))
            safe_cap = min(int(cap_len), payload_max, snap_cap)
            if safe_cap < int(cap_len):
                acc.malformed_blocks += 1
            data = body[20:20 + safe_cap]
            if safe_cap < orig_len:
                acc.truncated_packets += 1
            ts = ((ts_high << 32) | ts_low) * iface.ts_factor
            if not math.isfinite(ts) or abs(ts) > 1e15:
                ts = None
            packet = _parse_packet(data, iface.linktype, ts, orig_len)
            if packet:
                acc.add_packet(packet)
        elif block_type == 3 and len(body) >= 4:
            iface = interfaces[0] if interfaces else _Interface(linktype=1, snaplen=65535)
            cap_len = struct.unpack(endian + "I", body[:4])[0]
            payload_max = max(0, len(body) - 4)
            snap_cap = max(64, min(int(iface.snaplen or 65535), MAX_PCAP_PACKET_SLICE_BYTES))
            safe_cap = min(int(cap_len), payload_max, snap_cap)
            if safe_cap < int(cap_len):
                acc.malformed_blocks += 1
            packet = _parse_packet(body[4:4 + safe_cap], iface.linktype, None, safe_cap)
            if packet:
                acc.add_packet(packet)


def _pcapng_ts_factor(options: bytes, endian: str) -> float:
    off = 0
    while off + 4 <= len(options):
        code, length = struct.unpack(endian + "HH", options[off:off + 4])
        off += 4
        value = options[off:off + length]
        off += ((length + 3) // 4) * 4
        if code == 0:
            break
        if code == 9 and value:
            resolution = value[0]
            if resolution & 0x80:
                return 2 ** -(resolution & 0x7F)
            return 10 ** -resolution
    return 1e-6


def _parse_packet(data: bytes, linktype: int, ts: float | None, wire_len: int) -> _Packet | None:
    ethertype = None
    offset = None

    if linktype == 1 and len(data) >= 14:
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        if ethertype == 0x8100 and len(data) >= 18:
            ethertype = struct.unpack("!H", data[16:18])[0]
            offset = 18
    elif linktype == 113 and len(data) >= 16:
        ethertype = struct.unpack("!H", data[14:16])[0]
        offset = 16
    elif linktype in (101, 228):
        offset = 0
        ethertype = 0x0800 if data and data[0] >> 4 == 4 else 0x86DD
    else:
        return None

    if ethertype == 0x0800:
        return _parse_ipv4(data, offset or 0, ts, wire_len)
    if ethertype == 0x86DD:
        return _parse_ipv6(data, offset or 0, ts, wire_len)
    return None


def _parse_ipv4(data: bytes, offset: int, ts: float | None, wire_len: int) -> _Packet | None:
    if len(data) < offset + 20:
        return None
    ihl = (data[offset] & 0x0F) * 4
    if ihl < 20 or len(data) < offset + ihl:
        return None
    total_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]
    protocol = data[offset + 9]
    src = socket.inet_ntoa(data[offset + 12:offset + 16])
    dst = socket.inet_ntoa(data[offset + 16:offset + 20])
    l4_offset = offset + ihl
    packet = _Packet(ts=ts, src_ip=src, dst_ip=dst, protocol=protocol, wire_len=wire_len)
    _fill_l4(packet, data, l4_offset, offset + total_len)
    return packet


def _parse_ipv6(data: bytes, offset: int, ts: float | None, wire_len: int) -> _Packet | None:
    if len(data) < offset + 40:
        return None
    protocol = data[offset + 6]
    src = socket.inet_ntop(socket.AF_INET6, data[offset + 8:offset + 24])
    dst = socket.inet_ntop(socket.AF_INET6, data[offset + 24:offset + 40])
    packet = _Packet(ts=ts, src_ip=src, dst_ip=dst, protocol=protocol, wire_len=wire_len)
    _fill_l4(packet, data, offset + 40, len(data))
    return packet


def _fill_l4(packet: _Packet, data: bytes, l4_offset: int, end_offset: int) -> None:
    if packet.protocol not in (6, 17) or len(data) < l4_offset + 4:
        return
    packet.src_port, packet.dst_port = struct.unpack("!HH", data[l4_offset:l4_offset + 4])
    end_offset = min(max(l4_offset, end_offset), len(data))
    if packet.protocol == 6 and len(data) >= l4_offset + 20:
        data_offset = ((data[l4_offset + 12] >> 4) & 0x0F) * 4
        packet.payload = data[l4_offset + data_offset:end_offset]
    elif packet.protocol == 17 and len(data) >= l4_offset + 8:
        packet.payload = data[l4_offset + 8:end_offset]


def _parse_dns_query(payload: bytes) -> str | None:
    if len(payload) < 12:
        return None
    flags = struct.unpack("!H", payload[2:4])[0]
    if flags & 0x8000:
        return None
    qd_count = struct.unpack("!H", payload[4:6])[0]
    if qd_count < 1:
        return None
    offset = 12
    labels: list[str] = []
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(payload):
            return None
        labels.append(payload[offset:offset + length].decode("ascii", "ignore"))
        offset += length
    return ".".join(labels) if labels else None


def _parse_nbns_name(payload: bytes) -> str | None:
    if len(payload) < 45:
        return None
    flags = struct.unpack("!H", payload[2:4])[0]
    if flags & 0x8000:
        return None
    qd_count = struct.unpack("!H", payload[4:6])[0]
    if qd_count < 1:
        return None
    length = payload[12]
    if length != 32 or len(payload) < 45:
        return None
    encoded = payload[13:45]
    try:
        raw = []
        for i in range(0, 32, 2):
            high = encoded[i] - 65
            low = encoded[i + 1] - 65
            if high < 0 or low < 0:
                return None
            raw.append((high << 4) | low)
        name = bytes(raw[:15]).rstrip(b" \x00").decode("ascii", "ignore").strip()
    except Exception:
        return None
    return name or None


def _parse_dhcp_artifacts(payload: bytes) -> list[tuple[str, str]]:
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return []

    artifacts: list[tuple[str, str]] = []
    offset = 240
    while offset < len(payload):
        code = payload[offset]
        offset += 1
        if code == 255:
            break
        if code == 0:
            continue
        if offset >= len(payload):
            break
        length = payload[offset]
        offset += 1
        value = payload[offset:offset + length]
        offset += length

        if code == 12:
            artifacts.append(("DHCP hostname", value.decode("ascii", "ignore")))
        elif code == 15:
            artifacts.append(("DHCP domain", value.decode("ascii", "ignore")))
        elif code == 60:
            artifacts.append(("DHCP vendor class", value.decode("ascii", "ignore")))
        elif code == 81 and len(value) > 3:
            artifacts.append(("DHCP FQDN", value[3:].decode("ascii", "ignore")))

    return [(kind, val.strip()) for kind, val in artifacts if val.strip()]


def _parse_tls_sni(payload: bytes) -> str | None:
    try:
        if len(payload) < 43 or payload[0] != 22 or payload[5] != 1:
            return None
        record_len = int.from_bytes(payload[3:5], "big")
        body = payload[5:5 + record_len]
        offset = 4 + 2 + 32
        session_len = body[offset]
        offset += 1 + session_len
        cipher_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2 + cipher_len
        compression_len = body[offset]
        offset += 1 + compression_len
        ext_len = int.from_bytes(body[offset:offset + 2], "big")
        offset += 2
        end = min(len(body), offset + ext_len)
        while offset + 4 <= end:
            ext_type = int.from_bytes(body[offset:offset + 2], "big")
            ext_size = int.from_bytes(body[offset + 2:offset + 4], "big")
            offset += 4
            ext_data = body[offset:offset + ext_size]
            offset += ext_size
            if ext_type == 0 and len(ext_data) >= 5:
                name_len = int.from_bytes(ext_data[3:5], "big")
                name = ext_data[5:5 + name_len]
                return name.decode("ascii", "ignore") if name else None
    except Exception:
        return None
    return None


def _payload_text(payload: bytes) -> str | None:
    if not payload:
        return None
    sample = payload[:768]
    printable = sum(1 for b in sample if b in PRINTABLE_BYTES)
    if printable / max(1, len(sample)) < 0.85:
        return None
    text = sample.decode("utf-8", "replace")
    lines = [line.strip() for line in text.replace("\r", "\n").split("\n") if line.strip()]
    return " | ".join(lines[:5])[:500] if lines else None


def _payload_lines(text: str) -> list[str]:
    if not text:
        return []
    normalized = text.replace("\r", "\n").replace("|", "\n")
    return [line.strip() for line in normalized.split("\n") if line.strip()]


def _parse_http_artifacts(text: str) -> list[tuple[str, str, bool]]:
    lines = _payload_lines(text)
    if not lines:
        return []

    out: list[tuple[str, str, bool]] = []
    first = lines[0]
    if re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+", first, re.I):
        out.append(("HTTP request", first, False))
    elif first.upper().startswith("HTTP/"):
        out.append(("HTTP response", first, False))

    for line in lines[:100]:
        low = line.lower()
        if low.startswith("host:"):
            out.append(("HTTP host", line[5:].strip(), False))
        elif low.startswith("user-agent:"):
            out.append(("HTTP user-agent", line[11:].strip(), False))
        elif low.startswith("authorization:"):
            out.append(("HTTP authorization", line, True))
            match = re.match(r"authorization:\s*basic\s+(.+)", line, re.I)
            if match:
                decoded = _decode_basic_auth(match.group(1).strip())
                if decoded:
                    out.append(("HTTP Basic credentials", decoded, True))
        elif low.startswith("proxy-authorization:"):
            out.append(("HTTP proxy authorization", line, True))
        elif low.startswith("cookie:"):
            out.append(("HTTP cookie", line, True))
        elif low.startswith("set-cookie:"):
            out.append(("HTTP set-cookie", line, True))
        elif _looks_like_secret_parameter(line):
            out.append(("Possible web secret parameter", line, True))

    return out


def _parse_plaintext_credentials(text: str) -> list[tuple[str, str, bool]]:
    out: list[tuple[str, str, bool]] = []
    for line in _payload_lines(text)[:100]:
        low = line.lower()
        if re.match(r"^(user|acct)\s+\S+", low):
            out.append(("Plaintext username command", line, False))
        elif re.match(r"^pass\s+\S+", low):
            out.append(("Plaintext password command", line, True))
        elif re.match(r"^a\d+\s+login\s+\S+", low) or re.match(r"^login\s+\S+", low):
            out.append(("IMAP login command", line, True))
        elif low.startswith("auth login") or low.startswith("auth plain"):
            out.append(("SMTP auth command", line, True))
        elif re.search(r"(^|[&; ])(password|passwd|pwd)=", low):
            out.append(("Possible plaintext password parameter", line, True))
    return out


def _parse_ntlm_strings(payload: bytes) -> list[tuple[str, str]]:
    idx = payload.find(b"NTLMSSP\x00")
    if idx < 0:
        return []

    region = payload[max(0, idx - 600):idx + 5000]
    out: list[tuple[str, str]] = [("NTLMSSP marker", "NTLMSSP visible")]
    seen: set[str] = set()

    for match in re.finditer(rb"[A-Za-z0-9_.\\$@-]{4,}", region):
        value = match.group(0).decode("ascii", "ignore")
        if value not in seen and _useful_ntlm_string(value):
            seen.add(value)
            out.append(("NTLMSSP visible string", value))

    chars: list[str] = []
    for i in range(0, len(region) - 1, 2):
        c, z = region[i], region[i + 1]
        if z == 0 and 32 <= c < 127:
            chars.append(chr(c))
            continue
        if len(chars) >= 4:
            value = "".join(chars)
            if value not in seen and _useful_ntlm_string(value):
                seen.add(value)
                out.append(("NTLMSSP visible string", value))
        chars = []
    if len(chars) >= 4:
        value = "".join(chars)
        if value not in seen and _useful_ntlm_string(value):
            out.append(("NTLMSSP visible string", value))

    return out[:25]


def _decode_basic_auth(value: str) -> str:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True).decode("utf-8", "replace")
    except Exception:
        return ""


def _looks_like_secret_parameter(line: str) -> bool:
    low = line.lower()
    return bool(re.search(r"(^|[?&; ])(password|passwd|pwd|token|auth|session|sid)=", low))


def _useful_ntlm_string(value: str) -> bool:
    if not value or len(value) < 4:
        return False
    if value.upper() in {"NTLMSSP", "HTTP", "SMB"}:
        return False
    return any(ch.isalpha() for ch in value)


def _redact_value(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-2:]} [redacted]"


def _looks_like_http(packet: _Packet, text: str) -> bool:
    if packet.protocol != 6:
        return False
    if packet.src_port in (80, 8080, 8000, 8888) or packet.dst_port in (80, 8080, 8000, 8888):
        return True
    upper = text[:20].upper()
    return upper.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "HTTP/"))


def _extract_http_host(text: str) -> str:
    for part in text.split("|"):
        line = part.strip()
        if line.lower().startswith("host:"):
            return line[5:].strip()
    return ""


def _application_hint(protocol: int, src_port: int | None, dst_port: int | None) -> str:
    for port in (dst_port, src_port):
        if port is None:
            continue
        hint = APP_PORT_HINTS.get((protocol, port))
        if hint:
            return hint
    return PROTO_NAMES.get(protocol, str(protocol))


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip


def _format_ts(ts: float | None) -> str:
    if ts is None or not math.isfinite(ts):
        return ""
    try:
        return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except (OverflowError, OSError, ValueError):
        return ""


def _parse_ts(value: str) -> float | None:
    try:
        return _dt.datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").timestamp()
    except Exception:
        return None
