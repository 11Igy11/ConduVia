from __future__ import annotations

import datetime as _dt
import socket
import string
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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


@dataclass
class PcapSummary:
    file_path: str = ""
    file_name: str = ""
    file_size: int = 0
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
    dns_queries: list[dict[str, Any]] = field(default_factory=list)
    tls_sni: list[dict[str, Any]] = field(default_factory=list)
    http_hosts: list[dict[str, Any]] = field(default_factory=list)
    readable_samples: list[dict[str, Any]] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


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
    def __init__(self, *, max_flows: int, max_evidence: int):
        self.max_flows = max_flows
        self.max_evidence = max_evidence
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
        self.readable_samples: list[dict[str, Any]] = []
        self.flow_map: dict[tuple[Any, ...], dict[str, Any]] = {}

    def add_packet(self, packet: _Packet) -> None:
        self.packet_count += 1
        self.wire_bytes += max(0, int(packet.wire_len or 0))

        if packet.ts is not None:
            self.first_ts = packet.ts if self.first_ts is None else min(self.first_ts, packet.ts)
            self.last_ts = packet.ts if self.last_ts is None else max(self.last_ts, packet.ts)

        self.protocols[packet.protocol] += 1
        self.endpoints[packet.src_ip] += 1
        self.endpoints[packet.dst_ip] += 1

        if packet.src_port is not None:
            self.ports[(packet.protocol, packet.src_port)] += 1
        if packet.dst_port is not None:
            self.ports[(packet.protocol, packet.dst_port)] += 1

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
                self.dns_queries[query] += 1
                evidence_type = "DNS query"
                value = query

        if packet.protocol == 6:
            sni = _parse_tls_sni(payload)
            if sni:
                self.tls_sni[sni] += 1
                evidence_type = evidence_type or "TLS SNI"
                value = value or sni

        text = _payload_text(payload)
        if text:
            if _looks_like_http(packet, text):
                host = _extract_http_host(text)
                if host:
                    self.http_hosts[host] += 1
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

    def _store_sample(self, packet: _Packet, evidence_type: str, value: str) -> None:
        if len(self.readable_samples) >= self.max_evidence:
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
        flows = sorted(
            self.flow_map.values(),
            key=lambda f: int(f.get("bidirectional_bytes") or 0),
            reverse=True,
        )[: self.max_flows]

        likely_device = self.endpoints.most_common(1)[0][0] if self.endpoints else ""
        first_seen = _format_ts(self.first_ts)
        last_seen = _format_ts(self.last_ts)
        duration = 0.0
        if self.first_ts is not None and self.last_ts is not None:
            duration = max(0.0, self.last_ts - self.first_ts)

        notes = [
            "Encrypted traffic payload is not readable; ViaNyquist reports metadata such as endpoints, ports, DNS and TLS SNI.",
            "Readable payload samples are limited previews of bytes visible in the capture.",
        ]

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
                for k, v in self.protocols.most_common(10)
            ],
            top_endpoints=[
                {"ip": k, "packets": v}
                for k, v in self.endpoints.most_common(20)
            ],
            top_ports=[
                {"protocol": PROTO_NAMES.get(k[0], str(k[0])), "port": k[1], "packets": v}
                for k, v in self.ports.most_common(25)
            ],
            dns_queries=[
                {"query": k, "count": v}
                for k, v in self.dns_queries.most_common(50)
            ],
            tls_sni=[
                {"host": k, "count": v}
                for k, v in self.tls_sni.most_common(50)
            ],
            http_hosts=[
                {"host": k, "count": v}
                for k, v in self.http_hosts.most_common(30)
            ],
            readable_samples=self.readable_samples,
            flows=flows,
            notes=notes,
        )


def analyze_pcap(path: str | Path, *, max_flows: int = 5000, max_evidence: int = 300) -> PcapSummary:
    p = Path(path)
    if not p.exists() or not p.is_file():
        raise FileNotFoundError(f"PCAP file not found: {p}")

    acc = _PcapAccumulator(max_flows=max_flows, max_evidence=max_evidence)
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

    return acc.build_summary(p, file_format)


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
        data = f.read(inc_len)
        if len(data) < inc_len:
            acc.malformed_blocks += 1
            break
        if inc_len < orig_len:
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
            iface = interfaces[iface_id] if iface_id < len(interfaces) else _Interface(linktype=1, snaplen=65535)
            data = body[20:20 + cap_len]
            if cap_len < orig_len:
                acc.truncated_packets += 1
            ts = ((ts_high << 32) | ts_low) * iface.ts_factor
            packet = _parse_packet(data, iface.linktype, ts, orig_len)
            if packet:
                acc.add_packet(packet)
        elif block_type == 3 and len(body) >= 4:
            iface = interfaces[0] if interfaces else _Interface(linktype=1, snaplen=65535)
            cap_len = struct.unpack(endian + "I", body[:4])[0]
            packet = _parse_packet(body[4:4 + cap_len], iface.linktype, None, cap_len)
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
    if ts is None:
        return ""
    return _dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _parse_ts(value: str) -> float | None:
    try:
        return _dt.datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").timestamp()
    except Exception:
        return None
