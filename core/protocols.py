# core/protocols.py
from __future__ import annotations

def format_ip_proto(x) -> str:
    """
    Maps IP protocol numbers to human-friendly names.
    Always returns something meaningful, even for unknown values.
    """
    if x is None or x == "":
        return ""

    try:
        n = int(x)
    except Exception:
        # if it's already a name like "TCP", keep it
        return str(x)

    names = {
        1: "ICMP",
        2: "IGMP",
        6: "TCP",
        17: "UDP",
        41: "IPv6",
        47: "GRE",
        50: "ESP",
        51: "AH",
        58: "ICMPv6",
        89: "OSPF",
        132: "SCTP",
    }

    name = names.get(n)
    if name:
        return f"{name} ({n})"
    return f"Other ({n})"