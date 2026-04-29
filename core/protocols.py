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


def describe_ip_proto(x) -> str:
    """
    Returns a short plain-language description of an IP protocol number/name.
    Descriptions explain the protocol role, not the real-world service purpose.
    """
    if x is None or x == "":
        return ""

    try:
        n = int(x)
    except Exception:
        name = str(x).strip().upper()
        by_name = {
            "TCP": "Connection-oriented transport. Often used when ordered, reliable byte streams are needed.",
            "UDP": "Connectionless transport. Often used for short exchanges or latency-sensitive communication.",
            "ICMP": "Control and diagnostic protocol. Commonly used for network reachability and error messages.",
            "ICMPV6": "IPv6 control and diagnostic protocol. Used for IPv6 reachability, discovery, and error messages.",
            "GRE": "Encapsulation protocol. Can carry one network protocol inside another.",
            "ESP": "IPsec payload protection protocol. Indicates protected IP payloads, but not the application purpose.",
            "AH": "IPsec authentication protocol. Indicates authenticated IP payloads, but not the application purpose.",
            "SCTP": "Message-oriented transport protocol. Used by some telecom and specialized applications.",
        }
        return by_name.get(name, "Protocol label as provided by the dataset; purpose is not confirmed.")

    descriptions = {
        1: "Control and diagnostic protocol. Commonly used for network reachability and error messages.",
        2: "Group-management protocol. Used for multicast group membership signaling.",
        6: "Connection-oriented transport. Often used when ordered, reliable byte streams are needed.",
        17: "Connectionless transport. Often used for short exchanges or latency-sensitive communication.",
        41: "IPv6 encapsulation over IPv4. Indicates IPv6 traffic carried inside IPv4.",
        47: "Encapsulation protocol. Can carry one network protocol inside another.",
        50: "IPsec payload protection protocol. Indicates protected IP payloads, but not the application purpose.",
        51: "IPsec authentication protocol. Indicates authenticated IP payloads, but not the application purpose.",
        58: "IPv6 control and diagnostic protocol. Used for IPv6 reachability, discovery, and error messages.",
        89: "Routing protocol used by OSPF-capable network devices.",
        132: "Message-oriented transport protocol. Used by some telecom and specialized applications.",
    }
    return descriptions.get(n, "Uncommon or unrecognized IP protocol number; purpose is not confirmed.")


def format_ip_proto_with_description(x) -> str:
    formatted = format_ip_proto(x)
    description = describe_ip_proto(x)
    if not formatted:
        return ""
    if not description:
        return formatted
    return f"{formatted} - {description}"
