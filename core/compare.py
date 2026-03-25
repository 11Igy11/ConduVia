from typing import Dict, Any, Set, Tuple

def flow_key(flow: Dict[str, Any]) -> Tuple:
    return (
        str(flow.get("src_ip", "") or ""),
        str(flow.get("dst_ip", "") or ""),
        str(flow.get("application_name", "") or ""),
        str(flow.get("protocol", "") or ""),
        str(flow.get("requested_server_name", "") or ""),
    )

def build_flow_set(flows: list[Dict[str, Any]]) -> Set[Tuple]:
    return {flow_key(f) for f in flows if isinstance(f, dict)}

def compare_flows(current: list[Dict[str, Any]], previous: list[Dict[str, Any]]):
    current_set = build_flow_set(current)
    previous_set = build_flow_set(previous)

    new_keys = current_set - previous_set
    known_keys = current_set & previous_set

    return {
        "new": new_keys,
        "known": known_keys,
        "total_current": len(current_set),
        "total_previous": len(previous_set),
    }

def summarize_new_flows(new_flows: set[tuple]) -> dict:
    """
    Extract high-level indicators from flow fingerprints:
    (src_ip, dst_ip, application_name, protocol, requested_server_name)
    """
    apps = set()
    dst_ips = set()
    sni = set()

    for f in new_flows:
        try:
            _src_ip, dst_ip, app_name, _proto, domain = f
        except Exception:
            continue

        if app_name:
            apps.add(str(app_name))

        if dst_ip:
            dst_ips.add(str(dst_ip))

        if domain:
            sni.add(str(domain))

    return {
        "new_apps": sorted(apps),
        "new_dst_ips": sorted(dst_ips),
        "new_sni": sorted(sni),
    }