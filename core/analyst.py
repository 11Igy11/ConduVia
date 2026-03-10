# core/analyst.py
from __future__ import annotations
from core.timeutils import parse_flow_timestamp

import ipaddress
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any



# ----------------- helpers -----------------
def _safe_int(x: Any) -> int:
    if x is None:
        return 0
    if isinstance(x, bool):
        return int(x)
    if isinstance(x, int):
        return x
    try:
        return int(float(x))
    except Exception:
        return 0


def _pct(part: int | float, whole: int | float) -> float:
    w = float(whole) if whole else 0.0
    if w <= 0:
        return 0.0
    return (float(part) / w) * 100.0


def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def _parse_flow_dt(ts: Any) -> datetime | None:
    # 1) epoch (ms or s)
    if isinstance(ts, (int, float)):
        try:
            v = float(ts)
            # heuristika: ms epoch je obično > 1e12
            if v > 1e12:
                return datetime.utcfromtimestamp(v / 1000.0)
            # seconds epoch
            if v > 1e9:
                return datetime.utcfromtimestamp(v)
        except Exception:
            return None

    # 2) string formats
    if not ts:
        return None
    s = str(ts).strip()
    if len(s) < 16:
        return None

    fmts = (
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    )
    for fmt in fmts:
        try:
            return datetime.strptime(s, fmt)
        except Exception:
            pass
    return None


def _parse_meta_iso_dt(s: Any) -> datetime | None:
    """
    Meta bt/et sample:
      '2024-05-28T22:00:00.000+00:00'
    Python 3.11+ datetime.fromisoformat handles +00:00 offsets.
    """
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).strip())
    except Exception:
        return None


def _score_level(score: int) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 35:
        return "MED"
    return "LOW"


def _normalize_0_100(vals: list[int]) -> list[int]:
    """Normalize list to 0..100 ints, keeping shape (for mini-hist)."""
    if not vals:
        return []
    mx = max(vals)
    if mx <= 0:
        return [0 for _ in vals]
    out: list[int] = []
    for v in vals:
        try:
            p = int(round((v / mx) * 100))
        except Exception:
            p = 0
        if p < 0:
            p = 0
        if p > 100:
            p = 100
        out.append(p)
    return out

def _compute_coverage_window(flows: list[dict[str, Any]]) -> dict[str, Any]:
    first_seen = None
    last_seen = None
    active_days = set()

    for f in flows:
        if not isinstance(f, dict):
            continue

        dt = parse_flow_timestamp(f)
        if dt is None:
            continue

        if first_seen is None or dt < first_seen:
            first_seen = dt

        if last_seen is None or dt > last_seen:
            last_seen = dt

        active_days.add(dt.date())

    if first_seen is None or last_seen is None:
        return {
            "first_seen": None,
            "last_seen": None,
            "days_span": 0,
            "active_days": 0,
        }

    days_span = (last_seen.date() - first_seen.date()).days + 1

    return {
        "first_seen": first_seen,
        "last_seen": last_seen,
        "days_span": int(days_span),
        "active_days": int(len(active_days)),
    }


# ----------------- main -----------------
def compute_analyst_summary(flows: list[dict[str, Any]], meta: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Returns a dict with:
      - coverage (bt/et/days)
      - dominant app by bytes + by count
      - outbound/inbound stats (heuristic by private/public classification)
      - direction "mini bar" data (bytes + flows, pct)
      - dominance (top internal src, top dst)
      - activity density (hour histogram raw + normalized, peak/quiet, night share)
      - largest flow shares
      - risk score 0..100 + level + reasons
      - top outbound pair (src,dst) by outbound bytes
    Safe defaults if fields are missing.
    """
    meta = meta or {}
    flows = flows or []

    total_flows = len(flows)

    # ---- meta period ----
    bt_raw = meta.get("bt")
    et_raw = meta.get("et")
    bt_dt = _parse_meta_iso_dt(bt_raw)
    et_dt = _parse_meta_iso_dt(et_raw)
    duration_days = None
    if bt_dt and et_dt:
        try:
            duration_days = (et_dt - bt_dt).total_seconds() / 86400.0
            if duration_days < 0:
                duration_days = None
        except Exception:
            duration_days = None

    coverage_window = _compute_coverage_window(flows)

    # ---- aggregations ----
    total_bytes = 0

    # Directional heuristic (only for private/public classification)
    total_outbound_bytes = 0  # private src -> public dst
    total_inbound_bytes = 0   # public src -> private dst

    total_outbound_flows = 0
    total_inbound_flows = 0

    app_count = Counter()
    app_bytes = defaultdict(int)

    outbound_by_internal_src = defaultdict(int)  # src_ip -> outbound bytes
    outbound_by_dst = defaultdict(int)           # dst_ip -> outbound bytes
    outbound_pair_bytes = defaultdict(int)       # (src_ip, dst_ip) -> outbound bytes

    hour_hist = [0] * 24
    hour_bytes = [0] * 24

    day_hist = Counter()
    day_bytes = Counter()
    
    largest_total_flow_bytes = 0
    largest_total_flow: dict[str, Any] | None = None

    largest_outbound_flow_bytes = 0
    largest_outbound_flow: dict[str, Any] | None = None

    # For "total dominance by internal src" (bidirectional)
    total_by_internal_src = defaultdict(int)

    for f in flows:
        if not isinstance(f, dict):
            continue

        src = str(f.get("src_ip") or "")
        dst = str(f.get("dst_ip") or "")
        app = str(f.get("application_name") or "Unknown")

        b_total = _safe_int(f.get("bidirectional_bytes"))
        total_bytes += b_total

        app_count[app] += 1
        app_bytes[app] += b_total

        # total dominance by internal src (bidirectional)
        if src and _is_private_ip(src):
            total_by_internal_src[src] += b_total

        # timestamps -> hour histogram
        dt = parse_flow_timestamp(f)
        if dt is not None:
            hour = int(dt.hour)
            hour_hist[hour] += 1
            hour_bytes[hour] += b_total
            day_key = dt.strftime("%Y-%m-%d")
            day_hist[day_key] += 1
            day_bytes[day_key] += b_total

        # classify direction
        src_priv = bool(src) and _is_private_ip(src)
        dst_priv = bool(dst) and _is_private_ip(dst)
        src_pub = bool(src) and (not src_priv)
        dst_pub = bool(dst) and (not dst_priv)

        # ---------------- OUTBOUND (private -> public) ----------------
        if src_priv and dst_pub:
            total_outbound_flows += 1

            b_out = _safe_int(f.get("src2dst_bytes"))
            if b_out <= 0:
                b_out = b_total

            total_outbound_bytes += b_out
            outbound_by_internal_src[src] += b_out
            outbound_by_dst[dst] += b_out
            outbound_pair_bytes[(src, dst)] += b_out

            if b_out > largest_outbound_flow_bytes:
                largest_outbound_flow_bytes = b_out
                largest_outbound_flow = f

        # ---------------- INBOUND (public -> private) ----------------
        elif src_pub and dst_priv:
            total_inbound_flows += 1

            b_in = _safe_int(f.get("dst2src_bytes"))
            if b_in <= 0:
                b_in = b_total

            total_inbound_bytes += b_in

        # largest total flow (overall)
        if b_total > largest_total_flow_bytes:
            largest_total_flow_bytes = b_total
            largest_total_flow = f

    # ---- mini direction bar (in/out only) ----
    inout_bytes = total_outbound_bytes + total_inbound_bytes
    inout_flows = total_outbound_flows + total_inbound_flows

    direction_bar = {
        "outbound_bytes": int(total_outbound_bytes),
        "inbound_bytes": int(total_inbound_bytes),
        "outbound_bytes_pct": _pct(total_outbound_bytes, inout_bytes),
        "inbound_bytes_pct": _pct(total_inbound_bytes, inout_bytes),
        "outbound_flows": int(total_outbound_flows),
        "inbound_flows": int(total_inbound_flows),
        "outbound_flows_pct": _pct(total_outbound_flows, inout_flows),
        "inbound_flows_pct": _pct(total_inbound_flows, inout_flows),
    }

    # ---- top outbound pair ----
    top_outbound_pair = None
    if total_outbound_bytes > 0 and outbound_pair_bytes:
        (psrc, pdst), pb = max(outbound_pair_bytes.items(), key=lambda kv: kv[1])
        top_outbound_pair = {
            "src_ip": psrc,
            "dst_ip": pdst,
            "bytes": int(pb),
            "share_of_outbound_pct": _pct(pb, total_outbound_bytes),
        }

    # ---- dominant app ----
    dominant_app_bytes = None
    dominant_app_bytes_share = 0.0
    dominant_app_bytes_value = 0
    if app_bytes:
        dominant_app_bytes, dominant_app_bytes_value = max(app_bytes.items(), key=lambda kv: kv[1])
        dominant_app_bytes_share = _pct(dominant_app_bytes_value, total_bytes)

    dominant_app_count = None
    dominant_app_count_share = 0.0
    dominant_app_count_value = 0
    if app_count:
        dominant_app_count, dominant_app_count_value = app_count.most_common(1)[0]
        dominant_app_count_share = _pct(dominant_app_count_value, total_flows)

    # ---- outbound ratio of TOTAL bytes ----
    outbound_share_total = _pct(total_outbound_bytes, total_bytes)

    # ---- internal src dominance (outbound + total) ----
    top_internal_out_ip = None
    top_internal_out_bytes = 0
    top_internal_out_share_of_outbound = 0.0
    if outbound_by_internal_src:
        top_internal_out_ip, top_internal_out_bytes = max(outbound_by_internal_src.items(), key=lambda kv: kv[1])
        top_internal_out_share_of_outbound = _pct(top_internal_out_bytes, total_outbound_bytes)

    top_internal_total_ip = None
    top_internal_total_bytes = 0
    top_internal_total_share = 0.0
    if total_by_internal_src:
        top_internal_total_ip, top_internal_total_bytes = max(total_by_internal_src.items(), key=lambda kv: kv[1])
        top_internal_total_share = _pct(top_internal_total_bytes, total_bytes)

    # ---- destination dominance (outbound) ----
    top_dst_ip = None
    top_dst_out_bytes = 0
    top_dst_share_of_outbound = 0.0
    if outbound_by_dst:
        top_dst_ip, top_dst_out_bytes = max(outbound_by_dst.items(), key=lambda kv: kv[1])
        top_dst_share_of_outbound = _pct(top_dst_out_bytes, total_outbound_bytes)

    # ---- activity pattern ----
    peak_hour = None
    quiet_hour = None
    if sum(hour_hist) > 0:
        peak_hour = max(range(24), key=lambda h: hour_hist[h])
        quiet_hour = min(range(24), key=lambda h: hour_hist[h])

    # night share: 22-06
    total_timed = sum(hour_hist)
    night_count = sum(hour_hist[h] for h in [22, 23, 0, 1, 2, 3, 4, 5])
    business_count = sum(hour_hist[h] for h in range(8, 18))
    night_share = _pct(night_count, total_timed)
    business_share = _pct(business_count, total_timed)

        # ---- communication pattern ----
    active_days = 0
    active_days_pct = 0.0
    avg_flows_per_active_day = 0.0
    pattern = "unknown"

    days_with_activity: set[str] = set()
    for f in flows:
        if not isinstance(f, dict):
            continue
        dt = parse_flow_timestamp(f)
        if dt is not None:
            days_with_activity.add(dt.strftime("%Y-%m-%d"))

    active_days = len(days_with_activity)

    total_period_days = None
    if duration_days is not None:
        total_period_days = max(1, int(duration_days) + 1)
        active_days_pct = _pct(active_days, total_period_days)

    if active_days > 0:
        avg_flows_per_active_day = total_flows / active_days

    if total_flows == 0 or active_days == 0:
        pattern = "unknown"
    elif total_period_days is None:
        pattern = "active"
    else:
        if active_days_pct >= 80:
            pattern = "continuous"
        elif active_days_pct >= 40:
            pattern = "intermittent"
        elif active_days_pct >= 15:
            pattern = "bursty"
        else:
            pattern = "sparse"

    hour_hist_norm = _normalize_0_100(hour_hist)

    # ---- largest flow shares ----
    largest_total_share = _pct(largest_total_flow_bytes, total_bytes)
    largest_outbound_share = _pct(largest_outbound_flow_bytes, total_outbound_bytes)

    # ---- risk score (0..100) ----
    score = 0
    reasons: list[str] = []

    # S1: outbound ratio
    if outbound_share_total > 60:
        score += 30
        reasons.append(f"High outbound ratio: {outbound_share_total:.1f}% of total bytes (private→public).")
    elif outbound_share_total >= 35:
        score += 15
        reasons.append(f"Moderate outbound ratio: {outbound_share_total:.1f}% of total bytes (private→public).")

    # S2: single internal src dominance (outbound)
    if top_internal_out_share_of_outbound > 70:
        score += 25
        reasons.append(
            f"Single internal host dominates outbound: {top_internal_out_ip} = {top_internal_out_share_of_outbound:.1f}% outbound bytes."
        )
    elif top_internal_out_share_of_outbound >= 40:
        score += 10
        reasons.append(
            f"Outbound concentrated to one internal host: {top_internal_out_ip} = {top_internal_out_share_of_outbound:.1f}% outbound bytes."
        )

    # S3: single destination dominance (outbound)
    if top_dst_share_of_outbound > 70:
        score += 25
        reasons.append(f"Single destination dominates outbound: {top_dst_ip} = {top_dst_share_of_outbound:.1f}% outbound bytes.")
    elif top_dst_share_of_outbound >= 40:
        score += 10
        reasons.append(f"Outbound concentrated to one destination: {top_dst_ip} = {top_dst_share_of_outbound:.1f}% outbound bytes.")

    # S4: night-heavy activity
    if total_timed > 0:
        if night_share >= 60:
            score += 10
            reasons.append(f"Night-heavy activity: {night_share:.1f}% of timed flows between 22–06.")
        elif night_share >= 35:
            score += 5
            reasons.append(f"Noticeable night activity: {night_share:.1f}% of timed flows between 22–06.")

    # S5: single largest outbound flow share
    if total_outbound_bytes > 0:
        if largest_outbound_share >= 35:
            score += 10
            reasons.append(f"Bulk outbound transfer: largest outbound flow = {largest_outbound_share:.1f}% of outbound bytes.")
        elif largest_outbound_share >= 15:
            score += 5
            reasons.append(f"Larger-than-usual outbound flow: largest outbound flow = {largest_outbound_share:.1f}% of outbound bytes.")

    if score > 100:
        score = 100

    level = _score_level(score)

    # ---- build "largest flow" descriptors (compact) ----
    def _flow_brief(f2: dict[str, Any] | None, *, outbound: bool) -> dict[str, Any] | None:
        if not f2:
            return None
        return {
            "src_ip": f2.get("src_ip"),
            "src_port": f2.get("src_port"),
            "dst_ip": f2.get("dst_ip"),
            "dst_port": f2.get("dst_port"),
            "application_name": f2.get("application_name"),
            "protocol": f2.get("protocol"),
            "bytes": _safe_int(f2.get("src2dst_bytes")) if outbound else _safe_int(f2.get("bidirectional_bytes")),
            "sni": f2.get("requested_server_name") or "",
            "first_seen": f2.get("bidirectional_first_seen_ms") or f2.get("first_seen") or f2.get("timestamp") or "",
        }

    return {
        "coverage": {
            "total_flows": total_flows,
            "bt": bt_raw or "",
            "et": et_raw or "",
            "duration_days": duration_days,
            "active_days": int(active_days),
            "active_days_pct": float(active_days_pct),
            "avg_flows_per_active_day": float(avg_flows_per_active_day),
            "pattern": pattern,
        },
        "bytes": {
            "total_bytes": int(total_bytes),

            "total_outbound_bytes": int(total_outbound_bytes),
            "total_inbound_bytes": int(total_inbound_bytes),

            "total_outbound_flows": int(total_outbound_flows),
            "total_inbound_flows": int(total_inbound_flows),

            # share of TOTAL bytes
            "outbound_share_total_pct": outbound_share_total,

            # in/out split (only considering in+out bytes)
            "outbound_share_inout_pct": _pct(total_outbound_bytes, inout_bytes),
            "inbound_share_inout_pct": _pct(total_inbound_bytes, inout_bytes),

            # convenience blob for UI mini-bar
            "direction_bar": direction_bar,
        },
        "dominant_app": {
            "by_bytes": {
                "name": dominant_app_bytes or "—",
                "bytes": int(dominant_app_bytes_value),
                "share_pct": float(dominant_app_bytes_share),
            },
            "by_count": {
                "name": dominant_app_count or "—",
                "count": int(dominant_app_count_value),
                "share_pct": float(dominant_app_count_share),
            },
        },
        "dominance": {
            "top_internal_outbound": {
                "ip": top_internal_out_ip or "—",
                "bytes": int(top_internal_out_bytes),
                "share_of_outbound_pct": float(top_internal_out_share_of_outbound),
            },
            "top_internal_total": {
                "ip": top_internal_total_ip or "—",
                "bytes": int(top_internal_total_bytes),
                "share_of_total_pct": float(top_internal_total_share),
            },
            "top_destination_outbound": {
                "ip": top_dst_ip or "—",
                "bytes": int(top_dst_out_bytes),
                "share_of_outbound_pct": float(top_dst_share_of_outbound),
            },
        },
        "activity": {
            "hour_hist": hour_hist,
            "hour_hist_24": hour_hist,
            "hour_hist_norm": hour_hist_norm,
            "hour_bytes": hour_bytes,
            "hour_bytes_24": hour_bytes,

            "day_hist": dict(sorted(day_hist.items())),
            "day_bytes": dict(sorted(day_bytes.items())),

            "peak_hour": peak_hour,
            "quiet_hour": quiet_hour,
            "night_share_pct": float(night_share),
            "business_share_pct": float(business_share),
            "timed_flows": int(total_timed),
        },
        "largest": {
            "largest_total_flow": _flow_brief(largest_total_flow, outbound=False),
            "largest_total_share_pct": float(largest_total_share),
            "largest_outbound_flow": _flow_brief(largest_outbound_flow, outbound=True),
            "largest_outbound_share_pct": float(largest_outbound_share),
        },
        "risk": {
            "score": int(score),
            "level": level,
            "reasons": reasons,
            "top_outbound_pair": top_outbound_pair,
        },
    }