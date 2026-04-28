from __future__ import annotations

import base64
import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.protocols import format_ip_proto
from core.timeutils import parse_flow_timestamp


def _human_bytes(n: int | float | None) -> str:
    try:
        v = float(n or 0)
    except Exception:
        v = 0.0

    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0

    while v >= 1024 and i < len(units) - 1:
        v /= 1024.0
        i += 1

    if i == 0:
        return f"{int(v)} {units[i]}"

    return f"{v:.1f} {units[i]}"


def _safe_int(x: Any) -> int:
    try:
        return int(float(x or 0))
    except Exception:
        return 0


def _esc(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def _fmt_dt_short(x: Any) -> str:
    if not x:
        return "—"

    try:
        dt = datetime.fromisoformat(str(x).strip().replace("Z", "+00:00"))
        return dt.strftime("%d.%m.%Y.")
    except Exception:
        pass

    try:
        dt = parse_flow_timestamp({"timestamp": x})
        if dt is not None:
            return dt.strftime("%d.%m.%Y.")
    except Exception:
        pass

    return str(x)


def _load_template() -> str:
    project_root = Path(__file__).resolve().parents[2]
    return (project_root / "templates" / "registry_export.html").read_text(encoding="utf-8")


def _logo_data_uri() -> str:
    project_root = Path(__file__).resolve().parents[2]
    logo_path = project_root / "assets" / "ViaNyquist.png"

    if not logo_path.exists():
        return ""

    logo_b64 = base64.b64encode(logo_path.read_bytes()).decode("ascii")
    return f"data:image/png;base64,{logo_b64}"


def _simple_table(title: str, items: list[tuple[Any, Any]], col1: str, col2: str) -> str:
    rows = []

    for k, v in (items or [])[:15]:
        rows.append(
            "<tr>"
            f"<td>{_esc(k)}</td>"
            f"<td class='num'>{_esc(v)}</td>"
            "</tr>"
        )

    if not rows:
        rows.append("<tr><td colspan='2'>—</td></tr>")

    return f"""
    <section class="insight-card">
        <h3>{_esc(title)}</h3>
        <table class="mini-table">
            <thead>
                <tr>
                    <th>{_esc(col1)}</th>
                    <th class="num">{_esc(col2)}</th>
                </tr>
            </thead>
            <tbody>
                {''.join(rows)}
            </tbody>
        </table>
    </section>
    """


def _mini_hist_24_html(vals: list[int], *, height_px: int = 42) -> str:
    if not isinstance(vals, list) or len(vals) != 24:
        vals = [0] * 24

    mx = max([_safe_int(v) for v in vals] or [0])
    bars = []

    for h, raw in enumerate(vals):
        v = _safe_int(raw)
        pct = 0 if mx <= 0 else max(3, int((v / mx) * 100))

        bars.append(
            f"""
            <div class="hist-bar-wrap" title="{h:02d}:00 — {v}">
                <div class="hist-bar" style="height:{pct}%"></div>
                <div class="hist-label">{h:02d}</div>
            </div>
            """
        )

    return f"<div class='histogram'>{''.join(bars)}</div>"


def _direction_bar_html(out_pct: float, in_pct: float) -> str:
    try:
        o = float(out_pct)
    except Exception:
        o = 0.0

    try:
        i = float(in_pct)
    except Exception:
        i = 0.0

    total = o + i
    if total > 0:
        o = (o / total) * 100
        i = (i / total) * 100
    else:
        o = i = 0

    return f"""
    <div class="direction-bar">
        <div class="direction-out" style="width:{o:.1f}%"></div>
        <div class="direction-in" style="width:{i:.1f}%"></div>
    </div>
    """

def _friendly_column_name(col: str) -> str:
    labels = {
        "id": "ID",
        "expiration_id": "Expiration ID",

        "src_ip": "Source IP",
        "src_port": "Source Port",
        "src_mac": "Source MAC",
        "src_oui": "Source OUI",

        "dst_ip": "Destination IP",
        "dst_port": "Destination Port",
        "dst_mac": "Destination MAC",
        "dst_oui": "Destination OUI",

        "protocol": "Protocol",
        "application_name": "Application",
        "requested_server_name": "Server Name",

        "bidirectional_first_seen_ms": "First Seen",
        "bidirectional_last_seen_ms": "Last Seen",
        "bidirectional_duration_ms": "Duration",
        "bidirectional_packets": "Packets",
        "bidirectional_bytes": "Volume",

        "src2dst_packets": "Src → Dst Packets",
        "src2dst_bytes": "Src → Dst Bytes",
        "dst2src_packets": "Dst → Src Packets",
        "dst2src_bytes": "Dst → Src Bytes",

        "timestamp": "Timestamp",
        "date": "Date",
        "time": "Time",
    }

    if col in labels:
        return labels[col]

    return col.replace("_", " ").strip().title()

def _format_registry_value(col: str, value: Any) -> str:
    if value is None or value == "":
        return "—"

    if col == "protocol":
        return format_ip_proto(value)

    # first/last seen - supports both epoch ms and datetime string
    if "first_seen" in col or "last_seen" in col:
        try:
            # epoch milliseconds
            if isinstance(value, (int, float)) or str(value).strip().isdigit():
                ms = int(float(value))
                dt = datetime.fromtimestamp(ms / 1000)
                return dt.strftime("%d.%m.%Y. %H:%M:%S.%f")[:-3]

            # datetime string: 2026-01-04 00:00:02.450000
            raw = str(value).strip().replace("T", " ")
            dt = datetime.fromisoformat(raw)
            return dt.strftime("%d.%m.%Y. %H:%M:%S.%f")[:-3]

        except Exception:
            return str(value)

    # duration in ms
    if "duration_ms" in col:
        try:
            ms = int(float(value))
            hours = ms // 3600000
            minutes = (ms % 3600000) // 60000
            seconds = (ms % 60000) // 1000
            millis = ms % 1000
            return f"{hours:02d}:{minutes:02d}:{seconds:02d}.{millis:03d}"
        except Exception:
            return str(value)

    # bytes
    if col.endswith("_bytes") or col == "bidirectional_bytes":
        return _human_bytes(value)

    # booleans
    if col.endswith("_is_guessed") or col in (
        "application_is_guessed",
        "client_is_guessed",
        "server_is_guessed",
    ):
        try:
            return "Yes" if int(float(value)) == 1 else "No"
        except Exception:
            return str(value)

    return str(value)

def _full_dataset_table(flows: list[dict[str, Any]], columns: list[str]) -> str:
    if not flows or not columns:
        return ""

    thead = "".join(f"<th>{_esc(_friendly_column_name(c))}</th>" for c in columns)
    body_rows = []

    for row in flows:
        tds = []
        for c in columns:
            v = _format_registry_value(c, row.get(c, ""))
            tds.append(f"<td>{_esc(v)}</td>")

        body_rows.append("<tr>" + "".join(tds) + "</tr>")

    return f"""
    <section class="table-shell full-dataset">
        <div class="table-head">
            <h2>Full Dataset</h2>
        </div>

        <div class="table-wrap">
            <table>
                <thead>
                    <tr>{thead}</tr>
                </thead>
                <tbody>
                    {''.join(body_rows)}
                </tbody>
            </table>
        </div>
    </section>
    """


def export_registry_html(
    *,
    file_path: str,
    folder: str | Path,
    files: list[Path],
    flows: list[dict[str, Any]],
    meta: dict[str, Any],
    summary: dict[str, Any],
    analyst: dict[str, Any],
    columns: list[str],
    tab_defs: list[tuple[str, str, tuple[str, str]]],
    compare_result: dict[str, Any] | None = None,
    include_full: bool = False,
) -> None:
    meta = meta or {}
    summary = summary or {}
    analyst = analyst or {}
    flows = flows or []
    files = files or []
    columns = columns or []

    klasa = str(meta.get("OrigRegNo") or "—")
    urbroj = str(meta.get("RegNo") or "—")
    target = str(meta.get("target") or "—")
    bt = str(meta.get("bt") or "")
    et = str(meta.get("et") or "")

    period = "—"
    if bt or et:
        period = f"{_fmt_dt_short(bt)} – {_fmt_dt_short(et)}"

    total_flows = _safe_int(summary.get("total_flows", len(flows)))
    uniq_src = len({str(f.get("src_ip") or "") for f in flows if f.get("src_ip")})
    uniq_dst = len({str(f.get("dst_ip") or "") for f in flows if f.get("dst_ip")})
    uniq_apps = len({str(f.get("application_name") or "") for f in flows if f.get("application_name")})

    total_bytes = summary.get("total_bytes")
    if total_bytes is None:
        total_bytes = sum(_safe_int(f.get("bidirectional_bytes")) for f in flows)

    deviation = analyst.get("behavior_deviation", {}) or {}
    score = int(deviation.get("score", 0) or 0)
    level = str(deviation.get("level", "LOW") or "LOW")
    reasons = list(deviation.get("reasons", []) or [])

    cov = analyst.get("coverage", {}) or {}
    dom = analyst.get("dominant_app", {}) or {}
    dom_b = dom.get("by_bytes", {}) or {}
    dom_c = dom.get("by_count", {}) or {}

    bytes_s = analyst.get("bytes", {}) or {}
    out_share = float(bytes_s.get("outbound_share_total_pct", 0.0) or 0.0)

    dirb = bytes_s.get("direction_bar", {}) or {}
    out_b = _human_bytes(dirb.get("outbound_bytes", 0))
    in_b = _human_bytes(dirb.get("inbound_bytes", 0))
    out_p = float(dirb.get("outbound_bytes_pct", 0.0) or 0.0)
    in_p = float(dirb.get("inbound_bytes_pct", 0.0) or 0.0)

    domn = analyst.get("dominance", {}) or {}
    top_out = domn.get("top_internal_outbound", {}) or {}
    top_dst = domn.get("top_destination_outbound", {}) or {}

    act = analyst.get("activity", {}) or {}
    peak = act.get("peak_hour")
    quiet = act.get("quiet_hour")
    night = float(act.get("night_share_pct", 0.0) or 0.0)
    business = float(act.get("business_share_pct", 0.0) or 0.0)

    hour_bytes = act.get("hour_bytes_24") or act.get("hour_bytes") or [0] * 24
    hour_flows = act.get("hour_hist_24") or act.get("hour_hist") or [0] * 24

    if not isinstance(hour_bytes, list) or len(hour_bytes) != 24:
        hour_bytes = [0] * 24

    if not isinstance(hour_flows, list) or len(hour_flows) != 24:
        hour_flows = [0] * 24

    def hfmt(h: Any) -> str:
        return "—" if h is None else f"{int(h):02d}:00"

    coverage_parts = [f"{total_flows} flows"]

    if cov.get("duration_days") is not None:
        coverage_parts.append(f"{float(cov.get('duration_days')):.1f} days")

    if cov.get("active_days"):
        coverage_parts.append(f"{int(cov.get('active_days'))} active days")

    if cov.get("active_days_pct"):
        coverage_parts.append(f"{float(cov.get('active_days_pct')):.1f}% active")

    if cov.get("avg_flows_per_active_day"):
        coverage_parts.append(f"{float(cov.get('avg_flows_per_active_day')):.1f} flows/day")

    if cov.get("pattern"):
        coverage_parts.append(f"pattern: {cov.get('pattern')}")

    reasons_html = "".join(f"<li>{_esc(r)}</li>" for r in reasons[:5]) or "<li>—</li>"

    insight_cards = []

    for title, key, hdrs in tab_defs:
        items = list(summary.get(key, []) or [])[:15]

        if key == "top_proto":
            items = [(format_ip_proto(k), v) for k, v in items]

        insight_cards.append(_simple_table(title, items, hdrs[0], hdrs[1]))

    compare_html = ""
    cmp = compare_result or {}

    if cmp:
        compare_html = f"""
        <section class="panel">
            <h2>Dataset Compare</h2>
            <div class="compare-grid">
                <div><span>Current unique</span><strong>{_esc(cmp.get("total_current", 0))}</strong></div>
                <div><span>Previous unique</span><strong>{_esc(cmp.get("total_previous", 0))}</strong></div>
                <div><span>New</span><strong>{len(cmp.get("new", []) or [])}</strong></div>
                <div><span>Known</span><strong>{len(cmp.get("known", []) or [])}</strong></div>
            </div>
        </section>
        """

    full_table_html = _full_dataset_table(flows, columns) if include_full else ""

    template = _load_template()

    rendered = (
        template
        .replace("{{TITLE}}", "ViaNyquist Registry Report")
        .replace("{{LOGO}}", _esc(_logo_data_uri()))
        .replace("{{FOLDER}}", _esc(Path(folder).name if folder else "—"))
        .replace("{{EXPORTED_AT}}", datetime.now().strftime("%d.%m.%Y %H:%M:%S"))
        .replace("{{KLASA}}", _esc(klasa))
        .replace("{{URBROJ}}", _esc(urbroj))
        .replace("{{TARGET}}", _esc(target))
        .replace("{{PERIOD}}", _esc(period))
        .replace("{{TOTAL_FLOWS}}", _esc(total_flows))
        .replace("{{UNIQ_SRC}}", _esc(uniq_src))
        .replace("{{UNIQ_DST}}", _esc(uniq_dst))
        .replace("{{UNIQ_APPS}}", _esc(uniq_apps))
        .replace("{{TOTAL_BYTES}}", _esc(_human_bytes(total_bytes)))
        .replace("{{FILES_COUNT}}", _esc(len(files)))
        .replace("{{DEVIATION_SCORE}}", _esc(score))
        .replace("{{DEVIATION_LEVEL}}", _esc(level))
        .replace("{{DEVIATION_REASONS}}", reasons_html)
        .replace("{{COVERAGE}}", _esc(" | ".join(coverage_parts)))
        .replace("{{OUTBOUND_SHARE}}", f"{out_share:.1f}%")
        .replace("{{DOMINANT_APP}}", _esc(dom_b.get("name", "—")))
        .replace("{{DOMINANT_APP_BYTES_SHARE}}", f"{float(dom_b.get('share_pct', 0.0)):.1f}%")
        .replace("{{DOMINANT_APP_COUNT}}", _esc(dom_c.get("name", "—")))
        .replace("{{DOMINANT_APP_COUNT_SHARE}}", f"{float(dom_c.get('share_pct', 0.0)):.1f}%")
        .replace("{{TOP_INTERNAL}}", _esc(top_out.get("ip", "—")))
        .replace("{{TOP_INTERNAL_SHARE}}", f"{float(top_out.get('share_of_outbound_pct', 0.0)):.1f}%")
        .replace("{{TOP_DST}}", _esc(top_dst.get("ip", "—")))
        .replace("{{TOP_DST_SHARE}}", f"{float(top_dst.get('share_of_outbound_pct', 0.0)):.1f}%")
        .replace("{{PEAK_HOUR}}", _esc(hfmt(peak)))
        .replace("{{QUIET_HOUR}}", _esc(hfmt(quiet)))
        .replace("{{NIGHT_SHARE}}", f"{night:.1f}%")
        .replace("{{BUSINESS_SHARE}}", f"{business:.1f}%")
        .replace("{{OUT_BYTES}}", _esc(out_b))
        .replace("{{IN_BYTES}}", _esc(in_b))
        .replace("{{OUT_PCT}}", f"{out_p:.1f}%")
        .replace("{{IN_PCT}}", f"{in_p:.1f}%")
        .replace("{{DIRECTION_BAR}}", _direction_bar_html(out_p, in_p))
        .replace("{{HIST_BYTES}}", _mini_hist_24_html(hour_bytes))
        .replace("{{HIST_FLOWS}}", _mini_hist_24_html(hour_flows))
        .replace("{{INSIGHT_CARDS}}", "".join(insight_cards))
        .replace("{{COMPARE_BLOCK}}", compare_html)
        .replace("{{FULL_DATASET}}", full_table_html)
    )

    Path(file_path).write_text(rendered, encoding="utf-8")