from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any

from core.db import Project
from core.analysis_limits import EMBEDDED_SUMMARY_TOP_N
from core.exporters.case_context import build_case_context, case_context_table_html
from core.exporters.html_blocks import ranked_list_html, stats_html
from core.exporters.template_utils import load_export_template, render_template
from core.flow_stats import build_daily_activity_rows
from core.formatters import (
    bytes_mb_or_b,
    format_export_cell,
    format_short_date,
    human_bytes,
    safe_int,
)
from core.protocols import format_ip_proto


def _esc(x: Any) -> str:
    return html.escape("" if x is None else str(x))


def _fmt_dt_short(x: Any) -> str:
    return format_short_date(x, missing="—")


def _load_template() -> str:
    return load_export_template("registry_export.html")


def _simple_table(title: str, items: list[tuple[Any, Any]], col1: str, col2: str, *, limit: int = EMBEDDED_SUMMARY_TOP_N) -> str:
    del col1, col2
    return ranked_list_html(title, items, limit=limit, empty_text="—")


def _mini_hist_24_html(vals: list[int], *, height_px: int = 42) -> str:
    if not isinstance(vals, list) or len(vals) != 24:
        vals = [0] * 24

    mx = max([safe_int(v) for v in vals] or [0])
    bars = []

    for h, raw in enumerate(vals):
        v = safe_int(raw)
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


def _daily_activity_table_html(rows: list[dict[str, Any]], *, limit: int = EMBEDDED_SUMMARY_TOP_N) -> str:
    preview = list(rows or [])[:limit]
    if not preview:
        return "<p>—</p>"

    note = ""
    total = len(rows or [])
    if total > limit:
        note = f"<p class='period-context'>Top {limit} days by flow volume ({total:,} days in loaded period).</p>"

    ranked = [
        {
            "label": row.get("date_label") or row.get("date") or "—",
            "count": int(row.get("flows") or 0),
            "detail": str(row.get("bytes_label") or ""),
        }
        for row in preview
    ]
    return note + ranked_list_html("", ranked, meta_key="detail", empty_text="—")


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

def _format_registry_value(col: str, value: Any, *, flow: dict[str, Any] | None = None) -> str:
    if value is None or value == "":
        return "—"
    if col.endswith("_is_guessed") or col in (
        "application_is_guessed",
        "client_is_guessed",
        "server_is_guessed",
    ):
        try:
            return "Yes" if int(float(value)) == 1 else "No"
        except Exception:
            return str(value)
    formatted = format_export_cell(col, value, flow=flow)
    return formatted if formatted != "" else "—"

def _full_dataset_table(flows: list[dict[str, Any]], columns: list[str], *, title: str = "Full Dataset") -> str:
    if not flows or not columns:
        return ""

    thead = "".join(f"<th>{_esc(_friendly_column_name(c))}</th>" for c in columns)
    body_rows = []

    for row in flows:
        tds = []
        for c in columns:
            v = _format_registry_value(c, row.get(c, ""), flow=row)
            tds.append(f"<td>{_esc(v)}</td>")

        body_rows.append("<tr>" + "".join(tds) + "</tr>")

    return f"""
    <section class="section full-dataset">
        <div class="table-head">
            <h2>{_esc(title)}</h2>
        </div>
        <div class="table-wrap tall">
            <table class="data">
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
    project: Project | None = None,
    project_name: str = "",
    period_context: str = "",
) -> None:
    text = _report_text()
    meta = meta or {}
    summary = summary or {}
    analyst = analyst or {}
    flows = flows or []
    files = files or []
    columns = columns or []

    bt = str(meta.get("bt") or "")
    et = str(meta.get("et") or "")

    period = "—"
    if bt or et:
        period = f"{_fmt_dt_short(bt)} – {_fmt_dt_short(et)}"

    case_context = build_case_context(project, project_name=project_name, dataset_meta=meta)

    total_flows = safe_int(summary.get("total_flows", len(flows)))
    uniq_src = len({str(f.get("src_ip") or "") for f in flows if f.get("src_ip")})
    uniq_dst = len({str(f.get("dst_ip") or "") for f in flows if f.get("dst_ip")})
    uniq_apps = len({str(f.get("application_name") or "") for f in flows if f.get("application_name")})

    total_bytes = summary.get("total_bytes")
    if total_bytes is None:
        total_bytes = sum(safe_int(f.get("bidirectional_bytes")) for f in flows)

    deviation = analyst.get("behavior_deviation", {}) or {}
    reasons = list(deviation.get("reasons", []) or [])

    dom = analyst.get("dominant_app", {}) or {}
    dom_b = dom.get("by_bytes", {}) or {}
    dom_c = dom.get("by_count", {}) or {}

    bytes_s = analyst.get("bytes", {}) or {}
    out_share = float(bytes_s.get("outbound_share_total_pct", 0.0) or 0.0)

    dirb = bytes_s.get("direction_bar", {}) or {}
    out_b = human_bytes(dirb.get("outbound_bytes", 0))
    in_b = human_bytes(dirb.get("inbound_bytes", 0))
    out_p = float(dirb.get("outbound_bytes_pct", 0.0) or 0.0)
    in_p = float(dirb.get("inbound_bytes_pct", 0.0) or 0.0)

    domn = analyst.get("dominance", {}) or {}
    top_out = domn.get("top_internal_outbound", {}) or {}
    top_dst = domn.get("top_destination_outbound", {}) or {}

    act = analyst.get("activity", {}) or {}
    day_hist = act.get("day_hist", {}) or {}
    day_bytes = act.get("day_bytes", {}) or {}
    daily_activity_rows = build_daily_activity_rows(day_hist, day_bytes)
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

    activity_parts = [f"{total_flows:,} flows in loaded period"]

    if period_context:
        activity_parts.append(period_context)

    reasons_html = "".join(f"<li>{_esc(r)}</li>" for r in reasons[:8]) or f"<li>{_esc(text['no_pattern_flags'])}</li>"

    insight_cards = []

    for title, key, hdrs in tab_defs:
        items = list(summary.get(key, []) or [])[:15]

        if key == "top_proto":
            items = [(format_ip_proto(k), v) for k, v in items]
        if key in ("top_bytes_src", "top_bytes_dst", "top_bytes_app"):
            items = [(k, bytes_mb_or_b(v, precision=2)) for k, v in items]

        insight_cards.append(_simple_table(title, items, hdrs[0], hdrs[1]))

    compare_html = ""
    cmp = compare_result or {}

    if cmp:
        compare_html = f"""
        <section class="section">
            <h2>{_esc(text["dataset_compare"])}</h2>
            <div class="compare-grid">
                <div><span>{_esc(text["current_unique"])}</span><strong>{_esc(cmp.get("total_current", 0))}</strong></div>
                <div><span>{_esc(text["previous_unique"])}</span><strong>{_esc(cmp.get("total_previous", 0))}</strong></div>
                <div><span>{_esc(text["new"])}</span><strong>{len(cmp.get("new", []) or [])}</strong></div>
                <div><span>{_esc(text["known"])}</span><strong>{len(cmp.get("known", []) or [])}</strong></div>
            </div>
        </section>
        """

    full_table_html = _full_dataset_table(flows, columns, title=text["full_dataset"]) if include_full else ""
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    folder_name = Path(folder).name if folder else "—"
    project_label = _esc(project_name or case_context.get("project") or "Project")
    stats = stats_html([
        (text["total_flows"], f"{total_flows:,}"),
        (text["unique_src_ip"], uniq_src),
        (text["unique_dst_ip"], uniq_dst),
        (text["unique_apps"], uniq_apps),
        (text["total_bytes"], human_bytes(total_bytes)),
    ])

    rendered = render_template(
        _load_template(),
        {
            "LANG": "en",
            "TITLE": text["title"],
            "DOCUMENT_TYPE": text["document_type"],
            "REPORT_TITLE": text["title"],
            "PERIOD_LABEL": text["period"],
            "PERIOD": _esc(period),
            "EXPORTED_LABEL": text["exported"],
            "EXPORTED_AT": generated_at,
            "SOURCE_LABEL": text["dataset"],
            "SOURCE": _esc(folder_name),
            "SCOPE_LABEL": text["scope"],
            "SCOPE": _esc(f"{total_flows:,} flows · {len(files)} files"),
            "CASE_CONTEXT_LABEL": text["case_context"],
            "CASE_TABLE": case_context_table_html(case_context),
            "PROJECT_NAME": project_label,
            "PREPARED_LABEL": text["prepared"],
            "STATS_SECTION": f'<section class="section">{stats}</section>' if stats else "",
            "ANALYST_SUMMARY_LABEL": text["analyst_summary"],
            "PERIOD_CONTEXT_LABEL": text["period_context"],
            "PERIOD_CONTEXT": _esc(period_context or "—"),
            "TRAFFIC_PATTERN_FLAGS_LABEL": text["traffic_pattern_flags"],
            "TRAFFIC_FLAGS": reasons_html,
            "OBSERVED_ACTIVITY_LABEL": text["observed_activity"],
            "COVERAGE": _esc(" | ".join(activity_parts)),
            "OUTBOUND_SHARE_LABEL": text["outbound_share"],
            "OUTBOUND_SHARE": f"{out_share:.1f}%",
            "DAILY_ACTIVITY_LABEL": text["daily_activity"],
            "DAILY_ACTIVITY": _daily_activity_table_html(daily_activity_rows),
            "DOMINANT_APPLICATION_LABEL": text["dominant_application"],
            "DOMINANT_APP": _esc(dom_b.get("name", "—")),
            "DOMINANT_APP_BYTES_SHARE": f"{float(dom_b.get('share_pct', 0.0)):.1f}%",
            "BY_COUNT_LABEL": text["by_count"],
            "DOMINANT_APP_COUNT": _esc(dom_c.get("name", "—")),
            "DOMINANT_APP_COUNT_SHARE": f"{float(dom_c.get('share_pct', 0.0)):.1f}%",
            "TOP_OUTBOUND_RELATIONS_LABEL": text["top_outbound_relations"],
            "INTERNAL_LABEL": text["internal"],
            "TOP_INTERNAL": _esc(top_out.get("ip", "—")),
            "TOP_INTERNAL_SHARE": f"{float(top_out.get('share_of_outbound_pct', 0.0)):.1f}%",
            "DESTINATION_LABEL": text["destination"],
            "TOP_DST": _esc(top_dst.get("ip", "—")),
            "TOP_DST_SHARE": f"{float(top_dst.get('share_of_outbound_pct', 0.0)):.1f}%",
            "ACTIVITY_BY_BYTES_LABEL": text["activity_by_bytes"],
            "HIST_BYTES": _mini_hist_24_html(hour_bytes),
            "ACTIVITY_BY_FLOWS_LABEL": text["activity_by_flows"],
            "HIST_FLOWS": _mini_hist_24_html(hour_flows),
            "PEAK_LABEL": text["peak"],
            "PEAK_HOUR": _esc(hfmt(peak)),
            "QUIET_LABEL": text["quiet"],
            "QUIET_HOUR": _esc(hfmt(quiet)),
            "NIGHT_LABEL": text["night"],
            "NIGHT_SHARE": f"{night:.1f}%",
            "BUSINESS_LABEL": text["business"],
            "BUSINESS_SHARE": f"{business:.1f}%",
            "OUT_BYTES": _esc(out_b),
            "IN_BYTES": _esc(in_b),
            "OUT_PCT": f"{out_p:.1f}%",
            "IN_PCT": f"{in_p:.1f}%",
            "DIRECTION_BAR": _direction_bar_html(out_p, in_p),
            "INSIGHTS_LABEL": text["insights"],
            "INSIGHT_CARDS": "".join(insight_cards),
            "COMPARE_BLOCK": compare_html,
            "FULL_DATASET": full_table_html,
        },
        escape_values=False,
    )

    Path(file_path).write_text(rendered, encoding="utf-8")


def _report_text() -> dict[str, str]:
    return {
        "title": "Registry Report",
        "document_type": "Registry",
        "exported": "Exported",
        "period": "Period",
        "dataset": "Dataset",
        "scope": "Scope",
        "case_context": "Case context",
        "prepared": "Prepared",
        "total_flows": "Total flows",
        "unique_src_ip": "Unique src IP",
        "unique_dst_ip": "Unique dst IP",
        "unique_apps": "Unique apps",
        "total_bytes": "Total bytes",
        "analyst_summary": "Analyst Summary",
        "traffic_pattern_flags": "Traffic pattern flags",
        "period_context": "Period context",
        "daily_activity": "Daily activity (top by volume)",
        "no_pattern_flags": "No unusual traffic pattern flags detected for the loaded period.",
        "observed_activity": "Observed activity",
        "outbound_share": "Outbound share",
        "dominant_application": "Dominant application",
        "by_count": "By count",
        "top_outbound_relations": "Top outbound relations",
        "internal": "Internal",
        "destination": "Destination",
        "activity_by_bytes": "Activity by bytes",
        "activity_by_flows": "Activity by flows",
        "peak": "Peak",
        "quiet": "Quiet",
        "night": "Night",
        "business": "Business",
        "insights": "Rankings",
        "dataset_compare": "Dataset Compare",
        "current_unique": "Current unique",
        "previous_unique": "Previous unique",
        "new": "New",
        "known": "Known",
        "full_dataset": "Full Dataset",
    }
