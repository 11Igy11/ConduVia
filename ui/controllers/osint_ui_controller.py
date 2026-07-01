from __future__ import annotations

import webbrowser
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QEvent, QObject, Qt, QThread, Slot
from PySide6.QtWidgets import QListWidget, QListWidgetItem, QPushButton

from core.db import get_latest_osint_lookup, list_osint_lookups, save_osint_lookup
from core.osint.links import (
    build_domain_links,
    build_identifier_search_links,
    build_ip_links,
)
from core.osint.enrichers.base import EnrichResult
from core.osint.service import available_enrichers
from core.osint.identifier_decode import decode_identifier, format_identifier_notes_block
from core.osint.registrable_domain import registrable_domain
from core.osint.snapshot import build_osint_snapshot
from ui.osint_worker import OsintEnrichWorker
from ui.buttons import style_action_button
from ui.thread_utils import stop_qthread

if TYPE_CHECKING:
    from ui.app import App

ENTITY_ROLE = Qt.UserRole + 41

_LINK_PLACEHOLDERS: dict[str, list[str]] = {
    "identifier": ["Google name", "LinkedIn", "Facebook", "Google identifier", "Google phone"],
    "domain": ["Google", "crt.sh", "Wayback", "VirusTotal", "Shodan"],
    "ip": ["Google", "VirusTotal", "Shodan"],
}


class OsintUIController(QObject):
    def __init__(self, app: App):
        super().__init__(app)
        self.app = app
        self._snapshot: dict[str, Any] = {}
        self._selected: dict[str, Any] | None = None
        self._catalog: dict[str, list[dict[str, Any]]] = {
            "identifier": [],
            "ip": [],
            "domain": [],
        }
        self._thread: QThread | None = None
        self._worker: OsintEnrichWorker | None = None
        self._pending_enricher = ""
        self._last_decode_result = None
        self._pending_hit_record_ids: list[int] = []
        self._pending_hit_search = ""
        self._pending_hit_kind = ""

    def refresh(self) -> None:
        self._wire_hit_banner()
        app = self.app
        project_id = app.current_project_id
        if project_id is None:
            self._snapshot = {}
            self._selected = None
            self._catalog = {"identifier": [], "ip": [], "domain": []}
            app.lbl_osint_case.setText("No active project")
            app.lbl_osint_subject.setText("Select or open a project to build an OSINT pivot workspace.")
            self._clear_lists()
            self._set_entity_placeholder("Select an entity", "—")
            app.txt_osint_detail.clear()
            self._show_link_placeholders("identifier")
            if hasattr(app, "lbl_osint_hit"):
                app.lbl_osint_hit.hide()
            app.lbl_osint_checklist.hide()
            if hasattr(app, "txt_osint_filter"):
                app.txt_osint_filter.blockSignals(True)
                app.txt_osint_filter.clear()
                app.txt_osint_filter.blockSignals(False)
            self._set_busy(False)
            self._update_workspace_buttons()
            return

        self._snapshot = build_osint_snapshot(project_id)
        case_name = self._snapshot.get("project_name") or f"Project #{project_id}"
        app.lbl_osint_case.setText(case_name)
        self._update_subtitle(self._snapshot)

        self._catalog = {
            "identifier": list(self._snapshot.get("identifiers") or []),
            "ip": list(self._snapshot.get("ips") or []),
            "domain": list(self._snapshot.get("domains") or []),
        }
        if hasattr(app, "txt_osint_filter"):
            app.txt_osint_filter.blockSignals(True)
            app.txt_osint_filter.clear()
            app.txt_osint_filter.blockSignals(False)

        entity_lists = (
            app.list_osint_identifiers,
            app.list_osint_ips,
            app.list_osint_domains,
        )
        for lst in entity_lists:
            lst.blockSignals(True)
        try:
            self._repopulate_all_lists()
            self._populate_checklist(self._snapshot.get("checklist") or [])

            target = self._default_entity_list()
            if target.count():
                if hasattr(app, "osint_entity_tabs"):
                    if target is app.list_osint_identifiers:
                        app.osint_entity_tabs.setCurrentWidget(app.list_osint_identifiers)
                    elif target is app.list_osint_ips:
                        app.osint_entity_tabs.setCurrentWidget(app.list_osint_ips)
                    else:
                        app.osint_entity_tabs.setCurrentWidget(app.list_osint_domains)
                target.setCurrentRow(0)
                self._apply_entity_selection(target)
            else:
                self._selected = None
                self._set_entity_placeholder("No entities in case", "—")
                app.lbl_osint_registrable.hide()
                app.txt_osint_detail.setPlainText(
                    "Save JSON/PCAP evidence or subject identifiers on the project to populate this workspace."
                )
                self._show_link_placeholders(self._active_entity_kind())
        finally:
            for lst in entity_lists:
                lst.blockSignals(False)
        self._update_workspace_buttons()

    def _active_entity_kind(self) -> str:
        tabs = getattr(self.app, "osint_entity_tabs", None)
        if tabs is None:
            return "identifier"
        current = tabs.currentWidget()
        if current is self.app.list_osint_ips:
            return "ip"
        if current is self.app.list_osint_domains:
            return "domain"
        return "identifier"

    def _has_entity(self) -> bool:
        selected = self._selected or {}
        return bool(str(selected.get("kind") or "") and str(selected.get("value") or "").strip())

    def _update_workspace_buttons(self) -> None:
        app = self.app
        has_project = app.current_project_id is not None
        has_entity = self._has_entity()
        selected = self._selected or {}
        kind = str(selected.get("kind") or "")
        busy = self._thread is not None

        app.btn_osint_leaks.setEnabled(not busy)
        app.btn_osint_notes.setEnabled(has_entity and not busy)
        app.btn_osint_history.setEnabled(has_project and has_entity and not busy)
        app.btn_osint_flows.setEnabled(has_entity and kind == "ip" and not busy)
        app.btn_osint_pcap.setEnabled(has_project and not busy)

        self._update_identifier_buttons()
        self._update_fetch_buttons()

    @Slot()
    def on_entity_tab_changed(self) -> None:
        if not self._has_entity():
            self._show_link_placeholders(self._active_entity_kind())

    def _update_subtitle(self, snapshot: dict[str, Any]) -> None:
        subject = str(snapshot.get("subject_label") or "").strip()
        id_count = len(snapshot.get("identifiers") or [])
        ip_count = len(snapshot.get("ips") or [])
        domain_count = len(snapshot.get("domains") or [])
        stats = f"{id_count} identifiers · {ip_count} IPs · {domain_count} domains"
        app = self.app
        if subject:
            app.lbl_osint_subject.setText(f"{subject}  —  {stats}")
        else:
            app.lbl_osint_subject.setText(stats)

    def _default_entity_list(self) -> QListWidget:
        app = self.app
        if app.list_osint_identifiers.count():
            return app.list_osint_identifiers
        if app.list_osint_domains.count():
            return app.list_osint_domains
        if app.list_osint_ips.count():
            return app.list_osint_ips
        return app.list_osint_identifiers

    def _filter_text(self) -> str:
        if not hasattr(self.app, "txt_osint_filter"):
            return ""
        return (self.app.txt_osint_filter.text() or "").strip().casefold()

    def _rows_for_kind(self, kind: str) -> list[dict[str, Any]]:
        needle = self._filter_text()
        rows = list(self._catalog.get(kind) or [])
        if not needle:
            return rows
        filtered: list[dict[str, Any]] = []
        for row in rows:
            if kind == "identifier":
                hay = f"{row.get('label') or ''} {row.get('kind') or ''} {row.get('value') or ''}".casefold()
            else:
                hay = str(row.get("value") or "").casefold()
            if needle in hay:
                filtered.append(row)
        return filtered

    def _repopulate_all_lists(self) -> None:
        self._populate_list(self.app.list_osint_identifiers, self._rows_for_kind("identifier"), "identifier")
        self._populate_list(self.app.list_osint_ips, self._rows_for_kind("ip"), "ip")
        self._populate_list(self.app.list_osint_domains, self._rows_for_kind("domain"), "domain")

    @Slot()
    def on_filter_changed(self) -> None:
        if self.app.current_project_id is None:
            return
        selected_value = str((self._selected or {}).get("value") or "")
        selected_kind = str((self._selected or {}).get("kind") or "")

        lists = (
            self.app.list_osint_identifiers,
            self.app.list_osint_ips,
            self.app.list_osint_domains,
        )
        for lst in lists:
            lst.blockSignals(True)
        try:
            self._repopulate_all_lists()
            restored = False
            if selected_value and selected_kind:
                mapping = {
                    "identifier": self.app.list_osint_identifiers,
                    "ip": self.app.list_osint_ips,
                    "domain": self.app.list_osint_domains,
                }
                target = mapping.get(selected_kind)
                if target is not None:
                    for row in range(target.count()):
                        item = target.item(row)
                        meta = item.data(ENTITY_ROLE) if item else {}
                        if str(meta.get("value") or "") == selected_value:
                            target.setCurrentRow(row)
                            restored = True
                            break
            if not restored:
                target = self._default_entity_list()
                if target.count():
                    target.setCurrentRow(0)
                    self._apply_entity_selection(target)
                else:
                    self._selected = None
                    self._set_entity_placeholder("No matches", "—")
                    self.app.txt_osint_detail.clear()
                    self._show_link_placeholders(self._active_entity_kind())
                    self._update_workspace_buttons()
        finally:
            for lst in lists:
                lst.blockSignals(False)

    def _clear_lists(self) -> None:
        for widget in (
            self.app.list_osint_identifiers,
            self.app.list_osint_ips,
            self.app.list_osint_domains,
        ):
            widget.clear()
        self._clear_link_button_widgets()

    def _clear_link_button_widgets(self) -> None:
        layout = getattr(self.app, "osint_links_layout", None)
        if layout is None:
            return
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def _show_link_placeholders(self, kind: str = "identifier") -> None:
        layout = getattr(self.app, "osint_links_layout", None)
        if layout is None:
            return
        self._clear_link_button_widgets()
        self.app.lbl_osint_links_empty.hide()
        labels = _LINK_PLACEHOLDERS.get(kind, _LINK_PLACEHOLDERS["identifier"])
        for label in labels:
            button = QPushButton(label)
            style_action_button(button, object_name="OutlineButton")
            button.setMinimumWidth(72)
            button.setCursor(Qt.PointingHandCursor)
            button.setEnabled(False)
            layout.addWidget(button)
        layout.addStretch(1)

    def _set_entity_placeholder(self, value: str, type_label: str) -> None:
        self.app.lbl_osint_selected_value.setText(value)
        self.app.lbl_osint_entity_type.setText(type_label)

    def _populate_list(self, widget, rows: list[dict[str, Any]], kind: str) -> None:
        widget.clear()
        for row in rows:
            if kind == "identifier":
                label = f"{row.get('label') or row.get('kind')}: {row.get('value')}"
                meta = {"kind": "identifier", "value": row.get("value"), "identifier_kind": row.get("kind")}
            else:
                count = int(row.get("count") or 0)
                suffix = f"  ({count:,})" if count else ""
                label = f"{row.get('value')}{suffix}"
                meta = {"kind": kind, "value": row.get("value")}
            item = QListWidgetItem(label)
            item.setData(ENTITY_ROLE, meta)
            widget.addItem(item)

    def _identifier_type_label(self, selected: dict[str, Any]) -> str:
        kind = str(selected.get("kind") or "")
        if kind == "identifier":
            return str(selected.get("identifier_kind") or "Identifier")
        return kind.upper() if kind else "—"

    def _decode_kind(self, selected: dict[str, Any]) -> str:
        if str(selected.get("kind") or "") != "identifier":
            return ""
        return str(selected.get("identifier_kind") or "").strip().upper()

    def _update_identifier_buttons(self) -> None:
        app = self.app
        selected = self._selected or {}
        decode_kind = self._decode_kind(selected)
        app.btn_osint_decode_imei.setVisible(decode_kind == "IMEI")
        app.btn_osint_decode_operator.setVisible(decode_kind in {"IMSI", "MSISDN"})
        has_value = bool(str(selected.get("value") or "").strip())
        busy = self._thread is not None
        app.btn_osint_decode_imei.setEnabled(decode_kind == "IMEI" and has_value and not busy)
        app.btn_osint_decode_operator.setEnabled(
            decode_kind in {"IMSI", "MSISDN"} and has_value and not busy
        )

    def decode_imei(self) -> None:
        self._run_identifier_decode(force=True)

    def decode_operator(self) -> None:
        self._run_identifier_decode(force=True)

    def _run_identifier_decode(self, *, force: bool = False) -> None:
        selected = self._selected or {}
        kind = self._decode_kind(selected)
        value = str(selected.get("value") or "").strip()
        if not kind or not value:
            return

        if not force and self.app.current_project_id is not None:
            enricher = "imei_decode" if kind == "IMEI" else "operator_decode"
            cached = get_latest_osint_lookup(
                self.app.current_project_id,
                entity_kind="identifier",
                entity_value=value,
                enricher=enricher,
            )
            if cached:
                return

        result = decode_identifier(kind, value)
        if result is None:
            return

        self._last_decode_result = result
        project_id = self.app.current_project_id
        if project_id is not None:
            save_osint_lookup(
                project_id,
                entity_kind="identifier",
                entity_value=value,
                enricher=result.enricher,
                status=result.status,
                summary=result.summary,
                details=result.details,
            )
        self._append_decode_result(result)

    def _append_decode_result(self, result) -> None:
        block = result.as_text() if hasattr(result, "as_text") else str(result.summary or "")
        heading = f"{result.enricher} [{result.status}]"
        detail = self.app.txt_osint_detail.toPlainText().strip()
        chunk = f"{heading}\n{block}".strip()
        if chunk in detail:
            return
        if detail:
            self.app.txt_osint_detail.setPlainText(f"{detail}\n\n{chunk}")
        else:
            self.app.txt_osint_detail.setPlainText(chunk)
        self.app.lbl_osint_status.setText(result.summary or "Decode complete.")

    def _populate_checklist(self, rows: list[dict[str, Any]]) -> None:
        widget = self.app.lbl_osint_checklist
        if not rows:
            widget.hide()
            return
        lines = [str(row.get("label") or "") for row in rows if row.get("label")]
        widget.setText("Suggested: " + " · ".join(lines))
        widget.show()

    @Slot()
    def on_identifiers_selected(self) -> None:
        self._apply_entity_selection(self.app.list_osint_identifiers)

    @Slot()
    def on_ips_selected(self) -> None:
        self._apply_entity_selection(self.app.list_osint_ips)

    @Slot()
    def on_domains_selected(self) -> None:
        self._apply_entity_selection(self.app.list_osint_domains)

    def _apply_entity_selection(self, list_widget: QListWidget) -> None:
        if not isinstance(list_widget, QListWidget):
            return
        app = self.app
        item = list_widget.currentItem()
        if item is None:
            return

        for lst in (app.list_osint_identifiers, app.list_osint_ips, app.list_osint_domains):
            if lst is not list_widget:
                lst.blockSignals(True)
                lst.clearSelection()
                lst.blockSignals(False)

        meta = item.data(ENTITY_ROLE) or {}
        self._selected = dict(meta)
        self._render_selected_entity()
        self._update_workspace_buttons()

    def _render_selected_entity(self) -> None:
        app = self.app
        selected = self._selected or {}
        kind = str(selected.get("kind") or "")
        value = str(selected.get("value") or "")
        if not kind or not value:
            self._set_entity_placeholder("Select an entity", "—")
            app.lbl_osint_registrable.hide()
            app.txt_osint_detail.clear()
            self._show_link_placeholders(self._active_entity_kind())
            self._update_identifier_buttons()
            self._update_hit_banner("", "")
            self._update_workspace_buttons()
            return

        type_label = self._identifier_type_label(selected)
        self._set_entity_placeholder(value, type_label.upper())

        if kind == "domain":
            root = registrable_domain(value)
            if root and root != value.lower():
                app.lbl_osint_registrable.setText(f"Registrable domain: {root}")
                app.lbl_osint_registrable.show()
                selected["registrable_domain"] = root
            else:
                app.lbl_osint_registrable.hide()
        else:
            app.lbl_osint_registrable.hide()

        cached = self._cached_lookup_text(kind, value)
        app.txt_osint_detail.setPlainText(cached if cached else "")
        self._last_decode_result = self._cached_decode_result(kind, value)
        self._render_links(kind, value, selected)
        self._update_identifier_buttons()
        self._run_identifier_decode(force=False)
        if kind == "identifier":
            identifier_kind = str(selected.get("identifier_kind") or "")
            self._update_hit_banner(identifier_kind, value)
            self._run_leak_lookup(value, kind=identifier_kind)
        else:
            self._update_hit_banner("", "")

    def _update_hit_banner(self, identifier_kind: str, value: str) -> None:
        banner = getattr(self.app, "lbl_osint_hit", None)
        if banner is None:
            return
        from core.leaks.search import find_repository_hits

        text = str(value or "").strip()
        if not text:
            banner.hide()
            banner.clear()
            self._pending_hit_record_ids = []
            self._pending_hit_search = ""
            self._pending_hit_kind = ""
            return
        try:
            total, summary, record_ids = find_repository_hits(text, kind=identifier_kind)
        except Exception:
            banner.hide()
            banner.clear()
            self._pending_hit_record_ids = []
            self._pending_hit_search = ""
            self._pending_hit_kind = ""
            return
        if total:
            self._pending_hit_record_ids = list(record_ids or [])
            self._pending_hit_search = text
            self._pending_hit_kind = str(identifier_kind or "")
            banner.setText(
                f"\u2714  HIT in repository — {total} record(s): {summary}  "
                f"(click to open)"
            )
            banner.setCursor(Qt.PointingHandCursor)
            banner.setMinimumHeight(32)
            banner.show()
        else:
            banner.hide()
            banner.clear()
            self._pending_hit_record_ids = []
            self._pending_hit_search = ""
            self._pending_hit_kind = ""

    def open_hit_in_repository(self) -> None:
        if not self._pending_hit_search:
            return
        if hasattr(self.app, "open_leaks_viewer"):
            self.app.open_leaks_viewer(
                search_text=self._pending_hit_search,
                record_ids=self._pending_hit_record_ids,
            )

    def eventFilter(self, obj, event) -> bool:
        banner = getattr(self.app, "lbl_osint_hit", None)
        if obj is banner and event.type() == QEvent.Type.MouseButtonRelease:
            if event.button() == Qt.MouseButton.LeftButton and self._pending_hit_search:
                self.open_hit_in_repository()
                return True
        return super().eventFilter(obj, event)

    def _wire_hit_banner(self) -> None:
        banner = getattr(self.app, "lbl_osint_hit", None)
        if banner is None or getattr(banner, "_hit_click_wired", False):
            return
        banner.installEventFilter(self)
        banner._hit_click_wired = True

    def _run_leak_lookup(self, value: str, *, kind: str = "") -> None:
        from core.osint.enrichers.leaks import enrich_leaks

        try:
            result = enrich_leaks("identifier", value, kind=kind)
        except Exception:
            return
        if result.status == "ok" and result.details.get("hits"):
            self._append_decode_result(result)
            project_id = self.app.current_project_id
            if project_id is not None:
                save_osint_lookup(
                    project_id,
                    entity_kind="identifier",
                    entity_value=value,
                    enricher="repository",
                    status=result.status,
                    summary=result.summary,
                    details=result.details,
                )

    def _cached_lookup_text(self, kind: str, value: str) -> str:
        project_id = self.app.current_project_id
        if project_id is None:
            return ""
        enrichers = list(available_enrichers(kind))
        if kind == "identifier":
            decode_kind = self._decode_kind(self._selected or {})
            if decode_kind == "IMEI":
                enrichers.insert(0, "imei_decode")
            elif decode_kind in {"IMSI", "MSISDN"}:
                enrichers.insert(0, "operator_decode")
        blocks = []
        for enricher in enrichers:
            row = get_latest_osint_lookup(
                project_id,
                entity_kind=kind,
                entity_value=value,
                enricher=enricher,
            )
            if not row:
                continue
            status = row.get("status") or "ok"
            summary = row.get("summary") or ""
            blocks.append(f"{enricher} [{status}]\n{summary}")
        return "\n\n".join(blocks)

    def _cached_decode_result(self, kind: str, value: str) -> EnrichResult | None:
        if kind != "identifier":
            return None
        decode_kind = self._decode_kind(self._selected or {})
        if decode_kind == "IMEI":
            enricher = "imei_decode"
        elif decode_kind in {"IMSI", "MSISDN"}:
            enricher = "operator_decode"
        else:
            return None
        project_id = self.app.current_project_id
        if project_id is None:
            return None
        row = get_latest_osint_lookup(
            project_id,
            entity_kind=kind,
            entity_value=value,
            enricher=enricher,
        )
        if not row:
            return None
        return EnrichResult(
            enricher=enricher,
            entity_kind=kind,
            entity_value=value,
            status=str(row.get("status") or "ok"),
            summary=str(row.get("summary") or ""),
            details=dict(row.get("details") or {}),
        )

    def _render_links(self, kind: str, value: str, selected: dict[str, Any]) -> None:
        subject = self._snapshot.get("subject_label") or ""

        if kind == "identifier":
            links = build_identifier_search_links(
                name=subject,
                identifier=value,
                kind=str(selected.get("identifier_kind") or ""),
            )
        elif kind == "domain":
            root = str(selected.get("registrable_domain") or registrable_domain(value) or value)
            links = build_domain_links(root)
        elif kind == "ip":
            links = build_ip_links(value)
        else:
            links = []

        self._clear_link_button_widgets()
        layout = self.app.osint_links_layout
        if not links:
            self._show_link_placeholders(kind or self._active_entity_kind())
            return

        self.app.lbl_osint_links_empty.hide()
        for link in links:
            button = QPushButton(str(link.get("label") or "Link"))
            style_action_button(button, object_name="OutlineButton")
            button.setMinimumWidth(72)
            button.setCursor(Qt.PointingHandCursor)
            url = str(link.get("url") or "")
            button.clicked.connect(lambda checked=False, target=url: webbrowser.open(target))
            layout.addWidget(button)
        layout.addStretch(1)

    def copy_selected_entity(self) -> None:
        selected = self._selected or {}
        value = str(selected.get("value") or "").strip()
        if value:
            self.app.copy_text(value)

    def copy_detail(self) -> None:
        self.app.copy_text(self.app.txt_osint_detail.toPlainText())

    @Slot(object)
    def show_results_menu(self, pos) -> None:
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtWidgets import QMenu

        editor = self.app.txt_osint_detail
        menu = QMenu(editor)
        cursor = editor.textCursor()
        has_selection = cursor.hasSelection()
        act_copy_sel = menu.addAction("Copy")
        act_copy_sel.setEnabled(has_selection)
        act_copy_all = menu.addAction("Copy results")
        act_copy_all.setEnabled(bool(editor.toPlainText().strip()))
        selected = self._selected or {}
        entity_value = str(selected.get("value") or "").strip()
        act_copy_entity = menu.addAction("Copy entity value")
        act_copy_entity.setEnabled(bool(entity_value))

        chosen = menu.exec(editor.mapToGlobal(pos))
        if chosen is act_copy_sel and has_selection:
            QGuiApplication.clipboard().setText(cursor.selectedText())
        elif chosen is act_copy_all:
            self.copy_detail()
        elif chosen is act_copy_entity:
            self.copy_selected_entity()

    def add_detail_to_notes(self) -> None:
        selected = self._selected or {}
        value = str(selected.get("value") or "").strip()
        text = self.app.txt_osint_detail.toPlainText().strip()
        if not value and not text:
            return
        registrable = ""
        if str(selected.get("kind") or "") == "domain":
            registrable = str(selected.get("registrable_domain") or registrable_domain(value) or "")
        block = format_identifier_notes_block(
            entity_value=value or "—",
            entity_kind=str(selected.get("kind") or ""),
            entity_type_label=self._identifier_type_label(selected),
            registrable_domain=registrable,
            decode_result=self._last_decode_result,
            results_text=text,
        )
        self.app.notes_controller.append_ai_text(block)

    def jump_to_flows(self) -> None:
        selected = self._selected or {}
        value = str(selected.get("value") or "").strip()
        if not value:
            return
        self.app.go_to_explore_flows()
        self.app.explore_ui_controller.apply_filter_ip(value)

    def jump_to_pcap(self) -> None:
        self.app.go_page(self.app.IDX_PCAP, self.app._nav_pcap)

    def start_fetch(self, enricher: str) -> None:
        if self._thread is not None:
            return
        selected = self._selected or {}
        kind = str(selected.get("kind") or "")
        value = str(selected.get("value") or "")
        if not kind or not value:
            self.app._message_dialog("OSINT", "Select an entity first.", width=420)
            return
        if enricher not in available_enrichers(kind):
            self.app._message_dialog("OSINT", f"{enricher} is not available for {kind}.", width=420)
            return

        self._pending_enricher = enricher
        self._set_busy(True, enricher)
        self._worker = OsintEnrichWorker(enricher, kind, value)
        self._thread = QThread(self.app)
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_fetch_finished, Qt.ConnectionType.QueuedConnection)
        self._worker.error.connect(self._on_fetch_error, Qt.ConnectionType.QueuedConnection)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._worker.finished.connect(self._worker.deleteLater)
        self._worker.error.connect(self._worker.deleteLater)
        self._thread.finished.connect(self._cleanup_thread)
        self._thread.start()

    @Slot(object)
    def _on_fetch_finished(self, result) -> None:
        project_id = self.app.current_project_id
        selected = self._selected or {}
        kind = str(selected.get("kind") or "")
        value = str(selected.get("value") or "")
        if project_id is not None and kind and value:
            save_osint_lookup(
                project_id,
                entity_kind=kind,
                entity_value=value,
                enricher=str(result.enricher or self._pending_enricher),
                status=str(result.status or "ok"),
                summary=str(result.summary or ""),
                details=getattr(result, "details", {}) or {},
            )
        detail = self.app.txt_osint_detail.toPlainText().strip()
        block = result.as_text() if hasattr(result, "as_text") else str(result)
        heading = f"{result.enricher} [{result.status}]"
        prefix = f"{heading}\n{block}"
        if detail:
            prefix = f"{detail}\n\n{prefix}"
        self.app.txt_osint_detail.setPlainText(prefix)
        self._set_busy(False)

    @Slot(str)
    def _on_fetch_error(self, message: str) -> None:
        detail = self.app.txt_osint_detail.toPlainText().strip()
        prefix = f"{self._pending_enricher} [error]\n{message}"
        if detail:
            prefix = f"{detail}\n\n{prefix}"
        self.app.txt_osint_detail.setPlainText(prefix.strip())
        self._set_busy(False)

    @Slot()
    def _cleanup_thread(self) -> None:
        self._worker = None
        self._thread = None
        self._pending_enricher = ""

    def shutdown(self, wait_ms: int = 3000) -> None:
        stop_qthread(self._thread, wait_ms=wait_ms)
        self._cleanup_thread()

    def _set_busy(self, busy: bool, enricher: str = "") -> None:
        app = self.app
        if busy and enricher:
            app.lbl_osint_status.setText(f"Fetching {enricher}…")
        elif app.current_project_id is None:
            app.lbl_osint_status.setText("Open a project to begin.")
        else:
            app.lbl_osint_status.setText("Ready.")
        self._update_workspace_buttons()

    def _update_fetch_buttons(self) -> None:
        selected = self._selected or {}
        kind = str(selected.get("kind") or "")
        has_entity = self._has_entity()
        busy = self._thread is not None
        allowed = set(available_enrichers(kind)) if has_entity else set()
        mapping = {
            "dns": self.app.btn_osint_fetch_dns,
            "rdap": self.app.btn_osint_fetch_rdap,
            "reverse_dns": self.app.btn_osint_fetch_reverse,
            "geoip": self.app.btn_osint_fetch_geo,
            "virustotal": self.app.btn_osint_fetch_vt,
            "shodan": self.app.btn_osint_fetch_shodan,
        }
        for name, button in mapping.items():
            button.setEnabled(name in allowed and not busy)

    def export_results(self, export_format: str) -> None:
        from PySide6.QtWidgets import QFileDialog

        from core.db import get_project
        from core.exporters.osint_exporter import export_osint_results
        from ui.table_export import table_export_default_path

        text = self.app.txt_osint_detail.toPlainText().strip()
        if not text:
            self.app._message_dialog("OSINT export", "There are no OSINT results to export yet.", width=420)
            return

        selected = self._selected or {}
        kind = str(selected.get("kind") or "")
        value = str(selected.get("value") or "").strip()
        suffix_map = {"html": "html", "csv": "csv", "xlsx": "xlsx"}
        suffix = suffix_map.get(export_format)
        if suffix is None:
            return

        default_path = table_export_default_path(
            f"osint_{value or kind or 'results'}",
            suffix,
            project_id=self.app.current_project_id,
            category="json",
        )
        filter_map = {
            "html": "HTML files (*.html)",
            "csv": "CSV files (*.csv)",
            "xlsx": "Excel files (*.xlsx)",
        }
        path, ok = QFileDialog.getSaveFileName(
            self.app,
            f"Export OSINT results ({suffix.upper()})",
            default_path,
            filter_map[export_format],
        )
        if not ok or not path:
            return

        project_id = self.app.current_project_id
        project = get_project(project_id) if project_id is not None else None
        entity_label = self._identifier_type_label(selected) if kind == "identifier" else kind.title()
        try:
            export_osint_results(
                path,
                export_format,
                entity_kind=kind,
                entity_label=entity_label,
                entity_value=value,
                results_text=text,
                project=project,
                project_name=self.app.current_project_name,
                source_label=value,
            )
        except Exception as exc:
            self.app._message_dialog("OSINT export", "Failed to export OSINT results.", str(exc), width=520)
            return
        self.app._message_dialog("OSINT export", f"Exported OSINT results to:\n{path}", width=520)

    def show_lookup_history(self) -> None:
        project_id = self.app.current_project_id
        selected = self._selected or {}
        if project_id is None or not selected:
            return
        rows = list_osint_lookups(
            project_id,
            entity_kind=str(selected.get("kind") or ""),
            entity_value=str(selected.get("value") or ""),
            limit=20,
        )
        if not rows:
            self.app._message_dialog("OSINT history", "No cached lookups for this entity yet.", width=420)
            return
        lines = []
        for row in rows:
            lines.append(
                f"{row.get('created_at')} · {row.get('enricher')} [{row.get('status')}]: {row.get('summary')}"
            )
        self.app._message_dialog("OSINT history", "\n".join(lines), width=560)
