from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ui.app import App


def wire_app_ui(app: App) -> None:
    app._wire_navigation()

    app.search.textChanged.connect(app.search_controller.schedule_search_filter)
    app.table.selectionModel().selectionChanged.connect(app.explore_ui_controller.on_row_selected)
    app.table.verticalScrollBar().valueChanged.connect(app.explore_ui_controller.on_table_scrolled)

    app.btn_load_more.clicked.connect(app.explore_ui_controller.load_next_page)
    app.cmb_page_size.currentTextChanged.connect(app.explore_ui_controller.on_page_size_changed)
    app.cmb_json_day.currentIndexChanged.connect(app.dataset_controller.on_json_day_changed)
    app.cmb_json_file.currentIndexChanged.connect(app.dataset_controller.on_json_file_changed)
    app.cmb_json_period_mode.currentIndexChanged.connect(app.dataset_controller.on_json_period_mode_changed)
    app.btn_json_pick_range.clicked.connect(app.dataset_controller.configure_json_period_range)
    app.btn_expand_json_gaps.clicked.connect(app.dataset_controller.open_json_missing_days_dialog)

    app.btn_load.clicked.connect(app.dataset_controller.load_dataset_dialog)
    app.btn_show_import_progress.clicked.connect(app.dataset_controller.show_import_progress_dialog)
    app.btn_ai_summary.clicked.connect(app.explore_ui_controller.generate_ai_summary)
    app.btn_add_ai_to_notes.clicked.connect(app.add_ai_summary_to_notes)
    app.btn_toggle_conv.clicked.connect(app.explore_ui_controller.toggle_conversation)
    app.btn_expand_flows.clicked.connect(app.explore_ui_controller.toggle_flows_expanded)
    app.btn_mark_finding.clicked.connect(app.findings_controller.mark_as_finding)
    app.btn_ai_explain.clicked.connect(app.explore_ui_controller.explain_selected_flow)
    app.btn_export_flows.clicked.connect(app.explore_ui_controller.export_flows_table)

    app.btn_filter_src.clicked.connect(
        lambda: app.explore_ui_controller.apply_filter_ip(app.current_value("src_ip"))
    )
    app.btn_filter_dst.clicked.connect(
        lambda: app.explore_ui_controller.apply_filter_ip(app.current_value("dst_ip"))
    )
    app.btn_filter_sni.clicked.connect(
        lambda: app.explore_ui_controller.apply_filter_ip(app.current_value("requested_server_name"))
    )

    app.btn_new_project.clicked.connect(app.projects_ui_controller.create_project_dialog)
    app.btn_refresh_projects.clicked.connect(
        lambda: app.projects_ui_controller.refresh_projects(reset_active=True)
    )
    app.btn_open_project.clicked.connect(app.projects_ui_controller.open_selected_project)
    app.btn_edit_project.clicked.connect(app.projects_ui_controller.edit_selected_project)
    app.btn_delete_project.clicked.connect(app.projects_ui_controller.delete_selected_project)
    app.projects_list.itemSelectionChanged.connect(app.projects_ui_controller.on_project_selected_preview)
    app.projects_list.itemDoubleClicked.connect(
        lambda _: app.projects_ui_controller.open_selected_project()
    )

    fp = app.findings_page
    fc = app.findings_controller
    fp.selectionChanged.connect(fc.on_selected)
    fp.jumpRequested.connect(fc.jump_to_selected)
    fp.editRequested.connect(fc.edit_selected)
    fp.deleteRequested.connect(fc.delete_selected)
    fp.aiRequested.connect(fc.explain_selected)
    fp.doubleClickedFinding.connect(fc.jump_to_selected)
    fp.btn_find_clear.clicked.connect(fc.clear_filters)
    fp.cmb_find_status.currentTextChanged.connect(fc.apply_filter)
    fp.cmb_find_sort.currentTextChanged.connect(fc.apply_filter)
    fp.txt_find_search.textChanged.connect(fc.apply_filter)
    fp.txt_find_tag.textChanged.connect(fc.apply_filter)
    fp.contextMenuRequestedFromList.connect(fc.on_context_menu)

    app.txt_notes.textChanged.connect(app.notes_controller.on_changed)
    app.registry_page.openExploreWithConversation.connect(app._open_from_registry)
    app.registry_page.openExploreWithSearch.connect(app._open_from_registry_search)

    app.list_osint_identifiers.itemSelectionChanged.connect(app.osint_ui_controller.on_identifiers_selected)
    app.list_osint_ips.itemSelectionChanged.connect(app.osint_ui_controller.on_ips_selected)
    app.list_osint_domains.itemSelectionChanged.connect(app.osint_ui_controller.on_domains_selected)
    app.osint_entity_tabs.currentChanged.connect(app.osint_ui_controller.on_entity_tab_changed)
    app.txt_osint_filter.textChanged.connect(app.osint_ui_controller.on_filter_changed)
    app.btn_osint_decode_imei.clicked.connect(app.osint_ui_controller.decode_imei)
    app.btn_osint_decode_operator.clicked.connect(app.osint_ui_controller.decode_operator)
    app.btn_osint_notes.clicked.connect(app.osint_ui_controller.add_detail_to_notes)
    app.txt_osint_detail.customContextMenuRequested.connect(
        app.osint_ui_controller.show_results_menu
    )
    app.btn_osint_flows.clicked.connect(app.osint_ui_controller.jump_to_flows)
    app.btn_osint_pcap.clicked.connect(app.osint_ui_controller.jump_to_pcap)
    app.btn_osint_fetch_dns.clicked.connect(lambda: app.osint_ui_controller.start_fetch("dns"))
    app.btn_osint_fetch_rdap.clicked.connect(lambda: app.osint_ui_controller.start_fetch("rdap"))
    app.btn_osint_fetch_reverse.clicked.connect(lambda: app.osint_ui_controller.start_fetch("reverse_dns"))
    app.btn_osint_fetch_geo.clicked.connect(lambda: app.osint_ui_controller.start_fetch("geoip"))
    app.btn_osint_fetch_vt.clicked.connect(lambda: app.osint_ui_controller.start_fetch("virustotal"))
    app.btn_osint_fetch_shodan.clicked.connect(lambda: app.osint_ui_controller.start_fetch("shodan"))
    app.btn_osint_history.clicked.connect(app.osint_ui_controller.show_lookup_history)
    app.btn_osint_leaks.clicked.connect(app.open_leaks_viewer)
