# ViaNyquist Technical Documentation

Version: beta working documentation  
Last updated: 2026-05-11

## 1. Purpose

ViaNyquist is a desktop application for investigative review of network-flow JSON datasets and PCAP captures. The application is designed around case/project work: a user creates a project, defines the known case subject/device identifiers, loads JSON and PCAP evidence, saves findings and notes, and builds an activity profile from the accumulated project evidence.

The application should be treated as an investigative support tool. It interprets metadata and visible/plaintext evidence, but it does not decrypt encrypted traffic and it should not present metadata indicators as proof of message content, malware, identity, or intent.

## 2. Technology Stack

- Language: Python
- GUI: PySide6 / Qt Widgets
- Local database: SQLite
- AI integration: local Ollama-compatible HTTP API, default `http://localhost:11434/api/generate`
- Exports: HTML, CSV and Excel depending on module
- Tests: `unittest`
- Packaging: PyInstaller spec files and Inno Setup installer script

Main entrypoint:

```text
main.py -> ui.app.main()
```

## 3. High-Level Architecture

```text
ViaNyquist
+-- ui/
|   +-- app.py                       Main shell, navigation, JSON workspace and shared UI wiring
|   +-- pcap_page.py                 PCAP analysis UI
|   +-- registry_page.py             JSON registry/dashboard UI
|   +-- listing_page.py              Listing/export UI
|   +-- activity_profile_page.py     Project activity/profile UI
|   +-- settings_page.py             AI, language and theme settings
|   +-- findings_page.py             Findings management UI
|   +-- controllers/                 UI controllers for projects, datasets, notes, search and findings
+-- core/
|   +-- db.py                        SQLite persistence and migrations
|   +-- loader.py                    JSON loading
|   +-- parser.py                    Dataset metadata and registry columns
|   +-- analyzer.py                  Flow aggregations
|   +-- pcap_analyzer.py             PCAP/PCAPNG parser and evidence extraction
|   +-- behavior_profile.py          Activity/profile behavior indicators from flows
|   +-- project_profile.py           Project-level activity profile aggregation
|   +-- project_identity.py          Subject/target identifiers and OIB validation
|   +-- workspace.py                 Project workspace folders and manifest files
|   +-- ai/                          AI context building, prompts and service client
|   +-- exporters/                   HTML/CSV/Excel export helpers
+-- templates/                       HTML report templates
+-- tests/                           Core unit tests
+-- assets/                          Icons/logo
+-- installer/                       Inno Setup installer
```

The current design separates most domain logic into `core/`, while `ui/` owns presentation and user interaction. A few UI files are still large and should be refactored over time, especially `ui/app.py`, `ui/pcap_page.py` and `ui/registry_page.py`.

## 4. Data Model

SQLite database path:

```text
%LOCALAPPDATA%\ViaNyquist\vianyquist.db
```

The database is initialized by `core.db.init_db()`. The schema is migration-safe: missing columns are added with `ALTER TABLE` where needed.

Main tables:

| Table | Purpose |
| --- | --- |
| `projects` | Case/project metadata, workspace folder and known subject/device identifiers |
| `datasets` | JSON dataset load history per project |
| `pcap_sources` | Saved PCAP source summaries per project, unique by `(project_id, file_sha256)` |
| `findings` | Investigator-created findings from JSON/PCAP evidence |
| `activity_log` | Project activity timeline, such as dataset loaded, PCAP saved, finding created |
| `app_settings` | AI settings, language and UI preferences |

Important project identity fields:

- `subject_first_name`
- `subject_last_name`
- `subject_oib`
- `subject_msisdn`
- `subject_imsi`
- `subject_imei`
- `subject_ip`
- `subject_extra_identifiers`
- legacy fallback: `target_identifier`, `target_type`

`core.project_identity` normalizes identifiers for comparison and validates Croatian OIB numbers. JSON and PCAP loading should be blocked or warned when the evidence does not match the active project identifiers.

## 5. Workspace Model

Each project has a workspace folder. The workspace is intended to become the user-visible case folder for exported and generated artifacts.

Workspace marker:

```text
.vianyquist-workspace
```

Subfolders:

| Folder | Purpose |
| --- | --- |
| `datasets/` | Text references to saved JSON and PCAP sources |
| `exports/` | Default export location for HTML/CSV/Excel outputs |
| `findings/` | Finding reference files |
| `notes/` | Notes backup, currently `project_notes.txt` |
| `reports/` | Activity profile, activity log and case snapshot files |

`core.workspace.write_project_workspace_manifest()` writes a lightweight case index and supporting text files. Exports should default to `workspace/exports/` whenever an active project workspace exists.

## 6. Application Navigation

Primary navigation is in the left sidebar:

```text
Projects
JSON
PCAP
AI output
Notes
Profile

Refresh
Settings
Help
```

Current module roles:

- Projects: project creation/editing, case dashboard, recent JSON/PCAP lists, recent activity
- JSON: JSON dataset exploration, registry and listing views
- PCAP: PCAP loading, metadata/evidence/artifacts/connections, AI summary and export
- AI output: central display for generated AI text
- Notes: project-level notes
- Profile: activity/profile view built from saved project evidence
- Settings: AI provider, output language and theme settings
- Help: static user documentation

## 7. JSON Dataset Flow

JSON data is loaded through `core.loader` and normalized/interpreted through `core.parser`, `core.analyzer`, `core.flow_stats` and UI models in `ui.explore_models`.

Typical flow:

```text
User opens JSON dataset or folder
-> DatasetController validates active project and workspace
-> loader.py reads JSON records
-> parser.py extracts dataset metadata and registry columns
-> app.py / explore models present flows
-> user can search/filter, inspect details, create findings, generate AI summary
-> dataset reference is saved to project history
-> project activity log is updated
```

Important JSON UI surfaces:

- Summary: aggregate overview and AI interpretation
- Flows: raw/normalized flow rows with details panel
- Findings: investigator-created findings related to flows
- Registry: broader analytical dashboard
- Listing: selected-column listing and export

## 8. PCAP Analysis Flow

PCAP parsing is implemented in `core.pcap_analyzer`. It supports classic PCAP and PCAPNG structures and extracts metadata-level signals from packets.

Current PCAP evidence types include:

- protocol counts
- top endpoints
- top ports
- flow-like connection rows
- DNS queries
- TLS SNI hosts
- HTTP hosts and cleartext snippets
- readable payload samples
- artifacts such as local network discovery, web metadata, possible credentials, Windows/enterprise hints
- communication indicators for messaging/push-like and possible call/media-like activity
- hourly activity

Typical flow:

```text
User opens PCAP
-> PcapWorker runs analysis off the UI thread
-> pcap_analyzer.py parses packets and payload metadata
-> PcapPage renders Summary, Communications, Evidence, Network and AI Summary views
-> user can save PCAP source to active project
-> project device IP consistency is checked
-> project activity log is updated
-> export writes to workspace/exports when available
```

Important limitation:

Encrypted HTTPS, QUIC and application traffic content cannot be read from the capture alone. DNS names, TLS SNI names, endpoints, ports and timing are metadata. They show communication patterns, not message contents.

## 9. Activity Profile

The Profile module is a project-level aggregation. It should work from saved project data, not only currently loaded UI state.

Main builders:

- `core.project_profile.build_project_activity_profile()`
- `core.behavior_profile.build_flow_behavior_profile()`
- `core.project_datasets.load_project_dataset_flows()`

Profile data sources:

- saved JSON dataset references
- saved PCAP sources
- findings
- activity log
- project subject/device identifiers

The Profile page currently shows:

- evidence overview metrics
- PCAP device IP distribution
- activity event types
- behavior insights from JSON flows
- service groups by volume
- observed domains by volume
- activity by hour
- activity rhythm interpretation
- AI Profile Summary

Interpretation rules:

- The profile describes observed device/network behavior.
- It must not claim that a person was awake/asleep solely from network activity.
- It may describe likely active/quiet periods as investigative indicators.
- It should use all saved datasets for the active project where possible.

## 10. AI Integration

AI integration is implemented in:

```text
core/ai/assistant_service.py
core/ai/context_builder.py
core/ai/prompts.py
```

Settings are loaded from database settings and environment variables:

- `VIANYQUIST_AI_BASE_URL`
- `VIANYQUIST_AI_MODEL`
- `VIANYQUIST_AI_TIMEOUT`
- `VIANYQUIST_OUTPUT_LANGUAGE`

Default behavior:

- provider: Ollama-compatible `/api/generate`
- streaming: disabled
- timeout: configurable, default 600 seconds
- output language: Croatian or English, configured in Settings

AI text generation exists for:

- dataset summary
- selected flow explanation
- finding explanation
- PCAP summary
- activity profile summary

Prompting policy:

- stay grounded in supplied evidence
- explain network behavior in plain language
- avoid unsupported cybersecurity claims
- avoid hallucinating malware, compromise or threats unless directly visible in evidence
- clearly mention limitations of encrypted traffic and metadata-only indicators

## 11. Findings and Notes

Findings are structured records stored in SQLite. They can be created from JSON flows and should also be used for promoted PCAP artifacts or important time windows.

Finding fields include:

- title
- note
- source/destination IP and port
- protocol
- application name
- requested server name
- bytes, packets and duration
- status
- tags

Notes are project-level free text. They are stored in the database and backed up to the project workspace:

```text
workspace/notes/project_notes.txt
```

## 12. Export System

HTML report templates live in `templates/`.

Current templates:

- `listing_export.html`
- `registry_export.html`
- `pcap_export.html`
- `profile_export.html`
- `table_export.html`

Export helpers live in `core/exporters/`.

Current exporters:

- `listing_exporter.py`
- `registry_exporter.py`
- `pcap_exporter.py`
- `profile_exporter.py`
- `table_exporter.py`
- `case_context.py`
- `template_utils.py`

Exports should include case context when an active project exists:

- project name
- subject label
- known identifiers
- KLASA/URBROJ where applicable
- target/device information
- export timestamp

Known cleanup area:

- `registry_exporter.py` still contains some inline HTML helper generation.
- `registry_page.py` also contains Qt rich-text HTML helpers for dashboard widgets.
- Future cleanup should move repeated table/export dialog patterns into shared UI helpers.

## 13. Settings

Settings are stored in `app_settings`.

Current setting groups:

- AI:
  - base URL
  - model
  - timeout
- Output:
  - generated report/AI language
- UI:
  - theme

The application workflow remains English. Generated text and reports may be Croatian or English based on the output language setting.

## 14. Threading

Long-running operations should not block the UI thread.

Current threaded operations:

- PCAP analysis through `PcapWorker` and `QThread`
- AI text generation through `AITextWorker` and `QThread`

Qt rule:

UI widgets must be created and modified only on the main Qt thread. Worker threads should return plain data through signals.

## 15. Testing

Primary test file:

```text
tests/test_core.py
```

Recommended verification:

```powershell
python -m py_compile core\workspace.py ui\app.py ui\pcap_page.py ui\registry_page.py ui\listing_page.py ui\activity_profile_page.py tests\test_core.py
python -m unittest discover -s tests -v
```

Current test coverage includes:

- AI prompt/context grounding
- app settings persistence
- behavior/activity profile aggregation
- comparison logic
- HTML export context
- flow stats
- JSON loader behavior
- PCAP parsing and artifacts
- PCAP communication indicators
- PCAP project persistence
- project identity and OIB validation
- protocol descriptions
- time/formatter helpers
- workspace folder and manifest behavior

## 16. Packaging

Packaging files:

- `ViaNyquist.spec`
- `main.spec`
- `installer/ViaNyquist.iss`

Expected packaging flow:

```text
PyInstaller build
-> dist/build output
-> Inno Setup installer
```

Installer output should stay untracked and is ignored by `.gitignore`.

## 17. Current Technical Debt

Priority cleanup candidates:

1. `ui/app.py` is still broad and should eventually be split further.
2. `ui/pcap_page.py` contains many UI builders and export dialog helpers; shared table/dialog helpers would reduce duplication.
3. `ui/registry_page.py` has Qt rich-text HTML helpers and should be refactored carefully.
4. `core/exporters/registry_exporter.py` still builds parts of HTML in Python.
5. Light theme exists but needs visual polish.
6. PCAP communication classification is metadata-based and should expose confidence/reasoning clearly.
7. OSINT module is currently a placeholder.

## 18. Development Guidelines

- Keep case/project context as the source of truth.
- Do not load JSON or PCAP evidence without an active project and workspace.
- Store exports in the active project workspace by default.
- Deduplicate JSON and PCAP sources per project where possible.
- Treat PCAP evidence as metadata unless plaintext payload is visible.
- Keep AI outputs grounded in current context and avoid unsupported claims.
- Prefer `core/` logic for analysis and `ui/` only for presentation.
- Add tests for any new parser, classifier, persistence or export behavior.
