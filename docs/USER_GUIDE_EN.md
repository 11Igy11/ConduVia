# ViaNyquist User Guide

**Version:** Beta  
**Last updated:** June 2026

---

## 1. What is ViaNyquist?

ViaNyquist is a desktop application for reviewing and analysing network traffic in a case or project. You load JSON flow datasets and PCAP captures, explore communications, mark important items as **Findings**, write **Notes**, and build an **Activity Profile** from everything saved in the project.

The name honours **Harry Nyquist** (1889–1976), the Swedish-born engineer whose work at Bell Labs shaped how we understand signals in communication systems. In 1928 he showed that a continuous signal can be reconstructed from discrete samples — but only if those samples are taken often enough to capture what is really happening. That idea, later known as the **Nyquist sampling theorem**, is one of the foundations of digital telephony, radio, and every modern network.

Investigators face a similar problem. You rarely see an entire communication live and in full; you work from **captured** flows and packets — samples of activity taken at a point in time. ViaNyquist is built around that reality: helping you reconstruct a clear picture of behaviour from the evidence you have, without pretending the capture is more complete than it is.

ViaNyquist does **not** decrypt traffic. For encrypted sessions it shows metadata only: IP addresses, ports, protocols, DNS queries, TLS server names (SNI), timing, and volume. These are investigative indicators, not proof of message content, identity, or intent.

---

## 2. Recommended workflow

1. Create or open a **project** and set it as the **active case**.
2. Enter known **subject identifiers** (name, OIB, MSISDN, IMSI, IMEI, etc.).
3. Choose a **workspace parent folder** so exports and notes have a clear location.
4. **Load** a JSON dataset or PCAP file.
5. Review flows, registry summaries, PCAP evidence, and OSINT pivots.
6. Mark important items as **Findings**.
7. Record conclusions in **Notes**.
8. Review **Profile** for a wider picture of activity across the case.
9. **Export** reports to the project workspace when needed.

---

## 3. Navigation

The left sidebar contains:

| Button | Purpose |
|--------|---------|
| **Projects** | Case list, project details, recent JSON/PCAP/activity cards |
| **JSON** | Explore, Registry, and Listing for flow datasets |
| **PCAP** | Packet capture analysis |
| **OSINT** | Pivots on identifiers, IPs, and domains from saved evidence |
| **AI output** | Latest AI-generated summaries and explanations |
| **Notes** | Project notes editor (autosave) |
| **Profile** | Activity profile across saved evidence |
| **Refresh** | Reload projects, PCAP, findings, notes, profile, and settings |
| **Settings** | AI, theme, OSINT API keys, Repository |
| **Help** | Opens the user manual (PDF or HTML in `docs/`) |

The JSON section has three top tabs: **Explore**, **Registry**, **Listing**.

---

## 4. Projects

### 4.1 Active case dashboard

At the top of the Projects page you see the **active case** name and a short summary of the subject and identifiers. If no project is active, open one with **Set active**.

### 4.2 Project list

- **+ New** — create a project (name, description, workspace, identifiers, order metadata).
- **Edit** — edit the selected project.
- **Delete** — permanently removes the project, its datasets, findings, activity log, and workspace folders (with confirmation).
- **↻** — refresh the project list (resets the active case).

Select a project to preview details on the right. **Set active** makes it the working case for JSON, PCAP, Notes, Findings, and Profile.

### 4.3 New / Edit project dialog

**Project**

- **Project name** — required.
- **Description** — free text (multi-line).
- **Workspace parent** — required folder; ViaNyquist creates a workspace subfolder for this project. Use **Browse…** to pick a parent directory.

**Case subject / identifiers**

- **First name**, **Last name**, **OIB** (11 digits with valid Croatian check digit).
- **Mobile / MSISDN**, **IMSI**, **IMEI** — use the **+** button to add multiple values; **−** removes a row.
- **Other identifiers** — additional lines (e.g. email, legacy IDs).

**Case order metadata**

- **Klasa**, **Urbroj** — with **…** picker if saved values exist.
- **Order validity** — from / to dates; **…** opens saved validity periods.

After creating a project you may be asked **Open dataset** to load evidence immediately.

### 4.4 Project details panel

Shows ID, subject, identifiers, Klasa/Urbroj, order validity, description, workspace path, and timestamps.

### 4.5 Recent cards (bottom)

| Card | Action |
|------|--------|
| **Recent JSON files** | **Open JSON list** — load or open indexed JSON days |
| **Recent PCAP days** | **Open PCAP list** — open saved PCAP periods |
| **Recent activity** | **Open activity log** — project event timeline |

---

## 5. Loading evidence

### 5.1 From JSON (Explore)

Click **Load dataset** in the JSON header (or accept **Open dataset** after creating a project).

Choose:

1. **Folder** — scan a folder for JSON/PCAP evidence.
2. **JSON file** — single `.json` file.
3. **PCAP file** — switches to PCAP and opens the file loader.

**Folder import** offers **Import all**, **Choose date range**, or **Cancel**. JSON is indexed by calendar day. Use **Period** (Day / Month / **Selected period**), **Pick range…**, and **Missing days** to work with date spans.

### 5.2 From PCAP

On the PCAP page, click **Load dataset** and select one or more `.pcap` / `.pcapng` files. Use **Save Period to Project** to register the capture to the active project workspace.

### 5.3 From Projects

Use **Open JSON list** or **Open PCAP list** on the recent cards; multi-select rows and **Load selected**, or double-click a row.

---

## 6. JSON — Explore

Sub-tabs: **Summary**, **Flows**, **Findings**.

### 6.1 Header

- **Load dataset**, **Generate AI Summary**, **Add AI to Notes**
- Project path and stats; **Page size** and **Load next** for large datasets
- **Period** controls and search: `Search IP / SNI / app...`

### 6.2 Summary

- Cards: **Top source IPs**, **Top destination IPs**, **Top protocols**, **Top applications** — each with **Expand table**
- **AI assistant output** — filled by **Generate AI Summary**

### 6.3 Flows

- Filters: **Filter source**, **Filter destination**, **Filter SNI**
- **Conversation: OFF/ON** — focus on one endpoint pair
- **Expand Flows** / **Collapse Flows**
- **Export table** (CSV / Excel / HTML)
- **Mark as Finding** — save selected flow as a finding
- **Explain with AI** — send flow context to AI

Sortable table columns include Source/destination IP and port, Protocol, Application, Bytes, Duration, SNI. **Flow details** panel shows the selected row.

### 6.4 Findings (in Explore)

See section 11.

---

## 7. JSON — Registry

Tabs: **Report** | **Dataset**

- **Include full dataset** — enables the full table on the Dataset tab
- **Export HTML report** — registry report for the loaded JSON

**Report** includes flow statistics, observed activity, hourly patterns, direction breakdown, and rankings (endpoints, applications, protocols, volume). **Expand table** opens sortable dialogs. Double-clicking some rows can jump to Explore with a pre-filled search.

**Dataset** tab shows the full flow table with export options.

---

## 8. JSON — Listing

Tabular view of the loaded dataset with flexible columns.

- **View:** Default, All fields, Custom, or saved presets
- **Customize** — pick columns (Custom mode)
- **Presets ▾** — save, update, or delete column presets
- **Export** — CSV, Excel, or HTML

Default columns include Date, Time, IPs, ports, Protocol, Application, Server Name, Volume, Packets, Duration.

---

## 9. PCAP

### 9.1 Header

- **Load dataset**, **Save Period to Project**, **AI Summary**, **Add to Notes**, **Export Summary**
- **Period** row: day combo, Day / Month / Selected period, **Pick range…**, **Re-analyze Period**, **Missing days**

### 9.2 Tabs

| Tab | Content |
|-----|---------|
| **Summary** | Plain-language overview, key points, limitations, service groups, hourly activity |
| **Communications** | Communication highlights (service, indicator, host, volume, timing) |
| **Evidence** | **Evidence** (DNS, TLS SNI, HTTP hosts, visible samples) and **Artifacts** (extracted artefacts) |
| **Network** | **Overview** and **Connections** tables |
| **AI Summary** | AI explanation of the capture |

Many sections offer **Expand table** or **Open full … table** for larger views.

### 9.3 Limitations

HTTPS, QUIC, and most app traffic are encrypted. Without plaintext, only metadata and visible artefacts are shown. Messaging or call-like indicators are heuristic, not proof of user action.

---

## 10. OSINT

Pivot workspace for **Identifiers**, **IPs**, and **Domains** collected from saved project evidence.

On entity selection:

- **Repository** — search imported leak datasets
- **Decode IMEI** / **Decode operator** for device identifiers
- **Save to Notes**, **History**, **Flows** (IPs), **PCAP**
- **External links** and **Online lookup** (DNS, WHOIS, GeoIP, VirusTotal, Shodan, etc.)

Requires an active project. Configure API keys in **Settings → OSINT**.

---

## 11. Findings

A **Finding** is an item you mark as important for the case.

### 11.1 Create

In **Flows**, select a row and click **Mark as Finding**. Enter **Title**, optional **Note**, and **Tags** (comma-separated). The view switches to the Findings tab.

### 11.2 Browse and filter

- List shows time, status, title, endpoints, application, tags
- Filters: **Status**, search, tag, sort (**Newest**, **Oldest**, **Status**, **Title**), **Clear**

### 11.3 Actions

- **Edit** — single dialog: Title, Status, Tags, Analyst note
- **Delete**, **Jump to Flow**, **Explain with AI**
- Context menu and keyboard shortcuts (J, E, Del)
- Quick status: New / Investigating / Confirmed / False Positive

**Jump to Flow** opens Explore **Flows** in conversation mode for that finding’s endpoints.

Findings are stored per project; set the project **active** first.

---

## 12. AI output

Central place for the latest AI text. Context line shows source (JSON, PCAP, Profile, Finding, Flow) and project name.

**Add to Notes** copies the text into project notes.

AI is triggered from Explore (**Generate AI Summary**, **Explain with AI**), Findings (**Explain with AI**), PCAP (**AI Summary**), and Profile (**AI Profile Summary**).

**Important:** AI output is explanatory only. Verify claims against the data shown in the app. AI must not be treated as legal or technical proof.

Configure **Base URL**, **Model**, and **Timeout** under **Settings → AI** (default: local Ollama-compatible API).

---

## 13. Notes

Rich-text project notes with **autosave**.

**Editor** panel:

- Font family and size
- **B**, **I**, **U**, text colour, alignment
- **Image**, **Chart** (from profile/PCAP charts)
- **Export:** Word, HTML, PDF

Requires an active project. Notes are stored with the project and in the workspace.

---

## 14. Profile (Activity Profile)

Aggregated view of saved JSON, PCAP, findings, and activity for the active project.

- **AI Profile Summary**, **Add to Notes**, **Export Profile** (HTML)
- **Evidence Overview** metrics
- **Profile Summary** and **Activity rhythm**
- Charts: evidence sources, device IPs, event types, behaviour insights
- **Repository hits** banner when internal repository matches exist

Activity patterns are indicators only — they do not prove who used a device or whether a person was awake or asleep.

---

## 15. Settings

- **Save**, **Reload**
- **AI** — Base URL, Model, Timeout
- **Appearance** — Dark / Light theme
- **OSINT** — VirusTotal and Shodan API keys
- **IMEI TAC database** — **Import TAC CSV…**
- **Repository** — import leak datasets for OSINT **Repository** search

The application UI stays in English. AI and export language may follow your AI/report settings.

---

## 16. Refresh

**Refresh** (sidebar) reloads projects, notes, findings, profile, PCAP view, OSINT, and settings. Use it if the UI looks stale after import or save.

The **↻** button on the Projects list only refreshes the project list.

---

## 17. Exports

Default location: project workspace `exports/` (when workspace is configured).

| Area | Formats | How |
|------|---------|-----|
| Listing | CSV, Excel, HTML | **Export** |
| Explore Flows | CSV, Excel, HTML | **Export table** |
| Registry | HTML | **Export HTML report** |
| Registry dataset | CSV, Excel, HTML | **Open dataset table** |
| PCAP | HTML | **Export Summary** |
| Profile | HTML | **Export Profile** |
| Notes | Word, HTML, PDF | Editor **Word** / **HTML** / **PDF** |
| Expand-table dialogs | CSV, Excel, HTML | Dialog export buttons |

---

## 18. Workspace folder

Each project has a workspace under the chosen parent folder. Typical structure:

```
<workspace>/
  datasets/
  exports/
  findings/
  notes/
  reports/
  .vianyquist-workspace
```

---

## 19. Limitations and good practice

- No decryption of HTTPS, QUIC, or app-layer encryption
- Metadata ≠ message content
- Device activity ≠ proof a specific person used the device
- Do not treat AI text as evidence
- Use **Findings** for key items; **Notes** for your reasoning
- Check dataset/project identifier warnings before trusting a load

---

## 20. Glossary

| Term | Meaning |
|------|---------|
| **Flow** | Communication record between source and destination |
| **JSON dataset** | Indexed network flow export (by calendar day) |
| **PCAP** | Packet capture file |
| **Finding** | Investigator-marked important item |
| **SNI** | TLS server name indicator (visible hostname hint) |
| **MSISDN** | Mobile subscriber number |
| **IMSI** | SIM identifier |
| **IMEI** | Device identifier |
| **Activity Profile** | Cross-evidence summary for the project |

---

## 21. Help

Click **Help** in the sidebar. ViaNyquist opens `docs/USER_GUIDE_EN.html` (or `docs/USER_GUIDE.html`) in your default browser.

To rebuild HTML after editing the manual: `python docs/build_user_manual_html.py`

---

*ViaNyquist — investigative support tool. Use professional judgement alongside the data shown.*
