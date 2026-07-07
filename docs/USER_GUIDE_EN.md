# ViaNyquist User Guide

**Version:** Beta  
**Last updated:** July 2026

---

## 1. What is ViaNyquist?

ViaNyquist is a desktop application for reviewing and analysing network traffic in a case or project. You load JSON flow datasets and PCAP captures, explore communications, mark important items as **Findings**, write **Notes**, and build an **Activity Profile** from everything saved in the project.

The name honours **Harry Nyquist** (1889–1976), the Swedish-born engineer whose work at Bell Labs shaped how we understand signals in communication systems. In 1928 he showed that a continuous signal can be reconstructed from discrete samples — but only if those samples are taken often enough to capture what is really happening. That idea, later known as the **Nyquist sampling theorem**, is one of the foundations of digital telephony, radio, and every modern network.

Investigators face a similar problem. You rarely see an entire communication live and in full; you work from **captured** flows and packets — samples of activity taken at a point in time. ViaNyquist is built around that reality: helping you reconstruct a clear picture of behaviour from the evidence you have, without pretending the capture is more complete than it is.

The same idea extends to the built-in **AI assistant**. You cannot read tens of thousands of flows line by line; the AI should not pretend it has either. Instead, ViaNyquist builds a **structured context** from what you are already viewing — dataset statistics, a selected flow, a finding, a PCAP summary, or the project profile — and asks the model for help in plain language. **Summary** answers *what stands out in this evidence?* **Explain** answers *what does this one record mean, and what should I check next?* Results appear on the **AI output** page (and inline where you triggered them); you can copy them to **Notes**. By default the assistant runs **locally** through **Ollama**, so case data normally stays on your machine.

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

Tab bars across the app (JSON, PCAP, Explore sub-tabs, Registry, OSINT, and similar) are **click-only** for switching tabs — scrolling the mouse wheel over a tab bar does not change the selected tab.

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

IP addresses are **not** accepted in name or identifier fields (MSISDN, IMSI, IMEI). Use flow tables for IP review.

When you import a JSON dataset, lawful-interception metadata (Klasa, Urbroj, lawful interception dates, and subscriber identifiers when present) can be synced into the active project. You are prompted on the first import of a new source if project identifiers differ from the file.

**Case order metadata**

- **Klasa**, **Urbroj** — with **…** picker if saved values exist.
- **Lawful interception dates** — from / to dates; **…** opens saved interception periods.

After creating a project you may be asked **Open dataset** to load evidence immediately.

### 4.4 Project details panel

Shows ID, subject, identifiers, Klasa/Urbroj, lawful interception dates, description, workspace path, and timestamps.

### 4.5 Recent cards (bottom)

| Card | Action |
|------|--------|
| **Recent JSON files** | **Open JSON list** — load or open indexed JSON days; multi-select rows and **Delete selected** to remove indexed files from the project |
| **Recent PCAP days** | **Open PCAP list** — open saved PCAP periods; multi-select and **Delete selected** to remove indexed PCAP evidence |
| **Recent activity** | **Open activity log** — project event timeline (newest events at the bottom) |

---

## 5. Loading evidence

### 5.1 From JSON (Explore)

Click **Load dataset** in the JSON header (or accept **Open dataset** after creating a project).

Choose:

1. **Folder** — scan a folder for JSON/PCAP evidence.
2. **JSON file** — single `.json` file.
3. **PCAP file** — switches to PCAP and opens the file loader.

**Folder import** offers **Import all**, **Choose date range**, or **Cancel**. JSON is indexed by calendar day. Use **Period** (Day / Month / **Selected period**), **Pick range…**, and **Missing days** to work with date spans.

During import, a progress dialog shows indexing status. **Pause** temporarily stops processing; **Cancel import** aborts the session and rolls back evidence indexed in that import (so a half-finished folder load does not leave a broken dataset in the project).

### 5.2 From PCAP

On the PCAP page, click **Load dataset** and select one or more `.pcap` / `.pcapng` files. Large multi-day folders may be processed as an automatic batch (one period at a time) with optional auto-save to the project. Use **Save Period to Project** to register the current capture to the active project workspace.

### 5.3 From Projects

Use **Open JSON list** or **Open PCAP list** on the recent cards; multi-select rows and **Load selected**, or double-click a row.

### 5.4 Period selector and calendar day

Both JSON and PCAP use the same period controls in the header:

| Control | Purpose |
|---------|---------|
| **Period** | **Day**, **Month**, or **Selected period** |
| **Day combo** | Calendar day bucket (file count shown, e.g. `23/07/2024 (8 JSON)`) |
| **File combo** | **All files** for that day, or one source file (JSON and PCAP) |
| **Pick range…** | Custom date span |
| **Re-analyze Period** | Rebuild analysis from source files for the selected period |
| **Missing days** | Highlights gaps in indexed coverage |

When **Day** is selected, the header **Window** always shows the **full calendar day** (`00:00:00.000` – `23:59:59.999`). A separate line (**Traffic observed …**) shows when flows or packets actually occurred inside that day.

Re-analyze loads flows whose timestamps fall on the selected calendar day. Source files from the adjacent calendar day may also be scanned so traffic that crosses midnight is not split incorrectly. The status line explains when more files are scanned than appear in the day bucket (midnight overlap).

---

## 6. JSON — Explore

Sub-tabs: **Summary**, **Flows**, **Findings**.

Top-level JSON tabs (**Explore**, **Registry**, **Listing**) and Explore sub-tabs do **not** scroll when you use the mouse wheel over the tab bar — only the page content scrolls.

### 6.1 Header

- **Load dataset**, **Generate AI Summary**, **Add Summary to Notes**
- Project path and stats (green loading text while JSON is parsed, same style as PCAP import)
- **Page size** and **Load next** for large datasets
- **Period** row: day/month/range, file picker, **Re-analyze Period**, **Missing days**
- Search: `Search IP / SNI / app...`

### 6.2 Summary

- **Investigation snapshot** — headline, findings, activity patterns, service groups, and next steps generated from the loaded period (peak hours, bursts, messaging/social services, volume). No raw IP addresses in the snapshot text.
- Cards: **Top source IPs**, **Top destination IPs**, **Top protocols**, **Top applications** — each with **Expand table** (expand control in the chart header)
- **Generate AI Summary** sends structured context to the AI assistant; results appear on **AI output**

### 6.3 Flows

- **View** modes (like Listing): Default, All fields, Custom, or saved presets
- **Customize** — pick columns (e.g. add separate Date and Time columns)
- **Presets ▾** — save, update, or delete column layouts
- Filters: **Filter source**, **Filter destination**, **Filter SNI**
- **Conversation: OFF/ON** — focus on one endpoint pair
- **Expand Flows** / **Collapse Flows**
- **Export table** (CSV / Excel / HTML) — exports **visible** filtered rows; a warning appears if the export is not the full dataset
- **Mark as Finding** — save selected flow as a finding
- **Explain with AI** — send flow context to AI

Sortable table columns depend on the active view. **Flow details** panel shows the selected row.

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

- **Load dataset**, **Save Period to Project**, **AI Summary**, **Add Summary to Notes**, **Export Summary**
- **Period** row: day combo, Day / Month / Selected period, **file picker** (all files or one PCAP in the bucket), **Pick range…**, **Re-analyze Period**, **Missing days**
- Stats line: format, packets, volume, period window, and calendar-day notes when applicable

### 9.2 Tabs

| Tab | Content |
|-----|---------|
| **Summary** | Plain-language overview, key points, limitations, service groups, hourly activity (expand tables from chart headers) |
| **Communications** | Two sub-tabs: **Communications** (messaging, calls, push) and **Social** (YouTube, TikTok, Spotify, and similar content/API traffic) |
| **Evidence** | DNS, TLS SNI, HTTP hosts, visible samples, and extracted **Artifacts** |
| **Network** | **Overview** and **Connections** tables |

There is **no separate AI Summary tab** on PCAP. **AI Summary** runs analysis and opens the result on **AI output**.

### 9.3 Communications and Social

Communication indicators are **grouped** by service, indicator type, and host — not one row per flow.

| Column / concept | Meaning |
|------------------|---------|
| **Type** | Call / media, Messaging / push, Background / sync, Content / API, or Other |
| **Indicator** | Short plain-language label (e.g. push channel, likely call/media session) |
| **Sessions** | Number of flows combined into that row |
| **Confidence** | high / medium / low (metadata-based) |

The Communications card highlights **review leads** first. **Routine** background/sync rows (for example repetitive Apple push contacts) are grouped and de-emphasised; open **Open communications table** to see the full list (review leads first, routine at the bottom).

**Mark as Finding** saves the selected communication indicator (from the full table) to the project findings.

### 9.4 Summary text

The Summary tab and investigation snapshot describe:

- Peak activity hour and share of timed traffic
- Observed traffic window inside the calendar day
- Priority communication leads with time span and volume
- Social/content usage when present
- How many routine background flows were grouped separately

### 9.5 Limitations

HTTPS, QUIC, and most app traffic are encrypted. Without plaintext, only metadata and visible artefacts are shown. Messaging or call-like indicators are heuristic, not proof of user action or message content.

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

- **JSON → Flows** — select a row and click **Mark as Finding**
- **PCAP → Communications** — open the full communications table, select a grouped indicator, and click **Mark as Finding**

Enter **Title**, optional **Note**, and **Tags** (comma-separated). The view may switch to the Findings tab.

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

The **AI output** page (sidebar) is the central place for the latest generated text. A context line at the top shows the source (JSON dataset, PCAP, Profile, Finding, or Flow) and the active project name.

### Summary vs Explain

ViaNyquist uses two complementary AI actions. Both send **only a focused context** — not your whole case folder — to the configured model.

| Action | Typical buttons | What it is for |
|--------|-----------------|----------------|
| **Summary** | **Generate AI Summary**, **AI Summary**, **AI Profile Summary** | Overview after loading evidence: main services, endpoints, timing patterns, and stated limitations of the data. |
| **Explain** | **Explain with AI** | Interpretation of **one selected flow** or **one finding**: what the metadata suggests and what to verify in the tables. |

Use **Summary** when you open a new JSON day, PCAP period, or want a case-wide profile narrative. Use **Explain** when you are looking at a single row and want readable guidance before saving a **Finding** or writing **Notes**.

### Where AI is triggered

| Screen | Buttons | Where results appear |
|--------|---------|----------------------|
| **JSON → Explore** | **Generate AI Summary**, **Explain with AI** | Investigation snapshot context and **AI output** |
| **PCAP** | **AI Summary** | **AI output** (no separate PCAP AI tab) |
| **Findings** | **Explain with AI** | **AI output** |
| **Profile** | **AI Profile Summary** | **AI output** |

**Add Summary to Notes** copies the investigation snapshot (JSON or PCAP summary text) into project notes. On **Findings**, **Add Finding to Notes** copies selected finding rows (multi-select with Ctrl+click).

**Add to Notes** / legacy AI copy actions may still appear in some PCAP areas; prefer **Add Summary to Notes** for the structured snapshot.

While a request runs, the UI shows a progress message. Large JSON periods or PCAP captures can take several minutes — the **Timeout** in Settings controls the maximum wait.

### Ollama (local AI)

By default ViaNyquist uses **[Ollama](https://ollama.com)** — a free, local AI runtime for Windows, macOS, and Linux. Ollama serves models on your PC at **`http://localhost:11434`**. Inference does not require the internet once the model is downloaded; your evidence is not uploaded to a cloud AI service unless you change the Base URL yourself.

**Typical first-time setup:**

1. Install Ollama from [ollama.com](https://ollama.com). The ViaNyquist installer can optionally install Ollama and download the **llama3** model during setup.
2. Make sure Ollama is running (system tray icon, or run `ollama serve` in a terminal).
3. If needed, pull the model manually: `ollama pull llama3` (or another model name you prefer).
4. In ViaNyquist, open **Settings → AI**, confirm **Base URL** and **Model**, then click **Save**.

Default values match a standard Ollama install:

| Setting | Default | Meaning |
|---------|---------|---------|
| **Base URL** | `http://localhost:11434` | Ollama server address |
| **Model** | `llama3` | Model name (must exist in `ollama list`) |
| **Timeout** | 600 s | Maximum wait for long summaries |

If AI buttons fail with a connection error, Ollama is usually not running, the model name is wrong, or a firewall is blocking localhost.

You may point **Base URL** at another **Ollama-compatible** `/api/generate` endpoint if your organisation hosts models internally — but only do so if you accept where case context will be sent.

### Limits and good practice

AI output is **explanatory only**. Models can misread sparse data, over-interpret encrypted traffic, or sound confident when the evidence is weak.

- Verify every claim against the flows, tables, charts, and PCAP metadata in the app.
- Do **not** treat AI text as legal proof, expert testimony, or decrypted message content.
- Record your own professional conclusions in **Findings** and **Notes**.
- AI does not replace OSINT lookups, exports, or reading the underlying records.

See also **Settings → AI** and section **19. Limitations and good practice**.

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
- **Evidence Overview** metrics and period coverage
- **Profile Summary** and **Activity rhythm** (when traffic tends to occur)
- Charts: evidence sources, device IPs, behaviour insights, **Activity by hour** (with **Expand table** for hour / flows / volume)
- **Repository hits** banner when internal repository matches exist

The older standalone **Activity event types** chart has been removed; event history is available from **Recent activity** on the Projects page.

Activity patterns are indicators only — they do not prove who used a device or whether a person was awake or asleep.

---

## 15. Settings

- **Save**, **Reload**
- **AI** — **Base URL**, **Model**, **Timeout** for the local **Ollama** server (defaults: `http://localhost:11434`, `llama3`). See section **12. AI output** for setup and usage.
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
| Explore Flows | CSV, Excel, HTML | **Export table** (visible rows; warning if filtered) |
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
- PCAP **Communications** indicators (including call/media labels) are metadata heuristics only
- Device activity ≠ proof a specific person used the device
- Do not treat AI text as evidence
- Use **Findings** for key items; **Notes** for your reasoning
- Check dataset/project identifier warnings before trusting a load

---

## 20. Glossary

Alphabetical list of abbreviations and technical terms you may see in ViaNyquist screens, exports, and reports. Each entry gives the full meaning and how it appears in the application.

### Abbreviations (A–Z)

| Term | Meaning |
|------|---------|
| **AH** | **Authentication Header** — IPsec protocol that authenticates IP packets. Shown as a protocol label on flows; it indicates protected traffic, not the application in use. |
| **AI** | **Artificial Intelligence** — Optional assistant for **Summary** (overview of a dataset, PCAP, or profile) and **Explain** (one flow or finding). Runs locally via **Ollama** by default; configured under **Settings → AI**. Guidance only — not evidence. |
| **API** | **Application Programming Interface** — Online service access keys used in **Settings → OSINT** (VirusTotal, Shodan) and the AI **Base URL** for the local model server. |
| **CSV** | **Comma-Separated Values** — Spreadsheet-friendly export format. Available on Listing, Explore flow tables, Registry, PCAP tables, and expand-table dialogs. |
| **DNS** | **Domain Name System** — Maps host names to IP addresses. Shown in JSON flows, PCAP **Evidence**, and metadata summaries (DNS queries). |
| **ESP** | **Encapsulating Security Payload** — IPsec protocol that encrypts IP payloads. Listed as a protocol on flows when VPN/tunnel-style traffic is present. |
| **GeoIP** | **Geographic IP lookup** — Estimates country/region for a public IP. Available from **OSINT** online lookup buttons. |
| **GRE** | **Generic Routing Encapsulation** — Tunneling protocol that carries one protocol inside another. May appear in the **Protocol** column of flow data. |
| **HTML** | **HyperText Markup Language** — Rich report format for exports (Listing, Registry, PCAP, Profile) and the built-in user manual opened by **Help**. |
| **HTTP** | **HyperText Transfer Protocol** — Cleartext web traffic. ViaNyquist can show HTTP host names, headers, and sample payloads in PCAP when encryption is not used. |
| **HTTPS** | **HyperText Transfer Protocol Secure** — HTTP encrypted with TLS. Message content is not visible; only metadata (IPs, ports, timing, TLS SNI) is shown. |
| **ICMP** | **Internet Control Message Protocol** — Network diagnostic and control messages (for example reachability checks). Appears in protocol statistics and PCAP overviews. |
| **ICMPv6** | **Internet Control Message Protocol version 6** — IPv6 equivalent of ICMP for diagnostics and neighbour discovery. |
| **ID** | **Identifier** — Internal record number for a flow row, finding, or dataset entry in tables and exports. |
| **IGMP** | **Internet Group Management Protocol** — Multicast group membership signalling. May appear as a rare protocol label in flow data. |
| **IMEI** | **International Mobile Equipment Identity** — Unique mobile device number (15 digits). Entered in the project dialog; used for case context and OSINT pivots. |
| **IMSI** | **International Mobile Subscriber Identity** — SIM card identifier (up to 15 digits). Stored per project subject and shown in case summaries. |
| **IP** | **Internet Protocol** — Network addresses (**Source IP**, **Destination IP**, **Device IP**) that identify endpoints in JSON flows and PCAP analysis. |
| **IPsec** | **Internet Protocol Security** — Suite of protocols (ESP, AH) for encrypting or authenticating IP traffic. ViaNyquist shows protocol labels, not decrypted content. |
| **IPv4** | **Internet Protocol version 4** — Classic dotted-decimal addresses (for example `192.0.2.1`). Used throughout Explore, Listing, and PCAP views. |
| **IPv6** | **Internet Protocol version 6** — Longer hexadecimal addresses for modern networks. Handled the same way as IPv4 in tables and exports. |
| **JSON** | **JavaScript Object Notation** — Text file format for imported **flow datasets**, indexed by calendar day per project. Loaded in **JSON → Explore / Registry / Listing**. |
| **LIID** | **Lawful Interception ID** — Reference identifier from intercept/case metadata in some operator exports. Shown on the Registry header when present in the dataset. |
| **LLMNR** | **Link-Local Multicast Name Resolution** — Windows-style local name lookup on the LAN. PCAP may list LLMNR queries alongside mDNS. |
| **MAC** | **Media Access Control address** — Hardware address of a network interface (`Source MAC`, `Destination MAC` in Listing and Registry). |
| **mDNS** | **multicast DNS** — Local network name resolution (often `.local` hosts). Detected in PCAP artefacts and metadata counters. |
| **MSISDN** | **Mobile Station International Subscriber Directory Number** — Subscriber telephone number in international format. Entered as **Mobile / MSISDN** in project settings. |
| **NBNS** | **NetBIOS Name Service** — Legacy Windows name resolution on local networks. PCAP may show NBNS/NetBIOS queries as artefacts. |
| **NetBIOS** | **Network Basic Input/Output System** — Legacy Windows networking layer. Port 137 traffic may be labelled NetBIOS in PCAP hints. |
| **OIB** | **Personal identification number (Osobni identifikacijski broj)** — Croatian 11-digit personal ID with checksum. Validated when entered in the project dialog and Repository search. |
| **Ollama** | **Local AI runtime** — Serves language models on your PC (default `http://localhost:11434`). ViaNyquist sends structured case context to Ollama’s `/api/generate` endpoint; install from [ollama.com](https://ollama.com) or via the ViaNyquist installer option. |
| **OSINT** | **Open Source Intelligence** — Module for pivots on identifiers, domains, and IPs using external lookups (WHOIS/RDAP, GeoIP, VirusTotal, Shodan) and the local **Repository**. |
| **OSPF** | **Open Shortest Path First** — Routing protocol used between network devices. Appears only as a protocol label if present in captured traffic. |
| **OUI** | **Organizationally Unique Identifier** — First part of a MAC address identifying the vendor (`Source OUI`, `Destination OUI` in Listing). |
| **PCAP** | **Packet Capture** — Binary record of network packets (`.pcap` / `.pcapng`). Loaded on the **PCAP** page for metadata, artefacts, and exports. |
| **QUIC** | **Quick UDP Internet Connections** — Modern UDP-based transport used by HTTP/3. Encrypted payload; ViaNyquist shows metadata only (often labelled QUIC/HTTP3). |
| **RDAP** | **Registration Data Access Protocol** — Structured successor to WHOIS for domain and IP registration data. Fetched from **OSINT** via the **RDAP** button. |
| **SCTP** | **Stream Control Transmission Protocol** — Message-oriented transport used by some telecom systems. Shown as a protocol name when present in flows. |
| **SNI** | **Server Name Indication** — Hostname sent during a TLS handshake. Visible even when HTTPS content is encrypted; shown as **TLS SNI** in PCAP and flow fields. |
| **SSDP** | **Simple Service Discovery Protocol** — Local UPnP/device discovery on UDP port 1900. PCAP may list SSDP discovery artefacts. |
| **TCP** | **Transmission Control Protocol** — Reliable connection-oriented transport (IP protocol 6). Common for web, mail, and many apps; paired with port numbers in flow rows. |
| **TAC** | **Type Allocation Code** — First eight digits of an IMEI identifying device make/model. Decoded via the **IMEI TAC database** in Settings (bundled or imported CSV). |
| **TLS** | **Transport Layer Security** — Encrypts HTTPS and many other services. ViaNyquist shows TLS SNI and connection metadata, not decrypted application data. |
| **UDP** | **User Datagram Protocol** — Connectionless transport (IP protocol 17). Used for DNS, QUIC, VoIP-like patterns, and many short exchanges. |
| **URL** | **Uniform Resource Locator** — Web address string. External **OSINT** links open investigation URLs in your browser. |
| **User-Agent** | **HTTP client identifier header** — Names the browser or app in cleartext HTTP. PCAP **Artifacts** may surface User-Agent strings when visible. |
| **VPN** | **Virtual Private Network** — Encrypted tunnel traffic. Often appears as IPsec/GRE or unknown encrypted flows; content is not readable in ViaNyquist. |
| **WHOIS** | **Registration lookup service** — Public domain/IP ownership and contact records. Legacy protocol; ViaNyquist fetches equivalent data via **RDAP**. |
| **XLSX** | **Excel Open XML Spreadsheet** — Microsoft Excel export format (same tables as CSV/HTML exports). |
| **XMPP** | **Extensible Messaging and Presence Protocol** — Chat/messaging protocol. PCAP port hints may label XMPP/messaging traffic heuristically. |

### ViaNyquist terms

| Term | Meaning |
|------|---------|
| **Activity Profile** | Cross-evidence summary for the active project — JSON days, PCAP volume, findings, notes, and behaviour charts on the **Profile** page. |
| **Calendar day** | A full 24-hour period from `00:00:00` to `23:59:59` on the selected date. Day mode filters and displays traffic by flow timestamps, not only by source file name. |
| **Finding** | Investigator-marked important flow, communication indicator, or item, saved to the project with title, notes, and optional AI explanation. |
| **Flow** | One communication record between source and destination (IPs, ports, protocol, application, timing, volume). Core unit in **JSON → Explore** and Listing. |
| **Investigation snapshot** | Structured summary block on JSON **Summary** (headline, findings, patterns, next steps) built from analyst metrics without exposing raw IPs in the narrative. |
| **JSON dataset** | Indexed collection of flow JSON files for a project period (by calendar day). Distinct from a single PCAP capture. |
| **Review lead** | A grouped communication indicator prioritised for manual review (call/media or stronger messaging signals). |
| **Repository** | Local store of imported leak/breach datasets searched from **OSINT → Repository** (phones, emails, OIB, names, etc.). |
| **Routine background** | Low-priority grouped traffic (push/sync, generic contacts) shown separately from review leads in PCAP Communications. |
| **Workspace** | Per-project folder under the parent you choose at creation; holds `datasets/`, `exports/`, `findings/`, `notes/`, and `reports/`. |

---

## 21. Help

Click **Help** in the sidebar. ViaNyquist opens `docs/USER_GUIDE_EN.html` (or `docs/USER_GUIDE.html`) in your default browser.

To rebuild HTML after editing the manual: `python docs/build_user_manual_html.py`

---

*ViaNyquist — investigative support tool. Use professional judgement alongside the data shown.*
