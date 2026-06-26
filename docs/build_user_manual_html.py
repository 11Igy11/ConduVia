#!/usr/bin/env python3
"""Build English HTML user manual from docs/USER_GUIDE_EN.md."""

from __future__ import annotations

import html
import re
import shutil
from pathlib import Path

DOCS = Path(__file__).resolve().parent
PROJECT_ROOT = DOCS.parent
SOURCE = DOCS / "USER_GUIDE_EN.md"
OUTPUT_EN = DOCS / "USER_GUIDE_EN.html"
OUTPUT_HELP = DOCS / "USER_GUIDE.html"
ASSETS_DIR = DOCS / "manual-assets"
LOGO_SRC = PROJECT_ROOT / "assets" / "ViaNyquist.png"
LOGO_DST = ASSETS_DIR / "logo.png"

CSS = """
:root {
  --bg: #0f172a;
  --bg-soft: #111827;
  --panel: #1f2937;
  --panel-2: #273549;
  --line: rgba(148, 163, 184, 0.22);
  --text: #e5e7eb;
  --muted: #94a3b8;
  --accent: #3b82f6;
  --accent-soft: rgba(59, 130, 246, 0.14);
  --paper: #f8fafc;
  --ink: #1e293b;
  --shadow: 0 18px 40px rgba(15, 23, 42, 0.28);
}

* { box-sizing: border-box; }

body {
  margin: 0;
  font-family: "Segoe UI", "Inter", Arial, sans-serif;
  color: var(--ink);
  background: linear-gradient(180deg, #e2e8f0 0%, #f1f5f9 220px, #f8fafc 420px);
  line-height: 1.6;
}

a { color: #2563eb; text-decoration: none; }
a:hover { text-decoration: underline; }

.site-header {
  background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 52%, #1f2937 100%);
  color: var(--text);
  border-bottom: 1px solid rgba(96, 165, 250, 0.25);
  box-shadow: var(--shadow);
}

.header-inner {
  max-width: 1180px;
  margin: 0 auto;
  padding: 28px 32px 24px;
  display: flex;
  align-items: center;
  gap: 22px;
}

.header-logo {
  width: 72px;
  height: 72px;
  object-fit: contain;
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.06);
  padding: 8px;
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.header-text h1 {
  margin: 0;
  font-size: 2rem;
  font-weight: 800;
  letter-spacing: -0.02em;
}

.header-meta {
  margin: 8px 0 0;
  color: var(--muted);
  font-size: 0.95rem;
}

.page-layout {
  max-width: 1180px;
  margin: 0 auto;
  padding: 28px 24px 48px;
  display: grid;
  grid-template-columns: 250px minmax(0, 1fr);
  gap: 24px;
  align-items: start;
}

.toc {
  position: sticky;
  top: 20px;
  max-height: calc(100vh - 40px);
  overflow-y: auto;
  overscroll-behavior: contain;
  background: #ffffff;
  border: 1px solid #dbe3ee;
  border-radius: 16px;
  padding: 18px 16px;
  box-shadow: 0 10px 24px rgba(15, 23, 42, 0.06);
}

.toc::-webkit-scrollbar { width: 8px; }

.toc::-webkit-scrollbar-track {
  background: transparent;
  margin: 8px 0;
}

.toc::-webkit-scrollbar-thumb {
  background: #cbd5e1;
  border-radius: 999px;
}

.toc::-webkit-scrollbar-thumb:hover { background: #94a3b8; }

.toc h2 {
  margin: 0 0 12px;
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #64748b;
}

.toc ol {
  margin: 0;
  padding-left: 18px;
  font-size: 0.92rem;
}

.toc li { margin: 7px 0; }

.toc-root { padding-left: 18px; }

.toc-sub {
  list-style: none;
  margin: 4px 0 8px;
  padding-left: 14px;
  font-size: 0.84rem;
}

.toc-sub li { margin: 4px 0; }

.toc-sub a { color: #475569; }

.content {
  background: #ffffff;
  border: 1px solid #dbe3ee;
  border-radius: 18px;
  padding: 32px 36px 40px;
  box-shadow: 0 12px 30px rgba(15, 23, 42, 0.07);
}

.content h2 {
  font-size: 1.45rem;
  margin: 2.2rem 0 0.8rem;
  padding-top: 0.4rem;
  color: #0f172a;
  border-bottom: 2px solid #e2e8f0;
  padding-bottom: 8px;
  scroll-margin-top: 24px;
}

.content h2:first-child { margin-top: 0; }

.content h3 {
  font-size: 1.08rem;
  margin: 1.5rem 0 0.55rem;
  color: #1e3a5f;
  scroll-margin-top: 24px;
}

.content p { margin: 0.65rem 0; color: #334155; }

.content ul, .content ol {
  margin: 0.55rem 0 0.85rem 1.2rem;
  color: #334155;
}

.content li { margin: 0.3rem 0; }

.content table {
  width: 100%;
  border-collapse: collapse;
  margin: 0.9rem 0 1.2rem;
  font-size: 0.94rem;
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid #dbe3ee;
}

.content th, .content td {
  padding: 10px 12px;
  text-align: left;
  border-bottom: 1px solid #e5e7eb;
}

.content th {
  background: #1f2937;
  color: #f8fafc;
  font-weight: 700;
}

.content tr:nth-child(even) td { background: #f8fafc; }

.content code {
  background: #eef2ff;
  color: #312e81;
  padding: 2px 6px;
  border-radius: 6px;
  font-size: 0.9em;
}

.content pre {
  background: #0f172a;
  color: #e2e8f0;
  padding: 14px 16px;
  border-radius: 12px;
  overflow-x: auto;
  font-size: 0.88rem;
  border: 1px solid #334155;
}

.content hr {
  border: none;
  border-top: 1px solid #e2e8f0;
  margin: 1.8rem 0;
}

.content strong { color: #0f172a; }

.content .footer-note {
  margin-top: 2rem;
  padding-top: 1rem;
  border-top: 1px solid #e2e8f0;
  font-style: italic;
  color: #64748b;
  font-size: 0.95rem;
}

.site-footer {
  max-width: 1180px;
  margin: 0 auto 36px;
  padding: 0 24px;
  text-align: center;
  color: #64748b;
  font-size: 0.88rem;
}

@media (max-width: 920px) {
  .page-layout { grid-template-columns: 1fr; }
  .toc { position: static; max-height: none; overflow: visible; }
  .header-inner { padding: 22px 20px; }
  .content { padding: 24px 20px 30px; }
}

@media print {
  body { background: #fff; }
  .toc { display: none; }
  .site-header { box-shadow: none; }
  .content, .toc { box-shadow: none; }
  .page-layout { display: block; padding-top: 0; }
}
"""


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "section"


def _inline(text: str) -> str:
    text = html.escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    return text


def _extract_meta(md: str) -> tuple[str, str]:
    version = "Beta"
    updated = ""
    for line in md.splitlines():
        if "**Version:**" in line:
            version = line.split("Version:**", 1)[-1].strip().strip("*").strip()
        elif "**Last updated:**" in line:
            updated = line.split("Last updated:**", 1)[-1].strip().strip("*").strip()
    return version, updated


def _strip_section_number(title: str) -> str:
    return re.sub(r"^\d+\.\s+", "", title).strip() or title


def _strip_subsection_number(title: str) -> str:
    return re.sub(r"^\d+\.\d+\s+", "", title).strip() or title


def _main_section_number(title: str) -> int | None:
    match = re.match(r"^(\d+)\.", title)
    return int(match.group(1)) if match else None


def _extract_toc(md: str) -> list[tuple[str, str, int]]:
    """Return (slug, display title, level) for numbered sections 1–20 and their subsections."""
    items: list[tuple[str, str, int]] = []
    for line in md.splitlines():
        if line.startswith("## "):
            title = line[3:].strip()
            section = _main_section_number(title)
            if section is not None and section <= 20:
                items.append((_slugify(title), _strip_section_number(title), 2))
        elif line.startswith("### "):
            title = line[4:].strip()
            match = re.match(r"^(\d+)\.\d+\s", title)
            if match and int(match.group(1)) <= 20:
                items.append((_slugify(title), _strip_subsection_number(title), 3))
    return items


def _render_toc(items: list[tuple[str, str, int]]) -> str:
    if not items:
        return ""
    rows: list[str] = []
    index = 0
    while index < len(items):
        slug, title, level = items[index]
        if level != 2:
            index += 1
            continue
        sub_items: list[tuple[str, str, int]] = []
        next_index = index + 1
        while next_index < len(items) and items[next_index][2] == 3:
            sub_items.append(items[next_index])
            next_index += 1
        if sub_items:
            sub_rows = "\n".join(
                f'<li><a href="#{sub_slug}">{html.escape(sub_title)}</a></li>'
                for sub_slug, sub_title, _ in sub_items
            )
            rows.append(
                f'<li><a href="#{slug}">{html.escape(title)}</a>'
                f'<ul class="toc-sub">{sub_rows}</ul></li>'
            )
        else:
            rows.append(f'<li><a href="#{slug}">{html.escape(title)}</a></li>')
        index = next_index
    body = "\n".join(rows)
    return f'<nav class="toc"><h2>Contents</h2><ol class="toc-root">{body}</ol></nav>'


def md_to_html(md: str) -> str:
    lines = md.splitlines()
    out: list[str] = []
    in_ul = False
    in_ol = False
    in_pre = False
    in_table = False
    table_rows: list[str] = []
    skipped_intro = False

    def close_lists() -> None:
        nonlocal in_ul, in_ol
        if in_ul:
            out.append("</ul>")
            in_ul = False
        if in_ol:
            out.append("</ol>")
            in_ol = False

    def flush_table() -> None:
        nonlocal in_table, table_rows
        if not in_table:
            return
        if table_rows:
            out.append("<table>")
            for i, row in enumerate(table_rows):
                cells = [c.strip() for c in row.strip("|").split("|")]
                tag = "th" if i == 0 else "td"
                out.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
            out.append("</table>")
        table_rows = []
        in_table = False

    for raw in lines:
        line = raw.rstrip()

        if not skipped_intro:
            if line.startswith("# ") or line.startswith("**Version:**") or line.startswith("**Last updated:**"):
                continue
            if line.strip() == "---":
                skipped_intro = True
                continue
            if not line.strip():
                continue
            skipped_intro = True

        if line.startswith("```"):
            close_lists()
            flush_table()
            if in_pre:
                out.append("</pre>")
                in_pre = False
            else:
                out.append("<pre>")
                in_pre = True
            continue

        if in_pre:
            out.append(html.escape(line))
            continue

        if line.startswith("|") and "|" in line[1:]:
            close_lists()
            if not in_table:
                in_table = True
            if re.match(r"^\|[\s\-:|]+\|$", line):
                continue
            table_rows.append(line)
            continue

        flush_table()

        if not line.strip():
            close_lists()
            out.append("")
            continue

        if line.startswith("## "):
            close_lists()
            title = line[3:].strip()
            slug = _slugify(title)
            out.append(f'<h2 id="{slug}">{_inline(title)}</h2>')
        elif line.startswith("### "):
            close_lists()
            title = line[4:].strip()
            slug = _slugify(title)
            out.append(f'<h3 id="{slug}">{_inline(title)}</h3>')
        elif line.strip() == "---":
            close_lists()
            out.append("<hr>")
        elif re.match(r"^\d+\.\s", line):
            if not in_ol:
                close_lists()
                out.append("<ol>")
                in_ol = True
            content = re.sub(r"^\d+\.\s+", "", line)
            out.append(f"<li>{_inline(content)}</li>")
        elif line.startswith("- "):
            if not in_ul:
                close_lists()
                out.append("<ul>")
                in_ul = True
            out.append(f"<li>{_inline(line[2:].strip())}</li>")
        elif line.startswith("*") and line.endswith("*") and not line.startswith("**"):
            close_lists()
            out.append(f'<p class="footer-note">{_inline(line.strip("* ").strip())}</p>')
        else:
            close_lists()
            out.append(f"<p>{_inline(line)}</p>")

    close_lists()
    flush_table()
    if in_pre:
        out.append("</pre>")
    return "\n".join(out)


def _copy_logo() -> str:
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    if LOGO_SRC.exists():
        shutil.copy2(LOGO_SRC, LOGO_DST)
        return "manual-assets/logo.png"
    return ""


def build_page(md: str) -> str:
    version, updated = _extract_meta(md)
    toc_items = _extract_toc(md)
    body = md_to_html(md)
    logo_path = _copy_logo()
    logo_html = (
        f'<img class="header-logo" src="{html.escape(logo_path)}" alt="ViaNyquist logo">'
        if logo_path
        else '<div class="header-logo" aria-hidden="true"></div>'
    )
    meta_bits = [version]
    if updated:
        meta_bits.append(updated)
    meta_text = " · ".join(meta_bits)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ViaNyquist User Guide</title>
  <style>{CSS}</style>
</head>
<body>
  <header class="site-header">
    <div class="header-inner">
      {logo_html}
      <div class="header-text">
        <h1>ViaNyquist User Guide</h1>
        <p class="header-meta">{html.escape(meta_text)}</p>
      </div>
    </div>
  </header>
  <div class="page-layout">
    {_render_toc(toc_items)}
    <main class="content">
{body}
    </main>
  </div>
  <footer class="site-footer">ViaNyquist — investigative support tool. Verify all conclusions against the underlying evidence.</footer>
</body>
</html>
"""


def main() -> None:
    md = SOURCE.read_text(encoding="utf-8")
    page = build_page(md)
    for output in (OUTPUT_EN, OUTPUT_HELP):
        output.write_text(page, encoding="utf-8")
        print(f"Wrote {output}")
    if LOGO_DST.exists():
        print(f"Wrote {LOGO_DST}")


if __name__ == "__main__":
    main()
