"""
PhishyLens: auto write-up (Markdown + print-ready HTML) built ONLY from an existing analysis result.

    build_report(result, fmt="md"|"html", defang=True, include_sigma=True, app_version="") -> str

Section order: title block (verdict badge + key facts) → table of contents + "How to read" → Executive Summary →
Visual Map → Timeline (only when the result holds timestamps) → Classification and Kill Chain → ATT&CK techniques →
Why This Score → Findings (by severity, duplicates merged) → Indicators of Compromise → Recommended Actions
(Now / Today / This week checklist) → Detection Rules (Sigma) → Related Resources → Appendix.
Sections without data are skipped silently.

Both formats render the same block list, so they always carry identical content. Every user-controlled value is
escaped (Markdown: code spans / < > entities; HTML: html.escape, http(s)-only links). Secrets quoted in evidence are
masked everywhere; the IOC table is always defanged; with defang=True all free text is defanged too.
"""
import html
import re
from datetime import datetime, timezone

from utils.artifacts import (PRIORITY_ORDER, SEV_RANK, INFORMATIONAL, ioc_inventory, mask_secrets, prioritized_actions,
                             timeline_events)
from utils.defang import defang_obj, defang_text
from utils.diagrams import build_diagram, build_killchain_svg
from utils.sigma_gen import generate_rules
from utils.summary import build_exec_summary, highlight_spans
from utils.highlight import rich_html, evidence_html
from utils.summary_details import _block_lines

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEV_LABEL = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}


# ─── cell helpers ───────────────────────────────────────────────
def code(v):
    return {"code": "" if v is None else str(v)}


def rich(v):
    """Cell rendered through the escape-first highlighter in HTML, as a code span in Markdown."""
    return {"rich": "" if v is None else str(v)}


def link(text, url):
    return {"link": (str(text), str(url or ""))}


def _safe_url(url: str) -> str:
    return url if re.match(r"^https?://[^\s\"'<>]+$", url or "") else ""


def slug(title: str) -> str:
    """GitHub-style heading anchor, used for both the Markdown TOC and the HTML ids."""
    return re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", title.lower()).strip())


def _mask_obj(v):
    if isinstance(v, str):
        return mask_secrets(v)
    if isinstance(v, list):
        return [_mask_obj(x) for x in v]
    if isinstance(v, dict):
        return {k: _mask_obj(x) for k, x in v.items()}
    return v


def raw_url(raw: dict, tid: str) -> str:
    """Technique URL from the un-defanged result (links must stay clickable); validated before rendering."""
    for t in (raw.get("mitre") or {}).get("techniques") or []:
        if t.get("id") == tid:
            return t.get("url", "")
    return ""


def _killchain_mermaid(kc: dict) -> str:
    stages = kc.get("stages") or []
    if not stages:
        return ""
    lines = ["flowchart LR"]
    for i, s in enumerate(stages):
        mark = f"{len(s.get('evidence') or [])} finding(s)" if s.get("hit") else "no evidence"
        lines.append(f'  k{i}["{s.get("name", "").replace(chr(34), "")}<br/>{mark}"]')
    lines.append("  " + " --> ".join(f"k{i}" for i in range(len(stages))))
    hit = [f"k{i}" for i, s in enumerate(stages) if s.get("hit")]
    if hit:
        lines += ["  classDef hit stroke:#cf222e,stroke-width:2px", f"  class {','.join(hit)} hit"]
    return "\n".join(lines)


# ─── block builder ──────────────────────────────────────────────
def build_blocks(result: dict, defang: bool = True, include_sigma: bool = True, now: datetime | None = None,
                 app_version: str = "") -> list:
    raw = result if isinstance(result, dict) else {}
    r = _mask_obj(defang_obj(raw) if defang else raw)          # text source: secrets masked, optionally defanged
    now = now or datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    verdict, score = r.get("verdict") or "UNKNOWN", r.get("score")
    findings = [f for f in (r.get("findings") or []) if isinstance(f, dict)]
    real = [f for f in findings if f.get("name") not in INFORMATIONAL]
    cls, kc, mitre = r.get("classification") or {}, raw.get("kill_chain") or {}, r.get("mitre") or {}
    summ = build_exec_summary(raw, defang=defang)
    diagram = build_diagram(raw, "print", defang=defang)
    kc_svg = build_killchain_svg(raw, "print")
    events = timeline_events(raw)
    actions = prioritized_actions(raw)
    iocs = ioc_inventory(raw)
    techs = mitre.get("techniques") or []
    expl = (r.get("score_explanation") or {}).get("contributions") or []
    sigma = generate_rules(findings, str(r.get("mode") or "")) if include_sigma else {"rules": []}
    resources = _resources(raw)

    sections = [("Executive Summary", True), ("Visual Map", bool(diagram["svg"] or kc_svg)), ("Timeline of Events", bool(events)),
                ("Classification and Kill Chain", bool(cls.get("primary") or kc.get("stages"))), ("MITRE ATT&CK Techniques", bool(techs)),
                ("Why This Score", bool(expl)), ("Findings", True),
                ("Indicators of Compromise", bool(iocs) or bool((r.get("malware_family") or {}).get("name"))),
                ("Recommended Actions", bool(actions)), ("Detection Rules (Sigma)", bool(sigma["rules"])),
                ("Related Resources", bool(resources)), ("Appendix", True)]
    present = [s for s, ok in sections if ok]
    b = []

    # 1. title block
    b.append(("title", f"PhishyLens Write-up: {verdict}" + (f" ({score}%)" if score is not None else ""), verdict,
              [(k["label"], k["value"]) for k in summ["key_facts"]]))
    b.append(("kv", [("Mode", str(r.get("mode") or "").upper()), ("Input", code(str(r.get("input") or "")[:300])),
                     ("Scan ID", r.get("scan_id") or ""), ("Case", r.get("case_number") or ""), ("Generated", stamp)]))
    b.append(("toc", [(slug(s), s) for s in present]))
    b.append(("callout", "How to read this report",
              "Start with the Executive Summary: it is written for non-specialists. Severity runs Critical > High > Medium > Low; "
              "the Recommended Actions checklist is ordered Now / Today / This week. "
              + ("Indicators are defanged (hxxp://, evil[.]com) so they cannot be clicked by accident. " if defang else
                 "The IOC table is defanged; other text shows indicators as recorded. ")
              + "Passwords quoted in evidence are masked. Every statement comes from the analysis result; nothing is added beyond it."))

    # 2. executive summary
    b.append(("h2", "Executive Summary"))
    b.append(("lead", summ["headline"], True))
    if summ.get("story"):                                  # the data-driven story replaces What happened / Why it matters
        b.append(("story", summ["story"]))
    else:
        if summ["what_happened"]:
            b.append(("h3", "What happened"))
            b.append(("list", summ["what_happened"], True))
        b.append(("h3", "Why it matters"))
        b.append(("p", summ["why_it_matters"], True))
    if summ["do_now"]:
        b.append(("h3", "Do now"))
        b.append(("kv", [(a["priority"], a["action"]) for a in summ["do_now"]]))          # bold priority label + action
    # "Show details": always expanded in the write-ups; empty blocks are already dropped by the builder
    try:
        from utils.summary import build_summary_details
        det = build_summary_details(raw, defang=defang)
    except Exception:
        det = {"blocks": []}
    if det.get("blocks"):
        b.append(("xdetails", det))

    # 3. visual map
    if diagram["svg"] or kc_svg:
        b.append(("pagebreak",))
        b.append(("h2", "Visual Map"))
        if diagram["svg"]:
            b.append(("figure", diagram["svg"], diagram["mermaid"], f"{diagram['title']}: {len(diagram['nodes'])} nodes, "
                                                                     f"{len(diagram['edges'])} connections"
                      + (f" ({len(diagram.get('grouped') or [])} more grouped)" if diagram.get("grouped") else "")))
        if kc_svg:
            b.append(("figure", kc_svg, _killchain_mermaid(kc), "Kill chain: highlighted stages have evidence"))

    # 4. timeline (only with real timestamps)
    if events:
        b.append(("h2", "Timeline of Events"))
        clean = (lambda s: defang_text(mask_secrets(s))) if defang else mask_secrets
        b.append(("table", ["Time (as recorded)", "Line / hop", "Source", "Event", "Severity"],
                  [[e["time"], str(e.get("line") or ""), rich(clean(e.get("source", ""))), clean(e["event"]), SEV_LABEL.get(e.get("severity"), "n/a")]
                   for e in events[:60]]))

    # 5. classification + kill chain
    if cls.get("primary") or kc.get("stages"):
        b.append(("h2", "Classification and Kill Chain"))
        if cls.get("primary"):
            b.append(("kv", [("Primary", cls["primary"]), ("Secondary", ", ".join(cls.get("secondary") or []) or "n/a"),
                             ("Confidence", f"{cls.get('confidence', 0)}%"), ("Rationale", cls.get("rationale") or "")]))
        if kc.get("stages"):
            b.append(("p", f"Attacker reached: {kc.get('furthest_stage') or 'no stage evidenced'}."))
            b.append(("table", ["Stage", "Reached", "Evidence"],
                      [[s.get("name", ""), "yes" if s.get("hit") else "no", ", ".join(s.get("evidence") or []) or "none"] for s in kc["stages"]]))

    # 6. ATT&CK
    if techs:
        b.append(("h2", "MITRE ATT&CK Techniques"))
        b.append(("table", ["ID", "Name", "Tactic", "Confidence", "Link"],
                  [[t.get("id", ""), t.get("name", ""), t.get("tactic", ""), f"{t['confidence']}%" if t.get("confidence") is not None else "n/a",
                    link("attack.mitre.org", raw_url(raw, t.get("id")))] for t in techs]))

    # 7. why this score
    if expl:
        b.append(("h2", "Why This Score"))
        b.append(("table", ["Factor", "Points", "Severity", "Evidence"],
                  [[c.get("label") or c.get("factor", ""), f"+{c.get('points', 0)}%", c.get("severity", ""), code(c.get("evidence", ""))] for c in expl]))
        b.append(("p", f"Contributions sum to the final score of {(r.get('score_explanation') or {}).get('score', score)}%."))

    # 8. findings: grouped by severity, duplicates merged into one evidence list
    b.append(("h2", "Findings"))
    if real:
        merged = {}
        for f in real:
            m = merged.setdefault(f.get("name", ""), {"f": f, "evidence": [], "sev": f.get("severity", "LOW")})
            ev = str(f.get("evidence") or "")
            if ev and ev not in m["evidence"]:
                m["evidence"].append(ev)
            if SEV_RANK.get(f.get("severity"), 0) > SEV_RANK.get(m["sev"], 0):
                m["sev"] = f.get("severity")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            group = [m for m in merged.values() if m["sev"] == sev]
            if not group:
                continue
            b.append(("h3", f"{SEV_LABEL[sev]} ({len(group)})"))
            for m in group:
                f = m["f"]
                b.append(("finding", f.get("name", ""), sev, f.get("description", ""), m["evidence"][:10], f.get("recommendation", ""),
                          f.get("false_positive_possibility", "")))
    else:
        b.append(("p", "No findings beyond informational checks."))

    # 9. IOCs (always defanged) + malware family when a source named one
    mf = r.get("malware_family")
    if iocs or (mf and mf.get("name")):
        b.append(("h2", "Indicators of Compromise"))
        if iocs:
            b.append(("table", ["Type", "Value (defanged)", "Role", "Internal / public"],
                      [[i["type"], rich(defang_text(i["value"])), i["role"] or "n/a", i["scope"] or "n/a"] for i in iocs]))
        if mf and mf.get("name"):
            b.append(("kv", [("Malware family", mf["name"]), ("Reported by", mf.get("source", "")), ("First seen", mf.get("first_seen", "")),
                             ("Tags", ", ".join(mf.get("tags") or [])), ("Indicator", code(defang_text(mf.get("indicator", ""))))]))

    # 10. recommended actions checklist
    if actions:
        b.append(("h2", "Recommended Actions"))
        clean = (lambda s: defang_text(s)) if defang else (lambda s: s)
        b.append(("checklist", [(p, [clean(a["action"]) + (f" (for: {', '.join(a['findings'][:3])})" if a["findings"] else "")
                                     for a in actions if a["priority"] == p]) for p in PRIORITY_ORDER]))

    # 11. sigma
    if sigma["rules"]:
        b.append(("h2", "Detection Rules (Sigma)"))
        b.append(("p", f"{len(sigma['rules'])} experimental rule(s) generated from supported findings: review and tune before deployment."))
        for rule in sigma["rules"]:
            b.append(("h3", rule["title"]))
            b.append(("code", "yaml", rule["yaml"]))

    # 12. related resources
    if resources:
        b.append(("h2", "Related Resources"))
        b.append(("links", resources))

    # 13. appendix
    b.append(("pagebreak",))
    b.append(("h2", "Appendix"))
    sev_counts = {SEV_LABEL[s]: sum(1 for f in real if f.get("severity") == s) for s in SEV_LABEL}
    ioc_counts = {}
    for i in iocs:
        ioc_counts[i["type"]] = ioc_counts.get(i["type"], 0) + 1
    ls, ns = raw.get("log_stats") or {}, raw.get("network_stats") or {}
    rows = [("Findings by severity", ", ".join(f"{k} {v}" for k, v in sev_counts.items() if v) or "none"),
            ("IOCs by type", ", ".join(f"{k} {v}" for k, v in ioc_counts.items()) or "none"),
            ("Log lines parsed", f"{ls['parsed_lines']} of {ls.get('total_lines', ls['parsed_lines'])}" if ls.get("parsed_lines") else ""),
            ("Hosts / open ports", f"{len(ns.get('hosts') or [])} / {len(ns.get('ports') or [])}" if ns.get("hosts") else ""),
            ("Packets", str((ns.get("packets") or {}).get("packets") or "")),
            ("ATT&CK techniques", f"{len(techs)} (ATT&CK v{mitre.get('attack_version')})" if techs else ""),
            ("Analysis duration", f"{raw['duration_ms']} ms" if raw.get("duration_ms") else ""),
            ("Tool version", f"PhishyLens {app_version}" if app_version else "PhishyLens"),
            ("Generated", stamp)]
    b.append(("kv", [(k, v) for k, v in rows if v]))
    b.append(("note", "Built only from the analysis result: every sentence, table row, diagram node and edge comes from fields the "
                      "analyzers returned. No additional threat data was fetched and nothing was generated by an AI model."))
    return b


def _resources(raw: dict) -> list:
    """(label, url) pairs taken from the result: technique, mitigation and detection-strategy pages, plus CVEs in findings."""
    out, seen = [], set()

    def add(label, url):
        if _safe_url(url) and url not in seen:
            seen.add(url)
            out.append((label, url))

    for t in (raw.get("mitre") or {}).get("techniques") or []:
        add(f"{t.get('id')} {t.get('name')} (ATT&CK technique)", t.get("url", ""))
    for t in (raw.get("mitre") or {}).get("techniques") or []:
        for m in t.get("mitigations") or []:
            add(f"{m.get('id')} {m.get('name')} (mitigation)", m.get("url", ""))
        for d in t.get("detection") or []:
            add(f"{d.get('id')} {d.get('name')} (detection strategy)", d.get("url", ""))
    for f in raw.get("findings") or []:
        for cve in re.findall(r"CVE-\d{4}-\d{4,7}", f"{f.get('reference', '')} {f.get('description', '')}"):
            add(f"{cve} (NVD)", f"https://nvd.nist.gov/vuln/detail/{cve}")
    return out[:40]


# ─── Markdown ───────────────────────────────────────────────────
def _md_text(s) -> str:
    """Neutralise raw HTML in Markdown viewers (< and > only: '&' stays readable)."""
    return ("" if s is None else str(s)).replace("<", "&lt;").replace(">", "&gt;").replace("\r", "")


def _md_code(s: str) -> str:
    s = str(s).replace("\r", " ").replace("\n", " ")
    if not s:
        return "n/a"
    fence = "`" * (max((len(m) for m in re.findall(r"`+", s)), default=0) + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def _md_cell(v, table=False) -> str:
    if isinstance(v, dict) and ("code" in v or "rich" in v):
        out = _md_code(v.get("code", v.get("rich", "")))
    elif isinstance(v, dict) and "link" in v:
        text, url = v["link"]
        url = _safe_url(url)
        out = f"[{_md_text(text)}]({url})" if url else _md_text(text)
    else:
        out = _md_text(v)
    if table:
        out = out.replace("|", "\\|").replace("\n", " ")
    return out or "n/a"


def _fence(body: str, lang: str) -> str:
    fence = "`" * max(3, max((len(m) for m in re.findall(r"`+", body)), default=0) + 1)
    return f"{fence}{lang}\n{body}\n{fence}\n"


def _hl_on(blk) -> bool:
    return len(blk) > 2 and blk[2] is True


def _md_hl(text: str) -> str:
    """Key phrases from utils.summary.highlight_spans: IOCs as `code`, everything else **bold**; the rest escaped."""
    out, last = [], 0
    for s, e, kind in highlight_spans(text):
        out.append(_md_text(text[last:s]))
        out.append(_md_code(text[s:e]) if kind == "ioc" else f"**{_md_text(text[s:e])}**")
        last = e
    out.append(_md_text(text[last:]))
    return "".join(out)


def render_markdown(blocks: list) -> str:
    out = []
    for blk in blocks:
        kind = blk[0]
        if kind == "title":
            out.append(f"# {_md_text(blk[1])}\n")
            if blk[3]:
                out.append(" · ".join(f"**{_md_text(k)}:** {_md_text(v)}" for k, v in blk[3]) + "\n")
        elif kind in ("h2", "h3"):
            out.append(f"{'#' * int(kind[1])} {_md_text(blk[1])}\n")
        elif kind == "lead":
            out.append(f"> {_md_hl(blk[1])}\n")
        elif kind in ("p", "note"):
            out.append((f"_{_md_text(blk[1])}_" if kind == "note" else (_md_hl(blk[1]) if _hl_on(blk) else _md_text(blk[1]))) + "\n")
        elif kind == "toc":
            out.append("**Contents**\n")
            out.extend(f"{i}. [{_md_text(t)}](#{a})" for i, (a, t) in enumerate(blk[1], 1))
            out.append("")
        elif kind == "callout":
            out.append(f"> **{_md_text(blk[1])}:** {_md_text(blk[2])}\n")
        elif kind == "story":
            for sec in blk[1]:
                out.append(f"### {_md_text(sec['title'])}\n")
                parts = []
                for s in sec["sentences"]:
                    t = _md_hl(s["text"])
                    parts.append(f"_{t}_" if s.get("certainty") == "inferred" else t)
                out.append(" ".join(parts) + "\n")
            out.append("_Plain sentences are observed in the data; italic ones are rule-based inferences; \"could not be determined\" marks gaps._\n")
        elif kind == "xdetails":
            out.append("### Show details\n")
            for blkd in blk[1]["blocks"]:
                lines = _block_lines(blkd)
                if not lines:
                    continue
                out.append(f"#### {_md_text(blkd['title'])}\n")
                out.extend(f"- {'**' + _md_text(lab) + ':** ' if lab else ''}{_md_text(txt)}" for lab, txt in lines)
                out.append("")
            nd = [c["question"] for c in blk[1].get("coverage", []) if c["answered_by"].startswith("Not determined")]
            if nd:
                out.append(f"_Not determined from this data: {_md_text('; '.join(nd))}_\n")
        elif kind == "kv":
            out.extend(f"- **{_md_text(k)}:** {_md_cell(v)}" for k, v in blk[1] if v not in ("", None) and v != {"code": ""})
            out.append("")
        elif kind == "table":
            heads, rows = blk[1], blk[2]
            out.append("| " + " | ".join(_md_text(h) for h in heads) + " |")
            out.append("|" + "|".join("---" for _ in heads) + "|")
            out.extend("| " + " | ".join(_md_cell(c, table=True) for c in row) + " |" for row in rows)
            out.append("")
        elif kind == "list":
            out.extend(f"- {_md_hl(i) if _hl_on(blk) else _md_text(i)}" for i in blk[1])
            out.append("")
        elif kind == "checklist":
            for prio, items in blk[1]:
                if items:
                    out.append(f"**{_md_text(prio)}**\n")
                    out.extend(f"- [ ] {_md_text(i)}" for i in items)
                    out.append("")
        elif kind == "finding":
            _, name, sev, desc, evidence, rec, fp = blk
            out.append(f"#### {_md_text(name)}\n")
            if desc:
                out.append(_md_text(desc) + "\n")
            if evidence:
                out.append("Evidence:\n")
                out.extend(f"- {_md_code(e)}" for e in evidence)
                out.append("")
            for k, v in (("Recommendation", rec), ("False positives", fp)):
                if v:
                    out.append(f"- **{k}:** {_md_text(v)}")
            out.append("")
        elif kind == "figure":
            if blk[2]:
                out.append(f"_{_md_text(blk[3])} (Mermaid: renders on GitHub, GitLab, Obsidian; the HTML version embeds the SVG)_\n")
                out.append(_fence(blk[2], "mermaid"))
        elif kind == "links":
            out.extend(f"- [{_md_text(lbl)}]({url})" for lbl, url in blk[1] if _safe_url(url))
            out.append("")
        elif kind == "code":
            out.append(_fence(blk[2].rstrip("\n"), blk[1]))
        elif kind == "hr":
            out.append("---\n")
    return "\n".join(out).rstrip() + "\n"


# ─── HTML (dark on screen, light when printed / saved as PDF) ────
HTML_STYLE = """
:root{--bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--code-bg:#11161d;--border:#30363d;--text:#e6edf3;--text2:#b7c0ca;--text3:#8b949e;
 --accent:#58a6ff;--sev-critical:#ff7b72;--sev-high:#ffa657;--sev-medium:#e3b341;--sev-low:#a5c4e6;--sev-benign:#56d364;
 --c-ip:#56d4dd;--c-domain:#79c0ff;--c-hash:#d2a8ff;--c-mitre:#4fd1c5;--c-cmd:#e3b341;--c-secret:#8b949e;--mark-bg:rgba(227,179,65,.28);
 --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue","Noto Sans",Arial,sans-serif;
 --mono:ui-monospace,"Cascadia Code","SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
 --fs-xs:12px;--fs-sm:13px;--fs-base:15px;--fs-md:17px;--fs-lg:20px;--fs-xl:26px}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:var(--fs-base)/1.65 var(--sans)}
main{max-width:960px;margin:0 auto;padding:36px 24px 56px}h1{font-size:var(--fs-xl);margin:0 0 12px;line-height:1.25}
h2{font-size:var(--fs-lg);margin:36px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--border);scroll-margin-top:16px}
h3{font-size:var(--fs-md);margin:22px 0 8px}h4{font-size:var(--fs-base);margin:16px 0 6px}p{margin:8px 0 12px;max-width:75ch}
ul{margin:8px 0 14px;padding-left:22px;max-width:80ch}li{margin-bottom:4px}a{color:var(--accent)}
.lead{font-size:var(--fs-md);font-weight:600;line-height:1.5}
.verdict{display:inline-block;padding:3px 12px;border-radius:14px;font-weight:800;font-size:var(--fs-xs);letter-spacing:.06em;border:2px solid var(--text3);color:var(--text3)}
.verdict.MALICIOUS{border-color:var(--sev-critical);color:var(--sev-critical)}.verdict.SUSPICIOUS{border-color:var(--sev-medium);color:var(--sev-medium)}.verdict.BENIGN{border-color:var(--sev-benign);color:var(--sev-benign)}
.facts{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px;margin:14px 0}
.fact{border:1px solid var(--border);border-radius:8px;padding:10px 12px;background:var(--surface)}.fact b{display:block;font-size:var(--fs-lg);font-variant-numeric:tabular-nums}
.fact span{font-size:var(--fs-xs);color:var(--text3);text-transform:uppercase;letter-spacing:.05em;font-weight:700}
.toc{border:1px solid var(--border);border-radius:8px;padding:12px 18px;background:var(--surface)}.toc ol{margin:6px 0;padding-left:20px;columns:2}
.callout{border-left:4px solid var(--accent);background:var(--surface);padding:12px 16px;border-radius:0 8px 8px 0;margin:16px 0;max-width:80ch}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:8px 0 14px}dt{color:var(--text3);font-weight:600}dd{margin:0;min-width:0;overflow-wrap:anywhere}
table{width:100%;border-collapse:collapse;margin:8px 0 16px;font-size:var(--fs-sm)}th,td{border:1px solid var(--border);padding:8px 10px;text-align:left;vertical-align:top;overflow-wrap:break-word;line-height:1.5}
th{background:var(--surface);font-weight:650}code{font-family:var(--mono);font-size:.92em;background:var(--code-bg);padding:1px 5px;border-radius:4px;overflow-wrap:anywhere}
pre{background:var(--code-bg);border:1px solid var(--border);border-radius:6px;padding:14px;overflow:auto;font:var(--fs-sm)/1.55 var(--mono);white-space:pre;max-width:100%}
figure{margin:14px 0 20px;padding:12px;border:1px solid var(--border);border-radius:8px;background:#fff}figure svg{display:block;margin:0 auto}
figcaption{font-size:var(--fs-xs);color:#57606a;margin-top:6px;text-align:center}
.finding{border:1px solid var(--border);border-left:4px solid var(--text3);border-radius:6px;padding:10px 14px;margin:10px 0}
.finding.CRITICAL{border-left-color:var(--sev-critical)}.finding.HIGH{border-left-color:var(--sev-high)}.finding.MEDIUM{border-left-color:var(--sev-medium)}.finding.LOW{border-left-color:var(--sev-low)}
.finding h4{margin:2px 0 6px}.ev{margin:6px 0;font-size:var(--fs-sm);color:var(--text2)}
.logline{display:block;margin-top:4px;padding:6px 10px;background:var(--code-bg);border:1px solid var(--border);border-radius:6px;white-space:pre-wrap;overflow-wrap:anywhere;color:var(--text2)}
.checklist{list-style:none;padding-left:4px}.checklist li::before{content:'\\2610';margin-right:8px;color:var(--text3)}
.note{color:var(--text3);font-size:var(--fs-sm);font-style:italic}
.story{max-width:var(--measure)}.st-label{font-size:var(--fs-sm);text-transform:uppercase;letter-spacing:.05em;color:var(--text3);margin:14px 0 4px}
.st-inferred{font-style:italic}.st-unknown{color:var(--text3)}
.xdet{border:1px solid var(--border);border-radius:8px;padding:10px 14px;margin:12px 0;background:var(--surface)}
.xdet>summary{cursor:pointer;font-weight:650}.xdet h4{margin:14px 0 6px}.xdet-list{margin:4px 0 10px}
.xbadge{display:inline-block;font-size:var(--fs-xs);font-weight:700;border-radius:10px;padding:0 8px;border:1px solid var(--text3);color:var(--text3)}
.xbadge.observed{color:var(--sev-critical);border-color:var(--sev-critical)}.xbadge.possible{color:var(--sev-medium);border-color:var(--sev-medium)}
.hl{font-weight:600;border-radius:4px}.hl-ip,.hl-url,.hl-domain,.hl-hash,.hl-mitre,.hl-cve,.hl-cmd,.hl-secret{font-family:var(--mono);font-size:max(12px,.92em);overflow-wrap:anywhere}
.hl-ip{color:var(--c-ip)}.hl-domain{color:var(--c-domain)}.hl-url{color:var(--c-domain);text-decoration:underline dotted;text-underline-offset:3px}
.hl-hash{color:var(--c-hash)}.hl-mitre,.hl-cve{color:var(--c-mitre);border:1px solid var(--c-mitre);padding:0 5px}
.hl-cmd{color:var(--c-cmd);background:var(--code-bg);padding:0 4px}
.hl-secret{color:var(--c-secret);font-weight:400}.hl-num{font-weight:700}.hl-term{font-weight:650;border-bottom:2px solid var(--sev-medium);border-radius:0}
.hl-urgent,.hl-sev-critical{color:var(--sev-critical);font-weight:700}.hl-sev-high{color:var(--sev-high)}.hl-sev-medium{color:var(--sev-medium)}
.hl-sev-low{color:var(--sev-low)}.hl-sev-benign{color:var(--sev-benign)}mark.hl-match{background:var(--mark-bg);color:var(--text);border-radius:3px;padding:0 2px;font-weight:600}
@media print{:root{--bg:#ffffff;--surface:#f6f8fa;--surface2:#eef1f4;--code-bg:#f3f5f7;--border:#c9ccd1;--text:#1f2328;--text2:#3d444d;--text3:#57606a;--accent:#0860c4;
 --sev-critical:#c4161c;--sev-high:#a84300;--sev-medium:#845a00;--sev-low:#3d5f86;--sev-benign:#17702f;
 --c-ip:#0b6a7d;--c-domain:#0550ae;--c-hash:#7039c8;--c-mitre:#0f6b62;--c-cmd:#7a4c00;--c-secret:#57606a;--mark-bg:#fff1c2}
 body{font-size:11pt}main{max-width:none;padding:0}h2,h3,h4{break-after:avoid}table,pre,dl,figure,.finding,.callout,.facts{break-inside:avoid}
 tr{break-inside:avoid}.page-break{break-before:page}pre{white-space:pre-wrap}a{text-decoration:none}.toc ol{columns:2}}
@page{margin:15mm}
"""


def _h(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _html_cell(v) -> str:
    if isinstance(v, dict) and "rich" in v:
        return rich_html(v["rich"]) if v["rich"] else "n/a"
    if isinstance(v, dict) and "code" in v:
        return f"<code>{_h(v['code'])}</code>" if v["code"] else "n/a"
    if isinstance(v, dict) and "link" in v:
        text, url = v["link"]
        url = _safe_url(url)
        return f'<a href="{_h(url)}" rel="noopener noreferrer">{_h(text)}</a>' if url else _h(text)
    return _h(v) if v not in ("", None) else "n/a"


def _h_hl(text: str) -> str:
    """Summary phrases (terms, urgent wording, counts) + technical values, via the shared escape-first highlighter."""
    phrases = [{"text": text[s:e], "kind": k} for s, e, k in highlight_spans(text) if k != "ioc"]
    return rich_html(text, phrases)


def _is_our_svg(svg: str) -> bool:
    """Only SVG produced by utils.diagrams is inlined (it escapes all text); anything else is dropped."""
    return svg.startswith('<svg xmlns="http://www.w3.org/2000/svg"') and "<script" not in svg.lower() and "foreignobject" not in svg.lower()


def render_html(blocks: list) -> str:
    title = next((blk[1] for blk in blocks if blk[0] == "title"), "PhishyLens Write-up")
    body = []
    for blk in blocks:
        kind = blk[0]
        if kind == "title":
            body.append(f'<h1>{_h(blk[1])}</h1><p><span class="verdict {_h(blk[2])}">{_h(blk[2])}</span></p>')
            if blk[3]:
                body.append('<div class="facts">' + "".join(f"<div class=\"fact\"><span>{_h(k)}</span><b>{_h(v)}</b></div>" for k, v in blk[3]) + "</div>")
        elif kind == "h2":
            body.append(f'<h2 id="{_h(slug(blk[1]))}">{_h(blk[1])}</h2>')
        elif kind == "h3":
            body.append(f"<h3>{_h(blk[1])}</h3>")
        elif kind == "lead":
            body.append(f'<p class="lead">{_h_hl(blk[1])}</p>')
        elif kind == "p":
            body.append(f"<p>{_h_hl(blk[1]) if _hl_on(blk) else _h(blk[1])}</p>")
        elif kind == "note":
            body.append(f'<p class="note">{_h(blk[1])}</p>')
        elif kind == "toc":
            body.append('<nav class="toc" aria-label="Contents"><strong>Contents</strong><ol>' +
                        "".join(f'<li><a href="#{_h(a)}">{_h(t)}</a></li>' for a, t in blk[1]) + "</ol></nav>")
        elif kind == "callout":
            body.append(f'<aside class="callout"><strong>{_h(blk[1])}</strong><br>{_h(blk[2])}</aside>')
        elif kind == "story":
            for sec in blk[1]:
                sents = " ".join(f'<span class="st st-{_h(s.get("certainty", "observed"))}">{_h_hl(s["text"])}</span>' for s in sec["sentences"])
                body.append(f'<h3 class="st-label">{_h(sec["title"])}</h3><p class="story">{sents}</p>')
            body.append('<p class="note">Plain sentences are observed in the data; italic ones are rule-based inferences; '
                        'muted ones mark what could not be determined.</p>')
        elif kind == "xdetails":
            parts = ['<details class="xdet" open><summary>Show details</summary>']
            for blkd in blk[1]["blocks"]:
                lines = _block_lines(blkd)
                if not lines:
                    continue
                parts.append(f'<h4>{_h(blkd["title"])}</h4><ul class="xdet-list">')
                for lab, txt in lines:
                    badge = f'<span class="xbadge {_h(lab.lower().replace(" ", "-"))}">{_h(lab)}</span> ' if lab in ("Observed", "Possible", "Not evidenced") else \
                            (f"<strong>{_h(lab)}:</strong> " if lab else "")
                    parts.append(f"<li>{badge}{rich_html(txt)}</li>")
                parts.append("</ul>")
            nd = [c["question"] for c in blk[1].get("coverage", []) if c["answered_by"].startswith("Not determined")]
            if nd:
                parts.append(f'<p class="note">Not determined from this data: {_h("; ".join(nd))}</p>')
            parts.append("</details>")
            body.append("".join(parts))
        elif kind == "kv":
            rows = "".join(f"<dt>{_h(k)}</dt><dd>{_html_cell(v)}</dd>" for k, v in blk[1] if v not in ("", None) and v != {"code": ""})
            body.append(f"<dl>{rows}</dl>")
        elif kind == "table":
            head = "".join(f"<th>{_h(x)}</th>" for x in blk[1])
            rows = "".join("<tr>" + "".join(f"<td>{_html_cell(c)}</td>" for c in row) + "</tr>" for row in blk[2])
            body.append(f"<table><thead><tr>{head}</tr></thead><tbody>{rows}</tbody></table>")
        elif kind == "list":
            body.append("<ul>" + "".join(f"<li>{_h_hl(i) if _hl_on(blk) else _h(i)}</li>" for i in blk[1]) + "</ul>")
        elif kind == "checklist":
            for prio, items in blk[1]:
                if items:
                    body.append(f"<h3>{_h(prio)}</h3><ul class=\"checklist\">" + "".join(f"<li>{_h(i)}</li>" for i in items) + "</ul>")
        elif kind == "finding":
            _, name, sev, desc, evidence, rec, fp = blk
            ev = ("<ul>" + "".join(f'<li class="ev">{evidence_html({"name": name, "evidence": e})}</li>' for e in evidence) + "</ul>") if evidence else ""
            extra = "".join(f"<p><strong>{k}:</strong> {rich_html(v)}</p>" for k, v in (("Recommendation", rec), ("False positives", fp)) if v)
            body.append(f'<div class="finding {_h(sev)}"><h4>{_h(name)}</h4>{f"<p>{rich_html(desc)}</p>" if desc else ""}{ev}{extra}</div>')
        elif kind == "figure":
            if blk[1] and _is_our_svg(blk[1]):
                body.append(f"<figure>{blk[1]}<figcaption>{_h(blk[3])}</figcaption></figure>")
        elif kind == "links":
            body.append("<ul>" + "".join(f'<li><a href="{_h(u)}" rel="noopener noreferrer">{_h(l)}</a></li>' for l, u in blk[1] if _safe_url(u)) + "</ul>")
        elif kind == "code":
            body.append(f'<pre><code class="language-{_h(blk[1])}">{_h(blk[2])}</code></pre>')
        elif kind == "pagebreak":
            body.append('<div class="page-break"></div>')
        elif kind == "hr":
            body.append("<hr>")
    return ("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
            f"<title>{_h(title)}</title>\n<style>{HTML_STYLE}</style>\n</head>\n<body>\n<main>\n"
            + "\n".join(body) + "\n</main>\n</body>\n</html>\n")


def build_report(result: dict, fmt: str = "md", defang: bool = True, include_sigma: bool = True, app_version: str = "") -> str:
    blocks = build_blocks(result, defang=defang, include_sigma=include_sigma, app_version=app_version)
    return render_html(blocks) if fmt == "html" else render_markdown(blocks)


def report_filename(result: dict, fmt: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9_-]+", "", str((result or {}).get("scan_id") or (result or {}).get("mode") or "report"))[:40] or "report"
    return f"phishylens_writeup_{stem}.{'html' if fmt == 'html' else 'md'}"
