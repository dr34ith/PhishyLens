"""
PhishyLens: safe auto-highlighter for exported HTML (mirror of static/highlight.js).

The rules live ONCE, as JSON between /*RULES-JSON-START*/ and /*RULES-JSON-END*/ in static/highlight.js; this module
loads that block so the UI and the write-up highlight the same values. Output is escape-first: every slice of input
text is html.escape()d and matches are only wrapped in <span class="hl ..."> / <mark class="hl-match">.
"""
import html
import json
import os
import re
from functools import lru_cache

JS_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "highlight.js")
SEV_CLASS = {"CRITICAL": "hl-sev-critical", "HIGH": "hl-sev-high", "MEDIUM": "hl-sev-medium", "LOW": "hl-sev-low",
             "MALICIOUS": "hl-sev-critical", "SUSPICIOUS": "hl-sev-medium", "BENIGN": "hl-sev-benign"}
PHRASE_CLASS = {"term": "hl-term", "urgent": "hl-urgent", "num": "hl-num"}


@lru_cache(maxsize=1)
def load_config() -> dict:
    src = open(JS_PATH, encoding="utf-8").read()
    block = src.split("/*RULES-JSON-START*/", 1)[1].split("/*RULES-JSON-END*/", 1)[0]
    cfg = json.loads(block)
    for r in cfg["rules"]:
        if r.get("pattern"):
            r["rx"] = re.compile(r["pattern"], re.I if "i" in r.get("flags", "") else 0)
    return cfg


def spans(text: str, phrases=None) -> list:
    """Non-overlapping (start, end, cls): rule order is priority, then longer match, then position (same as JS)."""
    found = []
    for prio, r in enumerate(load_config()["rules"]):
        if r["cls"] == "@phrases":
            for p in phrases or []:
                cls, t = PHRASE_CLASS.get(p.get("kind")), p.get("text")
                if not cls or not t:
                    continue
                i = text.find(t)
                while i != -1:
                    found.append((i, i + len(t), cls, prio))
                    i = text.find(t, i + len(t))
            continue
        for m in r["rx"].finditer(text):
            if not m.group(0):
                continue
            s, e = m.start(), m.end()
            while s < e and text[s].isspace():
                s += 1
            cls = SEV_CLASS.get(m.group(0).upper()) if r["cls"] == "@sev" else r["cls"]
            found.append((s, e, cls, prio))
    found.sort(key=lambda f: (f[3], -(f[1] - f[0]), f[0]))
    taken = []
    for f in found:
        if all(f[1] <= t[0] or f[0] >= t[1] for t in taken):
            taken.append(f)
    return [(s, e, c) for s, e, c, _ in sorted(taken)]


def rich_html(text, phrases=None) -> str:
    t = "" if text is None else str(text)
    out, last = [], 0
    for s, e, cls in spans(t, phrases):
        out.append(html.escape(t[last:s]))
        out.append(f'<span class="hl {cls}">{html.escape(t[s:e])}</span>')
        last = e
    out.append(html.escape(t[last:]))
    return "".join(out)


def mark_log_line(line, attack_type: str = "") -> str:
    t = "" if line is None else str(line)
    pat = load_config()["attack_marks"].get(re.sub(r" \(inside encoded payload\)$", "", attack_type or ""))
    if not pat:
        return html.escape(t)
    out, last = [], 0
    for m in re.finditer(pat, t, re.I):
        if not m.group(0):
            continue
        out.append(html.escape(t[last:m.start()]))
        out.append(f'<mark class="hl-match">{html.escape(m.group(0))}</mark>')
        last = m.end()
    out.append(html.escape(t[last:]))
    return "".join(out)


def evidence_html(finding: dict) -> str:
    ev = str((finding or {}).get("evidence") or "")
    m = re.match(r"^(\d+ hit\(s\); first at line \d+: )([\s\S]*)$", ev)
    if m:
        return f'<span class="ev-prefix">{rich_html(m.group(1))}</span><code class="logline">{mark_log_line(m.group(2), finding.get("name", ""))}</code>'
    return rich_html(ev)


def classify(value: str) -> str:
    """The single highlight class covering the whole value (for diagram labels), or ''."""
    v = str(value or "")
    for s, e, cls in spans(v):
        if s == 0 and e == len(v):
            return cls
    return ""
