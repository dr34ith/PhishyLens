"""
PhishyLens: detailed, non-repetitive Executive Summary details (exec_summary["details"]).

    build_details(result, defang=False) -> {"version", "blocks": [...], "coverage": [...], "glossary": [...], "word_budget"}

Rules (see tests/test_summary_details.py):
  * Only fields already in the result. No network calls, deterministic, never guessed.
  * Attacker-controlled strings are sanitized (control/bidi chars stripped, 200-char cap, secrets masked).
  * Every item carries a "ref" (finding index, log line, raw ts or a field path) that exists in the result.
  * Single placement: each fact is OWNED by one block (item["facts"]); other blocks point to it ("see step 3").
    Nothing restates a sentence of the short summary (headline, bullets, do_now).
  * Generated sentences stay under 20 words; at most 5 items per block are visible by default and the visible
    total stays under WORD_BUDGET words (the rest sit behind "+N more").
  * Status vocabulary: Observed / Possible / Not evidenced. Never "confirmed", "compromised" or "breach".
"""
import json
import os
import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from functools import lru_cache

from utils.artifacts import (SEV_RANK, ip_inventory, ip_scope, mask_secrets, parse_cleartext, parse_host_port, parse_scan,
                             parse_suspicious_port, prioritized_actions, real_findings, timeline_events)
from utils.defang import defang_text

VERSION = 1
MAX_VISIBLE = 5
MAX_STORY = 8
WORD_BUDGET = 300
TEXT_LIMIT = 200
NOT_DETERMINED = "Not determined from this data"
GENERAL_GUIDANCE = "General guidance, not derived from your data"
STATUSES = ("Observed", "Possible", "Not evidenced")
REPUTATION_STATES = ("Not checked (private/reserved range)", "No reports found", "Flagged by", "Unavailable (rate limit/error)",
                     "Not configured")
STAGE_ORDER = ["Reconnaissance", "Delivery", "Exploitation", "Persistence", "Command & Control", "Actions on Objectives"]
BLOCK_ORDER = ["overview", "actors_and_targets", "assessment", "attack_story", "confidence_and_limits", "next_steps", "mode_extras"]
BLOCK_TITLES = {"overview": "Overview", "actors_and_targets": "Actors and targets", "assessment": "Assessment",
                "attack_story": "Attack story", "confidence_and_limits": "Confidence and limits", "next_steps": "Next steps",
                "mode_extras": "More detail"}
STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
TOOLS_RE = re.compile(r"\b(sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|ffuf|hydra|havij|zgrab|nuclei|metasploit|curl|wget)\b", re.I)
PATH_RE = re.compile(r"(/[\w.~%-]+(?:/[\w.~%-]+)*)")
URL_RE = re.compile(r"\b(?:https?|hxxps?)://[^\s'\"<>)]+", re.I)


# ─── static data ────────────────────────────────────────────────
@lru_cache(maxsize=1)
def glossary() -> dict:
    with open(os.path.join(STATIC, "glossary.json"), encoding="utf-8") as fh:
        return {k: v for k, v in json.load(fh).items() if not k.startswith("_")}


@lru_cache(maxsize=1)
def playbooks() -> dict:
    with open(os.path.join(STATIC, "playbooks.json"), encoding="utf-8") as fh:
        return {k: v for k, v in json.load(fh).items() if not k.startswith("_")}


# ─── sanitising ─────────────────────────────────────────────────
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩؜﻿]")


def clean(value, limit: int = TEXT_LIMIT) -> str:
    """Strip control / bidi / zero-width characters, collapse whitespace, mask secrets, cap length."""
    s = _CTRL.sub("", "" if value is None else str(value))
    s = re.sub(r"\s+", " ", s).strip()
    s = mask_secrets(s)
    return s if len(s) <= limit else s[:limit - 1].rstrip() + "…"


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(s).lower()).strip()


def _join(items, n=3) -> str:
    items = [str(i) for i in items if i]
    if not items:
        return ""
    if len(items) > n:
        return ", ".join(items[:n]) + f" and {len(items) - n} more"
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


# ─── registry: single placement ─────────────────────────────────
class Registry:
    def __init__(self, summary: dict):
        self.owner = {}
        self.summary_sentences = set()
        for s in [summary.get("headline", ""), *summary.get("what_happened", []), summary.get("why_it_matters", "")]:
            for sent in re.split(r"(?<=[.!?])\s+", s or ""):
                if _norm(sent):
                    self.summary_sentences.add(_norm(sent))
        self.summary_actions = {_norm(a.get("action", "")) for a in summary.get("do_now", []) if a.get("action")}

    def claim(self, block: str, key) -> bool:
        """True only the first time a fact is placed: anywhere else (same block included) it is a repeat."""
        key = tuple(key) if isinstance(key, list) else key
        if key in self.owner:
            return False
        self.owner[key] = block
        return True

    def owned(self, key):
        return self.owner.get(key)


# ─── helpers over the result ────────────────────────────────────
def _findings(result):
    return [f if isinstance(f, dict) else {} for f in (result.get("findings") or [])]


def _idx(result, name, start=0):
    for i, f in enumerate(_findings(result)):
        if i >= start and f.get("name") == name:
            return i
    return None


def _tech_ids(result, name):
    return [t["id"] for t in (result.get("mitre") or {}).get("techniques") or [] if name in (t.get("evidence_findings") or [])]


def _stage_of(result, names):
    """Furthest kill-chain stage whose evidence includes any of the findings (how far this step got)."""
    found = ""
    for st in (result.get("kill_chain") or {}).get("stages") or []:
        if st.get("hit") and any(n in (st.get("evidence") or []) for n in names):
            found = st.get("name", "")
    return found


def _hits_by_type(result):
    out = {}
    for h in (result.get("log_stats") or {}).get("sample_hits") or []:
        out.setdefault(h.get("type", ""), []).append(h)
    return out


def _ts_parse(ts: str):
    """(datetime, format_key) or (None, None). Syslog timestamps have no year → not usable for durations."""
    t = (ts or "").strip()
    for fmt, key in (("%d/%b/%Y:%H:%M:%S %z", "clf"), ("%Y-%m-%dT%H:%M:%S%z", "iso"), ("%Y-%m-%dT%H:%M:%S.%f%z", "iso")):
        try:
            return datetime.strptime(t.replace("Z", "+0000"), fmt), key
        except ValueError:
            pass
    try:
        if re.search(r"\d{4}", t) and "," in t:
            return parsedate_to_datetime(t), "rfc2822"
    except Exception:
        pass
    return None, None


def _duration(start_ts, end_ts, all_ts):
    parsed = [_ts_parse(t) for t in all_ts]
    if not parsed or any(p[0] is None for p in parsed) or len({p[1] for p in parsed}) != 1:
        return ""
    if len({p[0].utcoffset() for p in parsed}) != 1:
        return ""
    secs = int((_ts_parse(end_ts)[0] - _ts_parse(start_ts)[0]).total_seconds())
    if secs < 0:
        return ""
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return (f"{h}h " if h else "") + (f"{m}m " if m or h else "") + f"{s}s"


def reputation_state(result: dict, ip: str) -> str:
    """Exactly one of REPUTATION_STATES (the 'Flagged by …' state carries sources and counts). Never implies 'clean'."""
    if ip_scope(ip) in ("internal", "reserved"):
        return "Not checked (private/reserved range)"
    srcs = None
    if result.get("mode") == "ip" and str(result.get("input", "")).strip() == ip:
        srcs = result.get("intel_sources") or {}
    if srcs is not None:
        avail = [s for s in srcs.values() if isinstance(s, dict) and s.get("available")]
        flagged = [s for s in avail if s.get("flagged")]
        if flagged:
            parts = []
            for s in flagged:
                cnt = (f" {s['malicious_engines']}/{s['total_engines']}" if s.get("total_engines") else
                       f" {s['abuse_score']}%" if s.get("abuse_score") is not None else "")
                parts.append(f"{s.get('source')}{cnt}")
            return "Flagged by " + ", ".join(parts)
        if avail:
            return "No reports found"
        return "Unavailable (rate limit/error)" if any(isinstance(s, dict) and s.get("error") for s in srcs.values()) else "Not configured"
    for rep in (result.get("enrichment") or {}).get("ips") or []:
        if rep.get("indicator") != ip:
            continue
        if rep.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
            parts = []
            if rep.get("abuseipdb_score") is not None:
                parts.append(f"AbuseIPDB {rep['abuseipdb_score']}%")
            if rep.get("vt_total"):
                parts.append(f"VirusTotal {rep.get('vt_malicious', 0)}/{rep['vt_total']}")
            for n in rep.get("findings") or []:
                for src in ("AlienVault OTX", "ThreatFox"):
                    if n.startswith(src) and src not in parts:
                        parts.append(src)
            return "Flagged by " + (", ".join(parts) or "threat intelligence")
        if rep.get("reputation_score") is not None:
            return "No reports found"
        return "Not configured" if "Reputation Not Checked" in (rep.get("findings") or []) else "Unavailable (rate limit/error)"
    return "Not configured"


# ─── item / block construction ──────────────────────────────────
def _item(text, ref, facts=(), **extra):
    return {"text": text, "ref": ref, "facts": [list(f) if isinstance(f, tuple) else f for f in facts], **extra}


def _block(key, items, **extra):
    return {"key": key, "title": BLOCK_TITLES[key], "items": items, "visible": min(MAX_VISIBLE, len(items)), **extra}


# ── D) attack story (built first: owns findings, lines and technique ids) ──
_WHAT = {
    "SQL Injection": ("{ip} sent an SQL injection request to {path}.", "It can read or change database data."),
    "Cross-Site Scripting (XSS)": ("{ip} sent an XSS payload to {path}.", "It can run script in other users' browsers."),
    "Path Traversal / LFI": ("{ip} tried a path traversal read via {path}.", "It can expose files the web server should not serve."),
    "Command Injection": ("{ip} tried to run shell commands through {path}.", "It can give the attacker control of the server."),
    "Web Shell / Sensitive File Probe": ("{ip} probed for a sensitive file at {path}.", "Exposed secrets or a web shell give direct access."),
    "Log4Shell / JNDI Injection": ("{ip} sent a JNDI lookup string.", "Vulnerable Java apps can load remote code."),
    "Server-Side Request Forgery": ("{ip} asked the server to fetch an internal address.", "It can reach internal services."),
    "Directory / Vulnerability Scanning": ("{ip} requested many missing pages.", "It maps the site before targeted attacks."),
}


def _what_for(result, group, mode):
    """(what, why) sentences for a story step; group = {"names": [...], "ip":..., "evidence": [...], ...}."""
    names, ip = group["names"], group.get("ip") or "A source"
    first = names[0]
    F = {f.get("name"): f for f in _findings(result)}
    ev = " ".join(group.get("evidence") or [])
    if first in _WHAT:
        path = (PATH_RE.search(ev) or [None])[0] if PATH_RE.search(ev) else "the web app"
        what, why = _WHAT[first]
        extra = [n for n in names[1:] if n != first]
        tools = sorted({t.lower() for t in TOOLS_RE.findall(ev)})
        what = what.format(ip=ip, path=clean(path.split("?")[0], 60))
        if tools and "Scanner / Attack-Tool User-Agent" in names:
            what = what[:-1] + f" using {_join(tools, 2)}."
        return what, why
    if first == "Scanner / Attack-Tool User-Agent":
        tools = sorted({t.lower() for t in TOOLS_RE.findall(ev)}) or ["an attack tool"]
        return f"{ip} sent requests with the {_join(tools, 2)} user agent.", "Automated tools usually come before targeted attacks."
    if first == "SSH / Login Brute Force":
        m = re.search(r": (\d+) failed logins(?: \(\d+ distinct user\(s\): ([^)]*)\))?", F.get(first, {}).get("evidence", ""))
        n = m.group(1) if m else "several"
        return f"{ip} started a brute force run with {n} failed logins.", "Repeated guessing can break weak passwords."
    if first == "Successful Login After Failures":
        m = re.search(r"Accepted login for '([^']*)'", F.get(first, {}).get("evidence", ""))
        user = clean(m.group(1), 40) if m else "an account"
        return f"'{user}' logged in from {ip} after the failed attempts.", "The password guess may have worked."
    if any(n.startswith("PowerShell") or n in ("AMSI / Defender Tampering", "Reflection / In-Memory Loader", "LOLBin Proxy Execution") for n in names):
        feats = []
        for n, label in (("Encoded Command", "an encoded command"), ("Execution Policy Bypass", "a policy bypass"),
                         ("Hidden Window", "a hidden window"), ("Download Cradle", "a download cradle")):
            if any(n in x for x in names):
                feats.append(label)
        return f"{ip} ran encoded PowerShell with {_join(feats, 4) or 'suspicious options'}.", "Hidden PowerShell is a common way to run malware."
    if first == "TCP Port Scan Detected":
        p = parse_scan(F.get(first, {}).get("evidence", ""))
        if p:
            return f"{p[0]} sent SYN probes to {p[2]} ports on {p[1]}.", "A port scan maps services to attack next."
    if first == "Cleartext Credentials on the Wire":
        p = parse_cleartext(F.get(first, {}).get("evidence", ""))
        if p:
            return f"A {p[0]} login from {p[1]} to {p[2]} travelled in cleartext.", "Anyone on the path can reuse those credentials."
    if first == "Traffic to Suspicious Port":
        p = parse_suspicious_port(F.get(first, {}).get("evidence", ""))
        if p:
            return f"{p[0]} opened a connection to {p[1]} on port {p[2]}.", "That port is a common reverse shell default."
    if first.startswith("Risky Port Open:"):
        hosts = sorted({(parse_host_port(F.get(n, {}).get("evidence", "")) or ["?"])[0] for n in names})
        svcs = [re.sub(r"^Risky Port Open: \d+/", "", n) for n in names]
        return f"{_join(hosts, 2)} listens on {_plural(len(names), 'risky port')}, including {_join(svcs, 3)}.", "Each exposed service is a possible way in."
    if first.startswith("Vulnerable Service:") or first.startswith("NSE Finding:"):
        vulns = [re.sub(r"^(Vulnerable Service|NSE Finding): ", "", n) for n in names]
        return f"Service banners match known-vulnerable builds: {_join(vulns, 2)}.", "Public exploits exist for these versions."
    if first == "End-of-Life Operating System":
        return "The OS fingerprint points to an end-of-life release.", "It no longer receives security fixes."
    if first in ("SPF Authentication Failed", "DKIM Authentication Failed", "DMARC Authentication Failed") or re.match(r"^(SPF|DKIM|DMARC) Not Passing$", first):
        mechs = sorted({n.split(" ")[0] for n in names})
        return f"The receiving server recorded {_join(mechs)} results that did not pass.", "The sender identity cannot be trusted."
    if first == "Return-Path / From Mismatch":
        return "The envelope Return-Path uses a different domain than From.", "Bounces go somewhere other than the claimed sender."
    if first == "Reply-To Hijack":
        return "Replies are routed to a different domain than the sender.", "Answers would reach the attacker, not the brand."
    if first == "Display Name Brand Spoofing":
        return "The display name claims a brand the address does not belong to.", "Recipients trust the name they see."
    if first == "Link Text / Destination Mismatch":
        return "A link's visible text differs from where it really goes.", "Users click what they think is a safe site."
    if first in ("Double-Extension Attachment", "Risky Attachment Type"):
        return "The message carries an attachment with a risky file type.", "Opening it could run code on the computer."
    if first == "Urgency / Pressure Manipulation":
        return "The text pressures the reader to act quickly.", "Urgency stops people from checking the request."
    if first in ("Suspicious URL in Body", "Malicious URL in Body"):
        return "The body links to a suspicious address.", "The link is the likely trap."
    if first == "Suspicious Sender TLD":
        return "The sender domain uses a frequently abused top-level domain.", "Cheap domains are common in phishing."
    if first == "Shortened URL":
        return "The link starts at a URL shortener.", "It hides the real destination."
    if first == "Redirect Chain Detected":
        return "The address redirects before reaching its final page.", "Each hop can hide the real destination."
    if first == "Newly Registered Domain":
        return "The domain was registered very recently.", "New domains are common in phishing."
    if first == "Unencrypted Channel":
        return "The page is served without HTTPS.", "Anything typed on it can be read in transit."
    if first == "IP Address in URL":
        return "The address uses a raw IP instead of a domain.", "Legitimate sites rarely do this."
    if first == "Brand Impersonation":
        return "The address imitates a well-known brand.", "Lookalike names trick people into trusting the page."
    sev = F.get(first, {}).get("severity", "").title() or "Flagged"
    return f"{clean(first, 80)} was reported ({sev.lower()} severity).", ""


def _story_groups(result):
    """Ordered incident-like groups of findings. Logs: by (line, ip); network/email/url: by family and stage."""
    F = _findings(result)
    real = {f.get("name") for f in real_findings(result)}
    mode = result.get("mode", "")
    groups = []
    if mode == "logs" and result.get("log_stats"):
        ls = result["log_stats"]
        by_line = {}
        for h in ls.get("sample_hits") or []:
            if h.get("type") not in real and h.get("type", "").replace(" (inside encoded payload)", "") not in real and h.get("type") not in {f.get("name") for f in F}:
                continue
            key = (h.get("line") or 0, h.get("ip") or "")
            g = by_line.setdefault(key, {"names": [], "ip": h.get("ip") or "", "line": h.get("line"), "ts": h.get("ts", ""), "evidence": []})
            if h["type"] not in g["names"]:
                g["names"].append(h["type"])
            ev = clean(h.get("evidence", ""), 160)
            if ev and ev not in g["evidence"]:
                g["evidence"].append(ev)
        groups.extend(by_line.values())
        # behaviour findings carry no line: anchor them on their auth events
        auth = ls.get("auth_events") or []
        for name in ("SSH / Login Brute Force", "Successful Login After Failures"):
            i = _idx(result, name)
            if i is None:
                continue
            f = F[i]
            ip = (f.get("sources") or [""])[0]
            if name == "SSH / Login Brute Force":
                ev = next((a for a in auth if a.get("ip") == ip and a.get("result") == "failed"), None)
            else:
                ev = next((s for s in ls.get("login_after_failures") or [] if s.get("ip") == ip), None)
            groups.append({"names": [name], "ip": ip, "line": (ev or {}).get("line"), "ts": (ev or {}).get("ts", ""),
                           "evidence": [clean(f.get("evidence", ""), 160)], "finding": i})
        # PowerShell hits on the same line become one step
        groups.sort(key=lambda g: (g.get("line") or 10 ** 9))
        merged = []
        for g in groups:
            if merged and g.get("line") and merged[-1].get("line") == g.get("line") and merged[-1].get("ip") == g.get("ip"):
                merged[-1]["names"] += [n for n in g["names"] if n not in merged[-1]["names"]]
                merged[-1]["evidence"] += [e for e in g["evidence"] if e not in merged[-1]["evidence"]]
            else:
                merged.append(g)
        return merged
    # non-log modes: group by family, order by kill-chain stage then severity
    fam = {}
    for i, f in enumerate(F):
        n = f.get("name", "")
        if n not in real:
            continue
        key = ("Risky Port Open" if n.startswith("Risky Port Open:") else "Vulnerable" if n.startswith(("Vulnerable Service:", "NSE Finding:"))
               else "Auth" if re.match(r"^(SPF|DKIM|DMARC) ", n) else n)
        g = fam.setdefault(key, {"names": [], "evidence": [], "finding": i, "ip": ""})
        if n not in g["names"]:
            g["names"].append(n)
        ev = clean(f.get("evidence", ""), 160)
        if ev and ev not in g["evidence"]:
            g["evidence"].append(ev)
    groups = list(fam.values())
    groups.sort(key=lambda g: (STAGE_ORDER.index(_stage_of(result, g["names"])) if _stage_of(result, g["names"]) in STAGE_ORDER else 9,
                               -max(SEV_RANK.get(F[_idx(result, n)].get("severity"), 0) for n in g["names"])))
    return groups


def build_story(result, reg):
    items = []
    has_time = False
    for g in _story_groups(result):
        if len(items) >= MAX_STORY:
            break
        idxs = [i for i in (_idx(result, n) for n in g["names"]) if i is not None]
        if not idxs:                              # e.g. "(inside encoded payload)" hit whose finding name differs
            idxs = [i for i in (_idx(result, n.replace(" (inside encoded payload)", "")) for n in g["names"]) if i is not None]
        if g.get("line"):
            facts = [("line", g["line"])]                       # log steps are owned by their line
            if reg.owned(facts[0]):
                continue
            facts += [("finding", i) for i in idxs if not reg.owned(("finding", i))]
        else:
            facts = [("finding", i) for i in idxs]
            if any(reg.owned(f) for f in facts):
                continue
        techs = []
        for n in g["names"]:
            for t in _tech_ids(result, n):
                if t not in techs:
                    techs.append(t)
        new_techs = [t for t in techs if reg.claim("attack_story", ("tech", t))]
        for f in facts:
            reg.claim("attack_story", f)
        what, why = _what_for(result, g, result.get("mode", ""))
        when = clean(g.get("ts") or "", 60)
        has_time = has_time or bool(when)
        ref = ({"line": g["line"]} if g.get("line") else {"finding": idxs[0]} if idxs else {"field": "findings"})
        item = _item(what, ref, facts + [("tech", t) for t in new_techs], order=len(items) + 1, stage=_stage_of(result, g["names"]),
                     technique_ids=techs, evidence=clean("; ".join(g.get("evidence") or []), TEXT_LIMIT), why=why,
                     findings=idxs, line=g.get("line"))
        if when:
            item["when"] = when
        items.append(item)
    if not has_time:
        for it in items:
            it.pop("when", None)
    return _block("attack_story", items, ordered_by="time" if has_time else "kill-chain stage")


def _step_of(story, finding_idx=None, line=None):
    for it in story["items"]:
        if (finding_idx is not None and finding_idx in it.get("findings", [])) or (line is not None and it.get("line") == line):
            return it["order"]
    return None


# ── B) actors and targets ──
def build_actors_targets(result, reg):
    mode = result.get("mode", "")
    inv = ip_inventory(result)
    actors, targets = [], {"hosts": [], "accounts": [], "services": [], "paths": []}
    ls = result.get("log_stats") or {}
    hits = _hits_by_type(result)
    if mode == "logs":
        for t in ls.get("top_sources") or []:
            ip = t.get("ip")
            if not ip or not (t.get("attack_hits") or t.get("failed_logins")):
                continue
            ok = sum(1 for a in ls.get("auth_events") or [] if a.get("ip") == ip and a.get("result") == "accepted")
            ev = " ".join(h.get("evidence", "") for hs in hits.values() for h in hs if h.get("ip") == ip)
            tools = sorted({x.lower() for x in TOOLS_RE.findall(ev)})
            actors.append({"ip": ip, "role": (inv.get(ip, {}).get("roles") or ["observed host"])[0],
                           "counts": {"requests": t.get("requests", 0), "attack_hits": t.get("attack_hits", 0),
                                      "failed_logins": t.get("failed_logins", 0), "accepted_logins": ok},
                           "tools": tools, "attack_types": [clean(x, 60) for x in (t.get("attack_types") or [])][:5]})
        users = []
        for a in ls.get("auth_events") or []:
            u = clean(a.get("user", ""), 40)
            if u and u not in users:
                users.append(u)
        targets["accounts"] = users
        paths = []
        for typ, hs in hits.items():
            if typ not in _WHAT:                                # web attack types only (not user agents / PowerShell)
                continue
            for h in hs:
                m = PATH_RE.search(h.get("evidence", ""))
                if m:
                    p = clean(m.group(1).split("?")[0], 80)
                    if p not in paths and p != "/" and not re.fullmatch(r"/[\d.]+", p):
                        paths.append(p)
        targets["paths"] = paths
    elif mode == "network":
        for ip, e in inv.items():
            role = e["roles"][0]
            if role in ("scan source", "attacker", "destination"):
                scan = next((parse_scan(f.get("evidence", "")) for f in _findings(result) if f.get("name") == "TCP Port Scan Detected"
                             and parse_scan(f.get("evidence", "")) and parse_scan(f.get("evidence", ""))[0] == ip), None)
                pk = dict((t[0], t[1]) for t in ((result.get("network_stats") or {}).get("packets") or {}).get("top_talkers") or [])
                counts = {"ports_probed": scan[2] if scan else 0, "packets_sent": pk.get(ip, 0)}
                actors.append({"ip": ip, "role": role, "counts": {k: v for k, v in counts.items() if v}, "tools": [], "attack_types": []})
            elif "target" in e["roles"]:
                host = next((h for h in (result.get("network_stats") or {}).get("hosts") or [] if h.get("ip") == ip), {})
                targets["hosts"].append(ip + (f" ({clean(host['hostname'], 60)})" if host.get("hostname") else ""))
        for p in (result.get("network_stats") or {}).get("ports") or []:
            targets["services"].append(f"{p.get('host')}:{p.get('port')}/{clean(p.get('service', ''), 30)}")
        for f in _findings(result):
            if f.get("name") == "Cleartext Credentials on the Wire":
                m = re.search(r"\bUSER\s+(\S+)", f.get("evidence", ""))
                if m and clean(m.group(1), 40) not in targets["accounts"]:
                    targets["accounts"].append(clean(m.group(1), 40))
    elif mode == "email":
        fx = result.get("forensics") or {}
        for ip in fx.get("origin_ips") or []:
            actors.append({"ip": ip, "role": "origin", "counts": {}, "tools": [], "attack_types": []})
        to = (fx.get("headers") or {}).get("To")
        if to:
            targets["accounts"].append(clean(to, 80))
        hops = fx.get("received_chain") or []
        if hops:
            m = re.search(r"\bby\s+([^\s;]+)", hops[-1].get("hop", ""))
            if m:
                targets["hosts"].append(clean(m.group(1), 80))
    elif mode == "ip":
        ip = str(result.get("input", "")).strip()
        if ip:
            actors.append({"ip": ip, "role": (inv.get(ip, {}).get("roles") or ["observed host"])[0], "counts": {}, "tools": [], "attack_types": []})
    elif mode == "url":
        ip = (result.get("domain_info") or {}).get("resolved_ip")
        if ip and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", str(ip)):
            actors.append({"ip": ip, "role": "resolved IP", "counts": {}, "tools": [], "attack_types": []})

    items = []
    for a in actors:
        if not reg.claim("actors_and_targets", ("ip", a["ip"])):
            continue
        a["reputation_state"] = reputation_state(result, a["ip"])
        parts = [f"{k.replace('_', ' ')} {v}" for k, v in a["counts"].items() if v]
        text = f"{a['ip']} ({a['role']}): " + (", ".join(parts) if parts else "no activity counts recorded") + "."
        ref = ({"field": f"log_stats.top_sources[{[t.get('ip') for t in ls.get('top_sources') or []].index(a['ip'])}]"} if mode == "logs"
               else {"field": "forensics.origin_ips"} if mode == "email" else {"field": "domain_info.resolved_ip"} if mode == "url"
               else {"field": "input"} if mode == "ip" else {"field": "network_stats"} if result.get("network_stats") else {"field": "findings"})
        items.append(_item(text, ref, [("ip", a["ip"])], kind="actor", **a))
    tgt = {}
    for k, vals in targets.items():
        kept = [v for v in vals if reg.claim("actors_and_targets", ("target", k, v))]
        if kept:
            tgt[k] = kept
    target_ref = {"field": "log_stats"} if mode == "logs" else {"field": "network_stats"} if mode == "network" else {"field": "forensics"} if mode == "email" else {"field": "findings"}
    return _block("actors_and_targets", items, targets=tgt, targets_ref=target_ref,
                  targets_visible={k: min(MAX_VISIBLE, len(v)) for k, v in tgt.items()})


# ── C) assessment ──
def build_assessment(result, reg, story):
    mode = result.get("mode", "")
    F = _findings(result)
    names = {f.get("name") for f in real_findings(result)}
    ls = result.get("log_stats") or {}
    rows = []

    def add(q, status, basis, ref):
        rows.append({"question": q, "status": status, "basis": basis, "ref": ref})

    def see(i=None, line=None, fallback=""):
        s = _step_of(story, i, line)
        return f"See step {s}." if s else fallback

    if mode == "logs":
        succ = (ls.get("login_after_failures") or [])
        if succ:
            s = succ[0]
            add("Did a login succeed after failed attempts?", "Observed",
                f"An accepted login followed failures from the same IP. {see(line=s.get('line'))}".strip(), {"line": s.get("line")})
        elif "SSH / Login Brute Force" in names:
            i = _idx(result, "SSH / Login Brute Force")
            add("Did a login succeed after failed attempts?", "Not evidenced", "Only failed logins were recorded.", {"finding": i})
        dec = ls.get("powershell_decoded") or []
        with_url = [d for d in dec if URL_RE.search(d.get("decoded", ""))]
        if with_url:
            add("Was a payload downloaded or run?", "Observed",
                f"A decoded command downloads from a URL. {see(line=with_url[0].get('line'))}".strip(), {"line": with_url[0].get("line")})
        elif dec:
            add("Was a payload downloaded or run?", "Possible", "An encoded command was decoded but names no download URL.", {"line": dec[0].get("line")})
        web = [n for n in names if n in _WHAT]
        if web:
            i = _idx(result, sorted(web)[0])
            add("Did a web attack succeed?", "Not evidenced",
                "Per-request response codes are not kept; 200 alone would not prove exploitation.", {"finding": i})
    elif mode == "network":
        vuln = [i for i, f in enumerate(F) if f.get("name", "").startswith(("Vulnerable Service:", "NSE Finding:"))]
        if vuln:
            add("Is a known-vulnerable service exposed?", "Observed", f"Banners match known-vulnerable builds. {see(vuln[0])}".strip(), {"finding": vuln[0]})
        elif result.get("network_stats", {}).get("ports"):
            add("Is a known-vulnerable service exposed?", "Not evidenced", "No banner matched a known-vulnerable build.", {"field": "network_stats.ports"})
        cred = _idx(result, "Cleartext Credentials on the Wire")
        if cred is not None:
            add("Could captured credentials be reused?", "Possible", f"A login crossed the network unencrypted. {see(cred)}".strip(), {"finding": cred})
        c2 = _idx(result, "Traffic to Suspicious Port")
        if c2 is not None:
            add("Is a remote-control channel open?", "Possible", f"The port alone suggests it; payloads were not seen. {see(c2)}".strip(), {"finding": c2})
        eol = _idx(result, "End-of-Life Operating System")
        if eol is not None:
            add("Does a host run an unsupported OS?", "Possible", "Based on an OS fingerprint, which can be wrong.", {"finding": eol})
    elif mode == "email":
        auth = [i for i, f in enumerate(F) if re.match(r"^(SPF|DKIM|DMARC) (Authentication Failed|Not Passing)$", f.get("name", ""))]
        fails = [i for i in auth if F[i].get("name", "").endswith("Authentication Failed")]
        if fails:
            add("Does the sender fail authentication?", "Observed", f"The receiving server recorded failed checks. {see(fails[0])}".strip(), {"finding": fails[0]})
        elif auth:
            add("Does the sender fail authentication?", "Possible", "Checks did not pass but were not outright failures.", {"finding": auth[0]})
        elif (result.get("forensics") or {}).get("auth"):
            add("Does the sender fail authentication?", "Not evidenced", "No failing authentication result was recorded.", {"field": "forensics.auth"})
        lm = _idx(result, "Link Text / Destination Mismatch")
        if lm is not None:
            add("Do links lead somewhere other than shown?", "Possible", f"Link text and target differ. {see(lm)}".strip(), {"finding": lm})
        att = _idx(result, "Double-Extension Attachment")
        if att is None:
            att = _idx(result, "Risky Attachment Type")
        if att is not None:
            add("Could the attachment run code?", "Possible", f"Its file type can execute. {see(att)}".strip(), {"finding": att})
    elif mode == "url":
        flagged = [i for i, f in enumerate(F) if f.get("name", "").startswith("[") or f.get("name") == "Suspicious Redirect Destination"]
        if flagged and (result.get("redirect_trace") or {}).get("hops"):
            add("Does the chain end on a flagged domain?", "Observed", f"Threat data flags the destination. {see(flagged[0])}".strip(), {"finding": flagged[0]})
        elif flagged:
            add("Is the address flagged by threat data?", "Possible", f"A source lists it. {see(flagged[0])}".strip(), {"finding": flagged[0]})
        else:
            add("Is the address flagged by threat data?", "Not evidenced", "No reputation source flagged it.", {"field": "findings"})
        nd = _idx(result, "Newly Registered Domain")
        if nd is not None:
            add("Is the domain newly registered?", "Possible", f"Registration is recent. {see(nd)}".strip(), {"finding": nd})
        bi = _idx(result, "Brand Impersonation")
        if bi is not None:
            add("Does the address imitate a brand?", "Possible", f"The name resembles a brand. {see(bi)}".strip(), {"finding": bi})
    elif mode in ("hash", "ip"):
        src = result.get("intel_sources") or {}
        flagged = [s for s in src.values() if isinstance(s, dict) and s.get("available") and s.get("flagged")]
        avail = [s for s in src.values() if isinstance(s, dict) and s.get("available")]
        what = "hash" if mode == "hash" else "IP"
        if flagged:
            add(f"Do reputation sources flag this {what}?", "Possible", f"Flagged by {_join([s.get('source') for s in flagged])}.", {"field": "intel_sources"})
        elif avail:
            add(f"Do reputation sources flag this {what}?", "Not evidenced", "No checked source has a report; that is not proof it is safe.", {"field": "intel_sources"})
        else:
            add(f"Do reputation sources flag this {what}?", "Not evidenced", "No reputation source was available.", {"field": "intel_sources" if src else "input"})

    if str(result.get("verdict", "")).upper() == "BENIGN":       # calm output: nothing "Observed" on benign results
        for r in rows:
            if r["status"] == "Observed":
                r["status"] = "Possible"
    items = []
    for r in rows:
        if reg.claim("assessment", ("question", r["question"])):
            items.append(_item(r["question"], r["ref"], [("question", r["question"])], status=r["status"], basis=r["basis"],
                               question=r["question"]))
    return _block("assessment", items)


# ── A) overview ──
def build_overview(result, reg, story, actors):
    items = []
    events = timeline_events(result)
    ts = [e["time"] for e in events if e.get("time")]
    window = {}
    if ts:
        window = {"first": clean(ts[0], 60), "last": clean(ts[-1], 60)}
        d = _duration(ts[0], ts[-1], ts)
        if d:
            window["duration"] = d
        if window["first"] == window["last"]:
            window.pop("duration", None)
        if reg.claim("overview", ("window",)):
            text = (f"Activity recorded at {window['first']}." if window["first"] == window["last"] else
                    f"Activity runs from {window['first']} to {window['last']}" + (f" ({window['duration']})." if window.get("duration") else "."))
            items.append(_item(text, {"ts": ts[0]}, [("window",)], kind="window"))
    for c in (result.get("evidence_correlation") or [])[:MAX_VISIBLE]:
        sc = clean(c.get("scenario", ""), 80)
        if sc and reg.claim("overview", ("incident", sc)):
            items.append(_item(f"Incident pattern: {sc} ({str(c.get('confidence', '')).lower()} confidence).", {"field": "evidence_correlation"},
                               [("incident", sc)], kind="incident"))
    chips = {"attackers": [{"label": a["ip"], "target_block": "actors_and_targets"} for a in actors["items"]],
             "techniques": list({t: {"label": t, "target_block": "attack_story", "step": it["order"]}
                                 for it in reversed(story["items"]) for t in it.get("technique_ids", [])}.values())[::-1][:12],
             "targets": [{"label": v, "target_block": "actors_and_targets"} for k in ("hosts", "accounts") for v in actors.get("targets", {}).get(k, [])][:6]}
    return _block("overview", items, window=window, chips={k: v for k, v in chips.items() if v})


# ── E) confidence and limits ──
_OPEN_Q = {
    "SQL Injection": "Did the SQL injection return data? Only status and size are logged.",
    "Cross-Site Scripting (XSS)": "Was the script stored and shown to other users?",
    "Path Traversal / LFI": "Did the server return the requested file? Compare response sizes.",
    "Command Injection": "Did a shell command run? Check processes started by the web server.",
    "Successful Login After Failures": "What did the account do after logging in?",
    "SSH / Login Brute Force": "Were any of the guessed passwords valid elsewhere?",
    "PowerShell Encoded Command": "Did the downloaded script run on the endpoint?",
    "TCP Port Scan Detected": "Did the scan source connect to an open port afterwards?",
    "Cleartext Credentials on the Wire": "Are the exposed credentials used on other systems?",
    "Traffic to Suspicious Port": "Which process opened the suspicious connection?",
    "Vulnerable Service": "Is the real installed version vulnerable, or patched behind an old banner?",
    "SPF Authentication Failed": "Did anyone click the link or open the attachment?",
    "Link Text / Destination Mismatch": "Did anyone visit the real link target?",
    "Newly Registered Domain": "Did any user submit data on the destination page?",
    "Hash Matches Known Malware (Local Database)": "Where else does this file exist in your environment?",
}


def build_confidence(result, reg, story):
    F = _findings(result)
    real = real_findings(result)
    items = []
    conf = result.get("confidence") or (result.get("classification") or {}).get("confidence")
    if conf:
        level = "High" if conf >= 80 else "Medium" if conf >= 60 else "Low"
        if reg.claim("confidence_and_limits", ("confidence",)):
            items.append(_item(f"Confidence level: {level}.", {"field": "confidence" if result.get("confidence") else "classification.confidence"},
                               [("confidence",)], kind="level", level=level))
    merged = {}
    for c in (result.get("score_explanation") or {}).get("contributions") or []:
        lab = clean(str(c.get("label") or c.get("factor")).replace(" (inside encoded payload)", " (encoded)"), 60)
        merged[lab] = merged.get(lab, 0) + int(c.get("points") or 0)
    factors = sorted(merged.items(), key=lambda kv: -kv[1])[:3]
    if factors and reg.claim("confidence_and_limits", ("factors",)):
        items.append(_item("Top score factors, with points:", {"field": "score_explanation.contributions"}, [("factors",)], kind="factors",
                           link="Why This Score", factors=[{"label": lab, "points": pts} for lab, pts in factors]))
    # limits by rule
    ls = result.get("log_stats") or {}
    lines = {h.get("line") for h in ls.get("sample_hits") or []} | {a.get("line") for a in ls.get("auth_events") or []}
    ev_count = len([l for l in lines if l]) if ls else len([f for f in real if f.get("evidence")])
    limits = []
    if 0 < ev_count < 3:
        limits.append(("Based on fewer than 3 evidence lines.", {"finding": F.index(real[0]) if real else 0}))
    srcs = {h.get("ip") for h in ls.get("sample_hits") or [] if h.get("ip")} if ls else {a.get("ip") for a in []}
    if ls and len(srcs) == 1:
        limits.append(("All attack evidence comes from one source.", {"field": "log_stats.sample_hits"}))
    if not timeline_events(result) and real:
        limits.append(("No timestamps are kept, so order follows the kill chain.", {"field": "findings"}))
    enr = result.get("enrichment") or {}
    if enr and not enr.get("ips") and not enr.get("hashes") and enr.get("skipped_private"):
        limits.append(("Reputation was not checked: only private or reserved IPs.", {"field": "enrichment.skipped_private"}))
    elif result.get("intel_sources") and not any(isinstance(s, dict) and s.get("available") for s in result["intel_sources"].values()):
        limits.append(("No reputation source was available.", {"field": "intel_sources"}))
    if any(f.get("name", "").startswith("Vulnerable Service:") for f in real) and not any(f.get("name", "").startswith("NSE Finding:") and "VULNERABLE" in str(f.get("evidence", "")) for f in real):
        i = next(i for i, f in enumerate(F) if f.get("name", "").startswith("Vulnerable Service:"))
        limits.append(("Vulnerability rests on version banners only.", {"finding": i}))
    for text, ref in limits:
        if reg.claim("confidence_and_limits", ("limit", text)):
            items.append(_item(text, ref, [("limit", text)], kind="limit"))
    # likely false positives from the top findings
    top = sorted(real, key=lambda f: -SEV_RANK.get(f.get("severity"), 0))[:3]
    seen_fp = set()
    for f in top:
        fp = clean(re.split(r"(?<=[.!?])\s|; ", str(f.get("false_positive_possibility") or ""))[0], 120)
        if fp and fp.upper() != "N/A" and len(fp.split()) >= 3 and _norm(fp) not in seen_fp and len(fp.split()) < 20:
            seen_fp.add(_norm(fp))
            if reg.claim("confidence_and_limits", ("fp", _norm(fp))):
                items.append(_item(f"False positive note: {fp.rstrip('.')}.", {"finding": F.index(f)}, [("fp", _norm(fp))], kind="false_positive"))
    # open questions by finding type
    for f in top + [x for x in real if x not in top]:
        key = next((k for k in _OPEN_Q if f.get("name", "").startswith(k)), None)
        if key and reg.claim("confidence_and_limits", ("open", key)):
            items.append(_item(_OPEN_Q[key], {"finding": F.index(f)}, [("open", key)], kind="open_question"))
    # one-line "not checked"
    nc = []
    src = result.get("intel_sources") or {}
    nc += [s.get("source") for s in src.values() if isinstance(s, dict) and not s.get("available")]
    if enr.get("skipped_private"):
        nc.append("reputation of private/reserved IPs")
    if ls:
        nc.append("per-request response codes")
    nc = [clean(x, 40) for x in nc if x]
    if nc and reg.claim("confidence_and_limits", ("not_checked",)):
        items.append(_item("Not checked: " + _join(nc, 4) + ".", {"field": "intel_sources" if src else "log_stats" if ls else "findings"},
                           [("not_checked",)], kind="not_checked"))
    return _block("confidence_and_limits", items)


# ── F) next steps ──
def _short_action(text: str) -> str:
    """A finding recommendation trimmed to one short sentence (parenthetical detail dropped, under 20 words)."""
    t = clean(text, 160)
    t = re.sub(r"\s*\([^)]*\)", "", t).strip()
    t = re.split(r"(?<=[.!?])\s+", t)[0]
    w = t.split()
    return t if len(w) < 20 else " ".join(w[:18]).rstrip(",;") + " …"


def _near(a: str, sentences: set) -> bool:
    A = set(_norm(a).split())
    return any(A and B and len(A & B) / len(A | B) >= 0.8 for B in (set(x.split()) for x in sentences))


def build_next_steps(result, reg):
    F = _findings(result)
    respond = []
    for a in prioritized_actions(result):
        n = _norm(a["action"])
        if n in reg.summary_actions or not reg.claim("next_steps", ("action", n)):
            continue
        fi = next((i for i, f in enumerate(F) if f.get("name") in a.get("findings", [])), None)
        ref = {"finding": fi} if fi is not None else {"field": "recommended_action"}
        respond.append(_item(_short_action(a["action"]), ref, [("action", n)], kind="respond", priority=a["priority"]))
    investigate = []
    pb = playbooks()
    seen_keys = []
    for i, f in enumerate(real_findings(result)):
        key = next((k for k in pb if k != "default" and f.get("name", "").startswith(k)), None)
        if key and key not in seen_keys:
            seen_keys.append(key)
            for step in pb[key][:1]:
                if reg.claim("next_steps", ("guide", _norm(step))):
                    investigate.append(_item(step, {"finding": F.index(f)}, [("guide", _norm(step))], kind="investigate", label=GENERAL_GUIDANCE))
    if real_findings(result) and not investigate:
        for step in pb.get("default", [])[:1]:
            if reg.claim("next_steps", ("guide", _norm(step))):
                investigate.append(_item(step, {"finding": F.index(real_findings(result)[0])}, [("guide", _norm(step))], kind="investigate",
                                         label=GENERAL_GUIDANCE))
    items = respond + investigate
    blk = _block("next_steps", items, respond_count=len(respond), investigate_label=GENERAL_GUIDANCE)
    return blk


# ── G) mode extras (only facts nobody else owns) ──
def build_extras(result, reg):
    mode = result.get("mode", "")
    items = []

    def add(key, text, ref, **kw):
        if reg.claim("mode_extras", key):
            items.append(_item(text, ref, [key], **kw))

    if mode == "logs":
        ls = result.get("log_stats") or {}
        for d in ls.get("powershell_decoded") or []:
            add(("decoded", d.get("line")), f"Decoded command at line {d.get('line')}.", {"line": d.get("line")}, kind="code",
                code=clean(d.get("decoded", ""), TEXT_LIMIT))
        per_user = {}
        for a in ls.get("auth_events") or []:
            u = clean(a.get("user", ""), 40)
            per_user.setdefault(u, {"failed": 0, "accepted": 0, "line": a.get("line")})[a.get("result", "failed")] += 1
        for u, c in per_user.items():
            add(("logins", u), f"'{u}': {c['failed']} failed, {c['accepted']} accepted.", {"line": c["line"]}, kind="logins")
    elif mode == "email":
        fx = result.get("forensics") or {}
        h = fx.get("headers") or {}
        for field in ("From", "Return-Path", "Reply-To"):
            if h.get(field):
                add(("header", field), f"{field}: {clean(h[field], 120)}.", {"field": f"forensics.headers.{field}"}, kind="header")
        for a in fx.get("attachments") or []:
            add(("attachment", a.get("sha256")), f"Attachment {clean(a.get('filename'), 60)}: SHA-256 {a.get('sha256', '')}.",
                {"field": "forensics.attachments"}, kind="hash")
        for m in fx.get("html_link_mismatches") or []:
            add(("mismatch", m.get("actual")), f"Link shows {clean(m.get('shown'), 80)} but opens {clean(m.get('actual'), 80)}.",
                {"field": "forensics.html_link_mismatches"}, kind="link")
    elif mode == "url":
        di = result.get("domain_info") or {}
        if isinstance(di.get("domain_age_days"), int):
            add(("age",), f"Domain age: {di['domain_age_days']} days.", {"field": "domain_info.domain_age_days"}, kind="fact")
        if di.get("registrar") and di["registrar"] != "Unknown":
            add(("registrar",), f"Registrar: {clean(di['registrar'], 80)}.", {"field": "domain_info.registrar"}, kind="fact")
        tr = result.get("redirect_trace") or {}
        for i, hop in enumerate(tr.get("chain") or []):
            add(("hop", i), f"Hop {i + 1}: {clean(hop.get('url'), 120)} (HTTP {hop.get('status')}).", {"field": f"redirect_trace.chain[{i}]"}, kind="hop")
    elif mode in ("hash", "ip"):
        for key, s in (result.get("intel_sources") or {}).items():
            if not isinstance(s, dict):
                continue
            state = ("flagged" if s.get("flagged") else "no report" if s.get("available") else "unavailable" if s.get("error") else "not configured")
            add(("source", key), f"{clean(s.get('source') or key, 40)}: {state}.", {"field": f"intel_sources.{key}"}, kind="source")
    elif mode == "network":
        pk = ((result.get("network_stats") or {}).get("packets") or {})
        if pk.get("protocols"):
            add(("protocols",), "Protocols seen: " + ", ".join(f"{clean(k, 20)} {v}" for k, v in list(pk["protocols"].items())[:6]) + ".",
                {"field": "network_stats.packets.protocols"}, kind="fact")
    return _block("mode_extras", items)


# ── completeness contract ──
QUESTIONS = {
    "logs": ["Who attacked?", "What did they try?", "Against what?", "When?", "Did anything succeed?", "What was run or downloaded?", "What to do?"],
    "network": ["Scan source?", "Target hosts and ports?", "Exposed risky services?", "Cleartext credentials seen?", "Suspicious outbound traffic?", "What to do?"],
    "email": ["Real vs claimed sender?", "Authentication results?", "Links and attachments?", "Intended deception?", "What to do?"],
    "url": ["Redirect chain?", "Final destination?", "Domain age, lookalike and reputation?", "What to do?"],
    "hash": ["Identity (type, hashes)?", "Reputation by source?", "Behavior indicators?", "What to do?"],
    "ip": ["Identity?", "Reputation by source?", "Behavior indicators?", "What to do?"],
}


def build_coverage(result, blocks, summary):
    mode = result.get("mode", "")
    B = {b["key"]: b for b in blocks}
    has = lambda k: bool(B.get(k) and (B[k]["items"] or B[k].get("targets") or B[k].get("window")))
    F = {f.get("name", "") for f in real_findings(result)}
    any_f = lambda *pre: any(n.startswith(pre) for n in F)
    do_now = bool(summary.get("do_now"))
    ans = {}
    if mode == "logs":
        ans = {"Who attacked?": "actors_and_targets" if B["actors_and_targets"]["items"] else None,
               "What did they try?": "attack_story" if has("attack_story") else None,
               "Against what?": "actors_and_targets" if B["actors_and_targets"].get("targets") else None,
               "When?": "overview" if B["overview"].get("window") else None,
               "Did anything succeed?": "assessment" if has("assessment") else None,
               "What was run or downloaded?": "mode_extras" if any(i.get("kind") == "code" for i in B["mode_extras"]["items"]) else
               ("assessment" if any("payload" in i.get("question", "") for i in B["assessment"]["items"]) else None)}
    elif mode == "network":
        ans = {"Scan source?": "actors_and_targets" if any(i.get("role") == "scan source" for i in B["actors_and_targets"]["items"]) else None,
               "Target hosts and ports?": "actors_and_targets" if B["actors_and_targets"].get("targets") else None,
               "Exposed risky services?": "attack_story" if any_f("Risky Port Open:", "Vulnerable Service:", "NSE Finding:") else
               ("assessment" if any("vulnerable" in i.get("question", "") for i in B["assessment"]["items"]) else None),
               "Cleartext credentials seen?": "attack_story" if "Cleartext Credentials on the Wire" in F else None,
               "Suspicious outbound traffic?": "attack_story" if "Traffic to Suspicious Port" in F else None}
    elif mode == "email":
        ans = {"Real vs claimed sender?": "mode_extras" if any(i.get("kind") == "header" for i in B["mode_extras"]["items"]) else None,
               "Authentication results?": "assessment" if any("authentication" in i.get("question", "") for i in B["assessment"]["items"]) else None,
               "Links and attachments?": "mode_extras" if any(i.get("kind") in ("hash", "link") for i in B["mode_extras"]["items"]) else
               ("attack_story" if has("attack_story") else None),
               "Intended deception?": "attack_story" if has("attack_story") else None}
    elif mode == "url":
        ans = {"Redirect chain?": "mode_extras" if any(i.get("kind") == "hop" for i in B["mode_extras"]["items"]) else None,
               "Final destination?": "mode_extras" if any(i.get("kind") == "hop" for i in B["mode_extras"]["items"]) else None,
               "Domain age, lookalike and reputation?": "assessment" if has("assessment") else None}
    elif mode in ("hash", "ip"):
        first = QUESTIONS[mode][0]
        ans = {first: "mode_extras" if has("mode_extras") or result.get("input") else None,
               "Reputation by source?": "mode_extras" if any(i.get("kind") == "source" for i in B["mode_extras"]["items"]) else None,
               "Behavior indicators?": "attack_story" if has("attack_story") else None}
    ans["What to do?"] = "next_steps" if has("next_steps") else ("short summary" if do_now else None)
    return [{"question": q, "answered_by": ans.get(q) or NOT_DETERMINED} for q in QUESTIONS.get(mode, ["What to do?"])]


# ── glossary + word budget ──
def _item_texts(it):
    return [it.get(k) for k in ("text", "basis", "why") if it.get(k)]


def _apply_glossary(blocks):
    terms = glossary()
    used = []
    for b in blocks:
        for it in b["items"]:
            text = " ".join(_item_texts(it))
            for term, definition in terms.items():
                if term in used:
                    continue
                if re.search(r"(?<![\w-])" + re.escape(term) + r"(?![\w-])", text, re.I):
                    it.setdefault("define", []).append({"term": term, "definition": definition})
                    used.append(term)
    return [{"term": t, "definition": terms[t]} for t in used]


def _words(it) -> int:
    parts = _item_texts(it) + [it.get("evidence", ""), it.get("code", ""), " ".join(d["definition"] for d in it.get("define", []))]
    if it.get("kind") == "actor":
        parts.append(it.get("reputation_state", ""))
    return sum(len(str(p).split()) for p in parts if p)


def _fit_budget(blocks):
    """Round-robin: every non-empty block shows its first item, then add items while the visible total stays in budget."""
    for b in blocks:
        b["visible"] = 1 if b["items"] else 0
    total = sum(_words(b["items"][0]) for b in blocks if b["items"])
    total += sum(min(MAX_VISIBLE, len(v)) * 2 for b in blocks for v in (b.get("targets") or {}).values())
    grew = True
    while grew:
        grew = False
        for b in blocks:
            if b["visible"] < min(MAX_VISIBLE, len(b["items"])):
                w = _words(b["items"][b["visible"]])
                if total + w <= WORD_BUDGET:
                    b["visible"] += 1
                    total += w
                    grew = True
    for b in blocks:
        b["more"] = len(b["items"]) - b["visible"]
    return total


def build_details(result: dict, summary: dict = None, defang: bool = False) -> dict:
    """Detailed, non-repetitive summary details. `summary` = the short exec_summary (built if missing)."""
    result = result if isinstance(result, dict) else {}
    if isinstance(result.get("findings"), list):            # non-object findings → {} (keeps every finding index valid for refs)
        result = {**result, "findings": [f if isinstance(f, dict) else {} for f in result["findings"]]}
    if summary is None:
        from utils.summary import build_exec_summary
        summary = build_exec_summary(result)
    reg = Registry(summary)
    story = build_story(result, reg)                     # ownership priority: story → actors → assessment → …
    actors = build_actors_targets(result, reg)
    assessment = build_assessment(result, reg, story)
    overview = build_overview(result, reg, story, actors)
    confidence = build_confidence(result, reg, story)
    nxt = build_next_steps(result, reg)
    extras = build_extras(result, reg)
    blocks = [overview, actors, assessment, story, confidence, nxt, extras]
    # drop anything that restates (or nearly restates) a short-summary sentence; a story step keeps its evidence but
    # points to the summary instead of repeating it, so "see step N" references stay valid
    for b in blocks:
        kept = []
        for it in b["items"]:
            if _norm(it.get("text", "")) in reg.summary_sentences or _near(it.get("text", ""), reg.summary_sentences):
                if b["key"] != "attack_story":
                    continue
                it["text"] = "Described in the summary above; the evidence is below."
            kept.append(it)
        b["items"] = kept
        b["visible"] = min(MAX_VISIBLE, len(kept))
    coverage = build_coverage(result, blocks, summary)
    terms = _apply_glossary(blocks)
    words = _fit_budget(blocks)
    blocks = [b for b in blocks if b["items"] or b.get("targets") or b.get("window") or b.get("chips")]
    out = {"version": VERSION, "blocks": blocks, "coverage": coverage, "glossary": terms, "visible_words": words,
           "word_budget": WORD_BUDGET}
    out["copy"] = build_copy_formats(result, summary, out)            # always defanged + masked
    if defang:
        out = _defang_tree(out)
    return out


_NO_DEFANG_KEYS = {"key", "kind", "status", "stage", "facts", "ref", "target_block", "label", "priority", "role"}


def _defang_tree(v, key=None):
    if isinstance(v, str):
        return v if key in _NO_DEFANG_KEYS else defang_text(v)
    if isinstance(v, list):
        return [_defang_tree(x, key) for x in v]
    if isinstance(v, dict):
        return {k: (x if k in ("ref", "facts") else _defang_tree(x, k)) for k, x in v.items()}
    return v


# ─── copy formats (always defanged + masked) ────────────────────
def _block_lines(b):
    """Plain (label, text) lines for one block: used by the copy formats and the write-ups."""
    out = []
    key = b["key"]
    if key == "overview":
        if b.get("window"):
            w = b["window"]
            out.append(("Time window", f"{w['first']} to {w['last']}" + (f" ({w['duration']})" if w.get("duration") else "")))
        out += [("", it["text"]) for it in b["items"] if it.get("kind") == "incident"]
    elif key == "actors_and_targets":
        for it in b["items"]:
            out.append(("", f"{it['text']} Reputation: {it['reputation_state']}."
                        + (f" Tools: {', '.join(it['tools'])}." if it.get("tools") else "")))
        for k, vals in (b.get("targets") or {}).items():
            out.append((f"Targets ({k})", ", ".join(vals)))
    elif key == "assessment":
        out += [(it["status"], f"{it['question']} {it['basis']}") for it in b["items"]]
    elif key == "attack_story":
        for it in b["items"]:
            head = f"Step {it['order']}" + (f", {it['when']}" if it.get("when") else "")
            tag = ", ".join(x for x in [it.get("stage"), *it.get("technique_ids", [])] if x)
            out.append((head + (f" ({tag})" if tag else ""), it["text"] + (f" Evidence: '{it['evidence']}'." if it.get("evidence") else "")
                        + (f" Why it matters: {it['why']}" if it.get("why") else "")))
    elif key == "confidence_and_limits":
        for it in b["items"]:
            txt = it["text"]
            if it.get("factors"):
                txt += " " + "; ".join(f"{f['label']} +{f['points']}" for f in it["factors"])
            out.append(("", txt))
    elif key == "next_steps":
        out += [(it.get("priority", ""), it["text"]) for it in b["items"] if it.get("kind") == "respond"]
        inv = [it["text"] for it in b["items"] if it.get("kind") == "investigate"]
        if inv:
            out.append((GENERAL_GUIDANCE, " ".join(inv)))
    else:
        out += [("", it["text"] + (f" {it['code']}" if it.get("code") else "")) for it in b["items"]]
    return out


def build_copy_formats(result: dict, summary: dict, details: dict) -> dict:
    """{plain, markdown, oneline}: defanged and masked, for tickets and chat."""
    v, score = str(result.get("verdict") or "").upper(), result.get("score")
    cls = (result.get("classification") or {}).get("primary", "")
    head = f"PhishyLens: {v}" + (f" ({score}%)" if score is not None else "") + (f", {cls}" if cls else "")
    B = {b["key"]: b for b in details.get("blocks", [])}
    plain, md = [head, summary.get("headline", ""), ""], [f"**{head}**", "", summary.get("headline", ""), ""]
    story = summary.get("story") or []
    for sec in story:                                       # the story, section by section
        text = " ".join(s["text"] for s in sec.get("sentences", []))
        plain += [f"{sec['title']}: {text}", ""]
        md += [f"### {sec['title']}", text, ""]
    if not story and summary.get("what_happened"):          # results saved before the story existed
        plain += ["What happened:"] + [f"- {x}" for x in summary["what_happened"]] + [""]
        md += ["### What happened"] + [f"- {x}" for x in summary["what_happened"]] + [""]
    if not story and summary.get("why_it_matters"):
        plain += [f"Why it matters: {summary['why_it_matters']}", ""]
        md += ["### Why it matters", summary["why_it_matters"], ""]
    if summary.get("do_now"):
        plain += ["Do now:"] + [f"- [{a['priority']}] {a['action']}" for a in summary["do_now"]] + [""]
        md += ["### Do now"] + [f"- [ ] **{a['priority']}:** {a['action']}" for a in summary["do_now"]] + [""]
    for key in ("assessment", "next_steps") if story else ("assessment", "attack_story", "next_steps"):
        if key in B:
            lines = _block_lines(B[key])
            plain += [BLOCK_TITLES[key] + ":"] + [f"- {lab + ': ' if lab else ''}{txt}" for lab, txt in lines] + [""]
            md += [f"### {BLOCK_TITLES[key]}"] + [f"- {'**' + lab + ':** ' if lab else ''}{txt}" for lab, txt in lines] + [""]
    observed = [it["question"] for it in (B.get("assessment") or {}).get("items", []) if it.get("status") == "Observed"]
    one = [f"[{v}" + (f" {score}%]" if score is not None else "]") + " " + summary.get("headline", "")]
    found = next((s["text"] for sec in story if sec["section"] == "found" for s in sec["sentences"] if not s.get("clear")), "")
    if found:
        one.append("Found: " + found)
    elif observed:
        one.append("Observed: " + "; ".join(observed[:2]))
    if summary.get("do_now"):
        one.append("Next: " + summary["do_now"][0]["action"])
    fmt = lambda s: defang_text(mask_secrets(_CTRL.sub("", s)))          # control / bidi characters stripped too
    return {"plain": fmt("\n".join(plain).strip() + "\n"), "markdown": fmt("\n".join(md).strip() + "\n"),
            "oneline": fmt(" | ".join(x for x in one if x).replace("\n", " "))}
