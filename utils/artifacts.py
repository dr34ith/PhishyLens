"""
PhishyLens: facts extracted from an analysis result, shared by the executive summary, diagrams and write-up.

Everything here READS existing result fields (findings, evidence, iocs, network_stats, forensics, redirect_trace,
log_stats, mitre, kill_chain, classification). Nothing is inferred beyond what those fields state, so the summary,
the diagrams and the report can never disagree with each other or invent hosts, times or steps.
"""
import ipaddress
import re
from email.utils import parsedate_to_datetime

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
PRIORITY_BY_SEV = {"CRITICAL": "Now", "HIGH": "Today", "MEDIUM": "This week", "LOW": "This week"}
PRIORITY_ORDER = ["Now", "Today", "This week"]
INFORMATIONAL = {"No Indicators Detected", "No Threat Intelligence Hits", "Reputation Not Checked", "Not Found in Threat Databases",
                 "Hash Provenance Unknown", "Private IP Address", "Invalid Hash Format", "Empty File Hash"}

IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
_ARROW = r"\s*(?:→|->|>)\s*"

# ─── secrets ────────────────────────────────────────────────────
_SECRET_PATTERNS = [
    (re.compile(r"\b(PASS)\s+(\S+)"), r"\1 ********"),                                          # FTP / POP3 PASS command
    (re.compile(r"(?i)\b(password|passwd|pwd|pass|secret|token|api[_-]?key|auth)=([^&\s\"']+)"), r"\1=********"),
    (re.compile(r"(?i)(Authorization:\s*(?:Basic|Bearer|Digest))\s+\S+"), r"\1 ********"),
    (re.compile(r"\b(LOGIN)\s+(\S+)\s+(\S+)"), r"\1 \2 ********"),        # IMAP 'LOGIN user pass' (protocol keyword is upper-case)
]


def mask_secrets(text) -> str:
    """Mask passwords / tokens that analyzers quote verbatim in evidence (e.g. 'Request: PASS hunter2')."""
    s = "" if text is None else str(text)
    for rx, repl in _SECRET_PATTERNS:
        s = rx.sub(repl, s)
    return s


# ─── IP scope ───────────────────────────────────────────────────
_INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                    "169.254.0.0/16", "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128")]


def ip_scope(ip: str) -> str:
    """'internal' (RFC 1918 / loopback / link-local / CGNAT), 'public' (globally routable) or 'reserved'
    (documentation / test ranges such as 203.0.113.0/24; not internal, not routable)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    if any(a in n for n in _INTERNAL_NETS):
        return "internal"
    return "public" if a.is_global else "reserved"


def real_findings(result: dict) -> list:
    return [f for f in (result.get("findings") or []) if isinstance(f, dict) and f.get("name") not in INFORMATIONAL]


def top_severity(result: dict) -> str:
    sevs = [f.get("severity", "LOW") for f in real_findings(result)]
    return max(sevs, key=lambda s: SEV_RANK.get(s, 0)) if sevs else ""


# ─── network evidence parsers (formats emitted by analyzers/network_analyzer.py) ───
def parse_scan(ev: str):
    m = re.match(rf"^({IPV4.pattern}){_ARROW}({IPV4.pattern}): SYN to (\d+) distinct ports", ev or "")
    return (m.group(1), m.group(2), int(m.group(3))) if m else None


def parse_cleartext(ev: str):
    m = re.match(rf"^(\S+) ({IPV4.pattern}){_ARROW}({IPV4.pattern}): (.*)$", ev or "")
    return (m.group(1).upper(), m.group(2), m.group(3), m.group(4)) if m else None


def parse_suspicious_port(ev: str):
    m = re.match(rf"^({IPV4.pattern}){_ARROW}({IPV4.pattern}):(\d+) \((\d+) packets?\)", ev or "")
    return (m.group(1), m.group(2), int(m.group(3)), int(m.group(4))) if m else None


def parse_host_port(ev: str):
    m = re.match(rf"^({IPV4.pattern})(?::(\d+))?", ev or "")
    return (m.group(1), int(m.group(2)) if m.group(2) else None) if m else None


# ─── IP inventory with roles ────────────────────────────────────
ROLE_ORDER = ["scan source", "attacker", "target", "destination", "origin", "relay", "client", "resolved IP",
              "queried indicator", "flagged by intel", "indicator", "mentioned in evidence"]


def ip_inventory(result: dict) -> dict:
    """{ip: {"roles": [...], "scope": ..., "sources": [...field names...]}} for every IPv4 present in the result."""
    inv = {}

    def add(ip, role, source):
        if not ip or ip_scope(ip) == "":
            return
        e = inv.setdefault(ip, {"roles": [], "scope": ip_scope(ip), "sources": []})
        if role not in e["roles"]:
            e["roles"].append(role)
        if source not in e["sources"]:
            e["sources"].append(source)

    mode = result.get("mode", "")
    for f in result.get("findings") or []:
        name, ev = f.get("name", ""), str(f.get("evidence", ""))
        if name == "TCP Port Scan Detected" and parse_scan(ev):
            s, d, _ = parse_scan(ev); add(s, "scan source", name); add(d, "target", name)
        elif name == "Cleartext Credentials on the Wire" and parse_cleartext(ev):
            _, s, d, _ = parse_cleartext(ev); add(s, "client", name); add(d, "target", name)
        elif name == "Traffic to Suspicious Port" and parse_suspicious_port(ev):
            s, d, _, _ = parse_suspicious_port(ev); add(s, "client", name); add(d, "destination", name)
        elif name in ("ICMP Ping Sweep", "ARP Flood / Possible Spoofing") and parse_host_port(ev):
            add(parse_host_port(ev)[0], "scan source", name)
        elif mode == "network" and parse_host_port(ev) and not name.startswith("["):
            add(parse_host_port(ev)[0], "target", name)
        elif name == "Extracted IP Has Bad Reputation" and parse_host_port(ev):
            add(parse_host_port(ev)[0], "flagged by intel", name)
        for ip in f.get("sources") or []:
            add(ip, "attacker" if mode == "logs" else "indicator", f"{name} (sources)")

    ns = result.get("network_stats") or {}
    for h in ns.get("hosts") or []:
        add(h.get("ip"), "target", "network_stats.hosts")
    pk = ns.get("packets") or {}
    for ip in pk.get("scan_sources") or []:
        add(ip, "scan source", "network_stats.packets.scan_sources")
    for t in pk.get("top_talkers") or []:
        if t and t[0] not in inv:
            add(t[0], "client", "network_stats.packets.top_talkers")

    ls = result.get("log_stats") or {}
    for t in ls.get("top_sources") or []:
        add(t.get("ip"), "attacker" if (t.get("attack_hits") or t.get("failed_logins")) else "client", "log_stats.top_sources")

    fx = result.get("forensics") or {}
    for ip in fx.get("origin_ips") or []:
        add(ip, "origin", "forensics.origin_ips")
    for hop in fx.get("received_chain") or []:
        for ip in hop.get("ips") or []:
            add(ip, "relay", "forensics.received_chain")

    di = result.get("domain_info") or {}
    if IPV4.fullmatch(str(di.get("resolved_ip") or "")):
        add(di["resolved_ip"], "resolved IP", "domain_info.resolved_ip")
    if mode == "ip" and IPV4.fullmatch(str(result.get("input") or "")):
        add(result["input"], "queried indicator", "input")
    for ip in (result.get("iocs") or {}).get("ips") or []:
        add(ip, "indicator", "iocs.ips")
    for f in result.get("findings") or []:                       # anything else quoted in evidence
        for ip in IPV4.findall(str(f.get("evidence", ""))):
            add(ip, "mentioned in evidence", f.get("name", ""))

    for e in inv.values():                                      # most specific role first
        e["roles"].sort(key=lambda r: ROLE_ORDER.index(r) if r in ROLE_ORDER else 99)
        if len(e["roles"]) > 1:
            e["roles"] = [r for r in e["roles"] if r not in ("indicator", "mentioned in evidence")] or e["roles"]
    return inv


def ioc_inventory(result: dict) -> list:
    """Rows for the IOC table: every IP / domain / URL / e-mail / hash with type, role, scope."""
    rows, seen = [], set()
    for ip, e in ip_inventory(result).items():
        rows.append({"type": "IP", "value": ip, "role": ", ".join(e["roles"]), "scope": e["scope"]})
        seen.add(ip)
    fx = result.get("forensics") or {}
    hdr = fx.get("headers") or {}
    email_roles = {}
    for field, role in (("From", "sender (From)"), ("Return-Path", "envelope sender (Return-Path)"), ("Reply-To", "Reply-To"), ("To", "recipient")):
        for addr in re.findall(r"[\w.+%-]+@[\w.-]+\.[A-Za-z]{2,}", str(hdr.get(field) or "")):
            email_roles.setdefault(addr.lower(), role)
    links = set(fx.get("links") or [])
    shown = {m.get("shown") for m in fx.get("html_link_mismatches") or []}
    attach = {a.get("sha256"): a.get("filename") for a in fx.get("attachments") or []}
    tr = result.get("redirect_trace") or {}
    for typ, values in (result.get("iocs") or {}).items():
        for v in values or []:
            v = str(v)
            if v in seen or typ == "ips":
                continue
            seen.add(v)
            role = ""
            if typ == "emails":
                role = email_roles.get(v.lower(), "address in message")
            elif typ == "urls":
                role = ("final destination" if v == tr.get("final_url") and tr.get("hops") else
                        "link text (what the user sees)" if v in shown else "link target" if v in links else
                        "analyzed URL" if v == result.get("input") else "URL")
            elif typ == "hashes":
                role = f"attachment {attach[v]}" if v in attach else ("analyzed hash" if v == str(result.get("input", "")).lower() else "hash")
            elif typ == "domains":
                role = "domain"
            rows.append({"type": typ.rstrip("s").upper() if typ != "emails" else "EMAIL", "value": v, "role": role, "scope": ""})
    return rows


# ─── timeline (only events whose time is recorded in the result) ───
def _hop_date(hop: str) -> str:
    if ";" not in hop:
        return ""
    tail = hop.rsplit(";", 1)[1].strip()
    try:
        parsedate_to_datetime(tail)
        return tail
    except Exception:
        return ""


def timeline_events(result: dict) -> list:
    """[{time, source, event, severity, line?}] in artifact order. Empty when the result holds no timestamps."""
    ev = []
    ls = result.get("log_stats") or {}
    for h in ls.get("sample_hits") or []:
        if h.get("ts"):
            ev.append({"time": h["ts"], "line": h.get("line"), "source": h.get("ip") or "", "event": h.get("type", ""),
                       "severity": h.get("severity", "")})
    for a in ls.get("auth_events") or []:
        if a.get("ts"):
            ok = a.get("result") == "accepted"
            ev.append({"time": a["ts"], "line": a.get("line"), "source": a.get("ip", ""),
                       "event": f"{'Accepted' if ok else 'Failed'} login for '{a.get('user', '')}'",
                       "severity": "CRITICAL" if ok and any(x.get("line") == a.get("line") for x in ls.get("login_after_failures") or []) else
                                   ("" if ok else "LOW")})
    for d in ls.get("powershell_decoded") or []:
        if d.get("ts"):
            ev.append({"time": d["ts"], "line": d.get("line"), "source": d.get("ip") or "", "event": "Encoded PowerShell decoded",
                       "severity": "CRITICAL"})
    fx = result.get("forensics") or {}
    hdr = fx.get("headers") or {}
    if hdr.get("Date"):
        ev.append({"time": str(hdr["Date"]), "line": 0, "source": str(hdr.get("From") or ""), "event": "Message Date header", "severity": ""})
    for i, hop in enumerate(fx.get("received_chain") or [], 1):
        t = _hop_date(hop.get("hop", ""))
        if t:
            m = re.search(r"\bby\s+(\S+)", hop.get("hop", ""))
            ev.append({"time": t, "line": i, "source": ", ".join(hop.get("ips") or []),
                       "event": f"Received hop {i}" + (f" (by {m.group(1).rstrip(';')})" if m else ""), "severity": ""})
    ev.sort(key=lambda e: (e.get("line") or 0))
    seen, out = set(), []
    for e in ev:
        k = (e["time"], e["source"], e["event"])
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out


# ─── prioritized, de-duplicated actions ─────────────────────────
def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def prioritized_actions(result: dict) -> list:
    """[{priority, action, severity, findings[]}]; finding recommendations de-duplicated, most severe first."""
    acts = {}
    for f in sorted(real_findings(result), key=lambda f: -SEV_RANK.get(f.get("severity"), 0)):
        rec = mask_secrets(f.get("recommendation") or "").strip()
        if not rec:
            continue
        k = _norm(rec)
        a = acts.setdefault(k, {"priority": PRIORITY_BY_SEV.get(f.get("severity"), "This week"), "action": rec,
                                "severity": f.get("severity", "LOW"), "findings": []})
        if f.get("name") not in a["findings"]:
            a["findings"].append(f.get("name"))
    out = sorted(acts.values(), key=lambda a: (-SEV_RANK.get(a["severity"], 0), PRIORITY_ORDER.index(a["priority"])))
    ra = mask_secrets(result.get("recommended_action") or "").strip()
    if ra and _norm(ra) not in acts and result.get("verdict") in ("MALICIOUS", "SUSPICIOUS"):
        out.insert(0, {"priority": "Now" if result.get("verdict") == "MALICIOUS" else "Today", "action": ra,
                       "severity": top_severity(result) or "MEDIUM", "findings": ["overall verdict"]})
    return out
