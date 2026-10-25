"""
PhishyLens: attack diagrams as pure-Python SVG + Mermaid (no JS libraries, no external requests).

    build_diagram(result, theme="dark"|"print", defang=False) -> {type, title, nodes[], edges[], svg, mermaid}
    build_killchain_svg(result, theme="dark") -> str

Every node/edge is built from a value already in the result and carries it in "value" (plus "field" naming where it
came from), so tests can prove nothing is invented. Text is XML-escaped, long labels wrap, secrets are masked, IOCs
are defanged when defang=True, and node count is capped at MAX_NODES (the rest become one "+N more" node).
"""
import html
import re

from utils.artifacts import (SEV_RANK, ip_inventory, mask_secrets, parse_cleartext, parse_host_port, parse_scan,
                             parse_suspicious_port, real_findings)
from utils.defang import defang_text

MAX_NODES = 20
NODE_W, LINE_H, PAD, COL_GAP, ROW_GAP = 220, 16, 10, 90, 22
CHAIN_PER_ROW = 4

# Palettes mirror the CSS colour tokens in static/style.css (dark = :root, print = light theme / @media print);
# tests/test_ui_tokens.py checks every text colour for >= 4.5:1 contrast against bg / node / lane.
SANS = "system-ui, -apple-system, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif"
MONO = "ui-monospace, Cascadia Code, SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace"
THEMES = {
    "dark":  {"bg": "#0d1117", "node": "#161b22", "border": "#30363d", "text": "#e6edf3", "muted": "#8b949e", "edge": "#6e7681",
              "ok": "#56d364", "accent": "#4fd1c5", "lane": "#11161d", "font": SANS, "mono": MONO,
              "ip": "#56d4dd", "domain": "#79c0ff", "hash": "#d2a8ff",
              "sev": {"CRITICAL": "#ff7b72", "HIGH": "#ffa657", "MEDIUM": "#e3b341", "LOW": "#a5c4e6"}},
    "print": {"bg": "#ffffff", "node": "#ffffff", "border": "#8c959f", "text": "#1f2328", "muted": "#57606a", "edge": "#6e7781",
              "ok": "#17702f", "accent": "#0f6b62", "lane": "#f6f8fa", "font": SANS, "mono": MONO,
              "ip": "#0b6a7d", "domain": "#0550ae", "hash": "#7039c8",
              "sev": {"CRITICAL": "#c4161c", "HIGH": "#a84300", "MEDIUM": "#845a00", "LOW": "#3d5f86"}},
}
ROLE_SEV = {"scan source": "HIGH", "attacker": "HIGH", "destination": "MEDIUM"}


def _esc(s) -> str:
    return html.escape("" if s is None else str(s), quote=True)


def _wrap(text: str, width: int, max_lines: int) -> list:
    words, lines, cur = str(text or "").split(), [], ""
    for w in words:
        while len(w) > width:                                   # break long tokens (URLs, hashes)
            if cur:
                lines.append(cur); cur = ""
            lines.append(w[:width]); w = w[width:]
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= width:
            cur += " " + w
        else:
            lines.append(cur); cur = w
    if cur:
        lines.append(cur)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1][:max(0, width - 1)] + "…"
    return lines or [""]


def _max_sev(*sevs) -> str:
    sevs = [s for s in sevs if s]
    return max(sevs, key=lambda s: SEV_RANK.get(s, 0)) if sevs else ""


def _node(id_, label, sub=(), *, kind="node", role="", severity="", value="", field="", col=0, row=None, badges=(), highlight=False):
    return {"id": id_, "label": str(label), "sub": [str(s) for s in sub if s], "kind": kind, "role": role, "severity": severity,
            "value": str(value), "field": field, "col": col, "row": row, "badges": list(badges), "highlight": highlight}


def _edge(a, b, label="", *, severity="", value="", field="", dashed=False):
    return {"from": a, "to": b, "label": str(label), "severity": severity, "value": str(value), "field": field, "dashed": dashed}


def _host(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", str(url or ""), re.I)
    return m.group(1) if m else str(url or "")


# ─── models ─────────────────────────────────────────────────────
def _network_model(result):
    inv = ip_inventory(result)
    findings = real_findings(result)
    sev_of = {}
    for f in findings:
        for ip in set(re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", str(f.get("evidence", "")))):
            sev_of[ip] = _max_sev(sev_of.get(ip, ""), f.get("severity", ""))
    hosts = {h.get("ip"): h for h in (result.get("network_stats") or {}).get("hosts") or []}
    col_of = {"scan source": 0, "attacker": 0, "client": 0, "origin": 0, "target": 1, "destination": 2}
    nodes, edges = [], []
    for ip, e in inv.items():
        role = e["roles"][0]
        sub = [f"{role} · {e['scope']}"]
        h = hosts.get(ip) or {}
        if h.get("hostname"):
            sub.append(h["hostname"])
        if h.get("open_ports"):
            sub.append(f"{h['open_ports']} open ports")
        nodes.append(_node(f"ip:{ip}", ip, sub, kind="host", role=role, value=ip, field=e["sources"][0],
                           severity=_max_sev(sev_of.get(ip, ""), ROLE_SEV.get(role, "")), col=col_of.get(role, 2)))
    seen = set()
    for f in findings:
        name, ev, sev = f.get("name", ""), str(f.get("evidence", "")), f.get("severity", "")
        if name == "TCP Port Scan Detected" and parse_scan(ev):
            s, d, n = parse_scan(ev)
            edges.append(_edge(f"ip:{s}", f"ip:{d}", f"SYN × {n} ports", severity=sev, value=ev, field=name))
        elif name == "Cleartext Credentials on the Wire" and parse_cleartext(ev):
            p, s, d, _ = parse_cleartext(ev)
            if (s, d, p) not in seen:
                seen.add((s, d, p))
                edges.append(_edge(f"ip:{s}", f"ip:{d}", f"cleartext {p} login", severity=sev, value=ev, field=name))
        elif name == "Traffic to Suspicious Port" and parse_suspicious_port(ev):
            s, d, port, _ = parse_suspicious_port(ev)
            edges.append(_edge(f"ip:{s}", f"ip:{d}", f":{port} callback", severity=sev, value=ev, field=name))
    # open ports (nmap): one node per host:port, flagged ones first
    ports = {}
    for f in findings:
        name, ev = f.get("name", ""), str(f.get("evidence", ""))
        hp = parse_host_port(ev)
        if not hp or hp[1] is None or not name.startswith(("Risky Port Open:", "Vulnerable Service:")):
            continue
        p = ports.setdefault(hp, {"sev": "", "notes": [], "evidence": ev, "finding": name})
        p["sev"] = _max_sev(p["sev"], f.get("severity", ""))
        note = re.sub(r"^(Risky Port Open: \d+/|Vulnerable Service: )", "", name)
        if note not in p["notes"]:
            p["notes"].append(note)
    for prt in (result.get("network_stats") or {}).get("ports") or []:
        hp = (prt.get("host"), prt.get("port"))
        if hp not in ports:
            ports[hp] = {"sev": "", "notes": [], "evidence": f"{prt.get('host')}:{prt.get('port')}", "finding": "network_stats.ports"}
        ports[hp]["service"] = f"{prt.get('port')}/{prt.get('service')}"
        ports[hp]["version"] = prt.get("version", "")
        ports[hp]["state"] = prt.get("state", "open")
    for (ip, port), p in sorted(ports.items(), key=lambda kv: (-SEV_RANK.get(kv[1]["sev"], 0), str(kv[0][0]), kv[0][1] or 0)):
        if f"ip:{ip}" not in {n["id"] for n in nodes}:
            continue
        nid = f"port:{ip}:{port}"
        nodes.append(_node(nid, p.get("service") or f"port {port}", p["notes"][:2] + ([p["version"]] if p.get("version") else []),
                           kind="port", role="open port", severity=p["sev"], value=f"{ip}:{port}", field=p["finding"], col=3))
        edges.append(_edge(f"ip:{ip}", nid, p.get("state", "open"), severity=p["sev"], value=p["evidence"], field=p["finding"]))
    port_nodes = [n for n in nodes if n["kind"] == "port"]
    if not port_nodes:
        return {"type": "network", "title": "Network map", "layout": "columns", "nodes": nodes, "edges": edges}
    # hosts with open ports: each host's ports stacked in the column right of it, starting on the host's row (no crossings)
    sources = [n for n in nodes if n["kind"] == "host" and n["col"] == 0]
    others = [n for n in nodes if n["kind"] == "host" and n["col"] != 0]
    tcol = 1 if sources else 0
    for i, n in enumerate(sources):
        n["col"], n["row"] = 0, i
    row = 0
    ordered = []
    for h in others:
        mine = [p for p in port_nodes if p["value"].rsplit(":", 1)[0] == h["value"]]
        h["col"], h["row"] = tcol, row
        for k, p in enumerate(mine):
            p["col"], p["row"] = tcol + 1, row + k
        ordered += [h] + mine
        row += max(1, len(mine))
    nodes = sources + ordered + [n for n in nodes if n not in sources and n not in ordered]
    return {"type": "network", "title": "Network map", "layout": "grid", "nodes": nodes, "edges": edges}


def _email_model(result):
    fx = result.get("forensics") or {}
    if not fx.get("parsed"):
        return None
    hdr, auth = fx.get("headers") or {}, fx.get("auth") or {}
    names = {f.get("name"): f for f in real_findings(result)}
    nodes, edges, chain = [], [], []
    if hdr.get("From"):
        sev = _max_sev(*(names[n]["severity"] for n in ("Display Name Brand Spoofing", "Suspicious Sender TLD", "Sender Domain Spoofing") if n in names))
        chain.append(_node("from", "From", [hdr["From"]], kind="sender", role="sender", severity=sev, value=hdr["From"], field="forensics.headers.From"))
    if hdr.get("Return-Path"):
        chain.append(_node("rpath", "Return-Path", [hdr["Return-Path"]], kind="sender", role="envelope sender",
                           severity=(names.get("Return-Path / From Mismatch") or {}).get("severity", ""), value=hdr["Return-Path"],
                           field="forensics.headers.Return-Path"))
    hops = fx.get("received_chain") or []
    for i, hop in enumerate(hops, 1):
        h = hop.get("hop", "")
        frm, by = re.search(r"\bfrom\s+(\S+)", h), re.search(r"\bby\s+([^\s;]+)", h)
        sub = [f"from {frm.group(1)}" if frm else "", ", ".join(hop.get("ips") or []), f"by {by.group(1)}" if by else ""]
        chain.append(_node(f"hop{i}", f"Received hop {i}", sub, kind="hop", role="relay", value=h, field=f"forensics.received_chain[{i - 1}]"))
    authserv = (auth.get("raw") or "").split(";")[0].strip()
    rcpt_label = hdr.get("To") or (re.search(r"\bby\s+([^\s;]+)", hops[-1].get("hop", "")).group(1)
                                   if hops and re.search(r"\bby\s+([^\s;]+)", hops[-1].get("hop", "")) else authserv)
    badges = [(k.upper(), v) for k, v in (("spf", auth.get("spf")), ("dkim", auth.get("dkim")), ("dmarc", auth.get("dmarc"))) if v]
    if rcpt_label:
        chain.append(_node("rcpt", "Recipient" if hdr.get("To") else "Receiving server", [rcpt_label], kind="recipient", role="recipient",
                           value=rcpt_label, field="forensics.headers.To" if hdr.get("To") else "forensics.received_chain / auth",
                           badges=badges))
    elif badges and chain:
        chain[-1]["badges"] = badges
    for i, n in enumerate(chain):
        n["col"], n["row"] = i % CHAIN_PER_ROW, (i // CHAIN_PER_ROW) * 2
    nodes.extend(chain)
    for a, b in zip(chain, chain[1:]):
        if a["id"] == "from" and b["id"] == "rpath":
            mm = names.get("Return-Path / From Mismatch")
            edges.append(_edge("from", "rpath", "domain mismatch" if mm else "envelope", severity=(mm or {}).get("severity", ""),
                               value=(mm or {}).get("evidence", hdr.get("Return-Path", "")), field="Return-Path / From Mismatch" if mm else "forensics.headers",
                               dashed=bool(mm)))
        elif b["kind"] == "recipient":
            edges.append(_edge(a["id"], b["id"], "delivered", value=b["value"], field=b["field"]))
        else:
            edges.append(_edge(a["id"], b["id"], "relayed" if a["kind"] == "hop" else "sent via", value=b["value"], field=b["field"]))
    extra_row = (max([n["row"] for n in chain] or [0])) + 1
    if hdr.get("Reply-To"):
        hj = names.get("Reply-To Hijack")
        nodes.append(_node("replyto", "Reply-To", [hdr["Reply-To"]], kind="sender", role="reply address", severity=(hj or {}).get("severity", ""),
                           value=hdr["Reply-To"], field="forensics.headers.Reply-To", col=0, row=extra_row))
        if any(n["id"] == "from" for n in nodes):
            edges.append(_edge("from", "replyto", "Reply-To mismatch" if hj else "Reply-To", severity=(hj or {}).get("severity", ""),
                               value=(hj or {}).get("evidence", hdr["Reply-To"]), field="Reply-To Hijack" if hj else "forensics.headers.Reply-To", dashed=bool(hj)))
    target = "rcpt" if any(n["id"] == "rcpt" for n in nodes) else (chain[-1]["id"] if chain else None)
    col = 1
    for a in (fx.get("attachments") or [])[:3]:
        risky = a.get("double_extension") or a.get("dangerous_ext")
        sev = (names.get("Double-Extension Attachment") or names.get("Risky Attachment Type") or {}).get("severity", "") if risky else ""
        nid = f"att:{a.get('sha256', '')[:12]}"
        nodes.append(_node(nid, f"Attachment {a.get('filename', '')}", ["double extension" if a.get("double_extension") else
                                                                         "risky type" if a.get("dangerous_ext") else a.get("content_type", ""),
                                                                         f"sha256 {str(a.get('sha256', ''))[:16]}…"],
                           kind="payload", role="attachment", severity=sev, value=a.get("filename", ""), field="forensics.attachments", col=col, row=extra_row))
        col += 1
        if target:
            edges.append(_edge(target, nid, "attachment", severity=sev, value=a.get("filename", ""), field="forensics.attachments"))
    for m in (fx.get("html_link_mismatches") or [])[:2]:
        sev = (names.get("Link Text / Destination Mismatch") or {}).get("severity", "")
        nid = f"link:{col}"
        nodes.append(_node(nid, f"Link shows {_host(m.get('shown'))}", [f"opens {m.get('actual', '')}"], kind="payload", role="link mismatch",
                           severity=sev, value=m.get("actual", ""), field="forensics.html_link_mismatches", col=col, row=extra_row))
        col += 1
        if target:
            edges.append(_edge(target, nid, "link mismatch", severity=sev, value=m.get("actual", ""), field="forensics.html_link_mismatches", dashed=True))
    return {"type": "email", "title": "Email delivery path", "layout": "grid", "nodes": nodes, "edges": edges} if nodes else None


def _url_model(result):
    tr = result.get("redirect_trace") or {}
    names = {f.get("name"): f for f in real_findings(result)}
    chain = list(tr.get("chain") or [])
    nodes, edges = [], []
    if not chain and result.get("input"):
        chain = [{"url": result["input"], "status": "", "location": ""}]
    if not chain:
        return None
    shortener_host = (names.get("Shortened URL") or {}).get("evidence", "")
    final_url = tr.get("final_url") or result.get("final_url") or chain[-1].get("location") or chain[-1].get("url")
    risky_final = [n for n in ("Suspicious Redirect Destination", "Newly Registered Domain", "Brand Impersonation", "Suspicious Free TLD",
                               "IP Address in URL") if n in names] + [n for n in names if n.startswith("[")]
    for i, hop in enumerate(chain):
        host = _host(hop.get("url"))
        status = hop.get("status")
        sub = [f"HTTP {status}" if status not in (None, "", "ERR") else ("no response" if status == "ERR" else ""),
               "URL shortener" if shortener_host and host == shortener_host else "", hop.get("url", "")]
        nodes.append(_node(f"hop{i}", host or hop.get("url", ""), sub, kind="hop", role="redirect hop",
                           severity=(names.get("Shortened URL") or {}).get("severity", "") if shortener_host and host == shortener_host else "",
                           value=hop.get("url", ""), field=f"redirect_trace.chain[{i}]"))
    last = chain[-1]
    if last.get("location") and final_url:
        nodes.append(_node("final", _host(final_url), ["final destination", final_url], kind="final", role="final destination",
                           value=final_url, field="redirect_trace.final_url"))
    else:
        nodes[-1]["kind"], nodes[-1]["role"] = "final", "final destination"
        nodes[-1]["sub"].insert(0, "final destination")
    fin = nodes[-1]
    fin["highlight"] = True
    if risky_final:
        fin["severity"] = _max_sev(fin["severity"], *(names[n]["severity"] for n in risky_final))
        fin["sub"].append("flags: " + ", ".join(risky_final[:3]))
    for i, hop in enumerate(chain):
        if hop.get("location"):
            nxt = f"hop{i + 1}" if i + 1 < len(chain) else "final"
            edges.append(_edge(f"hop{i}", nxt, f"{hop.get('status')} redirect", value=hop.get("status"), field=f"redirect_trace.chain[{i}].status"))
    ip = (result.get("domain_info") or {}).get("resolved_ip")
    if ip and re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", str(ip)):
        nodes.append(_node(f"ip:{ip}", ip, ["resolved IP"], kind="host", role="resolved IP", value=ip, field="domain_info.resolved_ip"))
        edges.append(_edge(fin["id"], f"ip:{ip}", "resolves to", value=ip, field="domain_info.resolved_ip"))
    for i, n in enumerate(nodes):
        n["col"], n["row"] = i % CHAIN_PER_ROW, (i // CHAIN_PER_ROW) * 2
    return {"type": "url", "title": "Redirect chain", "layout": "grid", "nodes": nodes, "edges": edges}


def _source_status(s: dict) -> tuple:
    if s.get("available") and s.get("flagged"):
        counts = []
        if s.get("malicious_engines") is not None and s.get("total_engines"):
            counts.append(f"{s['malicious_engines']}/{s['total_engines']} engines")
        if s.get("abuse_score") is not None:
            counts.append(f"abuse score {s['abuse_score']}%")
        if s.get("total_reports"):
            counts.append(f"{s['total_reports']} reports")
        if s.get("pulse_count"):
            counts.append(f"{s['pulse_count']} pulses")
        return "flagged", counts or [mask_secrets(s.get("detail") or "")], "HIGH"
    if s.get("available"):
        return "not flagged", [mask_secrets(s.get("detail") or "")], ""
    if s.get("error"):
        return "lookup failed", [str(s.get("error"))[:60]], ""
    return "not checked", ["no API key configured"], ""


def _reputation_model(result):
    src = result.get("intel_sources") or {}
    ind = str(result.get("input") or "")
    if not ind and not src:
        return None
    nodes = [_node("ind", ind if len(ind) <= 40 else ind[:20] + "…" + ind[-8:],
                   [f"{result.get('mode', '').upper()} · {result.get('verdict', '')}", result.get("country", "") if result.get("country") not in (None, "Unknown") else ""],
                   kind="indicator", role="queried indicator", value=ind, field="input", col=0, row=0, highlight=True,
                   severity={"MALICIOUS": "CRITICAL", "SUSPICIOUS": "MEDIUM"}.get(result.get("verdict"), ""))]
    edges = []
    for i, (key, s) in enumerate(src.items()):
        if not isinstance(s, dict):
            continue
        status, counts, sev = _source_status(s)
        nid = f"src:{key}"
        nodes.append(_node(nid, s.get("source") or key, counts, kind="source", role=status, severity=sev, value=s.get("source") or key,
                           field=f"intel_sources.{key}", col=1, row=i))
        edges.append(_edge("ind", nid, status, severity=sev, value=status, field=f"intel_sources.{key}", dashed=status in ("not checked", "lookup failed")))
    return {"type": result.get("mode", "reputation"), "title": "Reputation sources", "layout": "grid", "nodes": nodes, "edges": edges}


def _logs_model(result):
    ls = result.get("log_stats") or {}
    groups = {}
    for h in ls.get("sample_hits") or []:
        k = (h.get("ip") or "unknown source", h.get("type", ""))
        g = groups.setdefault(k, {"line": h.get("line") or 0, "count": 0, "sev": "", "ts": h.get("ts", ""), "evidence": h.get("evidence", "")})
        g["count"] += 1
        g["sev"] = _max_sev(g["sev"], h.get("severity", ""))
    fails = {}
    for a in ls.get("auth_events") or []:
        if a.get("result") == "failed":
            g = fails.setdefault(a.get("ip"), {"line": a.get("line"), "count": 0, "users": [], "ts": a.get("ts", "")})
            g["count"] += 1
            if a.get("user") not in g["users"]:
                g["users"].append(a.get("user"))
    succ = ls.get("login_after_failures") or []
    if not groups and not fails and not succ and not ls.get("powershell_decoded"):
        return None
    names = {f.get("name"): f for f in real_findings(result)}
    lanes = []
    events = []
    for (ip, typ), g in groups.items():
        events.append({"ip": ip, "id": f"ev:{ip}:{typ}", "label": typ, "line": g["line"], "sev": g["sev"], "ts": g["ts"],
                       "sub": [f"×{g['count']} · line {g['line']}", g["ts"]], "value": typ, "field": "log_stats.sample_hits"})
    for ip, g in fails.items():
        events.append({"ip": ip, "id": f"fail:{ip}", "label": "Failed logins", "line": g["line"], "sev": "MEDIUM", "ts": g["ts"],
                       "sub": [f"×{g['count']} · {', '.join(u for u in g['users'][:3] if u)}", g["ts"]], "value": ip, "field": "log_stats.auth_events"})
    for s in succ:
        events.append({"ip": s.get("ip"), "id": f"ok:{s.get('ip')}:{s.get('line')}", "label": "Login succeeded after failures",
                       "line": s.get("line"), "sev": "CRITICAL", "ts": s.get("ts", ""), "sub": [f"user '{s.get('user')}' · line {s.get('line')}", s.get("ts", "")],
                       "value": s.get("user"), "field": "log_stats.login_after_failures"})
    for d in ls.get("powershell_decoded") or []:
        ip = d.get("ip") or "unknown source"
        events.append({"ip": ip, "id": f"ps:{d.get('line')}", "label": "Decoded PowerShell", "line": d.get("line"), "sev": "CRITICAL",
                       "ts": d.get("ts", ""), "sub": [mask_secrets(d.get("decoded", ""))[:70], f"line {d.get('line')}"], "value": d.get("decoded", ""),
                       "field": "log_stats.powershell_decoded"})
    events.sort(key=lambda e: (e["line"] or 0, -SEV_RANK.get(e["sev"], 0)))
    for e in events:
        if e["ip"] not in lanes:
            lanes.append(e["ip"])
    nodes = []
    for i, ip in enumerate(lanes):
        inv = ip_inventory(result).get(ip, {})
        nodes.append(_node(f"lane:{ip}", ip, [" · ".join(x for x in ((inv.get("roles") or [""])[0], inv.get("scope", "")) if x)],
                           kind="lane", role="source", value=ip, field="log_stats", row=i))
    for e in events:
        nodes.append(_node(e["id"], e["label"], e["sub"], kind="event", role=e["ip"], severity=e["sev"], value=e["value"], field=e["field"],
                           row=lanes.index(e["ip"]), col=e["line"] or 0))
    edges = []
    for s in succ:
        if s.get("ip") in fails:
            f = names.get("Successful Login After Failures") or {}
            edges.append(_edge(f"fail:{s['ip']}", f"ok:{s['ip']}:{s.get('line')}", f"after {fails[s['ip']]['count']} failures", severity="CRITICAL",
                               value=f.get("evidence", s.get("user")), field="Successful Login After Failures"))
    return {"type": "logs", "title": "Log timeline (by attacker and attack type)", "layout": "timeline", "nodes": nodes, "edges": edges}


# ─── capping ────────────────────────────────────────────────────
def _cap(d: dict) -> dict:
    nodes = d["nodes"]
    if len(nodes) <= MAX_NODES:
        return d
    keep_kinds = {"lane", "indicator", "sender", "recipient", "final"}
    must = [n for n in nodes if n["kind"] in keep_kinds]
    rest = sorted([n for n in nodes if n["kind"] not in keep_kinds], key=lambda n: -SEV_RANK.get(n["severity"], 0))
    keep = must + rest[:max(0, MAX_NODES - 1 - len(must))]
    keep_ids = {n["id"] for n in keep}
    dropped = [n for n in nodes if n["id"] not in keep_ids]
    kept = [n for n in nodes if n["id"] in keep_ids]                         # original order
    more = _node("more", f"+{len(dropped)} more", [", ".join(n["label"] for n in dropped[:3]) + (" …" if len(dropped) > 3 else "")],
                 kind="more", role="grouped", value=str(len(dropped)), field="nodes beyond cap",
                 col=max([n["col"] or 0 for n in kept] or [0]) if d["layout"] == "columns" else (dropped[0].get("col") or 0),
                 row=dropped[0].get("row"))
    d["nodes"] = kept + [more]
    d["edges"] = [e for e in d["edges"] if e["from"] in keep_ids and e["to"] in keep_ids]
    d["grouped"] = [n["value"] for n in dropped]
    return d


# ─── SVG rendering ──────────────────────────────────────────────
def _badge_rows(badges) -> list:
    """Pack (label, value) badges into rows that fit inside the node width."""
    rows, cur, used = [], [], 0
    for k, v in badges:
        label = f"{k} {v}"
        w = 10 + len(label) * 7.2
        if cur and used + w > NODE_W - 24:
            rows.append(cur); cur, used = [], 0
        cur.append((k, v, label, w)); used += w + 5
    if cur:
        rows.append(cur)
    return rows


def _box_height(n) -> int:
    lines = len(_wrap(n["label"], 26, 2)) + sum(len(_wrap(s, 32, 2)) for s in n["sub"][:3]) + len(_badge_rows(n["badges"]))
    return PAD * 2 + lines * LINE_H + 4 * bool(n["badges"]) + 2


def _defs(T) -> str:
    marks = "".join(f'<marker id="arr-{k}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
                    f'<path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>' for k, c in [("none", T["edge"])] + list(T["sev"].items()))
    return f"<defs>{marks}</defs>"


def _text(x, y, s, T, size=12, weight=400, color=None, anchor="start", mono=False) -> str:
    fam = f' font-family="{_esc(T["mono"])}"' if mono else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" fill="{color or T["text"]}" '
            f'text-anchor="{anchor}"{fam}>{_esc(s)}</text>')


_KIND_TOKEN = {"hl-ip": "ip", "hl-domain": "domain", "hl-url": "domain", "hl-hash": "hash"}


def _value_style(label: str, T) -> tuple:
    """(colour, mono?) for a node label: IPs cyan, domains/URLs blue, hashes purple (same rules as the UI highlighter)."""
    from utils.highlight import classify
    tok = _KIND_TOKEN.get(classify(label))
    return (T[tok], True) if tok else (None, False)


def _render_box(n, x, y, h, T, lab) -> str:
    sev_c = T["sev"].get(n["severity"]) if n["severity"] else None
    stroke = sev_c or (T["accent"] if n["highlight"] else T["border"])
    sw = 2.2 if (sev_c or n["highlight"]) else 1
    out = [f'<g class="node" data-id="{_esc(n["id"])}"><title>{_esc(lab(n["label"] + (": " + "; ".join(n["sub"]) if n["sub"] else "")))}</title>',
           f'<rect x="{x:.1f}" y="{y:.1f}" width="{NODE_W}" height="{h}" rx="8" fill="{T["node"]}" stroke="{stroke}" stroke-width="{sw}"/>']
    if sev_c:
        out.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="5" height="{h}" rx="2" fill="{sev_c}"/>')
    ty = y + PAD + 11
    vcol, vmono = _value_style(lab(n["label"]), T)
    for line in _wrap(lab(n["label"]), 26, 2):
        out.append(_text(x + 12, ty, line, T, 12.5, 700, vcol, mono=vmono)); ty += LINE_H
    for s in n["sub"][:3]:
        for line in _wrap(lab(s), 32, 2):
            out.append(_text(x + 12, ty, line, T, 12, 400, T["muted"])); ty += LINE_H
    for row in _badge_rows(n["badges"]):
        bx = x + 12
        ty += 2
        for k, v, label, w in row:
            ok = str(v).lower() == "pass"
            c = T["ok"] if ok else T["sev"]["CRITICAL"] if str(v).lower() in ("fail", "permerror", "softfail") else T["sev"]["MEDIUM"]
            out.append(f'<rect x="{bx:.1f}" y="{ty - 11:.1f}" width="{w:.1f}" height="15" rx="7" fill="none" stroke="{c}"/>')
            out.append(_text(bx + 5, ty, label, T, 12, 700, c)); bx += w + 5
        ty += LINE_H
    out.append("</g>")
    return "".join(out)


def _render_edge(e, pos, T, lab, anchors=None, fanout=1) -> tuple:
    """Returns (path_svg, label_svg); labels are drawn after the boxes so no box can hide them."""
    if e["from"] not in pos or e["to"] not in pos:
        return "", ""
    (x1, y1, w1, h1), (x2, y2, w2, h2) = pos[e["from"]], pos[e["to"]]
    c = T["sev"].get(e["severity"], T["edge"])
    mk = e["severity"] if e["severity"] in T["sev"] else "none"
    sfrac, tfrac = (anchors or {}).get("s", 0.5), (anchors or {}).get("t", 0.5)
    if x2 > x1 + w1 / 2:                     # target to the right: spread anchors along each side
        sx, sy, tx, ty = x1 + w1, y1 + h1 * sfrac, x2, y2 + h2 * tfrac
        d = f"M{sx:.1f},{sy:.1f} C{sx + 45:.1f},{sy:.1f} {tx - 45:.1f},{ty:.1f} {tx:.1f},{ty:.1f}"
    elif x2 + w2 < x1 + w1 / 2:              # target to the left (next chain row)
        sx, sy, tx, ty = x1 + w1 / 2, y1 + h1, x2 + w2 / 2, y2
        d = f"M{sx:.1f},{sy:.1f} C{sx:.1f},{sy + 40:.1f} {tx:.1f},{ty - 40:.1f} {tx:.1f},{ty:.1f}"
    else:                                    # same column: top → bottom
        down = y2 > y1
        sx, sy = x1 + w1 / 2, (y1 + h1) if down else y1
        tx, ty = x2 + w2 / 2, y2 if down else (y2 + h2)
        d = f"M{sx:.1f},{sy:.1f} C{sx:.1f},{(sy + ty) / 2:.1f} {tx:.1f},{(sy + ty) / 2:.1f} {tx:.1f},{ty:.1f}"
    dash = ' stroke-dasharray="6 4"' if e["dashed"] else ""
    path = (f'<g class="edge"><title>{_esc(lab(e["label"] + (": " + e["value"] if e["value"] else "")))}</title>'
            f'<path d="{d}" fill="none" stroke="{c}" stroke-width="{2 if e["severity"] else 1.4}"{dash} marker-end="url(#arr-{mk})"/></g>')
    label_svg = ""
    if e["label"]:
        # midpoint normally; near the target end when one node fans out to many (labels would stack at the source)
        nums = [float(v) for v in re.findall(r"-?\d+(?:\.\d+)?", d)]
        (p0x, p0y, c1x, c1y, c2x, c2y, p3x, p3y), t = nums[:8], (0.74 if fanout > 2 and x2 > x1 + w1 / 2 else 0.5)
        mx = (1 - t) ** 3 * p0x + 3 * (1 - t) ** 2 * t * c1x + 3 * (1 - t) * t ** 2 * c2x + t ** 3 * p3x
        my = (1 - t) ** 3 * p0y + 3 * (1 - t) ** 2 * t * c1y + 3 * (1 - t) * t ** 2 * c2y + t ** 3 * p3y
        label = _wrap(lab(e["label"]), 24, 1)[0]
        w = 12 + len(label) * 7
        label_svg = (f'<g class="edge-label"><rect x="{mx - w / 2:.1f}" y="{my - 10:.1f}" width="{w:.1f}" height="17" rx="8" fill="{T["bg"]}" '
                     f'stroke="{c}" stroke-width="1"/>{_text(mx, my + 3, label, T, 12, 600, c, "middle")}</g>')
    return path, label_svg


def _svg_wrap(body, W, H, T, title, desc) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W:.0f} {H:.0f}" width="100%" preserveAspectRatio="xMidYMin meet" '
            f'role="img" aria-labelledby="dg-title dg-desc" font-family="{_esc(T["font"])}" style="max-width:min(100%,{W:.0f}px);height:auto">'
            f'<title id="dg-title">{_esc(title)}</title><desc id="dg-desc">{_esc(desc)}</desc>'
            f'<rect x="0" y="0" width="{W:.0f}" height="{H:.0f}" rx="10" fill="{T["bg"]}"/>{_defs(T)}{body}</svg>')


def _legend(x, y, T, extra=()) -> str:
    parts, cx = [], x
    for k, c in T["sev"].items():
        parts.append(f'<rect x="{cx}" y="{y - 9}" width="10" height="10" rx="2" fill="{c}"/>')
        parts.append(_text(cx + 14, y, k.title(), T, 12, 400, T["muted"])); cx += 24 + len(k) * 6.5
    for label in extra:
        parts.append(f'<line x1="{cx}" y1="{y - 4}" x2="{cx + 22}" y2="{y - 4}" stroke="{T["muted"]}" stroke-dasharray="5 3"/>')
        parts.append(_text(cx + 28, y, label, T, 12, 400, T["muted"])); cx += 40 + len(label) * 6.2
    return "".join(parts)


def _render_grid(d, T, lab) -> str:
    nodes = d["nodes"]
    if d["layout"] == "columns":                          # compact empty role columns, stack rows per column
        cols = sorted({n["col"] for n in nodes})
        remap = {c: i for i, c in enumerate(cols)}
        counters = {}
        for n in nodes:
            n["_c"] = remap[n["col"]]
            n["_r"] = counters.get(n["_c"], 0)
            counters[n["_c"]] = n["_r"] + 1
    else:
        for n in nodes:
            n["_c"], n["_r"] = n["col"] or 0, n["row"] or 0
    ncols = max(n["_c"] for n in nodes) + 1
    row_h = {}
    for n in nodes:
        row_h[(n["_c"], n["_r"])] = _box_height(n)
    pos, top = {}, 52
    if d["layout"] == "columns":
        for n in nodes:
            y = top + sum(row_h.get((n["_c"], r), 0) + ROW_GAP for r in range(n["_r"]))
            pos[n["id"]] = (24 + n["_c"] * (NODE_W + COL_GAP), y, NODE_W, row_h[(n["_c"], n["_r"])])
    else:
        rows = sorted({n["_r"] for n in nodes})
        y_of, y = {}, top
        for r in rows:
            y_of[r] = y
            y += max(row_h[(n["_c"], n["_r"])] for n in nodes if n["_r"] == r) + ROW_GAP + 26
        for n in nodes:
            pos[n["id"]] = (24 + n["_c"] * (NODE_W + COL_GAP), y_of[n["_r"]], NODE_W, row_h[(n["_c"], n["_r"])])
    W = 48 + ncols * NODE_W + (ncols - 1) * COL_GAP
    H = max(y + h for _, y, _, h in pos.values()) + 48
    # spread edge endpoints along each box side (ordered by the other end's y) so parallel edges/labels don't collide
    rightward = [e for e in d["edges"] if e["from"] in pos and e["to"] in pos and pos[e["to"]][0] > pos[e["from"]][0] + NODE_W / 2]
    anchors, out_n, in_n = {}, {}, {}
    for e in rightward:
        out_n.setdefault(e["from"], []).append(e)
        in_n.setdefault(e["to"], []).append(e)
    for nid, es in out_n.items():
        for k, e in enumerate(sorted(es, key=lambda e: pos[e["to"]][1])):
            anchors.setdefault(id(e), {})["s"] = (k + 1) / (len(es) + 1)
    for nid, es in in_n.items():
        for k, e in enumerate(sorted(es, key=lambda e: pos[e["from"]][1])):
            anchors.setdefault(id(e), {})["t"] = (k + 1) / (len(es) + 1)
    rendered = [_render_edge(e, pos, T, lab, anchors.get(id(e)), len(out_n.get(e["from"], []))) for e in d["edges"]]
    body = [_text(24, 30, d["title"], T, 15, 700)]
    body += [p for p, _ in rendered]
    body += [_render_box(n, *pos[n["id"]][:2], pos[n["id"]][3], T, lab) for n in nodes]
    body += [lbl for _, lbl in rendered]
    body.append(_legend(24, H - 18, T, ["mismatch / not checked"] if any(e["dashed"] for e in d["edges"]) else ()))
    return _svg_wrap("".join(body), max(W, 520), H, T, d["title"], f"{len(nodes)} nodes, {len(d['edges'])} connections")


_SHORT_EVENT = [(" (inside encoded payload)", " (encoded)"), ("PowerShell ", "PS: "), ("Cross-Site Scripting (XSS)", "XSS"),
                ("Scanner / Attack-Tool User-Agent", "Scanner user-agent"), ("Web Shell / Sensitive File Probe", "Sensitive-file probe"),
                ("Login succeeded after failures", "Login succeeded"), ("Hidden Window / No Profile", "Hidden window"),
                ("Execution Policy Bypass", "Policy bypass"), ("Server-Side Request Forgery", "SSRF"), ("Log4Shell / JNDI Injection", "Log4Shell")]


def _short_event(label: str) -> str:
    """Display abbreviation of an attack-type value (the full value stays in the tooltip and node data)."""
    for a, b in _SHORT_EVENT:
        label = label.replace(a, b)
    return label


def _render_timeline(d, T, lab) -> str:
    """One row per source; markers in log-line order within the row (L = line number), labels on two tiers."""
    lanes = [n for n in d["nodes"] if n["kind"] == "lane"]
    events = [n for n in d["nodes"] if n["kind"] != "lane"]
    by_lane = {}
    for n in sorted(events, key=lambda n: (n["row"] or 0, n["col"] or 0)):
        by_lane.setdefault(n["row"] or 0, []).append(n)
    max_n = max((len(v) for v in by_lane.values()), default=1)
    left, lane_h, top = 200, 112, 56
    step = 150
    W = max(1000, left + 70 + (max_n - 1) * step + 90)
    body = [_text(24, 30, d["title"], T, 15, 700)]
    pos = {}
    for i, ln in enumerate(lanes):
        y = top + i * lane_h
        body.append(f'<rect x="12" y="{y}" width="{W - 24}" height="{lane_h - 10}" rx="8" fill="{T["lane"]}" stroke="{T["border"]}" stroke-width="0.6"/>')
        vcol, vmono = _value_style(lab(ln["label"]), T)
        body.append(_text(24, y + 30, lab(ln["label"]), T, 12.5, 700, vcol, mono=vmono))
        for s in ln["sub"][:1]:
            body.append(_text(24, y + 46, lab(s), T, 12, 400, T["muted"]))
        body.append(f'<line x1="{left}" y1="{y + 58}" x2="{W - 30}" y2="{y + 58}" stroke="{T["border"]}" stroke-width="1"/>')
    for row, evs in by_lane.items():
        for k, n in enumerate(evs):
            y = top + row * lane_h + 58
            x = left + 50 + k * step
            pos[n["id"]] = (x - 6, y - 6, 12, 12)
            c = T["sev"].get(n["severity"], T["muted"])
            diamond = n["label"] in ("Decoded PowerShell", "Login succeeded after failures")
            shape = (f'<path d="M{x:.1f},{y - 8:.1f} L{x + 8:.1f},{y:.1f} L{x:.1f},{y + 8:.1f} L{x - 8:.1f},{y:.1f} z" fill="{c}"/>' if diamond else
                     f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6.5" fill="{c}" stroke="{T["bg"]}" stroke-width="1.5"/>')
            ly = y - 16 if k % 2 == 0 else y - 32
            line_no = re.search(r"line (\d+)", " ".join(n["sub"]))
            body.append(f'<g class="node" data-id="{_esc(n["id"])}"><title>{_esc(lab(n["label"] + ": " + "; ".join(n["sub"])))}</title>{shape}'
                        f'<line x1="{x:.1f}" y1="{ly + 3:.1f}" x2="{x:.1f}" y2="{y - 8:.1f}" stroke="{c}" stroke-width="0.6" stroke-opacity="0.6"/>'
                        f'{_text(x, ly, _wrap(lab(_short_event(n["label"])), 26, 1)[0], T, 12, 600, c, "middle")}'
                        f'{_text(x, y + 22, "L" + line_no.group(1) if line_no else "", T, 12, 400, T["muted"], "middle")}</g>')
    for e in d["edges"]:
        if e["from"] in pos and e["to"] in pos:
            (x1, y1, _, _), (x2, y2, _, _) = pos[e["from"]], pos[e["to"]]
            c = T["sev"].get(e["severity"], T["edge"])
            body.append(f'<g class="edge"><title>{_esc(lab(e["label"]))}</title><path d="M{x1 + 12:.1f},{y1 + 6:.1f} C{x1 + 40:.1f},{y1 + 40:.1f} '
                        f'{x2 - 30:.1f},{y2 + 40:.1f} {x2:.1f},{y2 + 8:.1f}" fill="none" stroke="{c}" stroke-width="1.8" stroke-dasharray="5 3" '
                        f'marker-end="url(#arr-{e["severity"] if e["severity"] in T["sev"] else "none"})"/>'
                        f'{_text((x1 + x2) / 2, max(y1, y2) + 44, _wrap(lab(e["label"]), 28, 1)[0], T, 12, 600, c, "middle")}</g>')
    H = top + len(lanes) * lane_h + 40
    body.append(_text(W - 24, H - 8, "Ordered by log line within each source · L = line number · ◆ = login success / decoded PowerShell",
                      T, 12, 400, T["muted"], "end"))
    body.append(_legend(24, H - 8, T))
    return _svg_wrap("".join(body), W, H + 6, T, d["title"], f"{len(lanes)} sources, {len(events)} event groups, ordered by log line")


# ─── Mermaid ────────────────────────────────────────────────────
def _mm(s) -> str:
    return (str(s).replace('"', "#quot;").replace("<", "#lt;").replace(">", "#gt;").replace("|", "#124;")
            .replace("[", "#91;").replace("]", "#93;").replace("\n", " "))


def _mermaid(d, lab) -> str:
    ids = {n["id"]: f"n{i}" for i, n in enumerate(d["nodes"])}
    out = ["flowchart LR"]
    if d["layout"] == "timeline":
        for ln in [n for n in d["nodes"] if n["kind"] == "lane"]:
            out.append(f'  subgraph {ids[ln["id"]]}["{_mm(lab(ln["label"]))}"]')
            evs = [n for n in d["nodes"] if n["kind"] != "lane" and n["role"] == ln["value"]]
            for n in evs:
                out.append(f'    {ids[n["id"]]}["{_mm(lab(n["label"]))}<br/>{_mm(lab((n["sub"] or [""])[0]))}"]')
            for a, b in zip(evs, evs[1:]):
                out.append(f"    {ids[a['id']]} --- {ids[b['id']]}")
            out.append("  end")
    else:
        for n in d["nodes"]:
            sub = "<br/>".join(_mm(lab(s)) for s in n["sub"][:2])
            out.append(f'  {ids[n["id"]]}["{_mm(lab(n["label"]))}{"<br/>" + sub if sub else ""}"]')
    for e in d["edges"]:
        if e["from"] in ids and e["to"] in ids:
            arrow = "-.->" if e["dashed"] else "-->"
            out.append(f'  {ids[e["from"]]} {arrow}|"{_mm(lab(e["label"]))}"| {ids[e["to"]]}' if e["label"] else f"  {ids[e['from']]} {arrow} {ids[e['to']]}")
    sev_nodes = {}
    for n in d["nodes"]:
        if n["severity"]:
            sev_nodes.setdefault(n["severity"], []).append(ids[n["id"]])
    for sev, c in THEMES["print"]["sev"].items():
        if sev in sev_nodes:
            out.append(f"  classDef {sev.lower()} stroke:{c},stroke-width:2px")
            out.append(f"  class {','.join(sev_nodes[sev])} {sev.lower()}")
    return "\n".join(out)


# ─── public API ─────────────────────────────────────────────────
EMPTY = {"type": "none", "title": "", "nodes": [], "edges": [], "svg": "", "mermaid": ""}


def build_diagram(result: dict, theme: str = "dark", defang: bool = False) -> dict:
    result = result if isinstance(result, dict) else {}
    builder = {"network": _network_model, "email": _email_model, "url": _url_model, "logs": _logs_model,
               "hash": _reputation_model, "ip": _reputation_model}.get(result.get("mode"))
    d = builder(result) if builder else None
    if not d or not d["nodes"]:
        return dict(EMPTY)
    d = _cap(d)
    T = THEMES.get(theme, THEMES["dark"])
    lab = (lambda s: defang_text(mask_secrets(s))) if defang else mask_secrets
    svg = _render_timeline(d, T, lab) if d["layout"] == "timeline" else _render_grid(d, T, lab)
    # labels AND values pass through mask_secrets (edge values quote evidence such as 'Request: PASS …')
    clean_nodes = [{k: (lab(v) if isinstance(v, str) and k in ("label", "value") else [lab(x) for x in v] if k == "sub" else v)
                    for k, v in n.items() if not k.startswith("_")} for n in d["nodes"]]
    clean_edges = [{**e, "label": lab(e["label"]), "value": lab(e["value"])} for e in d["edges"]]
    return {"type": d["type"], "title": d["title"], "nodes": clean_nodes, "edges": clean_edges, "svg": svg,
            "mermaid": _mermaid(d, lab), "grouped": d.get("grouped", [])}


def build_killchain_svg(result: dict, theme: str = "dark") -> str:
    kc = (result or {}).get("kill_chain") or {}
    stages = kc.get("stages") or []
    if not stages:
        return ""
    T = THEMES.get(theme, THEMES["dark"])
    bw, bh, gap, top = 150, 92, 18, 56
    W = 24 * 2 + len(stages) * bw + (len(stages) - 1) * gap
    furthest = kc.get("furthest_stage", "")
    body = [_text(24, 30, "Kill chain", T, 15, 700),
            _text(W - 24, 30, f"Attacker reached: {furthest}" if furthest else "No kill-chain stage evidenced", T, 12, 600, T["muted"], "end")]
    for i, s in enumerate(stages):
        x = 24 + i * (bw + gap)
        c = T["sev"].get(s.get("max_severity") or "LOW") if s.get("hit") else T["border"]
        op = "1" if s.get("hit") else "0.45"
        glow = f'<rect x="{x - 3}" y="{top - 3}" width="{bw + 6}" height="{bh + 6}" rx="11" fill="none" stroke="{c}" stroke-opacity="0.35" stroke-width="5"/>' if s.get("hit") else ""
        body.append(f'<g class="stage" opacity="{op}"><title>{_esc(s.get("name"))}: {_esc(", ".join(s.get("evidence") or []) or "no evidence")}</title>{glow}'
                    f'<rect x="{x}" y="{top}" width="{bw}" height="{bh}" rx="9" fill="{T["node"]}" stroke="{c}" stroke-width="{2 if s.get("hit") else 1}"/>'
                    f'<rect x="{x}" y="{top}" width="{bw}" height="5" rx="2" fill="{c}"/>'
                    f'{_text(x + 12, top + 24, str(i + 1), T, 12, 600, T["muted"])}')
        for j, line in enumerate(_wrap(s.get("name", ""), 18, 2)):
            body.append(_text(x + 12, top + 42 + j * 15, line, T, 12.5, 700, T["text"] if s.get("hit") else T["muted"]))
        body.append(_text(x + 12, top + bh - 12, f"{len(s.get('evidence') or [])} finding(s)" if s.get("hit") else "no evidence", T, 12, 600,
                          c if s.get("hit") else T["muted"]))
        if s.get("name") == furthest:
            body.append(_text(x + bw - 10, top + 24, "REACHED", T, 12, 800, c, "end"))
        body.append("</g>")
        if i < len(stages) - 1:
            ax = x + bw + 3
            body.append(f'<path d="M{ax},{top + bh / 2} L{ax + gap - 6},{top + bh / 2}" stroke="{T["edge"]}" stroke-width="1.5" marker-end="url(#arr-none)"/>')
    H = top + bh + 34
    return _svg_wrap("".join(body), W, H, T, "Kill chain", f"Furthest stage: {furthest or 'none'}")
