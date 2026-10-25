"""
PhishyLens: Advanced Log Threat Detector (Phase 1)

Parses Syslog / auth.log, Nginx / Apache access logs, and JSON (NDJSON or array) logs, plus
PowerShell / Windows event text, and flags SQLi, XSS, path traversal, command injection,
scanner user-agents, SSH brute force and malicious PowerShell (encoded commands, execution bypass,
download cradles, AMSI bypass). Pure-Python, offline.
"""
import base64
import json
import re
import time
import uuid
import urllib.parse
from collections import Counter, defaultdict

from utils.scoring import calculate_score, score_to_verdict, attach_explanation, build_risk_breakdown, correlate_evidence
from utils.logger import get_logger

log = get_logger("logs")

MAX_LINES = 20000
MAX_BYTES = 4_000_000          # Vercel request body limit is 4.5 MB

# ─── LOG FORMAT PATTERNS ───────────────────────────────────────
NGINX_RE = re.compile(
    r'^(?P<ip>[\da-fA-F:.]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+HTTP/[\d.]+)?"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?')
SYSLOG_RE = re.compile(
    r'^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s[\d:]{8})|(?:\d{4}-\d{2}-\d{2}T[\d:.+\-Z]+))\s+(?P<host>\S+)\s+(?P<proc>[\w./\-]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$')
IP_RE = re.compile(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
SSH_FAIL_RE = re.compile(r'Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)')
SSH_INVALID_RE = re.compile(r'Invalid user (\S+) from ([\d.]+)')
SSH_OK_RE = re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)')

# ─── ATTACK SIGNATURES (applied to URL-decoded, lower-cased text) ───
SIGS = [
    # name, severity, regex, MITRE / ref
    ("SQL Injection", "CRITICAL",
     re.compile(r"(\bunion\b[\s/*+]+(?:all[\s/*+]+)?select\b|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|'\s*or\s*'1'\s*=\s*'1|\bselect\b.+\bfrom\b.+\b(information_schema|users|mysql\.user)\b|"
                r"\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\(|\bwaitfor\s+delay\b|\bextractvalue\s*\(|\bupdatexml\s*\(|;\s*(drop|insert|update|delete)\s+\w+|'\s*(?:--|#)|\d\s*--(?:\s|$)|/\*!\d*|\bxp_cmdshell\b|\bload_file\s*\()", re.I),
     "T1190 / CWE-89"),
    ("Cross-Site Scripting (XSS)", "HIGH",
     re.compile(r"(<\s*script|javascript\s*:|\bon(?:error|load|click|mouseover|focus)\s*=|<\s*img[^>]+src\s*=\s*['\"]?x|<\s*svg[^>]*on\w+\s*=|<\s*iframe|document\.cookie|alert\s*\(|String\.fromCharCode)", re.I),
     "T1189 / CWE-79"),
    ("Path Traversal / LFI", "HIGH",
     re.compile(r"(\.\./\.\./|\.\.\\\.\.\\|/etc/passwd|/etc/shadow|/proc/self/environ|boot\.ini|win\.ini|c:\\windows\\system32|php://(?:filter|input)|expect://|file://)", re.I),
     "T1083 / CWE-22"),
    ("Command Injection", "CRITICAL",
     re.compile(r"((?:[;|`]|&&)\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh|powershell|cmd)\b(?![=\-.])|\$\((?:cat|id|whoami|curl|wget|uname)\b|"
                r"\bcmd(?:\.exe)?\b[^\n]{0,20}?\s/[ck]\s|(?:[;|`]|&&|\$\()\s*/bin/(?:ba)?sh\b|\b(?:nc|ncat|netcat)\b[^\n]{0,30}\s-e\s+/bin/)", re.I),
     "T1059 / CWE-78"),
    ("Log4Shell / JNDI Injection", "CRITICAL", re.compile(r"\$\{(?:jndi|\$\{|lower|upper):", re.I), "CVE-2021-44228"),
    ("Server-Side Request Forgery", "HIGH",
     re.compile(r"(?:url|uri|redirect|dest|path|file|src)=(?:https?://)?(?:127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0|\[::1\])", re.I), "T1190 / CWE-918"),
    ("Web Shell / Sensitive File Probe", "HIGH",
     re.compile(r"(/(?:phpmyadmin|\.git/config|\.env|\.aws/credentials|id_rsa|web\.config|backup\.sql|shell\.php|c99\.php|r57\.php|cmd\.php|\.htpasswd)\b)", re.I), "T1505.003"),
    ("Scanner / Attack-Tool User-Agent", "MEDIUM",
     re.compile(r"(sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|ffuf|hydra|havij|zgrab|burpcollaborator|nuclei|metasploit)", re.I), "T1595"),
]

PS_SIGS = [
    ("PowerShell Encoded Command", "CRITICAL", re.compile(r"-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", re.I), "T1059.001 / T1027"),
    ("PowerShell Execution Policy Bypass", "HIGH", re.compile(r"-(?:ep|exec|executionpolicy)\s+(?:bypass|unrestricted)|set-executionpolicy\s+(?:bypass|unrestricted)", re.I), "T1059.001"),
    ("PowerShell Hidden Window / No Profile", "MEDIUM", re.compile(r"-(?:w|win|window|windowstyle)\s+(?:h|hidden)|-(?:nop|noprofile)\b|-noni\b", re.I), "T1564.003"),
    ("PowerShell Download Cradle", "CRITICAL", re.compile(r"(?:iex|invoke-expression)\s*\(?.*?(?:downloadstring|downloadfile|net\.webclient|invoke-webrequest|iwr|invoke-restmethod)|downloadstring\s*\(|start-bitstransfer|certutil(?:\.exe)?\s+-urlcache", re.I), "T1105 / T1059.001"),
    ("AMSI / Defender Tampering", "CRITICAL", re.compile(r"amsiutils|amsiinitfailed|set-mppreference\s+-disablerealtimemonitoring|add-mppreference\s+-exclusion", re.I), "T1562.001"),
    ("Reflection / In-Memory Loader", "HIGH", re.compile(r"\[reflection\.assembly\]::load|frombase64string\s*\(|virtualalloc|add-type\s+-memberdefinition", re.I), "T1620"),
    ("LOLBin Proxy Execution", "HIGH", re.compile(r"(?:mshta|regsvr32|rundll32|wmic|bitsadmin)(?:\.exe)?\s+.*?(?:http|scrobj\.dll|javascript:|process\s+call\s+create)", re.I), "T1218"),
]

BRUTE_THRESHOLD = 5      # failed logins from one IP
SCAN_404_THRESHOLD = 15  # 404s from one IP


# ─── LINE PARSING ──────────────────────────────────────────────
def _decode_variants(text: str) -> str:
    """URL-decode up to twice and lower-case so %27%20OR%201=1 and double-encoded payloads match."""
    t = text
    for _ in range(2):
        try:
            nt = urllib.parse.unquote_plus(t)
        except Exception:
            break
        if nt == t:
            break
        t = nt
    return t


def decode_ps_encoded(cmdline: str) -> str:
    """Decode the base64 (UTF-16LE) blob of a PowerShell -EncodedCommand argument."""
    m = re.search(r"-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", cmdline, re.I)
    if not m:
        return ""
    try:
        raw = base64.b64decode(m.group(1) + "=" * (-len(m.group(1)) % 4))
        return raw.decode("utf-16le", errors="ignore") if b"\x00" in raw else raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _parse_line(line: str, fmt_hint: str = ""):
    """Return (format, fields-dict). fields: ip, ts, method, path, status, ua, msg, user, raw."""
    s = line.strip()
    if not s:
        return None, None
    if s.startswith("{") or fmt_hint == "json":
        try:
            o = json.loads(s)
            flat = _flatten(o)
            pick = lambda *keys: next((str(flat[k]) for k in keys if k in flat and flat[k] not in (None, "")), "")
            return "json", {
                "ip": pick("remote_addr", "client_ip", "clientip", "src_ip", "source.ip", "ip", "remoteip", "c-ip", "sourceipaddress", "host.ip"),
                "ts": pick("timestamp", "@timestamp", "time", "ts", "eventtime", "datetime", "date"),
                "method": pick("method", "request_method", "http.request.method", "verb"),
                "path": pick("path", "uri", "url", "request", "request_uri", "http.request.path", "cs-uri-stem"),
                "status": pick("status", "response_code", "http.response.status_code", "statuscode", "sc-status"),
                "ua": pick("user_agent", "useragent", "http_user_agent", "http.user_agent", "agent"),
                "user": pick("user", "username", "user.name", "targetusername", "account"),
                "msg": pick("message", "msg", "commandline", "scriptblocktext", "command_line", "process.command_line", "event.original"),
                "raw": s,
            }
        except Exception:
            pass
    m = NGINX_RE.match(s)
    if m:
        d = m.groupdict()
        return "nginx/apache", {"ip": d["ip"], "ts": d["ts"], "method": d["method"], "path": d["path"], "status": d["status"],
                                "ua": d.get("ua") or "", "user": d["user"] if d["user"] != "-" else "", "msg": "", "raw": s}
    m = SYSLOG_RE.match(s)
    if m:
        d = m.groupdict()
        ip = (IP_RE.search(d["msg"]) or [None])[0] if IP_RE.search(d["msg"]) else ""
        return "syslog", {"ip": ip or "", "ts": d["ts"], "method": "", "path": "", "status": "", "ua": "", "user": "", "msg": d["msg"], "proc": d["proc"], "raw": s}
    # generic text line (PowerShell history, Windows event text export, etc.)
    ip = IP_RE.search(s)
    return "text", {"ip": ip.group(0) if ip else "", "ts": "", "method": "", "path": "", "status": "", "ua": "", "user": "", "msg": s, "raw": s}


def _flatten(o, prefix=""):
    out = {}
    if isinstance(o, dict):
        for k, v in o.items():
            key = f"{prefix}{k}".lower()
            if isinstance(v, dict):
                out.update(_flatten(v, key + "."))
            else:
                out[key] = v
                out.setdefault(str(k).lower(), v)
    return out


def _iter_lines(text: str):
    t = text.lstrip()
    if t.startswith("["):                                      # JSON array of events
        try:
            arr = json.loads(t)
            if isinstance(arr, list):
                for o in arr:
                    yield json.dumps(o) if isinstance(o, dict) else str(o)
                return
        except Exception:
            pass
    for ln in text.splitlines():
        yield ln


# ─── MAIN ANALYZER ─────────────────────────────────────────────
def analyze_logs(text) -> dict:
    start = time.time()
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8", errors="replace")
    if len(text) > MAX_BYTES:
        text = text[:MAX_BYTES]

    formats, hits = Counter(), []
    by_ip = defaultdict(lambda: {"requests": 0, "hits": 0, "failed_logins": 0, "invalid_users": 0, "status_404": 0, "attacks": set(), "users": set()})
    ssh_success_after_fail, fail_ips = [], set()
    auth_events = []                       # every parsed SSH login attempt (time, IP, user, failed/accepted) for the timeline
    status_codes = Counter()
    ps_decoded = []
    total = parsed = 0
    truncated = False

    for lineno, line in enumerate(_iter_lines(text), 1):
        if lineno > MAX_LINES:
            truncated = True
            break
        if not line.strip():
            continue
        total += 1
        fmt, f = _parse_line(line)
        if not f:
            continue
        parsed += 1
        formats[fmt] += 1
        ip = f["ip"]
        if ip:
            by_ip[ip]["requests"] += 1
        if f["status"]:
            status_codes[f["status"]] += 1
            if f["status"] == "404" and ip:
                by_ip[ip]["status_404"] += 1

        # SSH auth patterns (syslog / auth.log)
        if fmt in ("syslog", "text"):
            msg = f["msg"]
            # sshd logs "Invalid user x" AND "Failed password for invalid user x" for one attempt: count them
            # separately and take the max so a single attempt is not double-counted
            for rx, counter in ((SSH_FAIL_RE, "failed_logins"), (SSH_INVALID_RE, "invalid_users")):
                m = rx.search(msg)
                if m:
                    by_ip[m.group(2)][counter] += 1
                    by_ip[m.group(2)]["users"].add(m.group(1))
                    fail_ips.add(m.group(2))
                    if counter == "failed_logins":
                        auth_events.append({"line": lineno, "ts": f.get("ts", ""), "ip": m.group(2), "user": m.group(1), "result": "failed"})
                    break
            m = SSH_OK_RE.search(msg)
            if m:
                auth_events.append({"line": lineno, "ts": f.get("ts", ""), "ip": m.group(2), "user": m.group(1), "result": "accepted"})
            if m and m.group(2) in fail_ips:
                ssh_success_after_fail.append({"ip": m.group(2), "user": m.group(1), "line": lineno, "ts": f.get("ts", "")})

        # attack signature scan: URL/path/UA/msg (decoded)
        extra_raw = f.get("raw", "") if fmt == "json" or (fmt == "syslog" and f.get("raw") != f["msg"]) else ""
        haystack = _decode_variants(" ".join(x for x in (f["path"], f["ua"], f["msg"], extra_raw) if x)).lower() if fmt else ""
        for name, sev, rx, ref in SIGS:
            if rx.search(haystack):
                hits.append({"line": lineno, "ts": f.get("ts", ""), "ip": ip, "type": name, "severity": sev, "ref": ref, "evidence": _evidence(f, rx, haystack)})
                if ip:
                    by_ip[ip]["hits"] += 1
                    by_ip[ip]["attacks"].add(name)
        # PowerShell scan on raw (not lower-cased: base64 is case-sensitive)
        raw_dec = f["msg"] or f["raw"]
        if re.search(r"powershell|pwsh|iex|invoke-expression|amsi|downloadstring|certutil|mshta|regsvr32|rundll32|frombase64", raw_dec, re.I):
            for name, sev, rx, ref in PS_SIGS:
                if rx.search(raw_dec):
                    ev = rx.search(raw_dec).group(0)[:140]
                    hit = {"line": lineno, "ts": f.get("ts", ""), "ip": ip, "type": name, "severity": sev, "ref": ref, "evidence": ev}
                    if name == "PowerShell Encoded Command":
                        dec = decode_ps_encoded(raw_dec)
                        if dec:
                            hit["decoded"] = dec[:400]
                            ps_decoded.append({"line": lineno, "ts": f.get("ts", ""), "ip": ip, "decoded": dec[:400]})
                            # inspect what the encoded blob actually does (download cradle, AMSI bypass, ...)
                            for n2, s2, rx2, r2 in PS_SIGS[1:]:
                                m2 = rx2.search(dec)
                                if m2:
                                    hits.append({"line": lineno, "ts": f.get("ts", ""), "ip": ip, "type": n2 + " (inside encoded payload)", "severity": s2,
                                                 "ref": r2, "evidence": m2.group(0)[:140]})
                    hits.append(hit)

    # ─── aggregate behavioural detections ─────────────────────
    for d in by_ip.values():
        d["failed_logins"] = max(d["failed_logins"], d.pop("invalid_users"))
    behaviour = []
    for ip, d in by_ip.items():
        if d["failed_logins"] >= BRUTE_THRESHOLD:
            behaviour.append(("SSH / Login Brute Force", "HIGH" if d["failed_logins"] < 20 else "CRITICAL", ip,
                              f"{d['failed_logins']} failed logins ({len(d['users'])} distinct user(s): {', '.join(sorted(d['users']))[:80]})", "T1110"))
        if d["status_404"] >= SCAN_404_THRESHOLD:
            behaviour.append(("Directory / Vulnerability Scanning", "MEDIUM", ip, f"{d['status_404']} HTTP 404 responses from one source", "T1595.002"))
    for s in ssh_success_after_fail[:3]:
        behaviour.append(("Successful Login After Failures", "CRITICAL", s["ip"], f"Accepted login for '{s['user']}' (line {s['line']}) after failed attempts; possible compromise", "T1078"))

    findings = []
    grouped = defaultdict(list)
    for h in hits:
        grouped[(h["type"], h["severity"], h["ref"])].append(h)
    for (name, sev, ref), items in grouped.items():
        ips = sorted({i["ip"] for i in items if i["ip"]})
        findings.append({
            "severity": sev, "name": name, "evidence": f"{len(items)} hit(s); first at line {items[0]['line']}: {items[0]['evidence'][:110]}",
            "description": f"{name} pattern matched in {len(items)} log line(s) from {len(ips) or 'unknown'} source(s).",
            "confidence": 85 if sev in ("CRITICAL", "HIGH") else 65,
            "why_it_matters": "Signature match on request/command content indicates an active attack attempt or post-exploitation activity.",
            "recommendation": "Review the flagged lines, block offending IPs, and verify the target was not exploited (check response codes / follow-on activity).",
            "false_positive_possibility": "Low–Medium: pentests and vulnerability scanners generate identical traffic.",
            "reference": ref, "lines": [i["line"] for i in items[:25]], "sources": ips[:10]})
    for name, sev, ip, ev, ref in behaviour:
        findings.append({
            "severity": sev, "name": name, "evidence": f"{ip}: {ev}", "description": f"{name} behaviour from {ip}.", "confidence": 80,
            "why_it_matters": "Volume-based behaviour reveals automated attacks that single-line signatures miss.",
            "recommendation": "Block/rate-limit the source and enforce MFA / key-based auth.", "false_positive_possibility": "Low–Medium.",
            "reference": ref, "sources": [ip]})

    if not findings:
        findings.append({"severity": "LOW", "name": "No Indicators Detected", "evidence": f"{parsed} lines parsed",
                         "description": "No attack signatures or abusive behaviour matched.", "confidence": 15,
                         "why_it_matters": "Signature detection cannot find novel techniques.", "recommendation": "Correlate with other telemetry.",
                         "false_positive_possibility": "N/A", "reference": ""})

    # enrichment of attacker IPs (public only, top offenders)
    attackers = sorted(((ip, d) for ip, d in by_ip.items() if d["hits"] or d["failed_logins"] >= BRUTE_THRESHOLD), key=lambda x: -(x[1]["hits"] + x[1]["failed_logins"]))
    enrichment = {"ips": [], "hashes": [], "skipped_private": []}
    try:
        from utils.threat_intel import enrich_indicators
        enrichment = enrich_indicators([ip for ip, _ in attackers[:5]], [])
        findings.extend(enrichment.pop("findings", []))
    except Exception as e:
        log.error("log enrichment failed: %s", e)

    score = calculate_score(findings) if any(f["name"] != "No Indicators Detected" for f in findings) else 5
    verdict = score_to_verdict(score)
    top_ips = [{"ip": ip, "requests": d["requests"], "attack_hits": d["hits"], "failed_logins": d["failed_logins"],
                "attack_types": sorted(d["attacks"])} for ip, d in sorted(by_ip.items(), key=lambda x: -(x[1]["hits"] * 5 + x[1]["failed_logins"] * 3 + x[1]["requests"]))[:10]]
    timeline = [
        {"step": "Format Detection", "status": "complete", "detail": ", ".join(f"{k}: {v}" for k, v in formats.items()) or "none"},
        {"step": "Signature Scan", "status": "complete", "detail": f"{len(hits)} signature hit(s) across {parsed} lines"},
        {"step": "Behavioural Analysis", "status": "complete", "detail": f"{len(behaviour)} behavioural detection(s)"},
        {"step": "Risk Assessment", "status": "complete", "detail": f"Risk score: {score}% ({verdict})"},
    ]
    result = {
        "verdict": verdict, "score": score, "mode": "logs", "input": f"{total} log lines ({', '.join(formats) or 'unknown format'})",
        "scan_id": str(uuid.uuid4())[:8].upper(), "findings": findings, "timeline": timeline,
        "risk_breakdown": build_risk_breakdown(findings), "evidence_correlation": correlate_evidence(findings, "logs"),
        "summary": f"Parsed {parsed}/{total} lines ({', '.join(formats) or 'unknown'}). {len(hits)} attack signature hit(s), {len(behaviour)} behavioural detection(s).",
        "recommended_action": {"MALICIOUS": "Block attacker IPs, preserve logs, and investigate affected hosts for compromise.",
                               "SUSPICIOUS": "Review flagged lines and correlate with endpoint/WAF telemetry.",
                               "BENIGN": "No malicious activity detected in the supplied logs."}[verdict],
        "confidence": min(95, 55 + len(hits)), "duration_ms": int((time.time() - start) * 1000),
        "iocs": {"ips": [i["ip"] for i in top_ips if i["attack_hits"] or i["failed_logins"]], "urls": [], "emails": [], "domains": [], "hashes": []},
        "log_stats": {"total_lines": total, "parsed_lines": parsed, "formats": dict(formats), "status_codes": dict(status_codes.most_common(8)),
                      "top_sources": top_ips, "attack_counts": dict(Counter(h["type"] for h in hits)),
                      "powershell_decoded": ps_decoded[:10], "sample_hits": hits[:40],
                      "auth_events": auth_events[:60], "login_after_failures": ssh_success_after_fail[:10],
                      "truncated": truncated},
        "enrichment": enrichment,
    }
    return attach_explanation(result)


def _evidence(f: dict, rx, haystack: str) -> str:
    m = rx.search(haystack)
    if not m:
        return (f["path"] or f["msg"])[:120]
    a = max(0, m.start() - 25)
    return haystack[a:m.end() + 40].strip()[:160]
