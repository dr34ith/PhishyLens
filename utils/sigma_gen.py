"""
PhishyLens: Sigma rule generator.

    generate_rule(finding, mode)   -> {"title", "id", "yaml", "rules": [dict, ...]}   (raises UnsupportedFinding)
    generate_rules(findings, mode) -> {"rules": [...], "skipped": [...], "yaml": "..."}

Detection content is never invented:
  * PowerShell rules reuse the log analyzer's own regexes (analyzers/log_analyzer.PS_SIGS) via Sigma's |re modifier.
  * Web-attack rules use literal substrings taken from the analyzer's signature alternatives (SIGS).
  * Thresholds come from the analyzers (SCAN_404_THRESHOLD, BRUTE_THRESHOLD, 10 distinct ports for a SYN scan).
References are the ATT&CK URLs of the techniques utils/mitre_map maps the finding to.

Rules follow the Sigma specification v2 (https://github.com/SigmaHQ/sigma-specification): count-based detections
emit a base rule plus a correlation rule (multi-document YAML).
"""
import re
import uuid
from datetime import datetime, timezone

import yaml

from analyzers.log_analyzer import PS_SIGS, SCAN_404_THRESHOLD, BRUTE_THRESHOLD
from utils.mitre_map import techniques_for, load_mitre

PORT_SCAN_DISTINCT_PORTS = 10          # analyzers/network_analyzer.py: len(ports) >= 10
CORRELATION_TIMESPAN = "10m"           # tunable default for count-based rules (the analyzers count over the whole file)
LEVELS = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
ENCODED_SUFFIX = " (inside encoded payload)"
AUTHOR = "PhishyLens (auto-generated)"


class UnsupportedFinding(ValueError):
    """Raised when no honest Sigma rule can be built for a finding type."""


# ─── WEB ATTACKS (webserver taxonomy: cs-uri-query / cs-uri-stem / cs-user-agent) ───
WEB_QUERY_PATTERNS = {
    "SQL Injection": ["union select", "union all select", "' or '1'='1", "information_schema", "mysql.user", "sleep(",
                      "benchmark(", "waitfor delay", "extractvalue(", "updatexml(", "xp_cmdshell", "load_file("],
    "Cross-Site Scripting (XSS)": ["<script", "javascript:", "onerror=", "onload=", "onmouseover=", "<iframe", "<svg",
                                   "document.cookie", "alert(", "String.fromCharCode"],
    "Command Injection": [";cat ", "|cat ", "&&cat ", ";id", "|id", "&&id", ";whoami", "|whoami", "&&whoami", "$(whoami)",
                          "$(id)", "$(curl", "$(wget", ";/bin/sh", "|/bin/sh", ";/bin/bash", "|/bin/bash", "cmd.exe /c", " -e /bin/"],
    "Server-Side Request Forgery": ["=127.0.0.1", "=http://127.0.0.1", "=localhost", "=http://localhost", "=169.254.169.254",
                                    "=http://169.254.169.254", "=0.0.0.0", "=[::1]"],
}
WEB_PATH_PATTERNS = {
    "Path Traversal / LFI": ["../../", "..\\..\\", "/etc/passwd", "/etc/shadow", "/proc/self/environ", "boot.ini", "win.ini",
                             "c:\\windows\\system32", "php://filter", "php://input", "expect://", "file://"],
    "Web Shell / Sensitive File Probe": ["/phpmyadmin", "/.git/config", "/.env", "/.aws/credentials", "/id_rsa", "/web.config",
                                         "/backup.sql", "/shell.php", "/c99.php", "/r57.php", "/cmd.php", "/.htpasswd"],
}
SCANNER_AGENTS = ["sqlmap", "nikto", "nmap", "masscan", "acunetix", "nessus", "wpscan", "dirbuster", "gobuster", "ffuf",
                  "hydra", "havij", "zgrab", "burpcollaborator", "nuclei", "metasploit"]

# ─── POWERSHELL (Windows taxonomy): regex copied from analyzers/log_analyzer.PS_SIGS ───
PS_PATTERNS = {name: rx.pattern for name, _sev, rx, _ref in PS_SIGS}
PS_SCRIPT_BLOCK = {"AMSI / Defender Tampering", "Reflection / In-Memory Loader"}   # usually only visible in script-block logs

# ─── CLEARTEXT CREDENTIALS (network) ───
CLEARTEXT_PORTS = {"FTP": 21, "TELNET": 23, "SMTP": 25, "POP": 110, "IMAP": 143}


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _web(field: str, patterns: list) -> tuple:
    return {"category": "webserver"}, {"selection": {f"{field}|contains": patterns}, "condition": "selection"}


def _base_name(name: str) -> str:
    return name[:-len(ENCODED_SUFFIX)] if name.endswith(ENCODED_SUFFIX) else name


def _detection_for(finding: dict) -> dict:
    """Return {"logsource", "detection", "notes", "correlation"?} or raise UnsupportedFinding."""
    name = finding.get("name", "")
    base = _base_name(name)

    if base in WEB_QUERY_PATTERNS:
        ls, det = _web("cs-uri-query", WEB_QUERY_PATTERNS[base])
        return {"logsource": ls, "detection": det, "notes": "Matches the request query string; web logs that store the URI encoded need URL-decoding first."}
    if base in WEB_PATH_PATTERNS:
        pats = WEB_PATH_PATTERNS[base]
        return {"logsource": {"category": "webserver"},
                "detection": {"selection_stem": {"cs-uri-stem|contains": pats}, "selection_query": {"cs-uri-query|contains": pats},
                              "condition": "1 of selection_*"},
                "notes": "Matches the request path or query string."}
    if base == "Log4Shell / JNDI Injection":
        return {"logsource": {"category": "webserver"},
                "detection": {"keywords": ["${jndi:", "${${", "${lower:", "${upper:"], "condition": "keywords"},
                "notes": "Keyword search: the JNDI lookup can arrive in any logged header or parameter."}
    if base == "Scanner / Attack-Tool User-Agent":
        ls, det = _web("cs-user-agent", SCANNER_AGENTS)
        return {"logsource": ls, "detection": det, "notes": "User-agent strings are trivially spoofed; absence proves nothing."}
    if base == "Directory / Vulnerability Scanning":
        return {"logsource": {"category": "webserver"},
                "detection": {"selection": {"sc-status": 404}, "condition": "selection"},
                "correlation": {"type": "event_count", "group-by": ["c-ip"], "timespan": CORRELATION_TIMESPAN,
                                "condition": {"gte": SCAN_404_THRESHOLD}},
                "notes": f"Base rule matches single 404s; the correlation rule fires at {SCAN_404_THRESHOLD}+ 404s from one client."}
    if base == "SSH / Login Brute Force":
        return {"logsource": {"product": "linux", "service": "sshd"},
                "detection": {"keywords": ["Failed password for", "Failed publickey for", "Invalid user"], "condition": "keywords"},
                "notes": (f"Matches individual failed SSH logins. PhishyLens flags brute force at {BRUTE_THRESHOLD}+ failures from one "
                          "source: aggregate per source IP in your SIEM (raw sshd lines carry no parsed source field).")}
    if base in PS_PATTERNS:
        pattern = "(?i)" + PS_PATTERNS[base]
        if base in PS_SCRIPT_BLOCK or name.endswith(ENCODED_SUFFIX):
            return {"logsource": {"product": "windows", "category": "ps_script"},
                    "detection": {"selection": {"ScriptBlockText|re": pattern}, "condition": "selection"},
                    "notes": "Requires PowerShell Script Block Logging (Event ID 4104), which records decoded script content."}
        return {"logsource": {"product": "windows", "category": "process_creation"},
                "detection": {"selection": {"CommandLine|re": pattern}, "condition": "selection"},
                "notes": "CommandLine regex identical to the PhishyLens log detector."}
    if name == "TCP Port Scan Detected":
        return {"logsource": {"product": "zeek", "service": "conn"},
                "detection": {"selection": {"conn_state": ["S0", "REJ", "RSTOS0", "RSTR", "SH"]}, "condition": "selection"},
                "correlation": {"type": "value_count", "group-by": ["id.orig_h", "id.resp_h"], "timespan": CORRELATION_TIMESPAN,
                                "condition": {"field": "id.resp_p", "gte": PORT_SCAN_DISTINCT_PORTS}},
                "notes": f"Base rule matches unanswered/rejected connection attempts; the correlation fires when one source probes "
                         f"{PORT_SCAN_DISTINCT_PORTS}+ distinct ports on one target."}
    if name == "Cleartext Credentials on the Wire":
        proto = str(finding.get("evidence", "")).split(" ", 1)[0].upper()
        if proto in ("HTTP", "TCP"):
            return {"logsource": {"category": "webserver"},
                    "detection": {"selection": {"cs-uri-query|contains": ["password=", "passwd=", "pwd="]}, "condition": "selection"},
                    "notes": "Credentials in an unencrypted HTTP query string. HTTP Basic auth headers are not in standard web logs."}
        ports = [CLEARTEXT_PORTS[proto]] if proto in CLEARTEXT_PORTS else sorted(CLEARTEXT_PORTS.values())
        return {"logsource": {"category": "firewall"},
                "detection": {"selection": {"dst_port": ports}, "condition": "selection"},
                "notes": f"Flags sessions on cleartext authentication protocol port(s) {', '.join(map(str, ports))}."}
    raise UnsupportedFinding(name)


def supported_finding_names() -> list:
    names = (list(WEB_QUERY_PATTERNS) + list(WEB_PATH_PATTERNS) + ["Log4Shell / JNDI Injection", "Scanner / Attack-Tool User-Agent",
             "Directory / Vulnerability Scanning", "SSH / Login Brute Force"] + list(PS_PATTERNS) +
             ["TCP Port Scan Detected", "Cleartext Credentials on the Wire"])
    return names


def _tags_and_refs(name: str, mode: str) -> tuple:
    data = load_mitre()
    ids = techniques_for(name, mode) or []
    tags, refs = [], []
    for tid in ids:
        t = data.get(tid)
        if not t:
            continue
        for short in t.get("tactic_shortnames", []):
            tag = f"attack.{short}"
            if tag not in tags:
                tags.append(tag)
        tags.append(f"attack.{tid.lower()}")
        refs.append(t["url"])
    return tags, refs


def generate_rule(finding: dict, mode: str = "") -> dict:
    if not isinstance(finding, dict) or not str(finding.get("name", "")).strip():
        raise UnsupportedFinding("finding must be an object with a 'name'")
    name = str(finding["name"]).strip()
    spec = _detection_for({**finding, "name": name})
    tags, refs = _tags_and_refs(name, mode)
    rule_id = str(uuid.uuid4())
    evidence = str(finding.get("evidence") or "").replace("\n", " ")[:240]
    description = f"Detects activity matching the PhishyLens {_base_name(name)} detection ({mode or 'analyzer'} module). {spec['notes']}"
    if evidence:
        description += f" Observed evidence: {evidence}"
    fp = str(finding.get("false_positive_possibility") or "").strip()
    rule = {
        "title": f"PhishyLens - {name}",
        "id": rule_id,
        "name": f"phishylens_{_slug(name)}",
        "status": "experimental",
        "description": description,
        "references": refs or ["https://attack.mitre.org/"],
        "author": AUTHOR,
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "tags": tags,
        "logsource": spec["logsource"],
        "detection": spec["detection"],
        "falsepositives": [fp] if fp and fp.upper() != "N/A" else ["Unknown"],
        "level": LEVELS.get(str(finding.get("severity", "")).upper(), "medium"),
    }
    docs = [rule]
    if spec.get("correlation"):
        corr = {"title": f"PhishyLens - {name} (correlation)", "id": str(uuid.uuid4()), "status": "experimental",
                "description": f"Aggregates '{rule['title']}' events. {spec['notes']}",
                "references": rule["references"], "author": AUTHOR, "date": rule["date"], "tags": tags,
                "correlation": {"type": spec["correlation"]["type"], "rules": [rule["name"]], **{k: v for k, v in spec["correlation"].items() if k != "type"}},
                "falsepositives": rule["falsepositives"], "level": rule["level"]}
        docs.append(corr)
    text = yaml.safe_dump_all(docs, sort_keys=False, allow_unicode=True, width=1000, default_flow_style=False)
    return {"finding": name, "title": rule["title"], "id": rule_id, "yaml": text, "rules": docs}


def generate_rules(findings: list, mode: str = "") -> dict:
    rules, skipped, seen = [], [], set()
    for f in findings or []:
        if not isinstance(f, dict):
            skipped.append({"finding": "", "reason": "Not a finding object."})
            continue
        name = str(f.get("name", ""))
        key = (name, str(f.get("evidence", "")).split(" ", 1)[0].upper() if name == "Cleartext Credentials on the Wire" else "")
        if key in seen:
            continue
        seen.add(key)
        try:
            rules.append(generate_rule(f, mode))
        except UnsupportedFinding:
            skipped.append({"finding": name, "reason": "No Sigma template for this finding type."})
    return {"rules": rules, "skipped": skipped, "yaml": "---\n".join(r["yaml"] for r in rules)}
