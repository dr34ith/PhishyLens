"""
PhishyLens: MITRE ATT&CK mapping.

Maps analyzer finding names to Enterprise ATT&CK technique IDs and builds result["mitre"].
Technique text (name, tactics, description, detection, mitigations, url) always comes from
static/mitre.json, which scripts/build_mitre.py generates from MITRE's STIX bundle: nothing
here restates ATT&CK content.

A finding maps to [] when it is not adversary behaviour (informational rows, "not found",
reputation-only hits, hash-type detection). tests/test_mitre.py fails if any ID below is missing
from mitre.json, or if an analyzer emits a finding name that is not covered here.
"""
import json
import os
import re
from functools import lru_cache

from utils.logger import get_logger

log = get_logger("mitre")
MITRE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "mitre.json")

# ─── EXACT FINDING NAME → TECHNIQUE IDS ─────────────────────────
FINDING_TECHNIQUES = {
    # URL / phishing infrastructure (utils/threat_intel.py, analyzers/url_analyzer.py)
    "IP Address in URL":                 ["T1566.002", "T1204.001"],
    "Suspicious Free TLD":               ["T1583.001"],
    "Excessive Subdomains":              ["T1583.001"],
    "Newly Registered Domain":           ["T1583.001"],
    "Brand Impersonation":               ["T1684.001", "T1566.002"],
    "Deceptive Keywords Detected":       ["T1598.003"],
    "Shortened URL":                     ["T1608.005"],
    "Redirect Chain Detected":           ["T1608.005"],
    "Suspicious Redirect Destination":   ["T1566.002", "T1204.001"],

    # Email (analyzers/email_analyzer.py)
    "Missing Sender Authentication":     ["T1684.002"],
    "SPF Authentication Failed":         ["T1684.002"],
    "DKIM Authentication Failed":        ["T1684.002"],
    "DMARC Authentication Failed":       ["T1684.002"],
    "Return-Path / From Mismatch":       ["T1684.002"],
    "Reply-To Hijack":                   ["T1684.002"],
    "DKIM Domain Not Aligned":           ["T1684.002"],
    "Sender Domain Spoofing":            ["T1684.002"],
    "Suspicious Sender TLD":             ["T1583.001", "T1566"],
    "Display Name Brand Spoofing":       ["T1684.001", "T1684.002"],
    "Suspicious URL in Body":            ["T1566.002", "T1204.001"],
    "Malicious URL in Body":             ["T1566.002", "T1204.001"],
    "Link Text / Destination Mismatch":  ["T1566.002", "T1204.001"],
    "Urgency / Pressure Manipulation":   ["T1566"],
    "Urgency Manipulation":              ["T1566"],
    "Double-Extension Attachment":       ["T1036.007", "T1566.001", "T1204.002"],
    "Risky Attachment Type":             ["T1566.001", "T1204.002"],
    "Attachment Hash Known Malicious":   ["T1566.001", "T1204.002"],

    # Logs (analyzers/log_analyzer.py SIGS / PS_SIGS / behaviour)
    "SQL Injection":                     ["T1190"],
    "Cross-Site Scripting (XSS)":        ["T1189"],
    "Path Traversal / LFI":              ["T1190", "T1083"],
    "Command Injection":                 ["T1190", "T1059"],
    "Log4Shell / JNDI Injection":        ["T1190"],
    "Server-Side Request Forgery":       ["T1190"],
    "Web Shell / Sensitive File Probe":  ["T1505.003", "T1595.003"],
    "Scanner / Attack-Tool User-Agent":  ["T1595.002"],
    "PowerShell Encoded Command":        ["T1059.001", "T1027.010"],
    "PowerShell Execution Policy Bypass": ["T1059.001"],
    "PowerShell Hidden Window / No Profile": ["T1564.003"],
    "PowerShell Download Cradle":        ["T1105", "T1059.001"],
    "AMSI / Defender Tampering":         ["T1685"],
    "Reflection / In-Memory Loader":     ["T1620"],
    "LOLBin Proxy Execution":            ["T1218"],
    "SSH / Login Brute Force":           ["T1110"],
    "Directory / Vulnerability Scanning": ["T1595.003"],
    "Successful Login After Failures":   ["T1110", "T1078"],

    # Network (analyzers/network_analyzer.py)
    "Large Attack Surface":              ["T1046"],
    "Suspicious Listener Port":          ["T1571"],
    "End-of-Life Operating System":      ["T1190", "T1210"],
    "TCP Port Scan Detected":            ["T1046"],
    "ICMP Ping Sweep":                   ["T1018"],
    "ARP Flood / Possible Spoofing":     ["T1557.002"],
    "Possible DNS Tunnelling":           ["T1071.004"],
    "Cleartext Credentials on the Wire": ["T1040"],
    "Traffic to Suspicious Port":        ["T1571"],

    # Hash (analyzers/hash_analyzer.py): a known-bad file implies malicious-file delivery
    "Hash Matches Known Malware (Local Database)": ["T1204.002"],

    # IP (utils/threat_intel.lookup_ip)
    "Proxy/VPN Detected":                ["T1090"],
    "Hosting/Datacenter IP":             ["T1583.003"],
    "ThreatFox: Active IOC Match":       ["T1071"],

    # Not adversary behaviour → intentionally unmapped
    "No Indicators Detected":            [],
    "Unencrypted Channel":               [],   # weakness of the site, not a technique
    "Invalid Hash Format":               [],
    "Empty File Hash":                   [],
    "Not Found in Threat Databases":     [],
    "Hash Provenance Unknown":           [],
    "Private IP Address":                [],
    "No Threat Intelligence Hits":       [],
    "Reputation Not Checked":            [],
    "AbuseIPDB: Abuse History Confirmed": [],  # reputation lists say "bad", not which behaviour
    "AlienVault OTX: Found in Threat Pulses": [],
    "Extracted IP Has Bad Reputation":   [],
}

# ─── DYNAMIC NAMES (f-strings in the analyzers) ─────────────────
# Risky Port Open: {port}/{service}
REMOTE_SERVICE_PORTS = {
    23: ["T1021", "T1133"], 512: ["T1021", "T1133"], 513: ["T1021", "T1133"], 514: ["T1021", "T1133"],
    3389: ["T1021.001", "T1133"], 139: ["T1021.002"], 445: ["T1021.002", "T1210"], 135: ["T1021"],
    5900: ["T1021.005", "T1133"], 5985: ["T1021.006"], 2375: ["T1133"], 5555: ["T1133"],
    4444: ["T1571"], 1337: ["T1571"], 31337: ["T1571"], 6667: ["T1571"],
}
DEFAULT_EXPOSED_SERVICE = ["T1190"]          # databases, RMI, AJP, FTP, NFS, SNMP, ... reachable from the network

PATTERN_TECHNIQUES = [
    # (regex, ids, modes the rule applies to; None = any)
    (re.compile(r"^(SPF|DKIM|DMARC|ARC) (Not Passing|Authentication Failed)$"), ["T1684.002"], None),
    (re.compile(r"^Vulnerable Service: "), ["T1190"], None),
    (re.compile(r"^NSE Finding: "), ["T1190"], None),
    (re.compile(r"^Hash Type Identified: "), [], None),
    (re.compile(r"^\[[^\]]+\] Hash Confirmed Malicious$"), ["T1204.002"], None),
    (re.compile(r"^VirusTotal: Flagged by \d+ Engines?$"), [], None),              # IP reputation
    # "[VirusTotal] Flagged as Malicious" / "[urlscan.io] Flagged as Malicious"; URL vs file depends on mode
    (re.compile(r"^\[[^\]]+\] (Flagged as Malicious|Low Detection Count)$"), ["T1204.002"], {"hash"}),
    (re.compile(r"^\[[^\]]+\] (Flagged as Malicious|Low Detection Count)$"), ["T1566.002", "T1204.001"], None),
]
RISKY_PORT_RE = re.compile(r"^Risky Port Open: (\d+)/")
ENCODED_SUFFIX = " (inside encoded payload)"

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# technique confidence: strongest supporting finding, +5 per additional independent finding (max +15), cap 95
CONFIDENCE_CAP = 95
CONFIDENCE_BOOST_PER_FINDING = 5
CONFIDENCE_BOOST_MAX = 15
SEVERITY_DEFAULT_CONFIDENCE = {"CRITICAL": 80, "HIGH": 70, "MEDIUM": 55, "LOW": 35}   # only when a finding has no confidence


def technique_confidence(supporting: list) -> tuple:
    """(confidence 0-95, one-line explanation) from the findings that support one technique.
    'Independent' = distinct finding names (different detectors); repeats of one detector do not boost."""
    best = {}
    for f in supporting:
        name = f.get("name", "")
        raw = f.get("confidence")
        try:
            c, defaulted = (int(raw), False) if raw not in (None, "") else (SEVERITY_DEFAULT_CONFIDENCE.get(f.get("severity", "LOW"), 35), True)
        except (TypeError, ValueError):
            c, defaulted = SEVERITY_DEFAULT_CONFIDENCE.get(f.get("severity", "LOW"), 35), True
        c = max(0, min(100, c))
        if name not in best or c > best[name][0]:
            best[name] = (c, defaulted)
    if not best:
        return 0, "No supporting findings."
    ranked = sorted(best.items(), key=lambda kv: kv[1][0], reverse=True)
    top_name, (top_c, top_def) = ranked[0]
    extra = len(ranked) - 1
    boost = min(CONFIDENCE_BOOST_MAX, CONFIDENCE_BOOST_PER_FINDING * extra) if extra else 0
    total = min(CONFIDENCE_CAP, top_c + boost)
    why = f"Strongest supporting finding: {top_name} ({top_c}%{', severity default' if top_def else ''})."
    if extra:
        why += (f" +{boost} for {extra} more independent finding{'s' if extra != 1 else ''} "
                f"({', '.join(n for n, _ in ranked[1:4])}{' …' if extra > 3 else ''}).")
    else:
        why += " No corroborating finding, so no boost."
    if top_c + boost > CONFIDENCE_CAP:
        why += f" Capped at {CONFIDENCE_CAP}."
    return total, why


@lru_cache(maxsize=1)
def load_mitre() -> dict:
    try:
        with open(MITRE_PATH, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as e:                                # never break analysis over a missing data file
        log.error("cannot load %s: %s", MITRE_PATH, e)
        return {"_meta": {"tactics": []}}


def techniques_for(name: str, mode: str = "") -> list | None:
    """Technique IDs for a finding name; [] = deliberately unmapped; None = unknown finding name."""
    if name in FINDING_TECHNIQUES:
        return list(FINDING_TECHNIQUES[name])
    if name.endswith(ENCODED_SUFFIX):                      # log_analyzer: PS signature found inside a decoded -EncodedCommand
        base = techniques_for(name[:-len(ENCODED_SUFFIX)], mode)
        return None if base is None else list(dict.fromkeys(base + ["T1027.010"]))
    m = RISKY_PORT_RE.match(name)
    if m:
        return list(REMOTE_SERVICE_PORTS.get(int(m.group(1)), DEFAULT_EXPOSED_SERVICE))
    for rx, ids, modes in PATTERN_TECHNIQUES:
        if (modes is None or mode in modes) and rx.match(name):
            return list(ids)
    return None


def all_mapped_ids() -> set:
    ids = {i for v in FINDING_TECHNIQUES.values() for i in v}
    ids |= {i for v in REMOTE_SERVICE_PORTS.values() for i in v} | set(DEFAULT_EXPOSED_SERVICE)
    ids |= {i for _, v, _ in PATTERN_TECHNIQUES for i in v} | {"T1027.010"}
    return ids


def _short(name: str) -> str:
    """'Brute Force' -> 'brute force', 'Non-Standard Port' -> 'non-standard port'; keeps 'PowerShell', 'DNS', 'SMB/Windows'."""
    def word(w):
        if "/" in w:
            return w
        return "-".join(p.lower() if p[:1].isupper() and p[1:].islower() else p for p in w.split("-"))
    return " ".join(word(w) for w in name.split(" "))


def _summary(steps: list) -> str:
    if not steps:
        return ""
    parts = [f"{tactic} via {' and '.join(_short(n) for n in names[:2])}" for tactic, names in steps[:4]]
    s = parts[0]
    if len(parts) > 1:
        s += ", followed by " + parts[1]
    for p in parts[2:]:
        s += ", then " + p
    if len(steps) > 4:
        s += f", plus {len(steps) - 4} more tactic(s)"
    return s[0].upper() + s[1:]


def build_mitre(findings: list, mode: str = "") -> dict:
    """result['mitre'] = {techniques[], tactics_hit[], kill_chain_stage, attack_summary, ...}."""
    data = load_mitre()
    tactic_order = [t["name"] for t in data.get("_meta", {}).get("tactics", [])]
    rank = {t: i for i, t in enumerate(tactic_order)}

    techs, order, unknown, support = {}, [], set(), {}
    for f in findings or []:
        name = f.get("name", "")
        ids = techniques_for(name, mode)
        if ids is None:
            unknown.add(name)
            continue
        for tid in ids:
            t = data.get(tid)
            if not t:
                log.error("mapped technique %s for %r missing from mitre.json", tid, name)
                continue
            if tid not in techs:
                tactics = sorted(t["tactics"], key=lambda x: rank.get(x, 99))
                techs[tid] = {
                    "id": tid,
                    "name": f"{t['parent_name']}: {t['name']}" if t.get("parent_name") else t["name"],
                    "short_name": t["name"],
                    "tactic": tactics[0] if tactics else "",
                    "tactics": tactics,
                    "tactic_shortnames": t.get("tactic_shortnames", []),
                    "description": t["description"],
                    "detection": t["detection"],
                    "mitigations": t["mitigations"],
                    "platforms": t.get("platforms", []),
                    "url": t["url"],
                    "evidence_findings": [],
                    "max_severity": "LOW",
                }
                order.append(tid)
            tech = techs[tid]
            support.setdefault(tid, []).append(f)
            if name not in tech["evidence_findings"]:
                tech["evidence_findings"].append(name)
            sev = f.get("severity", "LOW")
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(tech["max_severity"], 0):
                tech["max_severity"] = sev
    if unknown:
        log.warning("no ATT&CK mapping for finding(s): %s", ", ".join(sorted(unknown)))

    for tid, tech in techs.items():
        tech["confidence"], tech["confidence_explanation"] = technique_confidence(support.get(tid, []))
    techniques = [techs[i] for i in order]
    tactics_hit = sorted({t for x in techniques for t in x["tactics"]}, key=lambda x: rank.get(x, 99))

    # narrative: primary tactic of each technique, in the order the evidence appeared
    # sub-technique names repeat across parents (T1566.002 / T1598.003 are both "Spearphishing Link"): use the parent then
    short_counts = {}
    for x in techniques:
        short_counts[x["short_name"]] = short_counts.get(x["short_name"], 0) + 1
    steps, seen = [], {}
    for x in techniques:
        label = x["short_name"]
        if short_counts[label] > 1 and data[x["id"]].get("parent_name"):
            label = data[x["id"]]["parent_name"]
        if x["tactic"] not in seen:
            seen[x["tactic"]] = len(steps)
            steps.append((x["tactic"], []))
        if label not in steps[seen[x["tactic"]]][1]:
            steps[seen[x["tactic"]]][1].append(label)

    return {
        "techniques": techniques,
        "tactics_hit": tactics_hit,
        "kill_chain_stage": tactics_hit[-1] if tactics_hit else "",      # furthest tactic reached in matrix order
        "attack_summary": _summary(steps),
        "tactic_order": tactic_order,
        "attack_version": data.get("_meta", {}).get("attack_version", ""),
        "unmapped_findings": sorted(unknown),
    }


def attach_mitre(result: dict, mode: str = "") -> dict:
    """Adds result['mitre'] (idempotent; never raises)."""
    try:
        result["mitre"] = build_mitre(result.get("findings", []), mode or result.get("mode", ""))
    except Exception as e:
        log.error("ATT&CK mapping failed: %s", e)
    return result
