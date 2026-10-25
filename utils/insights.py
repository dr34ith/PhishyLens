"""
PhishyLens: result insights derived from data the analyzers already produced.

  attach_classification(result)  → result["classification"]  {primary, secondary[], confidence, rationale}
  attach_kill_chain(result)      → result["kill_chain"]      {stages: [{name, hit, evidence[]}], furthest_stage}
  attach_malware_family(result)  → result["malware_family"]  {name, source, first_seen, tags[]} or None

Everything here is computed from result["findings"] and result["mitre"]; no new threat data is fetched
or invented.
"""
from utils.logger import get_logger

log = get_logger("insights")

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
INFORMATIONAL = {"No Indicators Detected"}
# tactics that support an attack rather than name it; a phishing email's spoofed headers (Stealth) should not
# out-rank the phishing itself (Initial Access) just because there are more header findings
SUPPORTING_TACTICS = {"Stealth", "Defense Evasion", "Defense Impairment", "Resource Development"}


def _family(tech: dict) -> str:
    """'Phishing: Spearphishing Link' -> 'Phishing' (classification is per technique family, not sub-technique)."""
    return tech.get("name", "").split(": ")[0]


def _finding_confidence(findings: list, names: set) -> int:
    vals = [int(f.get("confidence") or 0) for f in findings if f.get("name") in names]
    return max(vals) if vals else 0


def build_classification(result: dict) -> dict:
    findings = result.get("findings") or []
    techs = (result.get("mitre") or {}).get("techniques") or []

    # group techniques into "Tactic - Technique family" labels
    groups = {}
    for t in techs:
        label = f"{t.get('tactic') or 'Unknown Tactic'} - {_family(t)}"
        g = groups.setdefault(label, {"label": label, "ids": [], "evidence": [], "rank": 0, "tactic": t.get("tactic", ""),
                                       "confidence": 0})
        g["ids"].append(t["id"])
        for e in t.get("evidence_findings", []):
            if e not in g["evidence"]:
                g["evidence"].append(e)
        g["rank"] = max(g["rank"], SEVERITY_RANK.get(t.get("max_severity", "LOW"), 1))
        g["confidence"] = max(g["confidence"], int(t.get("confidence") or 0))

    if not groups:
        real = [f for f in findings if f.get("name") not in INFORMATIONAL]
        if not real or result.get("verdict") == "BENIGN":
            return {"primary": "No Attack Pattern Identified", "secondary": [],
                    "confidence": int(result.get("confidence") or 0),
                    "rationale": "No finding mapped to a MITRE ATT&CK technique"
                                 + (f"; {len(real)} informational/reputation finding(s) only." if real else ".")}
        names = [f.get("name", "") for f in real]
        return {"primary": "Unmapped Suspicious Activity", "secondary": [],
                "confidence": _finding_confidence(real, set(names)),
                "rationale": f"{len(real)} finding(s) ({', '.join(names[:3])}) did not map to an ATT&CK technique."}

    for g in groups.values():
        if not g["confidence"]:                       # technique confidence not computed yet → strongest supporting finding
            g["confidence"] = _finding_confidence(findings, set(g["evidence"]))
    ranked = sorted(groups.values(), key=lambda g: (g["rank"], g["tactic"] not in SUPPORTING_TACTICS, len(g["evidence"]), g["confidence"]),
                    reverse=True)
    top = ranked[0]
    sev = next((s for s, r in SEVERITY_RANK.items() if r == top["rank"]), "LOW")
    ev = top["evidence"]
    rationale = (f"{len(ev)} finding(s): {', '.join(ev[:3])}{' …' if len(ev) > 3 else ''}: map to "
                 f"{', '.join(top['ids'][:3])} under {top['tactic']}; strongest evidence is {sev}.")
    from utils.story import hedged, _soften
    if hedged(result):                               # not MALICIOUS or intel flags only: a technique is never stated as fact
        rationale = (f"Possible: {len(ev)} finding(s): {_soften(', '.join(ev[:3]))}{' …' if len(ev) > 3 else ''}: consistent with "
                     f"{', '.join(top['ids'][:3])} under {top['tactic']}; strongest evidence is {sev}.")
    return {
        "primary": top["label"],
        "secondary": [g["label"] for g in ranked[1:4]],
        "confidence": min(int(top["confidence"]), 95),
        "rationale": rationale,
        "techniques": top["ids"],
    }


# ─── KILL CHAIN ──────────────────────────────────────────────────
KILL_CHAIN_STAGES = ["Reconnaissance", "Delivery", "Exploitation", "Persistence", "Command & Control", "Actions on Objectives"]

# ATT&CK tactic → kill-chain stage. Uses each technique's PRIMARY tactic only, so one multi-tactic technique
# (e.g. T1078 Valid Accounts) cannot light up several stages at once.
TACTIC_TO_STAGE = {
    "Reconnaissance": "Reconnaissance",
    "Resource Development": "Reconnaissance",       # attacker preparation (domains, infrastructure) before delivery
    "Discovery": "Reconnaissance",                  # scans / sweeps observed in logs and captures
    "Initial Access": "Delivery",
    "Execution": "Exploitation",
    "Privilege Escalation": "Exploitation",
    "Credential Access": "Exploitation",
    "Stealth": "Exploitation",
    "Defense Evasion": "Exploitation",              # pre-v19 bundles
    "Defense Impairment": "Exploitation",
    "Lateral Movement": "Exploitation",             # exposure of remote services ≠ objectives reached
    "Persistence": "Persistence",
    "Command and Control": "Command & Control",
    "Collection": "Actions on Objectives",
    "Exfiltration": "Actions on Objectives",
    "Impact": "Actions on Objectives",
}
# in email / URL triage, spoofing, impersonation, masquerading and User Execution (T1204: a link/attachment waiting to be
# clicked) are part of getting the lure delivered; nothing in the artifact shows it was opened
DELIVERY_MODE_STEALTH = {"email", "url"}


def build_kill_chain(result: dict) -> dict:
    mode = result.get("mode", "")
    techs = (result.get("mitre") or {}).get("techniques") or []
    stages = {s: {"name": s, "hit": False, "evidence": [], "techniques": [], "max_severity": ""} for s in KILL_CHAIN_STAGES}
    for t in techs:
        tactic = t.get("tactic", "")
        stage = TACTIC_TO_STAGE.get(tactic)
        if mode in DELIVERY_MODE_STEALTH and (tactic in ("Stealth", "Defense Evasion") or t["id"].startswith("T1204")):
            stage = "Delivery"      # spoofing / masquerading / a lure awaiting the user's click: the attack is at delivery
        if not stage:
            continue
        st = stages[stage]
        st["hit"] = True
        st["techniques"].append(t["id"])
        for e in t.get("evidence_findings", []):
            if e not in st["evidence"]:
                st["evidence"].append(e)
        sev = t.get("max_severity", "LOW")
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(st["max_severity"], 0):
            st["max_severity"] = sev
    ordered = [stages[s] for s in KILL_CHAIN_STAGES]
    hit = [s["name"] for s in ordered if s["hit"]]
    return {"stages": ordered, "furthest_stage": hit[-1] if hit else ""}


def attach_kill_chain(result: dict) -> dict:
    try:
        result["kill_chain"] = build_kill_chain(result)
    except Exception as e:
        log.error("kill chain failed: %s", e)
    return result


# ─── MALWARE FAMILY ──────────────────────────────────────────────
def build_malware_family(result: dict) -> dict | None:
    """result["malware_family"] = {name, source, first_seen, tags[], indicator, matches[]}: only when ThreatFox or
    MalwareBazaar actually returned a family for one of the result's indicators; otherwise None (never guessed)."""
    from utils.threat_intel import malware_family_from_sources
    matches = []
    direct = malware_family_from_sources(result.get("intel_sources") or {})       # url / hash / ip analyses
    if direct:
        matches.append({**direct, "indicator": str(result.get("input") or "")})
    enr = result.get("enrichment") or {}
    for rep in (enr.get("hashes") or []) + (enr.get("ips") or []):                # email / logs / network enrichment
        fam = rep.get("malware_family") if isinstance(rep, dict) else None
        if fam and fam.get("name"):
            matches.append({**fam, "indicator": rep.get("indicator", "")})
    if not matches:
        return None
    top = matches[0]
    return {"name": top["name"], "source": top["source"], "first_seen": top.get("first_seen", ""),
            "tags": top.get("tags", []), "indicator": top["indicator"],
            "matches": [{"indicator": m["indicator"], "name": m["name"], "source": m["source"]} for m in matches]}


def attach_malware_family(result: dict) -> dict:
    try:
        result["malware_family"] = build_malware_family(result)
    except Exception as e:
        log.error("malware family extraction failed: %s", e)
        result["malware_family"] = None
    return result


def attach_classification(result: dict) -> dict:
    try:
        result["classification"] = build_classification(result)
    except Exception as e:
        log.error("classification failed: %s", e)
    return result
