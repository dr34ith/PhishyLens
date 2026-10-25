"""
PhishyLens v2
analyzers/hash_analyzer.py: File Hash Risk Analyzer
"""

import re
import uuid
import time
from utils.threat_intel import lookup_hash, intel_checks, check

# NOTE: the hashes of an EMPTY file (MD5 d41d8cd9…, SHA1 da39a3ee…, SHA256 e3b0c442…) used to be listed
# here, which produced a false MALICIOUS verdict for any zero-byte file. They are now handled separately.
EMPTY_FILE_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

KNOWN_MALICIOUS = {
    # EICAR antivirus test file (harmless, but detected as malware by design)
    "44d88612fea8a8f36de82e1278abb02f",
    "3395856ce81f2b7382dee72602f798b642f14140",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
}

KNOWN_CLEAN = {
    "8277e0910d750195b448797616e091ad76c25b36a8fdbb960b63bf74fdba94b4",
}

MD5_RE    = re.compile(r'^[a-fA-F0-9]{32}$')
SHA1_RE   = re.compile(r'^[a-fA-F0-9]{40}$')
SHA256_RE = re.compile(r'^[a-fA-F0-9]{64}$')


def analyze_hash(hash_value: str) -> dict:
    start      = time.time()
    hash_value = hash_value.strip().lower()
    findings   = []

    if MD5_RE.match(hash_value):
        hash_type = "MD5"
    elif SHA1_RE.match(hash_value):
        hash_type = "SHA-1"
    elif SHA256_RE.match(hash_value):
        hash_type = "SHA-256"
    else:
        return _result(
            "SUSPICIOUS", 50, hash_value,
            [{"severity": "MEDIUM", "name": "Invalid Hash Format",
              "evidence": hash_value[:20] + "...",
              "description": "Input does not match MD5, SHA-1, or SHA-256 format.",
              "confidence": 99,
              "why_it_matters": "Unrecognized hash formats cannot be looked up in threat intelligence databases.",
              "recommendation": "Verify the hash value and resubmit.",
              "false_positive_possibility": "N/A", "reference": ""}],
            "Hash format unrecognized. Cannot proceed with analysis.",
            {}, int((time.time() - start) * 1000)
        )

    findings.append({
        "severity":    "LOW",
        "name":        f"Hash Type Identified: {hash_type}",
        "evidence":    hash_value[:16] + "...",
        "description": f"Input identified as a {hash_type} cryptographic hash.",
        "confidence":  99,
        "why_it_matters": f"{hash_type} is a standard file fingerprinting algorithm. The hash uniquely identifies file content.",
        "recommendation": "Cross-reference with threat intelligence databases to determine file reputation.",
        "false_positive_possibility": "N/A",
        "reference": "",
    })

    intel          = lookup_hash(hash_value)
    intel_findings = intel.get("intel_findings", [])
    intel_sources  = intel.get("intel_sources", {})
    duration_ms    = int((time.time() - start) * 1000)

    if any(f.get("severity") == "CRITICAL" for f in intel_findings):
        findings = intel_findings + findings
        return _result("MALICIOUS", 94, hash_value, findings,
                       f"{hash_type} hash confirmed malicious by threat intelligence.",
                       intel_sources, duration_ms, local=None)

    if hash_value in EMPTY_FILE_HASHES:
        findings.insert(0, {
            "severity": "LOW", "name": "Empty File Hash", "evidence": hash_value[:16] + "...",
            "description": "This is the hash of a zero-byte file; it identifies no real content.",
            "confidence": 99, "why_it_matters": "Zero-byte files are harmless but can indicate failed downloads, wiped payloads or placeholder artifacts.",
            "recommendation": "Verify the original file was not truncated or wiped.", "false_positive_possibility": "N/A", "reference": "",
        })
        return _result("BENIGN", 5, hash_value, findings,
                       f"{hash_type} hash is the well-known digest of an empty (0-byte) file.",
                       intel_sources, duration_ms, local=None)

    if hash_value in KNOWN_MALICIOUS:
        findings.insert(0, {
            "severity":    "CRITICAL",
            "name":        "Hash Matches Known Malware (Local Database)",
            "evidence":    hash_value[:16] + "...",
            "description": "File fingerprint confirmed malicious in the local threat database.",
            "confidence":  95,
            "why_it_matters": "This exact file has been previously identified as malware. Hash matches are cryptographically precise.",
            "recommendation": "Quarantine the file immediately. Do not execute. Initiate incident response.",
            "false_positive_possibility": "Very low: hash collisions for these algorithms are computationally infeasible.",
            "reference": "Local threat database",
        })
        return _result("MALICIOUS", 92, hash_value, findings,
                       f"{hash_type} hash confirmed malicious at 92% confidence.",
                       intel_sources, duration_ms, local="flagged")

    if hash_value in KNOWN_CLEAN:
        return _result("BENIGN", 5, hash_value, findings,
                       f"{hash_type} hash matches a known-good file.",
                       intel_sources, duration_ms)

    if intel_findings:                       # only low-confidence hits (e.g. 1–2 VirusTotal engines)
        findings = intel_findings + findings
        return _result("SUSPICIOUS", 55, hash_value, findings,
                       f"{hash_type} hash has low-confidence detections; corroborate before treating as malware.",
                       intel_sources, duration_ms)

    # only sources that returned a real answer count; failed / unauthorised lookups are NOT evidence of a clean file
    available_sources = [s for s in intel_sources.values() if s.get("available")]
    failed_sources    = [s for s in intel_sources.values() if s.get("error")]

    if available_sources:
        findings.append({
            "severity":    "LOW",
            "name":        "Not Found in Threat Databases",
            "evidence":    hash_value[:16] + "...",
            "description": f"Checked {len(available_sources)} source(s): no malicious record found.",
            "confidence":  70,
            "why_it_matters": "Absence from threat databases suggests the file is either clean or novel. Novel malware may not yet appear in databases.",
            "recommendation": "If file origin is unknown, perform behavioral analysis in a sandbox environment.",
            "false_positive_possibility": "Medium: new malware samples may not yet be catalogued.",
            "reference": "",
        })
        return _result("BENIGN", 12, hash_value, findings,
                       f"{hash_type} hash not found in {len(available_sources)} threat intelligence source(s). Likely clean.",
                       intel_sources, duration_ms)

    # No API keys / every lookup failed; unknown provenance
    why_unknown = ("Every configured lookup failed (" + "; ".join(f"{s.get('source')}: {s.get('error')}" for s in failed_sources[:3]) + ")."
                   if failed_sources else "No threat intelligence sources are configured.")
    findings.append({
        "severity":    "MEDIUM",
        "name":        "Hash Provenance Unknown",
        "evidence":    hash_value[:16] + "...",
        "description": why_unknown + " File provenance cannot be determined.",
        "confidence":  40,
        "why_it_matters": "Without threat intelligence data, file safety cannot be confirmed. Configure VIRUSTOTAL_API_KEY and/or ABUSECH_API_KEY (MalwareBazaar + ThreatFox).",
        "recommendation": "Upload the file hash to VirusTotal manually, or analyze in a sandboxed environment.",
        "false_positive_possibility": "N/A",
        "reference": "https://www.virustotal.com",
    })
    return _result("SUSPICIOUS", 45, hash_value, findings,
                   f"{hash_type} hash; provenance unknown. Configure threat intel API keys for definitive results.",
                   intel_sources, duration_ms)


def _result(verdict, score, value, findings, summary, intel_sources=None, duration_ms=0, local="clear"):
    checks = intel_checks(intel_sources or {})
    if local:                                        # None: the local list was never consulted on this path
        checks = [check("Local malware list", local)] + checks
    if any(f.get("name") == "Invalid Hash Format" for f in findings):
        checks = [check("Hash format", "flagged")]
    return {
        "checks":         checks,
        "verdict":        verdict,
        "score":          score,
        "mode":           "hash",
        "input":          value,
        "findings":       findings,
        "summary":        summary,
        "intel_sources":  intel_sources or {},
        "scan_id":        str(uuid.uuid4())[:8].upper(),
        "confidence":     80 if any(s.get("available") for s in (intel_sources or {}).values()) else 40,
        "duration_ms":    duration_ms,
        "recommended_action": {
            "MALICIOUS":  "Quarantine the file immediately. Do not execute. Initiate incident response procedures.",
            "SUSPICIOUS": "Treat with caution. Analyze in a sandboxed environment before execution.",
            "BENIGN":     "No immediate action required. Standard security practices apply.",
        }.get(verdict, "Exercise caution."),
    }
