VERDICT_MALICIOUS  = "MALICIOUS"
VERDICT_SUSPICIOUS = "SUSPICIOUS"
VERDICT_BENIGN     = "BENIGN"

# Legacy aliases (DB backward compat)
VERDICT_GUILTY  = VERDICT_MALICIOUS
VERDICT_POI     = VERDICT_SUSPICIOUS
VERDICT_CLEARED = VERDICT_BENIGN

# Score thresholds
MALICIOUS_THRESHOLD  = 65
BENIGN_THRESHOLD     = 30

# Severity → weight
SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH":     16,
    "MEDIUM":    8,
    "LOW":       3,
}

# Risk category weights (must sum to 100)
RISK_CATEGORIES = {
    "url_structure":       {"label": "URL Structure",         "weight": 20},
    "domain_intelligence": {"label": "Domain Intelligence",   "weight": 25},
    "threat_intelligence": {"label": "Threat Intelligence",   "weight": 25},
    "ssl_certificate":     {"label": "SSL / TLS",             "weight": 10},
    "redirects":           {"label": "Redirects",             "weight": 10},
    "keywords":            {"label": "Keyword Analysis",      "weight": 10},
}

# Finding name → risk category mapping
FINDING_CATEGORY_MAP = {
    "IP Address in URL":               "url_structure",
    "Suspicious Free TLD":             "url_structure",
    "Excessive Subdomains":            "url_structure",
    "Unencrypted Channel":             "ssl_certificate",
    "Brand Impersonation":             "url_structure",
    "Deceptive Keywords Detected":     "keywords",
    "Missing Sender Authentication":   "domain_intelligence",
    "Urgency Manipulation":            "keywords",
    "Malicious URL in Body":           "threat_intelligence",
    "Suspicious URL in Body":          "threat_intelligence",
    "Sender Domain Spoofing":          "domain_intelligence",
}


def score_to_verdict(score: int) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return VERDICT_MALICIOUS
    if score <= BENIGN_THRESHOLD:
        return VERDICT_BENIGN
    return VERDICT_SUSPICIOUS


def calculate_score(findings: list) -> int:
    if not findings:
        return 5
    raw = sum(SEVERITY_WEIGHTS.get(f.get("severity", "LOW"), 3) for f in findings)
    score = min(int(raw * 1.8), 97)
    return max(score, 2)


def build_risk_breakdown(findings: list) -> list:
    """Return per-finding score breakdown rows."""
    rows = []
    for f in findings:
        sev = f.get("severity", "LOW")
        pts = SEVERITY_WEIGHTS.get(sev, 3)
        rows.append({
            "source":   f.get("name", "Unknown"),
            "detail":   f.get("evidence", ""),
            "severity": sev,
            "points":   f"+{pts}",
            "flagged":  sev in ("CRITICAL", "HIGH"),
            "category": FINDING_CATEGORY_MAP.get(f.get("name", ""), "threat_intelligence"),
        })
    return rows


def build_score_breakdown(findings: list) -> list:
    """Legacy alias."""
    return build_risk_breakdown(findings)


def correlate_evidence(findings: list, mode: str = "phishing") -> list:
    """
    Group findings into threat scenarios (evidence correlation).
    `mode` is "logs" / "network" for forensic artifacts (no phishing framing); anything else = phishing context.
    Returns a list of correlation objects.
    """
    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count     = sum(1 for f in findings if f.get("severity") == "HIGH")
    names          = {f.get("name", "") for f in findings}
    forensic       = mode in ("logs", "network")

    correlations = []

    if "Brand Impersonation" in names and ("Deceptive Keywords Detected" in names or "IP Address in URL" in names):
        correlations.append({
            "scenario": "Credential Harvesting Campaign",
            "confidence": "HIGH",
            "description": "Brand impersonation combined with deceptive keywords or direct IP usage is a hallmark of credential phishing infrastructure.",
            "indicators": [n for n in ("Brand Impersonation", "Deceptive Keywords Detected", "IP Address in URL") if n in names],
            "mitre": "T1566.002: Spearphishing Link",
        })

    disposable = names & {"Suspicious Free TLD", "Suspicious Sender TLD"}
    urgency    = names & {"Urgency / Pressure Manipulation", "Urgency Manipulation"}
    if disposable and urgency:
        correlations.append({
            "scenario": "Social Engineering via Disposable Domain",
            "confidence": "MEDIUM",
            "description": "Free/disposable TLD combined with urgency language suggests a low-cost phishing campaign designed for volume.",
            "indicators": sorted(disposable | urgency),
            "mitre": "T1566: Phishing",
        })

    if critical_count >= 2:
        crit = [f.get("name") for f in findings if f.get("severity") == "CRITICAL"]
        if forensic:
            correlations.append({
                "scenario": "Multiple Critical Attack Indicators",
                "confidence": "HIGH",
                "description": f"{critical_count} critical indicators detected in the same artifact; consistent with an active, multi-stage attack.",
                "indicators": crit,
                "mitre": "TA0001 Initial Access / TA0002 Execution",
            })
        else:
            correlations.append({
                "scenario": "High-Confidence Phishing Infrastructure",
                "confidence": "HIGH",
                "description": f"{critical_count} critical indicators detected simultaneously; consistent with purpose-built phishing infrastructure.",
                "indicators": crit,
                "mitre": "T1598: Phishing for Information",
            })

    if not correlations and (critical_count + high_count) >= 1:
        correlations.append({
            "scenario": "Suspicious Activity Detected",
            "confidence": "LOW",
            "description": "One or more elevated-severity indicators were found. Treat with caution and verify before interaction.",
            "indicators": [f.get("name") for f in findings if f.get("severity") in ("CRITICAL", "HIGH")],
            "mitre": "" if forensic else "T1566: Phishing",
        })

    return correlations


def build_verdict(score: int, findings: list = None, threat_type: str = "general") -> dict:
    verdict = score_to_verdict(score)

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 65:
        severity = "HIGH"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    color = "danger" if score >= 65 else "warning" if score >= 35 else "success"

    labels = {
        VERDICT_MALICIOUS:  f"Threat confirmed at {score}% confidence. Immediate action recommended.",
        VERDICT_SUSPICIOUS: f"Suspicious activity at {score}% confidence. Further investigation warranted.",
        VERDICT_BENIGN:     f"No significant threat detected. Risk score: {score}%.",
    }

    return {
        "verdict":        verdict,
        "score":          score,
        "severity":       severity,
        "color":          color,
        "threat_type":    threat_type,
        "summary":        labels.get(verdict, f"Analysis complete. Score: {score}%"),
        "findings":       findings or [],
    }


def score_summary(verdict: str, score: int, mode: str) -> str:
    labels = {
        VERDICT_MALICIOUS:  f"Threat confirmed at {score}% confidence. Immediate action recommended.",
        VERDICT_SUSPICIOUS: f"Suspicious at {score}% confidence. Further investigation warranted.",
        VERDICT_BENIGN:     f"No significant threat detected. Risk score: {score}%.",
    }
    return labels.get(verdict, f"Analysis complete. Score: {score}%")


# ═══════════════════════════════════════════════════════════════
#  PHASE 2: EXPLAINABLE SCORING
#  Additive breakdown whose contributions sum EXACTLY to the final
#  score (existing calculate_score() output is unchanged).
# ═══════════════════════════════════════════════════════════════
EXPLAIN_LABELS = {
    "Urgency / Pressure Manipulation": "Urgency language",
    "Urgency Manipulation":            "Urgency language",
    "Newly Registered Domain":         "Newly registered domain",
    "Suspicious Free TLD":             "Free / abused TLD",
    "Brand Impersonation":             "Brand impersonation",
    "IP Address in URL":               "Raw IP address in URL",
    "Unencrypted Channel":             "No HTTPS",
    "Deceptive Keywords Detected":     "Deceptive keywords",
    "Excessive Subdomains":            "Excessive subdomains",
    "Missing Sender Authentication":   "Missing SPF/DKIM",
    "Sender Domain Spoofing":          "Spoofed / disposable sender domain",
    "Suspicious Sender TLD":           "Disposable / abused sender TLD",
    "Display Name Brand Spoofing":     "Brand name in sender display name",
    "Malicious URL in Body":           "Phishing-style URL in body",
    "Suspicious URL in Body":          "Phishing-style URL in body",
}


def explain_score(findings: list, final_score: int = None) -> dict:
    """
    Returns {"score", "contributions": [{"factor","points","label","severity","why"}], "summary", "top_factors"}.
    points are integers that add up to `score` (largest-remainder rounding, so no hidden math).
    Informational LOW 'no indicators' rows are excluded when real risks exist.
    """
    real = [f for f in findings if f.get("name") not in ("No Indicators Detected",)]
    if not real:
        score = final_score if final_score is not None else calculate_score([])
        return {"score": score, "contributions": [], "top_factors": [],
                "summary": "No risk factors contributed to the score; baseline value only."}

    weights = [SEVERITY_WEIGHTS.get(f.get("severity", "LOW"), 3) * 1.8 for f in real]
    target = final_score if final_score is not None else calculate_score(findings)
    raw_total = sum(weights) or 1
    # proportional scaling (down when capped at 97, up when an analyzer assigns a fixed score) so rows sum to target
    scale = target / raw_total
    scaled = [w * scale for w in weights]
    floors = [int(w) for w in scaled]
    remainder = target - sum(floors)
    order = sorted(range(len(scaled)), key=lambda i: scaled[i] - floors[i], reverse=True)
    for i in order[:max(remainder, 0)]:
        floors[i] += 1

    rows = []
    for f, pts in zip(real, floors):
        label = EXPLAIN_LABELS.get(f.get("name"), f.get("name", "Unknown factor"))
        rows.append({
            "factor":   f.get("name", ""),
            "label":    label,
            "points":   pts,
            "display":  f"+{pts}% {label}",
            "severity": f.get("severity", "LOW"),
            "evidence": str(f.get("evidence", ""))[:120],
            "why":      f.get("why_it_matters") or f.get("description", ""),
        })
    rows.sort(key=lambda r: r["points"], reverse=True)
    top = rows[:3]
    summary = (f"Score {target}% = " + " ".join(r["display"] for r in rows[:6]) +
               (f" … (+{len(rows) - 6} more)" if len(rows) > 6 else ""))
    return {"score": target, "contributions": rows, "top_factors": [r["display"] for r in top], "summary": summary}


def attach_explanation(result: dict) -> dict:
    """Adds result['score_explanation'] to any analyzer result (idempotent)."""
    try:
        result["score_explanation"] = explain_score(result.get("findings", []), result.get("score"))
    except Exception:
        pass
    return result


FINDING_CATEGORY_MAP.update({
    "Urgency / Pressure Manipulation": "keywords",
    "Newly Registered Domain":         "domain_intelligence",
    "SPF Authentication Failed":       "domain_intelligence",
    "DKIM Authentication Failed":      "domain_intelligence",
    "DMARC Authentication Failed":     "domain_intelligence",
    "Return-Path / From Mismatch":     "domain_intelligence",
    "Reply-To Hijack":                 "domain_intelligence",
    "Extracted IP Has Bad Reputation": "threat_intelligence",
    "Attachment Hash Known Malicious": "threat_intelligence",
    "Suspicious Sender TLD":           "domain_intelligence",
    "Display Name Brand Spoofing":     "domain_intelligence",
    "Redirect Chain Detected":         "redirects",
    "Shortened URL":                   "redirects",
    "Suspicious Redirect Destination": "redirects",
})
