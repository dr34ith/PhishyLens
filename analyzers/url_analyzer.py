"""
PhishyLens v2
analyzers/url_analyzer.py: URL Risk Analyzer
"""

import re
import time
import uuid
import socket
import ipaddress
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor
from utils.threat_intel import quick_url_findings, enrich_domain, lookup_url_intel, new_domain_finding, url_host, intel_checks, has_ip_in_url, check
from utils.scoring import calculate_score, score_to_verdict, build_risk_breakdown, correlate_evidence, attach_explanation
from utils.logger import get_logger, track_api_call

log = get_logger("url")

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly",
              "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id", "lnkd.in", "bit.do", "v.gd", "shorte.st", "adf.ly"}
MAX_HOPS        = 10
HOP_TIMEOUT     = 3      # seconds per hop (Vercel functions are time-limited)
TOTAL_BUDGET    = 7.0    # seconds for the whole trace
UA = {"User-Agent": "Mozilla/5.0 (PhishyLens redirect-tracer; +safe-head-only)"}


def _host_is_safe(host: str) -> bool:
    """SSRF guard: every resolved address must be globally routable."""
    try:
        infos = socket.getaddrinfo(host, None)
        return bool(infos) and all(ipaddress.ip_address(str(i[4][0]).split("%")[0]).is_global for i in infos)
    except (socket.gaierror, UnicodeError, ValueError, OSError):
        return False


def trace_redirects(url: str) -> dict:
    """
    Follow HTTP 301/302/303/307/308 hops manually (HEAD, falling back to a streamed GET that is never read).
    Bodies are never downloaded. Private/internal destinations are refused. Meta-refresh / JS redirects are
    NOT executed (reported in 'notes').
    """
    chain, current, t0 = [], url, time.time()
    result = {"chain": chain, "final_url": url, "hops": 0, "blocked": "", "error": "", "loop": False,
              "notes": "HTTP-level redirects only; meta-refresh and JavaScript redirects are not executed."}
    seen = set()
    for _ in range(MAX_HOPS + 1):
        host = urllib.parse.urlparse(current).hostname or ""
        if current in seen:
            result["loop"] = True
            break
        seen.add(current)
        if time.time() - t0 > TOTAL_BUDGET:
            result["error"] = "Trace time budget exceeded"
            break
        if not _host_is_safe(host):
            result["blocked"] = f"Refused to contact {host or 'host'} (unresolvable or non-public address)"
            break
        hop = {"url": current, "status": None, "location": "", "ms": 0}
        h0 = time.time()
        try:
            r = requests.head(current, allow_redirects=False, timeout=HOP_TIMEOUT, headers=UA)
            if r.status_code in (403, 405, 501):
                r = requests.get(current, allow_redirects=False, timeout=HOP_TIMEOUT, headers=UA, stream=True)
                r.close()
            hop["status"] = r.status_code
            hop["ms"] = int((time.time() - h0) * 1000)
            loc = r.headers.get("Location", "")
            chain.append(hop)
            if r.status_code in (301, 302, 303, 307, 308) and loc:
                hop["location"] = urllib.parse.urljoin(current, loc)
                current = hop["location"]
                if not current.startswith(("http://", "https://")):
                    break
                continue
            break
        except Exception as e:
            hop["status"], hop["error"] = "ERR", str(e)[:120]
            chain.append(hop)
            result["error"] = str(e)[:150]
            track_api_call("redirect_trace", False, int((time.time() - h0) * 1000), str(e))
            break
    # last hop's Location if it redirected (even if that target was then blocked / not contacted), else the last URL fetched
    result["final_url"] = (chain[-1].get("location") or chain[-1]["url"]) if chain else url
    result["hops"] = sum(1 for h in chain if h.get("location"))
    return result


def _redirect_findings(original: str, tr: dict) -> list:
    out = []
    host = url_host(original)
    final_host = url_host(tr["final_url"])
    if host in SHORTENERS or host.replace("www.", "") in SHORTENERS:
        out.append({"severity": "MEDIUM", "name": "Shortened URL", "evidence": host,
                    "description": "URL uses a link-shortening service that hides the real destination.", "confidence": 70,
                    "why_it_matters": "Attackers use shorteners to obscure malicious destinations and bypass reputation filters.",
                    "recommendation": "Only visit after inspecting the resolved destination below.",
                    "false_positive_possibility": "High: shorteners are widely used legitimately.", "reference": "MITRE ATT&CK T1027"})
    if tr["hops"] >= 2:
        out.append({"severity": "HIGH" if tr["hops"] >= 4 else "MEDIUM", "name": "Redirect Chain Detected",
                    "evidence": f"{tr['hops']} redirect hop(s) → {tr['final_url'][:80]}",
                    "description": f"Link passes through {tr['hops']} HTTP redirects before reaching its final destination.", "confidence": 72,
                    "why_it_matters": "Multi-hop chains are used to launder reputation, filter researchers and hide the landing page.",
                    "recommendation": "Analyse the final destination, not the first link.",
                    "false_positive_possibility": "Medium: ad/analytics trackers produce redirects.", "reference": "MITRE ATT&CK T1204.001"})
    if tr["final_url"] != original and final_host and final_host != host:
        bad = [f for f in quick_url_findings(tr["final_url"]) if f["severity"] in ("CRITICAL", "HIGH")]
        if bad:
            out.append({"severity": "CRITICAL", "name": "Suspicious Redirect Destination",
                        "evidence": f"{tr['final_url'][:80]} ({', '.join(b['name'] for b in bad[:3])})",
                        "description": "The final landing page shows phishing indicators that were hidden behind the original link.", "confidence": 88,
                        "why_it_matters": "The visible link looked benign but resolves to a high-risk destination; textbook obfuscation.",
                        "recommendation": "Block the final domain and the entry link.",
                        "false_positive_possibility": "Low.", "reference": "MITRE ATT&CK T1566.002"})
    return out


def analyze_url(url: str) -> dict:
    start = time.time()
    url = url.strip()
    explicit_scheme = bool(re.match(r"^https?://", url, re.I))
    if explicit_scheme:
        url = url[:url.index("://")].lower() + url[url.index("://"):]
    else:
        url = "http://" + url

    timeline = [
        {"step": "Input Validation",  "status": "complete", "detail": "URL format validated and normalized"},
        {"step": "URL Normalization",  "status": "complete", "detail": f"Resolved to: {url}"},
    ]

    findings = quick_url_findings(url)
    timeline.append({"step": "Detection Engine", "status": "complete",
                     "detail": f"{len(findings)} heuristic indicator(s) detected"})

    parsed = urllib.parse.urlparse(url)
    domain = url_host(url) or parsed.netloc or url

    # threat intel + redirect deep-dive + real domain context (RDAP / DNS / ASN) run concurrently (serverless time limits)
    ex = ThreadPoolExecutor(max_workers=3)
    f_intel = ex.submit(lookup_url_intel, url)
    f_trace = ex.submit(trace_redirects, url)
    f_dom   = ex.submit(enrich_domain, domain)
    try:
        intel = f_intel.result(timeout=9)
    except Exception as e:
        log.error("url intel lookup failed: %s", e)
        intel = {"intel_sources": {}, "intel_findings": []}
    findings.extend(intel.get("intel_findings", []))
    timeline.append({"step": "Threat Intelligence", "status": "complete",
                     "detail": f"{len(intel.get('intel_findings', []))} threat intel hit(s)"})
    try:
        trace = f_trace.result(timeout=9)
    except Exception as e:
        log.error("redirect trace failed: %s", e)
        trace = {"chain": [], "final_url": url, "hops": 0, "blocked": "", "error": "Redirect trace timed out", "loop": False, "notes": ""}
    try:
        domain_info = f_dom.result(timeout=6)
    except Exception as e:
        log.warning("domain enrichment failed: %s", e)
        domain_info = {"domain": domain, "registered": "Unknown", "registrar": "Unknown", "resolved_ip": "Unknown"}
    ex.shutdown(wait=False, cancel_futures=True)

    # "Unencrypted Channel" needs evidence the link really is HTTP: an explicit http:// that does not upgrade to
    # HTTPS on redirect. A bare "example.com" was prefixed with http:// by us (browsers would try HTTPS/HSTS first).
    traced = bool(trace.get("chain")) and not trace.get("error")
    lands_http = explicit_scheme and (str(trace.get("final_url", "")).lower().startswith("http://") if traced else True)
    if not lands_http:
        findings = [f for f in findings if f["name"] != "Unencrypted Channel"]
    findings.extend(_redirect_findings(url, trace))
    age_finding = new_domain_finding(domain_info.get("domain_age_days"))
    if age_finding:
        findings.append(age_finding)
    timeline.append({"step": "Redirect Trace", "status": "complete",
                     "detail": (f"{trace['hops']} hop(s) → {trace['final_url'][:70]}" if not trace.get("blocked") else trace["blocked"])})

    score   = calculate_score(findings)
    verdict = score_to_verdict(score)

    timeline.append({"step": "Risk Assessment", "status": "complete",
                     "detail": f"Risk score: {score}% ({verdict})"})
    timeline.append({"step": "Final Report", "status": "complete", "detail": "Analysis complete"})

    if not findings:
        findings.append({
            "severity":    "LOW",
            "name":        "No Indicators Detected",
            "evidence":    domain,
            "description": "No phishing or malware indicators were detected in this URL.",
            "confidence":  10,
            "why_it_matters": "Clean results mean no known threat patterns matched. Novel or zero-day phishing pages may not yet be in threat databases.",
            "recommendation": "Proceed with caution if received unsolicited. Verify sender identity through separate channels.",
            "false_positive_possibility": "N/A",
            "reference": "",
        })

    risk_breakdown       = build_risk_breakdown(findings)
    evidence_correlation = correlate_evidence(findings)
    iocs                 = _extract_iocs(url, parsed, domain)
    duration_ms          = int((time.time() - start) * 1000)

    recommended_action = {
        "MALICIOUS":  "Block immediately. Do not visit this URL. Report to security team and audit systems that may have already accessed it.",
        "SUSPICIOUS": "Treat as untrusted. Verify through alternative channels before proceeding. Consider sandbox detonation.",
        "BENIGN":     "No immediate action required. Standard security hygiene applies.",
    }.get(verdict, "Exercise caution.")

    result = {
        "verdict":              verdict,
        "score":                score,
        "mode":                 "url",
        "input":                url,
        "findings":             findings,
        "domain_info":          domain_info,
        "summary":              _build_summary(verdict, score, domain),
        "intel_sources":        intel.get("intel_sources", {}),
        "risk_breakdown":       risk_breakdown,
        "evidence_correlation": evidence_correlation,
        "iocs":                 iocs,
        "timeline":             timeline,
        "recommended_action":   recommended_action,
        "scan_id":              str(uuid.uuid4())[:8].upper(),
        "confidence":           _calc_confidence(findings, intel),
        "duration_ms":          duration_ms,
        "redirect_trace":       trace,
        "final_url":            trace["final_url"],
        "checks":               _url_checks(url, explicit_scheme, lands_http, traced, trace, domain_info, findings, intel),
    }
    if trace["final_url"] != url:
        result["iocs"]["urls"].append(trace["final_url"])
    return attach_explanation(result)


def _url_checks(url, explicit_scheme, lands_http, traced, trace, domain_info, findings, intel) -> list:
    """Checks that really ran: flagged / clear / unavailable. A check that could not run is never 'clear'."""
    names = {f.get("name") for f in findings}
    out = []
    if lands_http:
        https = "flagged"
    elif (explicit_scheme and url.lower().startswith("https://")) or (traced and str(trace.get("final_url", "")).lower().startswith("https://")):
        https = "clear"
    else:
        https = "unavailable"                          # bare host we prefixed with http:// and could not trace
    out.append(check("HTTPS", https))
    out.append(check("URL shortener", "flagged" if "Shortened URL" in names else "clear"))
    out.append(check("IP in URL", "flagged" if has_ip_in_url(url) else "clear"))
    if trace.get("hops", 0) >= 2:
        redirect = "flagged"
    else:
        redirect = "clear" if traced and not trace.get("blocked") else "unavailable"
    out.append(check("Redirect chain", redirect))
    out.append(check("Brand impersonation", "flagged" if "Brand Impersonation" in names else "clear"))
    out.append(check("Abused top-level domain", "flagged" if "Suspicious Free TLD" in names else "clear"))
    out.append(check("Deceptive keywords", "flagged" if "Deceptive Keywords Detected" in names else "clear"))
    if not has_ip_in_url(url):
        age = domain_info.get("domain_age_days")
        out.append(check("Domain age", ("flagged" if "Newly Registered Domain" in names else "clear") if isinstance(age, int) else "unavailable"))
    return out + intel_checks(intel.get("intel_sources") or {})


def _build_summary(verdict: str, score: int, domain: str) -> str:
    summaries = {
        "MALICIOUS":  f"'{domain}' exhibits multiple high-confidence threat indicators. Risk score: {score}%. Immediate action recommended.",
        "SUSPICIOUS": f"'{domain}' shows anomalous patterns but lacks conclusive evidence. Risk score: {score}%. Further investigation warranted.",
        "BENIGN":     f"'{domain}' passed all primary integrity checks. Risk score: {score}%.",
    }
    return summaries.get(verdict, f"Analysis complete. Risk score: {score}%.")


def _extract_iocs(url: str, parsed, domain: str) -> dict:
    iocs = {"urls": [url], "domains": [], "ips": [], "paths": []}
    if domain:
        try:
            ipaddress.ip_address(domain)
            is_ip = True
        except ValueError:
            is_ip = False
        if is_ip:
            iocs["ips"].append(domain)
        else:
            iocs["domains"].append(domain)
    if parsed.path and parsed.path != '/':
        iocs["paths"].append(parsed.path)
    return iocs


def _calc_confidence(findings: list, intel: dict) -> int:
    base = 60
    intel_sources = intel.get("intel_sources", {})
    active = sum(1 for s in intel_sources.values() if s.get("available"))
    base += active * 10
    if findings:
        base += min(len(findings) * 3, 15)
    return min(base, 98)
