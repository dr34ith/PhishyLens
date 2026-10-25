import re
import os
import socket
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
import ipaddress, time
from utils.logger import get_logger, track_api_call

log = get_logger('threat_intel')

# ─── CONSTANTS ────────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "secure", "update", "confirm", "signin",
    "banking", "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "chase", "wellsfargo", "security", "alert",
]

# Free or very low-cost TLDs that are disproportionately abused for phishing (Spamhaus / Interisle reports)
FREE_TLDS = [
    "tk", "ml", "ga", "cf", "gq", "link", "click", "download", "review", "country",
    "work", "date", "men", "loan", "win", "bid", "trade", "webcam", "science",
    "party", "racing", "accountant", "website", "space", "tech", "site", "online",
    "club", "store", "xyz", "top", "zip", "mov", "icu", "buzz", "rest", "cyou",
]

# brand -> extra official registrable domains (the brand's own name as registrable label, e.g. amazon.co.uk, is always official)
BRANDS = {
    "paypal":     ("paypalobjects.com",),
    "microsoft":  ("microsoftonline.com", "live.com", "office.com", "office365.com", "outlook.com",
                   "sharepoint.com", "azure.com", "windows.net", "bing.com", "msn.com"),
    "amazon":     ("amazonaws.com", "media-amazon.com"),
    "google":     ("youtube.com", "gmail.com", "googleusercontent.com", "gstatic.com", "googleapis.com", "goo.gl"),
    "apple":      ("icloud.com",),
    "netflix":    ("nflxext.com", "nflximg.net"),
    "chase":      (),
    "wellsfargo": ("wf.com",),
}
BRAND_DISPLAY = {"paypal": "PayPal", "wellsfargo": "Wells Fargo"}
# short brand words that occur inside ordinary words (pineapple, purchase): require a whole hostname label/token
_AMBIGUOUS_BRANDS = {"apple", "chase"}

# second-level labels used under ccTLDs (example.co.uk, example.com.au)
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "mil", "ltd", "plc", "sch"}

SOURCE_NAMES = {"virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "otx": "AlienVault OTX", "ipapi": "ip-api.com",
                "threatfox": "ThreatFox", "malwarebazaar": "MalwareBazaar", "urlscan": "urlscan.io"}

VT_CONFIRM_ENGINES = 3      # 1–2 engine hits on VirusTotal are frequently false positives
LOW_COUNT = 2               # 2 or fewer engines / pulses / reports = a low-count, low-confidence signal
WEAK_RECOMMENDATION = "Review the listing and corroborate with another source before blocking."
WEAK_FALSE_POSITIVE = "Medium: community-sourced listings can include benign or shared infrastructure."
_REQUEST_TIMEOUT = 5
_LOOKUP_BUDGET = 8          # seconds for one parallel group of intel lookups

# ─── HOST HELPERS ─────────────────────────────────────────────

def url_host(url: str) -> str:
    """Lower-case hostname of a URL (no scheme, userinfo or port). '' if unparseable."""
    url = (url or "").strip()
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", url, re.I):
        url = "http://" + url
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain: login.example.co.uk -> example.co.uk, a.b.example.com -> example.com."""
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) < 2:
        return host or ""
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_ip_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # obfuscated integer / hex IPv4 hosts (http://3232235777/, http://0xC0A80001/)
        return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-f]{8}", host))


# ─── HEURISTIC HELPERS ────────────────────────────────────────

def has_ip_in_url(url: str) -> bool:
    return _is_ip_host(url_host(url))


def get_tld(domain: str) -> str:
    parts = domain.split('.')
    return parts[-1] if len(parts) > 1 else ""


def is_free_tld(url: str) -> bool:
    host = url_host(url)
    return not _is_ip_host(host) and get_tld(host) in FREE_TLDS


def count_subdomains(url: str) -> int:
    host = url_host(url)
    if not host or _is_ip_host(host):
        return 0
    return max(len(host.split('.')) - len(registrable_domain(host).split('.')), 0)


def official_brand(host: str) -> str | None:
    """Return the brand key if `host` belongs to that brand's own infrastructure."""
    reg = registrable_domain(host)
    name = reg.split(".")[0]
    for brand, extra in BRANDS.items():
        if name == brand or reg in extra:
            return brand
    return None


def has_suspicious_keywords(url: str) -> list:
    host = url_host(url)
    if host and official_brand(host):
        return []                                   # paypal.com/signin is PayPal's real login page, not deception
    lower = url.lower()
    return [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower]


def detect_brand_impersonation(url: str) -> str | None:
    """Brand name inside a hostname the brand does not own (paypal.com.evil.tk, secure-paypal.xyz)."""
    host = url_host(url)
    if not host or _is_ip_host(host) or official_brand(host):
        return None
    tokens = set(re.split(r"[.\-]", host))
    for brand in BRANDS:
        if (brand in tokens) if brand in _AMBIGUOUS_BRANDS else (brand in host):
            return BRAND_DISPLAY.get(brand, brand.title())
    return None


def enrich_domain(host: str) -> dict:
    """Real domain context: RDAP registration data, DNS resolution and IP geolocation/ASN. Unknown values say so."""
    host = url_host(host)
    info = {"domain": host or "n/a", "registrable_domain": "n/a", "registered": "Unknown", "domain_age_days": "Unknown",
            "registrar": "Unknown", "resolved_ip": "Unresolved", "country": "Unknown", "asn": "Unknown", "isp": "Unknown"}
    if not host:
        return info
    ip = host if _is_ip_host(host) else ""
    if not ip:
        info["registrable_domain"] = registrable_domain(host)
        rd = domain_rdap(host)
        if rd:
            info["registered"] = rd.get("registered") or "Unknown"
            info["domain_age_days"] = rd["age_days"] if rd.get("age_days") is not None else "Unknown"
            info["registrar"] = rd.get("registrar") or "Unknown"
        try:
            ip = socket.gethostbyname(host)
        except (socket.gaierror, UnicodeError, OSError):
            ip = ""
    if ip:
        info["resolved_ip"] = ip
        if is_public_ip(ip):
            geo = _ipapi_lookup(ip)
            if geo.get("available"):
                info["country"] = geo.get("country") or "Unknown"
                info["asn"] = geo.get("asn") or "Unknown"
                info["isp"] = geo.get("isp") or "Unknown"
        else:
            info["country"] = "Private / non-routable address"
    return info


def quick_url_findings(url: str) -> list:
    """Heuristic findings for a URL: no external API calls."""
    findings = []
    host = url_host(url)

    if has_ip_in_url(url):
        findings.append({
            "severity":    "CRITICAL",
            "name":        "IP Address in URL",
            "evidence":    host,
            "description": "Direct IP used instead of a domain; common in disposable phishing infrastructure.",
            "confidence":  95,
            "why_it_matters": "Legitimate services use domain names. Raw IPs bypass DNS-based reputation filtering and suggest infrastructure designed to evade detection.",
            "recommendation": "Do not visit. Block the IP at the network perimeter and report to your security team.",
            "false_positive_possibility": "Very low: legitimate web services almost never use raw IPs in user-facing URLs.",
            "reference": "MITRE ATT&CK T1583.005",
        })

    if is_free_tld(url):
        tld = get_tld(host)
        findings.append({
            "severity":    "HIGH",
            "name":        "Suspicious Free TLD",
            "evidence":    f".{tld}",
            "description": "Free or low-cost TLD frequently abused by phishing operators.",
            "confidence":  75,
            "why_it_matters": f"The .{tld} TLD is free or very cheap with minimal registration verification, making it attractive for short-lived phishing campaigns.",
            "recommendation": "Treat as untrusted. Verify domain registration date and compare with expected communication channels.",
            "false_positive_possibility": "Medium: some legitimate services use these TLDs, but volume of abuse is high.",
            "reference": "MITRE ATT&CK T1583.001",
        })

    brand = detect_brand_impersonation(url)
    if brand:
        findings.append({
            "severity":    "CRITICAL",
            "name":        "Brand Impersonation",
            "evidence":    f"{brand} in {host}",
            "description": f"Hostname contains '{brand}' but is not a {brand}-owned domain.",
            "confidence":  92,
            "why_it_matters": f"Attackers use {brand}'s brand recognition to trick users into entering credentials. The actual domain does not belong to {brand}.",
            "recommendation": "Do not enter any credentials. Navigate directly to the official site. Report this URL to your security team immediately.",
            "false_positive_possibility": "Low: a brand name inside a hostname the brand does not own is a strong signal.",
            "reference": "MITRE ATT&CK T1566.002",
        })

    kws = has_suspicious_keywords(url)
    if kws:
        findings.append({
            "severity":    "HIGH",
            "name":        "Deceptive Keywords Detected",
            "evidence":    ", ".join(kws[:3]),
            "description": "URL contains high-priority deception keywords.",
            "confidence":  70,
            "why_it_matters": "Phishing URLs frequently include words like 'login', 'verify', or 'secure' to appear legitimate and encourage credential entry.",
            "recommendation": "Cross-check the domain against the official domain of any service referenced. Never enter credentials on pages reached through unsolicited links.",
            "false_positive_possibility": "Medium: legitimate sites may use these terms in paths, but combination with other indicators raises risk.",
            "reference": "MITRE ATT&CK T1566",
        })

    subs = count_subdomains(url)
    if subs > 2:
        findings.append({
            "severity":    "MEDIUM",
            "name":        "Excessive Subdomains",
            "evidence":    f"{subs} subdomain levels",
            "description": "Deep nesting used to obscure the real domain.",
            "confidence":  60,
            "why_it_matters": "Attackers pad subdomains to make the real (malicious) domain harder to spot: e.g. secure.bank.com.attacker.com looks legitimate at a glance.",
            "recommendation": "Identify the actual registered domain (the part before the TLD), not the subdomain chain.",
            "false_positive_possibility": "Medium: some CDN and microservice architectures use deep subdomain hierarchies.",
            "reference": "MITRE ATT&CK T1036.005",
        })

    if url.lower().startswith("http://"):
        findings.append({
            "severity":    "MEDIUM",
            "name":        "Unencrypted Channel",
            "evidence":    "HTTP (no TLS)",
            "description": "No encryption: credentials would be transmitted in plaintext.",
            "confidence":  65,
            "why_it_matters": "Any credentials or data submitted over HTTP can be intercepted via man-in-the-middle attacks. All legitimate login pages use HTTPS.",
            "recommendation": "Never enter credentials on an HTTP page. If this is a redirect target, treat the entire chain as untrusted.",
            "false_positive_possibility": "Low for credential-gathering pages: virtually all legitimate login portals enforce HTTPS.",
            "reference": "CWE-319",
        })

    return findings


# ─── THREAT INTEL API CALLERS ─────────────────────────────────
# Result contract: {"source", "available", "flagged", "detail", ...}
#   available=False + no error  -> source not configured (no API key)
#   available=False + error     -> lookup attempted but failed (HTTP error, timeout, bad key): NOT a clean result
#   available=True              -> a real answer was obtained

def _http_error(source: str, r, hint: str = "") -> dict:
    msg = f"HTTP {r.status_code}"
    if r.status_code in (401, 403):
        msg += "; API key missing or invalid" + hint
    elif r.status_code == 429:
        msg += "; rate limited"
    return {"source": source, "available": False, "flagged": False, "error": msg, "detail": msg}


def _vt_stats_result(stats: dict) -> dict:
    malicious = int(stats.get("malicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values())
    return {"source": "VirusTotal", "available": True, "flagged": malicious > 0,
            "malicious_engines": malicious, "total_engines": total,
            "detail": f"{malicious}/{total} engines flagged as malicious" if total else "No engine results recorded"}


def _vt_get(path: str, not_found: str) -> dict:
    key = os.getenv('VIRUSTOTAL_API_KEY', '')
    if not key:
        return {"source": "VirusTotal", "available": False}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": key}, timeout=_REQUEST_TIMEOUT)
        if r.status_code == 404:
            return {"source": "VirusTotal", "available": True, "flagged": False, "detail": not_found}
        if not r.ok:
            return _http_error("VirusTotal", r)
        return _vt_stats_result(r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {}) or {})
    except Exception as e:
        return {"source": "VirusTotal", "available": False, "error": str(e)[:150]}


def _vt_lookup_url(url: str) -> dict:
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
    return _vt_get(f"urls/{url_id}", "Not previously scanned")


def _vt_lookup_hash(hash_val: str) -> dict:
    return _vt_get(f"files/{hash_val}", "Hash not found in database")


def _vt_lookup_ip(ip: str) -> dict:
    return _vt_get(f"ip_addresses/{ip}", "IP not found in database")


def _abuseipdb_lookup(ip: str) -> dict:
    key = os.getenv('ABUSEIPDB_API_KEY', '')
    if not key:
        return {"source": "AbuseIPDB", "available": False}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=_REQUEST_TIMEOUT
        )
        if not r.ok:
            return _http_error("AbuseIPDB", r)
        d = r.json().get("data", {})
        score = d.get("abuseConfidenceScore", 0) or 0
        reports = d.get("totalReports", 0) or 0
        whitelisted = bool(d.get("isWhitelisted"))
        # the confidence score already weighs report volume/recency; raw report counts alone (e.g. 8.8.8.8) are not abuse
        flagged = score >= 25 and not whitelisted
        return {
            "source": "AbuseIPDB", "available": True, "flagged": flagged,
            "abuse_score": score, "total_reports": reports, "whitelisted": whitelisted,
            "country": d.get("countryCode", ""), "usage_type": d.get("usageType", ""),
            "detail": f"Abuse score {score}%, {reports} reports" + (" (whitelisted)" if whitelisted else "")
        }
    except Exception as e:
        return {"source": "AbuseIPDB", "available": False, "error": str(e)[:150]}


def _urlscan_lookup(url: str) -> dict:
    key = os.getenv('URLSCAN_API_KEY', '')
    if not key:
        return {"source": "urlscan.io", "available": False}
    try:
        r = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={"API-Key": key, "Content-Type": "application/json"},
            json={"url": url, "visibility": "private"},
            timeout=_REQUEST_TIMEOUT
        )
        if not r.ok:
            return _http_error("urlscan.io", r)
        # a submission only returns a scan UUID; the verdict is produced asynchronously, so this is NOT a clean result
        return {
            "source": "urlscan.io", "available": True, "flagged": False, "pending": True,
            "result_url": r.json().get("result", ""),
            "detail": "Scan submitted: verdict not yet available (open the result link)"
        }
    except Exception as e:
        return {"source": "urlscan.io", "available": False, "error": str(e)[:150]}


def _otx_get(path: str) -> dict:
    key = os.getenv('OTX_API_KEY', '')
    if not key:
        return {"source": "AlienVault OTX", "available": False}
    try:
        r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/{path}/general",
                         headers={"X-OTX-API-KEY": key}, timeout=_REQUEST_TIMEOUT)
        if not r.ok:
            return _http_error("AlienVault OTX", r)
        d = r.json()
        pulse_count = d.get("pulse_info", {}).get("count", 0) or 0
        whitelist = [v.get("source") or v.get("name") for v in (d.get("validation") or []) if isinstance(v, dict)]
        # popular benign indicators (google.com, 8.8.8.8) appear in many pulses as context; OTX marks them via 'validation'
        flagged = pulse_count > 0 and not whitelist
        detail = (f"Found in {pulse_count} threat pulses" if pulse_count else "Not found in threat pulses")
        if whitelist:
            detail += f"; whitelisted by OTX ({', '.join(str(w) for w in whitelist[:3])})"
        return {"source": "AlienVault OTX", "available": True, "flagged": flagged, "pulse_count": pulse_count, "detail": detail}
    except Exception as e:
        return {"source": "AlienVault OTX", "available": False, "error": str(e)[:150]}


def _otx_lookup_url(url: str) -> dict:
    host = url_host(url)
    if _is_ip_host(host) and ":" not in host:
        return _otx_get(f"IPv4/{host}")
    return _otx_get(f"domain/{host}")


def _otx_lookup_ip(ip: str) -> dict:
    return _otx_get(f"{'IPv6' if ':' in ip else 'IPv4'}/{ip}")


def _ipapi_lookup(ip: str) -> dict:
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,isp,org,as,proxy,hosting,query",
            timeout=_REQUEST_TIMEOUT
        )
        if not r.ok:
            return _http_error("ip-api.com", r)
        d = r.json()
        if d.get("status") != "success":
            return {"source": "ip-api.com", "available": False, "error": f"Lookup failed: {d.get('message', 'unknown')}"}
        is_proxy = bool(d.get("proxy", False))
        is_hosting = bool(d.get("hosting", False))
        parts = [p for p, on in (("Proxy/VPN detected", is_proxy), ("Hosting/datacenter IP", is_hosting)) if on]
        return {
            "source": "ip-api.com", "available": True, "flagged": is_proxy or is_hosting,
            "country": d.get("country", ""), "country_code": d.get("countryCode", ""),
            "isp": d.get("isp", ""), "org": d.get("org", ""), "asn": d.get("as", ""),
            "is_proxy": is_proxy, "is_hosting": is_hosting,
            "detail": ", ".join(parts) or "No proxy/hosting indicators"
        }
    except Exception as e:
        return {"source": "ip-api.com", "available": False, "error": str(e)[:150]}


def _abusech_headers() -> dict | None:
    """abuse.ch (MalwareBazaar / ThreatFox) require a free Auth-Key since 2025; unauthenticated calls return 401."""
    key = os.getenv("ABUSECH_API_KEY", "")
    return {"Auth-Key": key} if key else None


def _malwarebazaar_lookup(hash_val: str) -> dict:
    headers = _abusech_headers()
    if headers is None:
        return {"source": "MalwareBazaar", "available": False}
    try:
        r = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_val},
            headers=headers, timeout=_REQUEST_TIMEOUT
        )
        if not r.ok:
            return _http_error("MalwareBazaar", r, " (set ABUSECH_API_KEY)")
        d = r.json()
        status = d.get("query_status")
        if status in ("hash_not_found", "no_results"):
            return {"source": "MalwareBazaar", "available": True, "flagged": False, "detail": "Not found in MalwareBazaar"}
        if status == "ok" and d.get("data"):
            info = d["data"][0]
            return {
                "source": "MalwareBazaar", "available": True, "flagged": True,
                "malware_name": info.get("signature") or "Unknown",
                "file_type": info.get("file_type", ""),
                "tags": info.get("tags") or [],
                "first_seen": info.get("first_seen") or "",
                "detail": f"Known malware sample: {info.get('signature') or 'unclassified'}"
            }
        return {"source": "MalwareBazaar", "available": False, "error": f"Unexpected response: {status}"}
    except Exception as e:
        return {"source": "MalwareBazaar", "available": False, "error": str(e)[:150]}


def _threatfox_lookup(ioc: str) -> dict:
    headers = _abusech_headers()
    if headers is None:
        return {"source": "ThreatFox", "available": False}
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ioc},
            headers=headers, timeout=_REQUEST_TIMEOUT
        )
        if not r.ok:
            return _http_error("ThreatFox", r, " (set ABUSECH_API_KEY)")
        d = r.json()
        status = d.get("query_status")
        if status == "no_result":
            return {"source": "ThreatFox", "available": True, "flagged": False, "detail": "Not found in IOC database"}
        if status == "ok" and d.get("data"):
            info = d["data"][0]
            return {
                "source": "ThreatFox", "available": True, "flagged": True,
                "threat_type": info.get("threat_type", ""),
                "malware": info.get("malware_printable") or info.get("malware", ""),
                "confidence": info.get("confidence_level", 0),
                "tags": info.get("tags") or [],
                "first_seen": info.get("first_seen") or "",
                "detail": f"IOC matched: {info.get('malware_printable') or info.get('malware') or 'Unknown malware'} ({info.get('threat_type', '')})"
            }
        return {"source": "ThreatFox", "available": False, "error": f"Unexpected response: {status}"}
    except Exception as e:
        return {"source": "ThreatFox", "available": False, "error": str(e)[:150]}


# ─── SIGNAL STRENGTH + CHECKS ─────────────────────────────────
def _solid(name: str, r: dict) -> bool:
    """A flag that is not a low-count signal on its own (used to count independent corroboration)."""
    if not (r.get("available") and r.get("flagged")):
        return False
    if name in ("threatfox", "malwarebazaar"):
        return True
    if name == "virustotal":
        return int(r.get("malicious_engines") or 0) >= VT_CONFIRM_ENGINES
    if name == "otx":
        return int(r.get("pulse_count") or 0) > LOW_COUNT
    if name == "abuseipdb":
        return int(r.get("total_reports") or 0) > LOW_COUNT
    return name == "urlscan"


def signal_strength(name: str, results: dict) -> str:
    """'strong': abuse.ch (ThreatFox / MalwareBazaar) match, VirusTotal with several engines, or 2+ independent solid
    sources. 'weak': a single community-sourced listing (OTX pulse mention, urlscan verdict alone) or a low count."""
    r = results.get(name) or {}
    if name in ("threatfox", "malwarebazaar"):
        return "strong"
    if name == "virustotal" and int(r.get("malicious_engines") or 0) >= VT_CONFIRM_ENGINES:
        return "strong"
    solid = [n for n, x in results.items() if isinstance(x, dict) and _solid(n, x)]
    return "strong" if _solid(name, r) and len(solid) >= 2 else "weak"


def _weaken(finding: dict) -> dict:
    """Weak signal: MEDIUM, corroborate-first wording (strong findings keep today's wording)."""
    finding.update({"severity": "MEDIUM", "strength": "weak", "recommendation": WEAK_RECOMMENDATION,
                    "false_positive_possibility": WEAK_FALSE_POSITIVE})
    return finding


def source_outcome(r: dict) -> str:
    """flagged / clear / unavailable for one intel source. Pending, failed or unconfigured lookups are never 'clear'."""
    if not isinstance(r, dict) or not r.get("available") or r.get("pending") or r.get("error"):
        return "unavailable"
    return "flagged" if r.get("flagged") else "clear"


def check(name: str, outcome: str) -> dict:
    """One entry of result["checks"] (kept apart from findings: checks are not evidence)."""
    return {"name": name, "outcome": outcome}


def intel_checks(results: dict) -> list:
    order = list(SOURCE_NAMES)                       # fixed order: parallel lookups finish in any order
    items = sorted((results or {}).items(), key=lambda kv: order.index(kv[0]) if kv[0] in order else len(order))
    return [check((r.get("source") if isinstance(r, dict) else "") or SOURCE_NAMES.get(n, n), source_outcome(r)) for n, r in items]


# ─── PARALLEL LOOKUP ORCHESTRATORS ────────────────────────────

def _run_parallel(callers: dict, budget: float = _LOOKUP_BUDGET) -> dict:
    """Run lookups concurrently; a slow source is reported as timed out instead of failing the whole analysis."""
    ex = ThreadPoolExecutor(max_workers=len(callers))
    futures = {ex.submit(fn): name for name, fn in callers.items()}
    results = {}
    try:
        for fut in as_completed(futures, timeout=budget):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as e:
                results[name] = {"source": SOURCE_NAMES.get(name, name), "available": False, "error": str(e)[:150]}
    except FuturesTimeout:
        log.warning("intel lookups exceeded %ss budget: %s", budget, [n for n in callers if n not in results])
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    for name in callers:
        results.setdefault(name, {"source": SOURCE_NAMES.get(name, name), "available": False, "error": "Timed out"})
    return results


def _vt_finding(r: dict, subject: str) -> dict:
    n, total = r.get("malicious_engines", 0), r.get("total_engines", 0)
    confirmed = n >= VT_CONFIRM_ENGINES
    return {
        "severity":    "CRITICAL" if confirmed else "MEDIUM",
        "name":        "[VirusTotal] Flagged as Malicious" if confirmed else "[VirusTotal] Low Detection Count",
        "evidence":    r.get("detail", ""),
        "description": f"{n} of {total} VirusTotal engines flag this {subject} as malicious.",
        "confidence":  90 if confirmed else 55,
        "why_it_matters": ("Multiple independent engines agreeing is a strong maliciousness signal." if confirmed else
                           "One or two engine detections are often false positives, but warrant a closer look."),
        "recommendation": ("Block immediately and investigate any systems that interacted with it." if confirmed else
                           "Review which engines flagged it and corroborate with other sources before blocking."),
        "false_positive_possibility": "Low." if confirmed else "Medium–High: single-engine detections are frequently wrong.",
        "reference": "Source: VirusTotal",
        "strength": "strong" if confirmed else "weak",
    }


def lookup_url_intel(url: str) -> dict:
    results = _run_parallel({
        "virustotal": lambda: _vt_lookup_url(url),
        "urlscan":    lambda: _urlscan_lookup(url),
        "otx":        lambda: _otx_lookup_url(url),
        "threatfox":  lambda: _threatfox_lookup(url),
    })

    findings = []
    for name, r in results.items():
        if not (r.get("available") and r.get("flagged")):
            continue
        if name == "virustotal":
            findings.append(_vt_finding(r, "URL"))
            continue
        f = {
            "severity":    "CRITICAL" if name == "threatfox" else "HIGH",
            "name":        f"[{r['source']}] Flagged as Malicious",
            "evidence":    r.get("detail", ""),
            "description": f"Threat intelligence source {r['source']} lists this URL/domain as malicious.",
            "confidence":  90,
            "why_it_matters": f"{r['source']} is a widely used threat intelligence platform. A positive flag here indicates the indicator has been observed in malicious activity.",
            "recommendation": "Block immediately. Investigate any systems that may have visited this URL.",
            "false_positive_possibility": "Low.",
            "reference": f"Source: {r['source']}",
            "strength": "strong",
        }
        if signal_strength(name, results) == "weak":
            _weaken(f)
            f["confidence"] = 55
        findings.append(f)

    return {"intel_sources": results, "intel_findings": findings}


def lookup_hash(hash_val: str) -> dict:
    results = _run_parallel({
        "virustotal":    lambda: _vt_lookup_hash(hash_val),
        "malwarebazaar": lambda: _malwarebazaar_lookup(hash_val),
        "threatfox":     lambda: _threatfox_lookup(hash_val),
    })

    findings = []
    for name, r in results.items():
        if not (r.get("available") and r.get("flagged")):
            continue
        if name == "virustotal":
            findings.append(_vt_finding(r, "file"))
            continue
        findings.append({
            "severity":    "CRITICAL",
            "name":        f"[{r['source']}] Hash Confirmed Malicious",
            "evidence":    r.get("detail", ""),
            "description": f"{r['source']} has this hash on record as malicious.",
            "confidence":  95,
            "why_it_matters": "A hash match in a threat database means this exact file has been analyzed and confirmed malicious by security researchers.",
            "recommendation": "Quarantine the file immediately. Do not execute. Initiate incident response procedures.",
            "false_positive_possibility": "Very low: hash matches are cryptographically exact.",
            "reference": f"Source: {r['source']}",
            "strength": signal_strength(name, results),
        })

    return {"intel_sources": results, "intel_findings": findings}


def lookup_ip(ip_address: str) -> dict:
    findings = []
    recommended = {
        "MALICIOUS":  "Block this IP at the perimeter, search logs for any contact with it, and investigate affected hosts.",
        "SUSPICIOUS": "Monitor and restrict traffic to/from this IP; corroborate with additional intelligence before blocking.",
        "BENIGN":     "No immediate action required based on available intelligence.",
    }

    if not is_public_ip(ip_address):
        findings.append({
            "severity": "LOW",
            "name": "Private IP Address",
            "evidence": ip_address,
            "description": "Internal/private (non-globally-routable) IP address: public threat intelligence does not apply.",
            "confidence": 99,
            "why_it_matters": "Reputation feeds only track internet-routable addresses; activity from this IP must be investigated internally.",
            "recommendation": "Identify the internal host via DHCP/asset inventory if it appears in suspicious activity.",
        })
        return {
            "verdict": "BENIGN", "score": 5, "mode": "ip", "input": ip_address, "ip": ip_address,
            "findings": findings, "reputation": "not applicable", "intel_checked": 0,
            "summary": f"Private/internal IP {ip_address}. Not externally routable; no external reputation lookup performed.",
            "recommended_action": "No external reputation applies. Investigate internally if this IP is involved in an incident.",
            "intel_sources": {},
            "checks": [check("Public reputation lookup (private address)", "unavailable")],
        }

    intel = _run_parallel({
        "virustotal": lambda: _vt_lookup_ip(ip_address),
        "abuseipdb":  lambda: _abuseipdb_lookup(ip_address),
        "otx":        lambda: _otx_lookup_ip(ip_address),
        "ipapi":      lambda: _ipapi_lookup(ip_address),
        "threatfox":  lambda: _threatfox_lookup(ip_address),
    })

    ipapi = intel.get("ipapi", {})
    country = ipapi.get("country") or "Unknown"
    country_code = ipapi.get("country_code", "")
    isp = ipapi.get("isp") or "Unknown"
    asn = ipapi.get("asn") or "Unknown"

    vt = intel.get("virustotal", {})
    if vt.get("available") and vt.get("flagged"):
        malicious = vt.get("malicious_engines", 0)
        total = vt.get("total_engines", 0)
        confirmed = malicious >= VT_CONFIRM_ENGINES
        findings.append({
            "severity": "CRITICAL" if confirmed else "MEDIUM",
            "name": f"VirusTotal: Flagged by {malicious} Engine{'s' if malicious != 1 else ''}",
            "evidence": f"{malicious}/{total} engines flagged",
            "description": f"VirusTotal reports {malicious} of {total} security engines flagged this IP as malicious.",
            "confidence": 90 if confirmed else 55,
            "why_it_matters": "Multiple engines agreeing is a strong signal." if confirmed else "Low engine counts are often false positives.",
            "strength": "strong" if confirmed else "weak",
        })

    abuse = intel.get("abuseipdb", {})
    if abuse.get("available") and abuse.get("flagged"):
        score = abuse.get("abuse_score", 0)
        reports = abuse.get("total_reports", 0)
        f = {
            "severity": "CRITICAL" if score >= 75 else "HIGH",
            "name": "AbuseIPDB: Abuse History Confirmed",
            "evidence": f"Score {score}%, {reports} reports",
            "description": f"AbuseIPDB reports {reports} abuse incidents with a {score}% confidence score.",
            "confidence": score,
            "strength": "strong",
        }
        findings.append(_weaken(f) if signal_strength("abuseipdb", intel) == "weak" and reports <= LOW_COUNT else f)

    otx = intel.get("otx", {})
    if otx.get("available") and otx.get("flagged"):
        pulses = otx.get("pulse_count", 0)
        f = {
            "severity": "HIGH",
            "name": "AlienVault OTX: Found in Threat Pulses",
            "evidence": f"{pulses} threat pulses",
            "description": f"This IP appears in {pulses} AlienVault OTX threat intelligence pulses.",
            "confidence": 80,
            "strength": "strong",
        }
        findings.append(_weaken(f) if signal_strength("otx", intel) == "weak" else f)

    if ipapi.get("available"):
        if ipapi.get("is_proxy"):
            # anonymity infrastructure is context, not proof of abuse (ip-api also marks e.g. Google DNS as proxy)
            findings.append({
                "severity": "MEDIUM",
                "name": "Proxy/VPN Detected",
                "evidence": f"{isp}",
                "description": "ip-api.com identifies this as a proxy, VPN or Tor exit node.",
                "confidence": 60,
            })
        if ipapi.get("is_hosting"):
            findings.append({
                "severity": "LOW",
                "name": "Hosting/Datacenter IP",
                "evidence": f"{isp}",
                "description": "ip-api.com identifies this as a hosting or datacenter IP, not a residential connection.",
                "confidence": 65,
            })

    tf = intel.get("threatfox", {})
    if tf.get("available") and tf.get("flagged"):
        findings.append({
            "severity": "CRITICAL",
            "name": "ThreatFox: Active IOC Match",
            "evidence": tf.get("detail", ""),
            "description": "This IP is listed as an active Indicator of Compromise in ThreatFox.",
            "confidence": 95,
            "strength": "strong",
        })

    reputation_sources = [k for k in ("virustotal", "abuseipdb", "otx", "threatfox") if intel.get(k, {}).get("available")]
    if not findings:
        if reputation_sources:
            findings.append({
                "severity": "LOW",
                "name": "No Threat Intelligence Hits",
                "evidence": ip_address,
                "description": f"Checked {len(reputation_sources)} reputation source(s): none flagged this IP.",
                "confidence": 60,
            })
        else:
            findings.append({
                "severity": "LOW",
                "name": "Reputation Not Checked",
                "evidence": ip_address,
                "description": "No reputation source (VirusTotal, AbuseIPDB, OTX, ThreatFox) was available; configure API keys for a reputation verdict.",
                "confidence": 20,
                "why_it_matters": "Without reputation data this result reflects only geolocation/hosting checks, not whether the IP is malicious.",
            })

    from utils.scoring import calculate_score, score_to_verdict
    score = calculate_score(findings)
    verdict = score_to_verdict(score)

    abuse_score   = abuse.get("abuse_score", 0) if abuse.get("available") else 0
    total_reports = abuse.get("total_reports", 0) if abuse.get("available") else 0
    usage_type    = (abuse.get("usage_type") or isp) if abuse.get("available") else isp

    reputation_map = {"MALICIOUS": "malicious", "SUSPICIOUS": "suspicious", "BENIGN": "clean"}
    reputation = reputation_map.get(verdict, "unknown") if reputation_sources or verdict != "BENIGN" else "unknown"
    coverage = (f"{len(reputation_sources)} reputation source(s) checked" if reputation_sources
                else "no reputation sources configured: verdict based on geolocation/hosting data only")

    return {
        "verdict":       verdict,
        "score":         score,
        "mode":          "ip",
        "input":         ip_address,
        "findings":      findings,
        "summary":       f"IP {ip_address} ({country}); {verdict} at {score}% risk score; {coverage}.",
        "ip":            ip_address,
        "reputation":    reputation,
        "intel_checked": len(reputation_sources),
        "abuse_score":   abuse_score,
        "country_code":  country_code,
        "country":       country,
        "isp":           isp,
        "asn":           asn,
        "usage_type":    usage_type,
        "total_reports": total_reports,
        "intel_sources": intel,
        "recommended_action": recommended[verdict],
        "checks":        intel_checks(intel),
    }


# ═══════════════════════════════════════════════════════════════
#  PHASE 2 ADDITIONS: caching, call tracking, enrichment, RDAP
# ═══════════════════════════════════════════════════════════════

def is_public_ip(value: str) -> bool:
    """True only for globally routable IPv4/IPv6 addresses (SSRF + private-IP guard)."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return ip.is_global


_CACHE: dict = {}
_CACHE_TTL = int(os.getenv("INTEL_CACHE_TTL", "900"))   # seconds


def _instrument(fn_name: str):
    """Wrap an API caller with a TTL cache (protects VT free-tier quota) and failure tracking."""
    original = globals()[fn_name]

    def wrapper(*args):
        key = (fn_name,) + args
        hit = _CACHE.get(key)
        if hit and time.time() - hit[0] < _CACHE_TTL:
            return hit[1]
        t0 = time.time()
        res = original(*args)
        ms = int((time.time() - t0) * 1000)
        if res.get("available") is False and not res.get("error"):
            return res                                   # no API key configured -> not a failure
        failed = bool(res.get("error"))
        track_api_call(fn_name.strip("_"), not failed, ms, res.get("error") or "")
        if not failed:
            _CACHE[key] = (time.time(), res)
        else:
            res = dict(res, rate_limited=("429" in str(res.get("error"))))
        return res

    wrapper.__name__ = fn_name
    globals()[fn_name] = wrapper


for _n in ("_vt_lookup_url", "_vt_lookup_hash", "_vt_lookup_ip", "_abuseipdb_lookup", "_urlscan_lookup",
           "_otx_lookup_url", "_otx_lookup_ip", "_ipapi_lookup", "_malwarebazaar_lookup", "_threatfox_lookup"):
    _instrument(_n)


def domain_rdap(domain: str) -> dict:
    """Registration date / age / registrar via public RDAP (no key). {} if unknown."""
    host = url_host(domain)
    if not host or _is_ip_host(host) or "." not in host:
        return {}
    reg = registrable_domain(host)
    key = ("rdap", reg)
    hit = _CACHE.get(key)
    if hit and time.time() - hit[0] < 86400:
        return hit[1]
    t0 = time.time()
    try:
        r = requests.get(f"https://rdap.org/domain/{reg}", timeout=4, headers={"Accept": "application/rdap+json"})
        if not r.ok:
            track_api_call("rdap", False, int((time.time() - t0) * 1000), f"HTTP {r.status_code}")
            return {}
        d = r.json()
        out = {"registrable_domain": reg}
        for ev in d.get("events", []):
            if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                dt = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                out["registered"] = dt.date().isoformat()
                out["age_days"] = (datetime.now(timezone.utc) - dt).days
        for ent in d.get("entities", []):
            if "registrar" in (ent.get("roles") or []):
                vcard = (ent.get("vcardArray") or [None, []])[1]
                fn = next((v[3] for v in vcard if isinstance(v, list) and len(v) > 3 and v[0] == "fn"), "")
                out["registrar"] = fn or ent.get("handle", "")
                break
        _CACHE[key] = (time.time(), out)
        track_api_call("rdap", True, int((time.time() - t0) * 1000))
        return out
    except Exception as e:
        track_api_call("rdap", False, int((time.time() - t0) * 1000), str(e))
    return {}


def domain_age_days(domain: str) -> int | None:
    """Domain registration age via public RDAP (no key). None if unknown."""
    return domain_rdap(domain).get("age_days")


def new_domain_finding(age: int | None, threshold_days: int = 30) -> dict | None:
    if not isinstance(age, int) or age > threshold_days:
        return None
    return {
        "severity": "HIGH", "name": "Newly Registered Domain",
        "evidence": f"Registered {age} day(s) ago",
        "description": f"Domain was registered only {age} day(s) ago: most phishing domains are used within weeks of registration.",
        "confidence": 80,
        "why_it_matters": "Phishing and malware domains are typically burned within days. Legitimate brands have long registration histories.",
        "recommendation": "Treat as untrusted. Check WHOIS/RDAP registrant data and passive DNS before any interaction.",
        "false_positive_possibility": "Medium: new legitimate sites and campaigns also use fresh domains.",
        "reference": "MITRE ATT&CK T1583.001",
    }


def newly_registered_finding(domain: str, threshold_days: int = 30) -> dict | None:
    return new_domain_finding(domain_age_days(domain), threshold_days)


_NO_FAMILY = {"", "unknown", "unknown malware", "unclassified", "none", "n/a"}


def malware_family_from_sources(sources: dict) -> dict | None:
    """Family as reported by MalwareBazaar (signature) or ThreatFox (malware_printable): never guessed.
    Returns {name, source, first_seen, tags} or None when no source named a family."""
    for key, field in (("malwarebazaar", "malware_name"), ("threatfox", "malware")):
        s = (sources or {}).get(key) or {}
        name = str(s.get(field) or "").strip()
        if s.get("available") and s.get("flagged") and name.lower() not in _NO_FAMILY:
            tags = [str(t) for t in (s.get("tags") or []) if t]
            return {"name": name, "source": s.get("source") or SOURCE_NAMES.get(key, key),
                    "first_seen": s.get("first_seen") or "", "tags": tags[:12]}
    return None


def reputation_summary_ip(ip: str) -> dict:
    """Compact reputation card for one IP (VT + AbuseIPDB + OTX + ThreatFox via lookup_ip)."""
    r = lookup_ip(ip)
    src = r.get("intel_sources", {}) or {}
    vt, ab = src.get("virustotal", {}), src.get("abuseipdb", {})
    checked = r.get("intel_checked", 0)
    return {
        "indicator": ip, "type": "ip",
        "reputation_score": r.get("score", 0) if checked else None,
        "verdict": r.get("verdict", "BENIGN") if checked else "UNKNOWN",
        "country": r.get("country", ""), "isp": r.get("isp", ""),
        "abuseipdb_score": ab.get("abuse_score") if ab.get("available") else None,
        "abuseipdb_reports": ab.get("total_reports") if ab.get("available") else None,
        "vt_malicious": vt.get("malicious_engines") if vt.get("available") else None,
        "vt_total": vt.get("total_engines") if vt.get("available") else None,
        "findings": [f.get("name") for f in r.get("findings", [])],
        "malware_family": malware_family_from_sources(src),
    }


def reputation_summary_hash(h: str) -> dict:
    r = lookup_hash(h)
    src = r.get("intel_sources", {}) or {}
    vt = src.get("virustotal", {})
    sevs = {f.get("severity") for f in r.get("intel_findings", [])}
    checked = [s.get("source") for s in src.values() if s.get("available")]
    if "CRITICAL" in sevs:
        verdict, score = "MALICIOUS", 94
    elif sevs:
        verdict, score = "SUSPICIOUS", 55
    elif checked:
        verdict, score = "BENIGN", 12
    else:
        verdict, score = "UNKNOWN", None
    return {
        "indicator": h, "type": "hash",
        "reputation_score": score, "verdict": verdict,
        "vt_malicious": vt.get("malicious_engines") if vt.get("available") else None,
        "vt_total": vt.get("total_engines") if vt.get("available") else None,
        "sources_checked": checked,
        "malware_family": malware_family_from_sources(src),
    }


def enrich_indicators(ips=(), hashes=(), max_ips: int = 5, max_hashes: int = 3) -> dict:
    """
    Auto-enrich extracted IOCs. Only PUBLIC IPs are queried. Runs in parallel with a global time budget.
    Returns {"ips": [...], "hashes": [...], "findings": [...]}: findings plug into the scoring engine.
    """
    pub = [i for i in dict.fromkeys(ips) if is_public_ip(i)][:max_ips]
    hs = list(dict.fromkeys(h.lower() for h in hashes))[:max_hashes]
    out = {"ips": [], "hashes": [], "findings": [], "skipped_private": [i for i in dict.fromkeys(ips) if not is_public_ip(i)]}
    if not pub and not hs:
        return out
    ex = ThreadPoolExecutor(max_workers=6)
    jobs = {}
    for i in pub:
        jobs[ex.submit(reputation_summary_ip, i)] = ("ips", i)
    for h in hs:
        jobs[ex.submit(reputation_summary_hash, h)] = ("hashes", h)
    try:
        for fut in as_completed(jobs, timeout=9):
            kind, val = jobs[fut]
            try:
                out[kind].append(fut.result())
            except Exception as e:
                log.error("enrichment failed for %s: %s", val, e)
    except FuturesTimeout as e:                      # time budget exceeded: return what we have
        log.warning("enrichment budget exceeded: %s", e)
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    for rep in out["ips"]:
        if rep["verdict"] in ("MALICIOUS", "SUSPICIOUS"):
            detail = ", ".join(x for x in (
                f"AbuseIPDB {rep['abuseipdb_score']}%" if rep["abuseipdb_score"] is not None else "",
                f"VT {rep['vt_malicious']}/{rep['vt_total']}" if rep["vt_total"] else "",
                "; ".join(rep["findings"][:2])) if x)
            out["findings"].append({
                "severity": "CRITICAL" if rep["verdict"] == "MALICIOUS" else "HIGH",
                "name": "Extracted IP Has Bad Reputation",
                "evidence": f"{rep['indicator']}: {detail}",
                "description": f"IP {rep['indicator']} extracted from the artifact is rated {rep['verdict']} by threat intelligence.",
                "confidence": 85,
                "why_it_matters": "An origin or relay IP with abuse history strongly suggests attacker infrastructure.",
                "recommendation": "Block at the perimeter and search logs for other contact with this IP.",
                "false_positive_possibility": "Low–Medium: shared hosting / VPN exits can carry stale reports.",
                "reference": "AbuseIPDB / VirusTotal / OTX / ThreatFox",
            })
    for rep in out["hashes"]:
        if rep["verdict"] == "MALICIOUS":
            out["findings"].append({
                "severity": "CRITICAL", "name": "Attachment Hash Known Malicious",
                "evidence": rep["indicator"][:32] + "…",
                "description": "A file hash extracted from the artifact is confirmed malicious by threat intelligence.",
                "confidence": 95,
                "why_it_matters": "Hash matches are exact: this very file has been analyzed and flagged.",
                "recommendation": "Quarantine the file, do not open it, and start incident response.",
                "false_positive_possibility": "Very low.", "reference": "VirusTotal / MalwareBazaar / ThreatFox",
            })
    return out
