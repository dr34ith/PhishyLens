"""
PhishyLens v2
analyzers/email_analyzer.py: Email Risk Analyzer
"""

import re
import uuid
import time
import hashlib
import ipaddress
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from utils.scoring import (calculate_score, score_to_verdict, build_risk_breakdown,
                           correlate_evidence, attach_explanation)
from utils.logger import get_logger

log = get_logger("email")

DANGEROUS_EXT = {"exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "bat", "cmd", "com", "pif",
                 "jar", "lnk", "iso", "img", "dll", "msi", "docm", "xlsm", "pptm", "one", "html", "htm", "svg", "chm"}
DOC_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "jpeg", "png", "zip"}
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

URGENCY_PATTERNS = re.compile(
    r'\b(urgent|immediately|suspended|limited|verify|24 hours|48 hours|confirm|expires|locked|action required)\b',
    re.IGNORECASE
)
URL_PATTERN     = re.compile(r'https?://[^\s"\'<>]+')
EMAIL_PATTERN   = re.compile(r'From:.*<(.+?)>')
SUBJECT_PATTERN = re.compile(r'Subject:\s*(.+)')


# ─── FORENSIC HEADER / MIME PARSER ─────────────────────────────
class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text, self.text, self._skip = [], None, [], [], 0
    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href, self._text = dict(attrs).get("href"), []
        elif tag in ("script", "style"):
            self._skip += 1
    def handle_data(self, data):
        if not self._skip:
            self.text.append(data)
        if self._href is not None:
            self._text.append(data)
    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def _addr_domain(value: str) -> str:
    m = re.search(r"@([A-Za-z0-9.\-]+)", value or "")
    return m.group(1).lower().rstrip(".") if m else ""


def _same_site(a: str, b: str) -> bool:
    """True if two hostnames are equal or one is a subdomain of the other (www.paypal.com ~ paypal.com)."""
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _auth_result(text: str, mech: str) -> str:
    m = re.search(rf"\b{mech}\s*=\s*([a-zA-Z]+)", text or "", re.I)
    return m.group(1).lower() if m else ""


def parse_email_forensics(raw) -> dict:
    """Parse raw RFC-822 text/bytes into forensic artifacts. Never raises."""
    data = raw if isinstance(raw, (bytes, bytearray)) else raw.encode("utf-8", errors="replace")
    f = {"parsed": False, "headers": {}, "received_chain": [], "origin_ips": [], "auth": {}, "attachments": [],
         "links": [], "html_link_mismatches": [], "body_text": "", "html_text": ""}
    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as e:
        log.error("email parse failed: %s", e)
        return f

    def h(name):
        v = msg.get(name)
        return str(v).strip() if v is not None else ""

    f["parsed"] = bool(msg.keys())
    f["headers"] = {k: h(k) for k in ("From", "To", "Subject", "Date", "Message-ID", "Return-Path", "Reply-To",
                                      "Sender", "X-Mailer", "User-Agent", "X-Originating-IP", "X-Sender-IP",
                                      "Received-SPF", "DKIM-Signature", "X-Spam-Status") if h(k)}

    # Received chain (oldest hop last in the header list -> reverse for chronological order)
    for hop in reversed(msg.get_all("Received", [])):
        hop = " ".join(str(hop).split())
        ips = [i for i in IP_RE.findall(hop) if _valid_ip(i)]
        f["received_chain"].append({"hop": hop[:300], "ips": ips})

    # Origin IPs
    cand = []
    for k in ("X-Originating-IP", "X-Sender-IP"):
        cand += IP_RE.findall(h(k))
    for hop in f["received_chain"][:3]:
        cand += hop["ips"]
    f["origin_ips"] = list(dict.fromkeys(i for i in cand if _valid_ip(i)))

    # Authentication results (SPF / DKIM / DMARC)
    auth_blob = " ".join(str(x) for x in msg.get_all("Authentication-Results", []))
    spf_hdr   = h("Received-SPF")
    f["auth"] = {
        "spf":   _auth_result(auth_blob, "spf") or (spf_hdr.split()[0].lower() if spf_hdr else ""),
        "dkim":  _auth_result(auth_blob, "dkim"),
        "dmarc": _auth_result(auth_blob, "dmarc"),
        "arc":   _auth_result(auth_blob, "arc"),
        "dkim_domain": (re.search(r"header\.d=([\w.\-]+)", auth_blob) or re.search(r"\bd=([\w.\-]+)", h("DKIM-Signature")) or [None, ""])[1],
        "smtp_mailfrom": (re.search(r"smtp\.mailfrom=([^\s;]+)", auth_blob) or [None, ""])[1],
        "raw": auth_blob[:500],
    }

    # Body + attachments
    html_parts = []
    try:
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            fname = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            if fname or part.get_content_disposition() == "attachment":
                ext = fname.rsplit(".", 1)[-1].lower() if fname and "." in fname else ""
                parts = (fname or "").lower().split(".")
                double = len(parts) >= 3 and parts[-1] in DANGEROUS_EXT and parts[-2] in DOC_EXT
                f["attachments"].append({
                    "filename": fname or "(unnamed)", "content_type": ctype, "size": len(payload),
                    "md5": hashlib.md5(payload).hexdigest(), "sha256": hashlib.sha256(payload).hexdigest(),
                    "dangerous_ext": ext in DANGEROUS_EXT, "double_extension": double,
                })
            elif ctype == "text/plain":
                f["body_text"] += payload.decode(part.get_content_charset() or "utf-8", errors="replace")
            elif ctype == "text/html":
                html_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    except Exception as e:
        log.error("email MIME walk failed: %s", e)

    for html in html_parts:
        lp = _LinkParser()
        try:
            lp.feed(html)
        except Exception:
            continue
        f["html_text"] += " ".join(" ".join(lp.text).split()) + "\n"
        for href, text in lp.links:
            if not href:
                continue
            f["links"].append(href)
            # only compare when the visible text itself looks like a URL / hostname
            t = re.search(r"(?:https?://|\bwww\.)((?:[\w\-]+\.)+[a-z]{2,})", text, re.I)
            hr = re.search(r"https?://([^/\s:?#]+)", href)
            if t and hr and not _same_site(t.group(1), hr.group(1)):
                f["html_link_mismatches"].append({"shown": text[:80], "actual": href[:120]})
    return f


def _valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v); return True
    except ValueError:
        return False


def _f(sev, name, evidence, desc, conf, why, rec, fp, ref):
    return {"severity": sev, "name": name, "evidence": evidence, "description": desc, "confidence": conf,
            "why_it_matters": why, "recommendation": rec, "false_positive_possibility": fp, "reference": ref}


def _forensic_findings(fx: dict) -> list:
    out, hd, au = [], fx["headers"], fx["auth"]
    from_dom   = _addr_domain(hd.get("From", ""))
    rpath_dom  = _addr_domain(hd.get("Return-Path", ""))
    reply_dom  = _addr_domain(hd.get("Reply-To", ""))

    if not any(au.get(m) for m in ("spf", "dkim", "dmarc")) and not hd.get("DKIM-Signature"):
        out.append(_f("MEDIUM", "Missing Sender Authentication", "No Authentication-Results / Received-SPF / DKIM-Signature headers",
                      "No SPF, DKIM or DMARC results are present; sender identity cannot be verified from the headers.", 65,
                      "SPF, DKIM and DMARC let receivers verify that mail genuinely came from the claimed domain. Without them the sender could be anyone.",
                      "Treat sender identity as unverified. If you pasted only part of the message, include the full original headers.",
                      "High: pasted excerpts and some internal relays omit these headers.", "RFC 7208 / RFC 6376 / RFC 7489"))
    for mech, sev_fail in (("spf", "HIGH"), ("dkim", "HIGH"), ("dmarc", "CRITICAL")):
        res = au.get(mech)
        if res in ("fail", "permerror", "temperror"):
            out.append(_f(sev_fail, f"{mech.upper()} Authentication Failed", f"{mech}={res}",
                          f"The receiving server reported {mech.upper()} = {res}.", 92,
                          f"A {mech.upper()} failure means the message could not be validated as coming from the claimed domain; the strongest header-level spoofing signal.",
                          "Treat the sender as forged. Do not trust From: display.", "Low: misconfigured senders and forwarding can break SPF/DKIM.",
                          {"spf": "RFC 7208", "dkim": "RFC 6376", "dmarc": "RFC 7489"}[mech]))
        elif res in ("softfail", "none", "neutral"):
            out.append(_f("MEDIUM", f"{mech.upper()} Not Passing", f"{mech}={res}",
                          f"{mech.upper()} returned '{res}'; sender not authorised/validated.", 70,
                          "Weak or absent authentication leaves room for domain spoofing.",
                          "Verify sender out-of-band.", "Medium: common for small/legacy senders.", "RFC 7208 / 6376 / 7489"))
    if from_dom and rpath_dom and not _same_site(from_dom, rpath_dom):
        out.append(_f("MEDIUM", "Return-Path / From Mismatch", f"From @{from_dom} vs Return-Path @{rpath_dom}",
                      "The envelope sender differs from the visible From domain.", 72,
                      "Spoofers control the visible From but the bounce address often reveals the true sending infrastructure.",
                      "Investigate the Return-Path domain/IP.", "Medium: mailing-list and ESP services legitimately differ.", "MITRE ATT&CK T1672"))
    if from_dom and reply_dom and not _same_site(from_dom, reply_dom):
        out.append(_f("MEDIUM", "Reply-To Hijack", f"From @{from_dom} vs Reply-To @{reply_dom}",
                      "Replies are redirected to a different domain than the sender.", 75,
                      "BEC/phishing actors use Reply-To to capture victim replies while the From looks legitimate.",
                      "Do not reply. Confirm via a known channel.", "Medium.", "MITRE ATT&CK T1566"))
    if au.get("dkim_domain") and from_dom and not _same_site(au["dkim_domain"], from_dom):
        out.append(_f("LOW", "DKIM Domain Not Aligned", f"d={au['dkim_domain']} vs From @{from_dom}", "DKIM signed by a different domain than From.", 55,
                      "DMARC alignment requires the signing domain to match From.", "Check DMARC alignment.", "High: ESPs sign with their own domain.", "RFC 7489"))
    for a in fx["attachments"]:
        if a["double_extension"]:
            out.append(_f("CRITICAL", "Double-Extension Attachment", a["filename"], "File masquerades as a document but ends in an executable extension.", 93,
                          "Classic trick to disguise malware as a harmless document.", "Quarantine; never open.", "Very low.", "MITRE ATT&CK T1036.007"))
        elif a["dangerous_ext"]:
            out.append(_f("HIGH", "Risky Attachment Type", f"{a['filename']} (sha256 {a['sha256'][:16]}…)", "Attachment type commonly used to deliver malware.", 80,
                          "Executables, scripts, macro documents, ISO/LNK and HTML smuggling files are top delivery formats.", "Detonate in a sandbox; check hash on VirusTotal.",
                          "Medium.", "MITRE ATT&CK T1566.001"))
    for m in fx["html_link_mismatches"][:2]:
        out.append(_f("HIGH", "Link Text / Destination Mismatch", f"shows '{m['shown']}' → {m['actual']}", "Visible link text points to a different domain than the real href.", 90,
                      "Deceptive anchors are a hallmark of credential-phishing emails.", "Do not click; analyse the real URL.", "Low.", "MITRE ATT&CK T1566.002"))
    return out


def _email_checks(fx: dict, findings: list) -> list:
    """Header / content checks that really ran: flagged / clear / unavailable (never 'clear' without data)."""
    from utils.threat_intel import check
    names = {f.get("name") for f in findings}
    hd, au, out = fx.get("headers") or {}, fx.get("auth") or {}, []
    for mech in ("spf", "dkim", "dmarc"):
        res = au.get(mech)
        out.append(check(mech.upper(), "clear" if res == "pass" else "flagged" if res else "unavailable"))
    from_dom = _addr_domain(hd.get("From", ""))
    rpath = _addr_domain(hd.get("Return-Path", ""))
    out.append(check("Return-Path vs From", "unavailable" if not (from_dom and rpath)
                else "flagged" if "Return-Path / From Mismatch" in names else "clear"))
    reply = _addr_domain(hd.get("Reply-To", ""))
    out.append(check("Reply-To vs From", "unavailable" if not (from_dom and reply)
                else "flagged" if "Reply-To Hijack" in names else "clear"))
    if fx.get("parsed"):
        out.append(check("Link text vs destination", "flagged" if fx.get("html_link_mismatches") else "clear"))
        risky = any(a.get("dangerous_ext") or a.get("double_extension") for a in fx.get("attachments") or [])
        out.append(check("Attachments", "flagged" if risky else "clear"))
    return out


def analyze_email(email_text) -> dict:
    from utils.threat_intel import FREE_TLDS, BRANDS, BRAND_DISPLAY, official_brand, is_free_tld, detect_brand_impersonation, url_host
    start    = time.time()
    findings = []
    forensics = parse_email_forensics(email_text)
    if isinstance(email_text, (bytes, bytearray)):
        email_text = email_text.decode("utf-8", errors="replace")
    hd = forensics["headers"]
    has_body = bool(forensics.get("body_text", "").strip() or forensics.get("html_text", "").strip())
    # human-readable content = subject + decoded plain/HTML body (raw MIME is only used if parsing found no body)
    content = "\n".join([hd.get("Subject", ""), forensics.get("body_text", ""), forensics.get("html_text", "")]) if has_body else email_text
    url_text = content + "\n" + "\n".join(forensics.get("links", []))

    # Sender domain on a free / heavily abused TLD
    from_hdr   = hd.get("From", "")
    sender_dom = _addr_domain(from_hdr)
    if not sender_dom:
        m = EMAIL_PATTERN.search(email_text)
        sender_dom = _addr_domain(m.group(1)) if m else ""
    sender_tld = sender_dom.rsplit(".", 1)[-1] if "." in sender_dom else ""
    if sender_tld in FREE_TLDS:
        findings.append({
            "severity":    "HIGH",
            "name":        "Suspicious Sender TLD",
            "evidence":    sender_dom,
            "description": f"Sending domain uses the .{sender_tld} TLD, which is free or very cheap and heavily abused for phishing.",
            "confidence":  75,
            "why_it_matters": "Attackers register disposable domains on these TLDs to send phishing emails that appear legitimate at first glance.",
            "recommendation": "Do not interact with this email. Verify sender through a separate communication channel.",
            "false_positive_possibility": "Medium: some legitimate senders use these TLDs.",
            "reference": "MITRE ATT&CK T1583.001",
        })

    # Display name claims a brand the sending domain does not belong to: "PayPal" <x@evil.xyz>
    display = from_hdr.split("<")[0].strip().strip('"').lower() if "<" in from_hdr else ""
    claimed = next((b for b in BRANDS if b in display.replace(" ", "")), None)
    if claimed and sender_dom and official_brand(sender_dom) != claimed:
        name = BRAND_DISPLAY.get(claimed, claimed.title())
        findings.append({
            "severity":    "HIGH",
            "name":        "Display Name Brand Spoofing",
            "evidence":    f'"{from_hdr.split("<")[0].strip().strip(chr(34))}" sent from @{sender_dom}',
            "description": f"The sender display name claims to be {name}, but the address is not on a {name} domain.",
            "confidence":  85,
            "why_it_matters": "Most mail clients show only the display name, so victims see a trusted brand while the real address is attacker-controlled.",
            "recommendation": "Check the actual sender address. Contact the brand through its official site, not via this email.",
            "false_positive_possibility": "Low–Medium: some brands send via third-party ESP domains.",
            "reference": "MITRE ATT&CK T1566 / T1656",
        })

    # Embedded URLs
    urls = list(dict.fromkeys(u.rstrip(".,;:)]}'\"") for u in URL_PATTERN.findall(url_text)))
    # report the single strongest suspicious link (brand lookalike / abused TLD beat a merely credential-themed path);
    # links on the brand's own domains (https://paypal.com/...) are not suspicious by themselves
    suspicious = []
    for url in urls[:50]:
        host = url_host(url)
        if not host or official_brand(host):
            continue
        brand, free = detect_brand_impersonation(url), is_free_tld(url)
        cred_path = re.search(r'verify|login|signin|secure|account', url.split("?")[0], re.I)
        if brand or free or cred_path:
            reasons = [r for r in (f"impersonates {brand}" if brand else "",
                                   f"free/abused .{host.rsplit('.', 1)[-1]} TLD" if free else "",
                                   "credential-themed path" if cred_path else "") if r]
            suspicious.append((bool(brand) + bool(free), url, reasons))
    if suspicious:
        strength, url, reasons = max(suspicious, key=lambda x: x[0])
        findings.append({
            "severity":    "HIGH",
            "name":        "Suspicious URL in Body",
            "evidence":    f"{url[:80]} ({', '.join(reasons)})" + (f" +{len(suspicious) - 1} more" if len(suspicious) > 1 else ""),
            "description": "Suspicious URL embedded in message: matches common credential-harvesting link patterns.",
            "confidence":  80 if strength else 65,
            "why_it_matters": "Embedded phishing links are the most common delivery mechanism for credential theft.",
            "recommendation": "Do not click. Copy the URL and analyze it separately using the URL analyzer.",
            "false_positive_possibility": "Medium: legitimate account emails also link to login pages.",
            "reference": "MITRE ATT&CK T1566.002",
        })

    # Urgency language (subject + body only, not headers)
    urgency = list(dict.fromkeys(u.lower() for u in URGENCY_PATTERNS.findall(content)))
    if urgency:
        findings.append({
            "severity":    "HIGH" if len(urgency) >= 2 else "MEDIUM",
            "name":        "Urgency / Pressure Manipulation",
            "evidence":    ", ".join(urgency[:5]),
            "description": f"Message uses {len(urgency)} distinct pressure/urgency term(s) to rush the recipient.",
            "confidence":  75 if len(urgency) >= 2 else 55,
            "why_it_matters": "Creating a false sense of urgency is a core social engineering technique. It bypasses rational evaluation and triggers impulsive action.",
            "recommendation": "Pause before acting. Verify the request through official channels; legitimate organizations do not demand immediate action via email alone.",
            "false_positive_possibility": "Medium: legitimate service alerts may also use urgency language.",
            "reference": "MITRE ATT&CK T1598",
        })

    # Phase 1: header forensics + attachment checks
    findings.extend(_forensic_findings(forensics))

    # Phase 2: auto-enrich origin IPs and attachment hashes (VirusTotal / AbuseIPDB / ...)
    enrichment = {"ips": [], "hashes": [], "skipped_private": []}
    try:
        from utils.threat_intel import enrich_indicators
        enrichment = enrich_indicators(forensics["origin_ips"], [a["sha256"] for a in forensics["attachments"]])
        findings.extend(enrichment.pop("findings", []))
    except Exception as e:
        log.error("email enrichment failed: %s", e)

    score   = calculate_score(findings) if findings else 8
    verdict = score_to_verdict(score)

    subject_match = SUBJECT_PATTERN.search(email_text)
    subject_str   = hd.get("Subject") or (subject_match.group(1).strip() if subject_match else "Unknown Subject")

    risk_breakdown       = build_risk_breakdown(findings)
    evidence_correlation = correlate_evidence(findings)
    duration_ms          = int((time.time() - start) * 1000)

    recommended_action = {
        "MALICIOUS":  "Do not interact with this email. Report to security team. Check if any links were clicked or attachments opened.",
        "SUSPICIOUS": "Exercise caution. Verify sender identity through alternative channels before responding or clicking any links.",
        "BENIGN":     "No immediate concerns. Standard email security practices apply.",
    }.get(verdict, "Exercise caution.")

    result = {
        "verdict":              verdict,
        "score":                score,
        "mode":                 "email",
        "input":                email_text,
        "findings":             findings,
        "summary":              f"Email '{subject_str[:60]}' analyzed. Risk: {verdict} (score {score}%).",
        "risk_breakdown":       risk_breakdown,
        "evidence_correlation": evidence_correlation,
        "recommended_action":   recommended_action,
        "scan_id":              str(uuid.uuid4())[:8].upper(),
        "confidence":           70,
        "duration_ms":          duration_ms,
        "iocs":                 {"urls": urls,
                                         "emails": sorted({a for a in re.findall(r"[\w.+\-]+@[\w.\-]+\.[a-z]{2,}", email_text, re.I)})[:25],
                                         "domains": sorted({d for d in [sender_dom] + [url_host(u) for u in urls] if d})[:25],
                                         "ips": forensics["origin_ips"],
                                         "hashes": [a["sha256"] for a in forensics["attachments"]]},
        "forensics":            {k: v for k, v in forensics.items() if k not in ("body_text", "html_text")},
        "enrichment":           enrichment,
        "checks":               _email_checks(forensics, findings),
    }
    return attach_explanation(result)
