"""
PhishyLens: the Executive Summary as a data-driven story (exec_summary["story"]).

    build_story(result, headline="", do_now=()) -> [{section, title, sentences: [{text, ref, certainty, define?}]}]

Sections, in order (a section with no data is omitted):
  artifact  "The artifact"              what was submitted and its identity facts
  found     "What we found"             the strongest evidence, with real numbers and sources, then the checks that came back clear
  unfolded  "How it unfolded"           the order of events (timestamps / line numbers when the data has them)
  means     "What it means"             verdict and score in words, top 3 score factors, evidence strength, what would change it
  limits    "What we couldn't check"    sources that were unavailable, checks that could not run, the top 2 open questions

Rules (tests/test_story.py):
  * Deterministic templates over result fields only: no LLM, no network calls. A template whose data is missing is skipped.
  * certainty: "observed" (a value in the result), "inferred" (a rule-based conclusion, worded "suggests" / "is consistent
    with") or "unknown" (worded "could not be determined").
  * Every sentence has a ref into the result ({"finding": i}, {"line": n}, {"ts": raw}, {"field": "a.b[0]"}); the only
    exception is a "nothing else flagged" sentence, marked clear=True.
  * At most 4 sentences per section, every sentence under 25 words, about 180-320 visible words in total.
  * Never "confirmed", "compromised", "breach", or an attacker's goal stated as fact. Attacker strings are sanitized.
"""
import re

from utils.artifacts import SEV_RANK, INFORMATIONAL, parse_cleartext, parse_scan, parse_suspicious_port, real_findings
from utils.defang import defang_text
from utils.scoring import BENIGN_THRESHOLD, MALICIOUS_THRESHOLD
from utils.summary_details import TOOLS_RE, URL_RE, _tech_ids, clean, glossary

SECTIONS = [("artifact", "The artifact"), ("found", "What we found"), ("unfolded", "How it unfolded"),
            ("means", "What it means"), ("limits", "What we couldn't check")]
CERTAINTIES = ("observed", "inferred", "unknown")
MAX_SENTENCES = 4
MAX_WORDS = 24                                  # "under 25 words"
WORD_MAX = 320
UNKNOWN = "could not be determined"
FORBIDDEN = re.compile(r"\b(?:confirmed|compromised|breach(?:ed|es)?)\b", re.I)
INFER_RX = re.compile(r"\bsuggests?\b|\bconsistent with\b", re.I)
SOURCE_ORDER = ["threatfox", "malwarebazaar", "virustotal", "abuseipdb", "otx", "urlscan", "ipapi"]
LOW_COUNT = 2

WEB_TERMS = {"SQL Injection": "SQL injection", "Cross-Site Scripting (XSS)": "XSS", "Path Traversal / LFI": "path traversal",
             "Command Injection": "command injection", "Log4Shell / JNDI Injection": "Log4Shell", "Server-Side Request Forgery": "SSRF",
             "Web Shell / Sensitive File Probe": "sensitive-file probe", "Scanner / Attack-Tool User-Agent": "attack-tool scanning",
             "Directory / Vulnerability Scanning": "directory scanning"}
PLAIN = {"Successful Login After Failures": "a successful login after failed attempts", "SSH / Login Brute Force": "brute force",
         "TCP Port Scan Detected": "a port scan", "Cleartext Credentials on the Wire": "cleartext credentials",
         "Traffic to Suspicious Port": "traffic to a suspicious port", "DMARC Authentication Failed": "a DMARC failure",
         "SPF Authentication Failed": "an SPF failure", "DKIM Authentication Failed": "a DKIM failure",
         "Double-Extension Attachment": "a double-extension attachment", "Risky Attachment Type": "a risky attachment type",
         "Link Text / Destination Mismatch": "a disguised link", "Reply-To Hijack": "a Reply-To hijack",
         "Return-Path / From Mismatch": "a Return-Path mismatch", "Urgency / Pressure Manipulation": "urgency pressure",
         "Display Name Brand Spoofing": "a spoofed display name", "Suspicious Sender TLD": "an abused sender domain",
         "Suspicious URL in Body": "a suspicious link", "End-of-Life Operating System": "an end-of-life OS",
         "ICMP Ping Sweep": "a ping sweep", "Possible DNS Tunnelling": "possible DNS tunnelling",
         "Suspicious Free TLD": "an abused top-level domain", "Deceptive Keywords Detected": "lure words in the URL",
         "Brand Impersonation": "brand impersonation", "IP Address in URL": "a raw IP address", "Excessive Subdomains": "padded subdomains",
         "Unencrypted Channel": "no HTTPS"}
PROBE_TYPES = {"Scanner / Attack-Tool User-Agent", "Directory / Vulnerability Scanning", "Web Shell / Sensitive File Probe"}

# top open questions per finding type, worded as "could not be determined"
OPEN_Q = {
    "SQL Injection": "Whether the SQL injection returned data could not be determined; only status and size are logged.",
    "Cross-Site Scripting (XSS)": "Whether the script was stored and shown to other users could not be determined.",
    "Path Traversal / LFI": "Whether the server returned the requested file could not be determined.",
    "Web Shell / Sensitive File Probe": "Whether the probed files exist on the server could not be determined.",
    "Command Injection": "Whether the injected command ran on the server could not be determined.",
    "SSH / Login Brute Force": "Whether the guessed passwords work on other systems could not be determined.",
    "Successful Login After Failures": "What the account did after logging in could not be determined from this log.",
    "PowerShell Download Cradle (inside encoded payload)": "Whether the downloaded script ran on the endpoint could not be determined.",
    "PowerShell Download Cradle": "Whether the downloaded script ran on the endpoint could not be determined.",
    "TCP Port Scan Detected": "Whether the scan source later connected to an open port could not be determined.",
    "Cleartext Credentials on the Wire": "Whether the exposed credentials are used on other systems could not be determined.",
    "Traffic to Suspicious Port": "Which process opened the suspicious connection could not be determined.",
    "End-of-Life Operating System": "The exact OS build could not be determined; fingerprints can be wrong.",
    "Double-Extension Attachment": "Whether anyone opened the attachment could not be determined.",
    "Risky Attachment Type": "Whether anyone opened the attachment could not be determined.",
    "Link Text / Destination Mismatch": "Whether anyone clicked the disguised link could not be determined.",
    "Suspicious URL in Body": "Whether anyone visited the linked page could not be determined.",
    "Brand Impersonation": "Whether the page collects credentials could not be determined; page content was not fetched.",
    "Newly Registered Domain": "Who registered the domain could not be determined from RDAP data.",
    "Shortened URL": "Whether the short link changes destination over time could not be determined.",
}
OPEN_Q_PREFIX = {"Vulnerable Service:": "Whether the installed versions are really vulnerable could not be determined; banners can be outdated.",
                 "NSE Finding:": "Whether the installed versions are really vulnerable could not be determined; banners can be outdated.",
                 "Risky Port Open:": "Whether each exposed service is needed could not be determined.",
                 "[": "Why the intel sources listed it could not be determined from the counts alone.",
                 "AlienVault OTX:": "Why the intel sources listed it could not be determined from the counts alone.",
                 "VirusTotal:": "Why the intel sources listed it could not be determined from the counts alone."}


# ─── small helpers ──────────────────────────────────────────────
def _soften(s: str) -> str:
    """Quoted source text must not carry the forbidden certainty words either."""
    def repl(m):
        w = m.group(0).lower()
        return "reported" if w.startswith("confirm") else "accessed" if w.startswith("compromis") else "incident"
    return FORBIDDEN.sub(repl, s)


def v(value, limit: int = 60) -> str:
    """A value quoted from the result: sanitized (control/bidi stripped, secrets masked), capped, softened."""
    return _soften(clean(value, limit))


def _a(n) -> str:
    """'A' / 'An' before a spoken number (an 8%, an 11%, an 18%, an 80-89%)."""
    return "An" if str(int(n)).startswith("8") or int(n) in (11, 18) else "A"


def _words(s: str) -> int:
    return len(s.split())


def _join(items, n=3) -> str:
    items = [str(i) for i in items if i]
    if not items:
        return ""
    if len(items) > n:
        return ", ".join(items[:n]) + f" and {len(items) - n} more"
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _plural(n, word, many=None):
    return f"{n} {word if n == 1 else (many or word + 's')}"


def _pick(*candidates) -> str:
    """First candidate that fits the sentence limit (templates are written long → short)."""
    for c in candidates:
        if c and _words(c) <= MAX_WORDS:
            return c
    c = next((c for c in reversed(candidates) if c), "")
    return " ".join(c.split()[:MAX_WORDS - 1]) + " …" if c else ""


def _s(text, ref, certainty="observed", **extra) -> dict:
    return {"text": text, "ref": ref, "certainty": certainty, **extra}


def _F(result):
    return [f if isinstance(f, dict) else {} for f in (result.get("findings") or [])]


def _idx(result, name=None, prefix=None):
    for i, f in enumerate(_F(result)):
        n = f.get("name", "")
        if (name is not None and n == name) or (prefix is not None and n.startswith(prefix)):
            return i
    return None


def _real(result):
    return [(i, f) for i, f in enumerate(_F(result)) if f.get("name") and f.get("name") not in INFORMATIONAL
            and not f.get("name", "").startswith("Hash Type Identified")]


def _techs(result, names, n=2) -> str:
    out = []
    for name in names:
        for t in _tech_ids(result, name):
            if t not in out:
                out.append(t)
    return f" ({', '.join(out[:n])})" if out else ""


def _host(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", str(url or ""), re.I)
    return m.group(1) if m else str(url or "")


INTEL_LABELS = [(re.compile(r"^\[([^\]]+)\] Flagged as Malicious$"), r"\1 flag"), (re.compile(r"^\[([^\]]+)\] Low Detection Count$"), r"\1 low detection count"),
                (re.compile(r"^\[([^\]]+)\] Hash Confirmed Malicious$"), r"\1 hash match"),
                (re.compile(r"^AbuseIPDB: Abuse History Confirmed$"), "AbuseIPDB abuse history"),
                (re.compile(r"^AlienVault OTX: Found in Threat Pulses$"), "OTX threat pulses"), (re.compile(r"^ThreatFox: Active IOC Match$"), "ThreatFox IOC match"),
                (re.compile(r"^VirusTotal: Flagged by (\d+) Engines?$"), r"VirusTotal (\1 engines)")]
NOT_FACTORS = re.compile(r"^Hash Type Identified")


def _label(name: str) -> str:
    """Short, plain label for a finding name."""
    for rx, rep in INTEL_LABELS:
        if rx.match(name or ""):
            return _soften(rx.sub(rep, name))
    n = re.sub(r"^\[[^\]]+\]\s*", "", name or "")
    n = re.sub(r"^(Vulnerable Service|NSE Finding): ", "", n)
    n = n.replace(" (inside encoded payload)", "")
    m = re.match(r"^Risky Port Open: (\d+)/(.+)$", n)
    if m:
        return f"{m.group(2)} on port {m.group(1)}"
    return _soften(WEB_TERMS.get(n, n))


def _plain(name: str) -> str:
    return PLAIN.get(name) or ("encoded PowerShell" if str(name).startswith("PowerShell") else _label(name))


def is_intel_name(name: str) -> bool:
    return bool(re.match(r"^\[|^(VirusTotal|AbuseIPDB|AlienVault OTX|ThreatFox|MalwareBazaar):|^(Proxy/VPN Detected|Hosting/Datacenter IP|"
                         r"Extracted IP Has Bad Reputation|Attachment Hash Known Malicious)$", name or ""))


def intel_only(result) -> bool:
    """True when every real finding is a threat-intel / reputation flag (no first-hand evidence)."""
    real = _real(result)
    return bool(real) and all(is_intel_name(f.get("name", "")) for _, f in real)


def hedged(result) -> bool:
    return str(result.get("verdict") or "").upper() != "MALICIOUS" or intel_only(result)


def _sources(result):
    src = result.get("intel_sources") or {}
    keys = sorted((k for k in src if isinstance(src[k], dict)), key=lambda k: SOURCE_ORDER.index(k) if k in SOURCE_ORDER else 99)
    return [(k, src[k]) for k in keys]


def _low_count(key, r) -> bool:
    if key == "virustotal":
        return int(r.get("malicious_engines") or 0) <= LOW_COUNT
    if key == "otx":
        return int(r.get("pulse_count") or 0) <= LOW_COUNT
    if key == "abuseipdb":
        return int(r.get("total_reports") or 0) <= LOW_COUNT
    return key == "urlscan"


def _source_state(r) -> str:
    if not isinstance(r, dict):
        return "unavailable"
    if r.get("available") and r.get("pending"):
        return "pending"
    if r.get("available"):
        return "flagged" if r.get("flagged") else "clear"
    err = str(r.get("error") or "")
    if "429" in err or "rate limit" in err.lower():
        return "rate-limited"
    return "unavailable" if err else "not configured"


# ─── 1. the artifact ────────────────────────────────────────────
def _artifact(result, claimed):
    mode, out = result.get("mode", ""), []
    if mode == "url":
        url = str(result.get("input") or "")
        m = re.match(r"^([a-z][a-z0-9+.-]*)://([^/?#]+)([^?#]*)(\?[^#]*)?", url, re.I)
        if m:
            path = m.group(3) or "/"
            shape = v(path, 40) + ("?…" if m.group(4) else "")
            out.append(_s(f"You analyzed {m.group(1).lower()}://{v(m.group(2), 60)}{shape}.", {"field": "input"}))
        di = result.get("domain_info") or {}
        known = lambda k: di.get(k) not in (None, "", "Unknown", "Unresolved", "n/a")
        if di and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", str(di.get("domain") or "")):
            where = ", ".join(v(di[k], 40) for k in ("country", "asn") if known(k))
            isp = v(di["isp"], 40) if known("isp") and str(di.get("isp")) not in str(di.get("asn")) else ""
            parts = []
            if known("registrar"):
                parts.append(f"is registered with {v(di['registrar'], 50)}")
            if known("resolved_ip"):
                parts.append(f"is hosted at {v(di['resolved_ip'], 45)}" + (f" ({where})" if where else "") + (f" by {isp}" if isp else ""))
            ref = {"field": "domain_info.registrar" if known("registrar") else "domain_info.resolved_ip"}
            age = di.get("domain_age_days")
            if isinstance(age, int):
                parts.append(f"was registered {_plural(age, 'day')} ago" + (f" ({v(di['registered'], 12)})" if known("registered") else ""))
                claimed.add("domain_age")
            if parts:
                out.append(_s(_pick("The domain " + _join(parts, 4) + ".", "The domain " + _join(parts[:2], 4) + "."), ref))
            unknown = [w for k, w in (("registrar", "registrar"), ("resolved_ip", "hosting address")) if k in di and not known(k)]
            if "domain_age_days" in di and not isinstance(age, int):
                unknown.append("registration age")
                claimed.add("domain_age")
            if unknown:
                field = "domain_info.domain_age_days" if "registration age" in unknown else "domain_info.registrar"
                out.append(_s(f"Its {_join(unknown, 3)} {UNKNOWN}.", {"field": field}, "unknown"))
    elif mode == "hash":
        h = str(result.get("input") or "")
        kind = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(h), "")
        if kind:
            out.append(_s(f"You submitted a {kind} file hash, {v(h[:16], 20)}….", {"field": "input"}))
        mb = (result.get("intel_sources") or {}).get("malwarebazaar") or {}
        if mb.get("file_type"):
            out.append(_s(f"MalwareBazaar records the file type as {v(mb['file_type'], 20)}.", {"field": "intel_sources.malwarebazaar.file_type"}))
    elif mode == "ip":
        ip = v(result.get("input") or result.get("ip"), 45)
        known = lambda k: str(result.get(k) or "") not in ("", "Unknown")
        where = ", ".join(v(result[k], 40) for k in ("country", "asn") if known(k))
        if ip:
            isp = f" operated by {v(result['isp'], 40)}" if known("isp") and str(result.get("isp")) not in str(result.get("asn")) else ""
            out.append(_s(_pick(f"You submitted the IP {ip}" + (f", located in {where}" if where else "") + isp + ".",
                                f"You submitted the IP {ip}" + (f", located in {where}" if where else "") + "."),
                          {"field": "country" if known("country") else "input"}))
            if not known("country") and "country" in result:
                out.append(_s(f"Its location and network owner {UNKNOWN}.", {"field": "country"}, "unknown"))
    elif mode == "email":
        hd = (result.get("forensics") or {}).get("headers") or {}
        if hd.get("From"):
            subj = f', with the subject "{v(hd["Subject"], 50)}"' if hd.get("Subject") else ""
            out.append(_s(_pick(f"The message claims to come from {v(hd['From'], 70)}{subj}.", f"The message claims to come from {v(hd['From'], 70)}."),
                          {"field": "forensics.headers.From"}))
        att = (result.get("forensics") or {}).get("attachments") or []
        if att:
            names = [f"{v(a.get('filename'), 40)} ({_plural(int(a.get('size') or 0), 'byte')})" for a in att]
            out.append(_s(f"It carries {_plural(len(att), 'attachment')}: {_join(names, 2)}.", {"field": "forensics.attachments[0]"}))
        if hd.get("Date"):
            out.append(_s(f"The Date header reads {v(hd['Date'], 40)}.", {"field": "forensics.headers.Date"}))
    elif mode == "logs":
        ls = result.get("log_stats") or {}
        if ls.get("total_lines"):
            fm = ls.get("formats") or {}
            fmts = _join([f"{v(k, 20)} ({n})" for k, n in sorted(fm.items(), key=lambda x: -x[1])], 3)
            out.append(_s(f"You submitted {_plural(ls['total_lines'], 'log line')}" + (f" in these formats: {fmts}" if fmts else "") + ".",
                          {"field": "log_stats.total_lines"}))
            if ls.get("parsed_lines") is not None and ls["parsed_lines"] < ls["total_lines"]:
                out.append(_s(f"{ls['parsed_lines']} of them could be parsed.", {"field": "log_stats.parsed_lines"}))
        ts = _log_times(ls)
        if len(ts) >= 2 and ts[0][1] != ts[-1][1]:
            out.append(_s(f"The entries run from {v(ts[0][1], 32)} (line {ts[0][0]}) to {v(ts[-1][1], 32)} (line {ts[-1][0]}).", {"ts": ts[0][1]}))
        elif ts:
            out.append(_s(f"The flagged entries carry one timestamp, {v(ts[0][1], 32)}.", {"ts": ts[0][1]}))
    elif mode == "network":
        ns = result.get("network_stats") or {}
        hosts, pk = ns.get("hosts") or [], ns.get("packets") or {}
        if hosts:
            names = [v(h.get("ip"), 45) + (f" ({v(h['hostname'], 30)})" if h.get("hostname") else "") for h in hosts]
            ports = sum(int(h.get("open_ports") or 0) for h in hosts)
            out.append(_s(f"You submitted an Nmap scan of {_plural(len(hosts), 'host')} ({_join(names, 3)}) with {_plural(ports, 'open port')}.",
                          {"field": "network_stats.hosts"}))
        if pk.get("packets"):
            protos = _join([f"{v(k, 12)} {n}" for k, n in sorted((pk.get("protocols") or {}).items(), key=lambda x: -x[1])], 3)
            out.append(_s(f"You submitted a packet capture with {_plural(pk['packets'], 'packet')}" + (f" ({protos})" if protos else "") + ".",
                          {"field": "network_stats.packets.packets"}))
    return out


def _log_times(ls):
    seen = {}
    for k in ("sample_hits", "auth_events", "login_after_failures"):
        for e in ls.get(k) or []:
            if isinstance(e, dict) and e.get("line") and e.get("ts"):
                seen.setdefault(e["line"], e["ts"])
    return sorted(seen.items())


# ─── 2. what we found ───────────────────────────────────────────
def _source_sentence(key, r):
    src = v(r.get("source") or key, 30)
    low = _low_count(key, r)
    tail = ", a low-confidence signal that needs manual verification" if low else ""
    ref = {"field": f"intel_sources.{key}"}
    if key == "virustotal" and r.get("total_engines"):
        return _s(f"VirusTotal flagged it in {r.get('malicious_engines', 0)} of {r['total_engines']} engines{tail}.", ref, strength="weak" if low else "strong")
    if key == "otx" and r.get("pulse_count") is not None:
        return _s(f"AlienVault OTX lists it in {_plural(int(r['pulse_count']), 'threat pulse')}{tail}.", ref, strength="weak" if low else "strong")
    if key == "abuseipdb":
        return _s(f"AbuseIPDB gives it an abuse score of {r.get('abuse_score', 0)}% from {_plural(int(r.get('total_reports') or 0), 'report')}{tail}.",
                  ref, strength="weak" if low else "strong")
    if key == "threatfox":
        what = v(r.get("malware"), 30) or "a known threat"
        return _s(f"ThreatFox matched it to {what}" + (f" ({v(r['threat_type'], 25)})" if r.get("threat_type") else "") + ".", ref, strength="strong")
    if key == "malwarebazaar":
        fam = v(r.get("malware_name"), 30)
        return _s(f"MalwareBazaar lists it as a known {fam + ' ' if fam and fam.lower() != 'unknown' else ''}malware sample.", ref, strength="strong")
    if key == "ipapi":
        return _s(f"ip-api.com reports: {v(r.get('detail'), 60)}.", ref)
    return _s(f"{src} flagged it: {v(' '.join(str(r.get('detail') or 'listed as malicious').split()[:12]), 80)}{tail}.", ref,
              strength="weak" if low else "strong")


URL_FOUND = {
    "Brand Impersonation": lambda f: (lambda m: f"The host contains the brand name {v(m.group(1), 20)} but {v(m.group(1), 20)} does not own it."
                                      if m else "The address imitates a well-known brand.")(re.match(r"^(.+?) in ", f.get("evidence", ""))),
    "Newly Registered Domain": lambda f: f"The domain was {v(f.get('evidence', '').lower(), 40)}.",
    "Shortened URL": lambda f: f"The link starts at the URL shortener {v(f.get('evidence'), 40)}, which hides the real destination.",
    "Suspicious Redirect Destination": lambda f: "The landing page shows warning signs: " + _join(
        [_plain(x.strip()) for x in v((re.search(r"[(](.*)[)]$", f.get("evidence", "")) or [None, ""])[1], 120).split(",") if x.strip()], 3) + ".",
    "IP Address in URL": lambda f: f"The URL uses the raw IP {v(f.get('evidence'), 45)} instead of a domain name.",
    "Suspicious Free TLD": lambda f: f"The domain uses the often-abused {v(f.get('evidence'), 15)} top-level domain.",
    "Deceptive Keywords Detected": lambda f: f"The URL contains the lure words {v(f.get('evidence'), 40)}.",
    "Excessive Subdomains": lambda f: f"The host is padded with {v(f.get('evidence'), 25)}.",
    "Unencrypted Channel": lambda f: "The page is served without HTTPS, so anything typed on it can be read in transit.",
}


def _found(result, claimed):
    mode, out = result.get("mode", ""), []
    real = _real(result)
    if mode in ("url", "hash", "ip"):
        for key, r in _sources(result):
            if r.get("available") and r.get("flagged") and len(out) < 3:
                out.append(_source_sentence(key, r))
                claimed.add(("source", key))
        for i, f in sorted(real, key=lambda x: -SEV_RANK.get(x[1].get("severity"), 0)):
            if len(out) >= 3:
                break
            n = f.get("name", "")
            if is_intel_name(n) or n == "Redirect Chain Detected":
                continue
            tpl = URL_FOUND.get(n)
            text = tpl(f) if tpl else f"{_label(n)}: {v(f.get('evidence'), 70)}."
            out.append(_s(_pick(text, f"{_label(n)}."), {"finding": i}))
            claimed.add(("finding", i))
        if not out and real:
            i, f = real[0]
            out.append(_s(_pick(f"{_label(f.get('name'))}: {v(f.get('description') or f.get('evidence'), 90)}", f"{_label(f.get('name'))}."), {"finding": i}))
    else:
        ls = result.get("log_stats") or {}
        sev = {}
        if mode == "logs" and ls.get("attack_counts"):
            hits = sum(int(n or 0) for n in ls["attack_counts"].values())
            srcs = [t for t in ls.get("top_sources") or [] if t.get("attack_hits") or t.get("failed_logins")]
            behaviour = len([f for _, f in real if f.get("name") in ("SSH / Login Brute Force", "Successful Login After Failures")])
            out.append(_s(_pick(f"The log holds {_plural(hits, 'attack signature hit')}" + (f" and {_plural(behaviour, 'behaviour detection')}" if behaviour else "")
                                + (f" from {_plural(len(srcs), 'source')}" if srcs else "") + ".", f"The log holds {_plural(hits, 'attack signature hit')}."),
                          {"field": "log_stats.attack_counts"}))
        elif real:
            for _, f in real:
                sev[f.get("severity", "LOW")] = sev.get(f.get("severity", "LOW"), 0) + 1
            parts = [f"{n} {s.title()}" for s, n in sorted(sev.items(), key=lambda x: -SEV_RANK.get(x[0], 0))]
            text = (f"The analysis raised {_plural(len(real), 'finding')}: {_join(parts, 4)}." if len(sev) > 1 else
                    f"The analysis raised {_plural(len(real), 'finding')}, all rated {next(iter(sev)).title()}." if len(real) > 1 else
                    f"The analysis raised one finding, rated {next(iter(sev)).title()}.")
            out.append(_s(text, {"field": "findings"}))
        top, seen_l = [], set()
        for i, f in sorted(real, key=lambda x: (-SEV_RANK.get(x[1].get("severity"), 0), x[0])):
            lab = _plain(f.get("name"))
            if lab not in seen_l:
                seen_l.add(lab)
                top.append((i, lab, f.get("severity", "")))
        if top:
            crit = [t for t in top if t[2] == top[0][2]]
            same = mode != "logs" and len(sev) == 1
            if len(crit) == 1:
                text = f"The strongest evidence is {crit[0][1]}, rated {crit[0][2].title()}."
            elif same:
                text = _pick(f"Together they show {_join([t[1] for t in crit], 3)}.", f"Together they show {_join([t[1] for t in crit], 2)}.")
            else:
                text = _pick(f"The strongest evidence, all rated {top[0][2].title()}, is {_join([t[1] for t in crit], 3)}.",
                             f"The strongest evidence is {_join([t[1] for t in crit], 2)}, rated {top[0][2].title()}.")
            out.append(_s(text, {"finding": top[0][0]}))
        for rep in (result.get("enrichment") or {}).get("ips") or []:
            if rep.get("verdict") in ("MALICIOUS", "SUSPICIOUS") and len(out) < 3:
                k = (result.get("enrichment") or {}).get("ips").index(rep)
                out.append(_s(f"Threat intel rates the extracted IP {v(rep.get('indicator'), 45)} as {rep['verdict']}.", {"field": f"enrichment.ips[{k}]"}))
    # closing sentences: the checks that ran and came back clear (local checks, then intel sources that answered clean)
    checks = [c for c in result.get("checks") or [] if isinstance(c, dict)]
    src_names = {str((r or {}).get("source")) for _, r in _sources(result)}
    local = [v(c.get("name"), 40) for c in checks if c.get("outcome") == "clear" and c.get("name") not in src_names]
    srcs = [v(c.get("name"), 40) for c in checks if c.get("outcome") == "clear" and c.get("name") in src_names] if mode not in ("hash", "ip") else []
    tail = []
    if local:
        everything = not real and all(c.get("outcome") == "clear" for c in checks if c.get("name") not in src_names)
        lead = ("Every local check came back clear" if everything else
                "These checks on the submitted link came back clear" if mode == "url" else "These checks came back clear")
        tail.append(_s(_pick(f"{lead}: {_join(local, 8)}.", f"{lead}: {_join(local, 5)}.", f"{lead}: {_join(local, 3)}."), {"field": "checks"}, clear=True))
    if srcs:
        tail.append(_s(f"{_join(srcs, 4)} did not flag it.", {"field": "intel_sources"}, clear=True))
    if not tail and not real and not checks and str(result.get("verdict")).upper() == "BENIGN":
        tail.append(_s("Nothing else was flagged.", None, clear=True))
    if tail:
        claimed.add("checks_clear")
    return out[:MAX_SENTENCES - len(tail)] + tail


# ─── 3. how it unfolded ─────────────────────────────────────────
def _stage_index(result, name):
    for k, st in enumerate((result.get("kill_chain") or {}).get("stages") or []):
        if name in (st.get("evidence") or []):
            return k
    return 99


def _unfolded_logs(result):
    ls = result.get("log_stats") or {}
    F = _F(result)
    events = []                                   # (line, priority, sentence)
    by_ip = {}
    for h in ls.get("sample_hits") or []:
        if isinstance(h, dict) and h.get("ip") and h.get("type"):
            by_ip.setdefault(h["ip"], []).append(h)
    for ip, hits in by_ip.items():
        hits = sorted(hits, key=lambda h: h.get("line") or 0)
        probe = [h for h in hits if h["type"] in PROBE_TYPES]
        exploit = [h for h in hits if h["type"] not in PROBE_TYPES and not h["type"].startswith("PowerShell")]
        tools = []
        for h in hits:
            for t in TOOLS_RE.findall(h.get("evidence") or ""):
                if t.lower() not in tools:
                    tools.append(t.lower())
        types = []
        for h in exploit:
            t = WEB_TERMS.get(h["type"], _label(h["type"]))
            if t not in types:
                types.append(t)
        ipv = v(ip, 45)
        if probe or exploit:
            first = (probe or exploit)[0]
            when = f"At line {first['line']}" + (f" ({v(first['ts'], 32)})" if first.get("ts") else "")
            techs = _techs(result, [h["type"] for h in exploit] or [h["type"] for h in probe])
            uniq_probe = len({h.get("line") for h in probe})
            uses = f" using {_join(tools, 2)}" if tools else ""
            if probe and exploit:
                at = f"At line {first['line']}"
                text = _pick(f"{when}, {ipv} began with {_plural(uniq_probe, 'probing request')}{uses}, then sent {_join(types, 3)} attempts{techs}.",
                             f"{at}, {ipv} began with {_plural(uniq_probe, 'probing request')}{uses}, then sent {_join(types, 3)} attempts{techs}.",
                             f"{at}, {ipv} began probing{uses}, then sent {_join(types, 3)} attempts{techs}.",
                             f"{when}, {ipv} began probing{uses}, then sent {_join(types, 2)} attempts{techs}.",
                             f"{ipv} probed the site, then sent {_join(types, 2)} attempts{techs}.")
            elif exploit:
                text = _pick(f"{when}, {ipv} sent {_join(types, 3)} attempts{uses}{techs}.", f"{ipv} sent {_join(types, 2)} attempts{techs}.")
            else:
                text = _pick(f"{when}, {ipv} sent {_plural(uniq_probe, 'probing request')}{uses}{techs}.", f"{ipv} sent probing requests{techs}.")
            events.append((first["line"], 3, _s(text, {"line": first["line"]})))
    # credential attack, then any successful login
    bi = _idx(result, "SSH / Login Brute Force")
    if bi is not None:
        f = F[bi]
        m = re.match(r"^(\S+): (\d+) failed logins(?: \(\d+ distinct user\(s\): ([^)]*)\))?", f.get("evidence", ""))
        if m:
            ip = m.group(1)
            ev = next((a for a in ls.get("auth_events") or [] if a.get("ip") == ip and a.get("result") == "failed"), {})
            users = _join([v(u.strip(), 20) for u in (m.group(3) or "").split(",") if u.strip()], 3)
            when = f", starting {v(ev['ts'], 32)}" if ev.get("ts") else ""
            text = _pick(f"{v(ip, 45)} made {m.group(2)} failed logins" + (f" as {users}" if users else "") + f"{when}{_techs(result, [f['name']], 1)}.",
                         f"{v(ip, 45)} made {m.group(2)} failed logins{_techs(result, [f['name']], 1)}.")
            ref = {"line": ev["line"]} if ev.get("line") else {"finding": bi}
            events.append((ev.get("line") or 10 ** 6, 2, _s(text, ref)))
    for s in ls.get("login_after_failures") or []:
        if isinstance(s, dict) and s.get("ip"):
            text = _pick(f"{v(s['ip'], 45)} then logged in successfully as '{v(s.get('user'), 20)}' at line {s.get('line')}, which suggests possible account compromise.",
                         f"{v(s['ip'], 45)} then logged in successfully as '{v(s.get('user'), 20)}', which suggests possible account compromise.")
            events.append((s.get("line") or 10 ** 6, 0, _s(text, {"line": s["line"]} if s.get("line") else {"finding": _idx(result, "Successful Login After Failures") or 0},
                                                          "inferred")))
            break
    # decoded commands / download URLs
    for d in ls.get("powershell_decoded") or []:
        if not isinstance(d, dict):
            continue
        hit = next((h for h in ls.get("sample_hits") or [] if h.get("line") == d.get("line")), {})
        when = f"At {v(hit['ts'], 32)}" if hit.get("ts") else f"At line {d.get('line')}"
        url = (URL_RE.findall(str(d.get("decoded") or "")) or [""])[0]
        names = [h["type"] for h in ls.get("sample_hits") or [] if h.get("line") == d.get("line")]
        techs = _techs(result, names, 2)
        if url:
            text = _pick(f"{when} the log records an encoded PowerShell command that, once decoded, downloads {v(url, 70)}{techs}.",
                         f"{when} an encoded PowerShell command, once decoded, downloads {v(url, 70)}.")
        else:
            text = f"{when} the log records an encoded PowerShell command; the decoded text is in the log section{techs}."
        events.append((d.get("line") or 10 ** 6, 1, _s(_pick(text), {"line": d["line"]} if d.get("line") else {"field": "log_stats.powershell_decoded"})))
        break
    keep = sorted(events, key=lambda e: e[1])[:MAX_SENTENCES]          # priority: login, commands, credentials, web activity
    return [e[2] for e in sorted(keep, key=lambda e: e[0])]


def _unfolded_network(result):
    F, out = _F(result), []
    for i, f in enumerate(F):
        if f.get("name") == "TCP Port Scan Detected" and parse_scan(f.get("evidence", "")):
            s, d, n = parse_scan(f["evidence"])
            out.append(_s(f"{v(s, 45)} sent SYN probes to {_plural(int(n), 'port')} on {v(d, 45)}{_techs(result, [f['name']], 1)}.", {"finding": i}))
            break
    if (i := _idx(result, "ICMP Ping Sweep")) is not None:
        out.append(_s(f"{v(F[i].get('evidence', '').split(' ')[0], 45)} pinged many hosts to find live machines{_techs(result, [F[i]['name']], 1)}.", {"finding": i}))
    risky = [(k, f) for k, f in enumerate(F) if f.get("name", "").startswith("Risky Port Open:")]
    vuln = [(k, f) for k, f in enumerate(F) if f.get("name", "").startswith(("Vulnerable Service:", "NSE Finding:"))]
    if risky:
        hosts = sorted({f.get("evidence", "").split(":")[0] for _, f in risky})
        services = [re.sub(r"^Risky Port Open: \d+/", "", f["name"]) for _, f in risky]
        out.append(_s(_pick(f"{_join([v(h, 45) for h in hosts], 2)} {'exposes' if len(hosts) == 1 else 'expose'} {_plural(len(risky), 'risky service')}, "
                            f"including {_join([v(x, 20) for x in services], 3)}{_techs(result, [f['name'] for _, f in risky], 2)}.",
                            f"{_join([v(h, 45) for h in hosts], 2)} {'exposes' if len(hosts) == 1 else 'expose'} {_plural(len(risky), 'risky service')}."),
                      {"finding": risky[0][0]}))
    if vuln:
        names = [_label(f["name"]) for _, f in sorted(vuln, key=lambda x: -SEV_RANK.get(x[1].get("severity"), 0))]
        out.append(_s(_pick(f"Service banners match {_plural(len(vuln), 'known-vulnerable build')}, including {_join([v(n, 40) for n in names], 2)}"
                            f"{_techs(result, [f['name'] for _, f in vuln], 2)}.", f"Service banners match {_plural(len(vuln), 'known-vulnerable build')}."),
                      {"finding": vuln[0][0]}))
    if (i := _idx(result, "End-of-Life Operating System")) is not None and len(out) < MAX_SENTENCES:
        h = F[i].get("evidence", "").split(":")[0]
        out.append(_s(f"The OS fingerprint for {v(h, 45)} is consistent with an end-of-life release.", {"finding": i}, "inferred"))
    creds = [(k, parse_cleartext(f.get("evidence", ""))) for k, f in enumerate(F) if f.get("name") == "Cleartext Credentials on the Wire"]
    creds = [(k, c) for k, c in creds if c]
    if creds:
        k, (p, s, d, _) = creds[0]
        out.append(_s(f"A {v(p, 10)} login from {v(s, 45)} to {v(d, 45)} crossed the network in cleartext{_techs(result, ['Cleartext Credentials on the Wire'], 1)}.",
                      {"finding": k}))
    for k, f in enumerate(F):
        if f.get("name") == "Traffic to Suspicious Port" and parse_suspicious_port(f.get("evidence", "")):
            s, d, port, _ = parse_suspicious_port(f["evidence"])
            out.append(_s(f"{v(s, 45)} contacted {v(d, 45)} on port {port}, a common reverse shell default{_techs(result, [f['name']], 1)}.", {"finding": k}))
            break
    if (i := _idx(result, "Possible DNS Tunnelling")) is not None:
        out.append(_s("Oversized DNS queries are consistent with DNS tunnelling.", {"finding": i}, "inferred"))
    if len(out) > MAX_SENTENCES:                      # keep scan, the strongest exposure and the outbound end of the chain
        out = out[:2] + out[-2:]
    return out


def _unfolded_email(result):
    fx = result.get("forensics") or {}
    hd, au, F, out = fx.get("headers") or {}, fx.get("auth") or {}, _F(result), []
    chain = fx.get("received_chain") or []
    if chain:
        origin = (fx.get("origin_ips") or [""])[0]
        out.append((0, _s(f"The message passed through {_plural(len(chain), 'mail server')}" + (f", first seen at {v(origin, 45)}" if origin else "") + ".",
                          {"field": "forensics.received_chain"})))
    rp = _idx(result, "Return-Path / From Mismatch")
    rt = _idx(result, "Reply-To Hijack")
    m1 = re.match(r"^From @(\S+) vs Return-Path @(\S+)", F[rp].get("evidence", "")) if rp is not None else None
    m2 = re.match(r"^From @(\S+) vs Reply-To @(\S+)", F[rt].get("evidence", "")) if rt is not None else None
    if m1 or m2:
        claim = v((m1 or m2).group(1), 50)
        tail = _join([x for x in (f"bounces go to {v(m1.group(2), 50)}" if m1 else "", f"replies go to {v(m2.group(2), 50)}" if m2 else "") if x], 2)
        out.append((1, _s(f"It claims to be from {claim}, but {tail}.", {"finding": rp if rp is not None else rt})))
    res = [(m.upper(), au.get(m)) for m in ("spf", "dkim", "dmarc") if au.get(m)]
    if res:
        bad = [f"{m} {r}" for m, r in res if r != "pass"]
        good = [m for m, r in res if r == "pass"]
        text = (f"The receiving server recorded {_join(bad, 3)}" + (f"; {_join(good, 3)} passed" if good else "") + "." if bad
                else f"The receiving server recorded {_join(good, 3)} as passing.")
        out.append((2, _s(text, {"field": "forensics.auth"})))
    tricks = []
    if (u := _idx(result, "Urgency / Pressure Manipulation")) is not None:
        tricks.append((u, f"urgency words ({v(', '.join(F[u].get('evidence', '').split(', ')[:3]), 40)})"))
    mism = fx.get("html_link_mismatches") or []
    if mism and (lm := _idx(result, "Link Text / Destination Mismatch")) is not None:
        tricks.append((lm, f"a link that shows {v(_host(mism[0].get('shown')), 40)} but opens {v(_host(mism[0].get('actual')), 40)}"))
    if tricks:
        out.append((3, _s(_pick(f"The text uses {_join([t[1] for t in tricks], 2)}.", f"The text uses {tricks[0][1]}."), {"finding": tricks[0][0]})))
    att = fx.get("attachments") or []
    risky = [a for a in att if a.get("double_extension") or a.get("dangerous_ext")]
    if risky:
        a = risky[0]
        what = "an executable disguised as a document" if a.get("double_extension") else "a file type often used for malware"
        k = _idx(result, "Double-Extension Attachment") if a.get("double_extension") else _idx(result, "Risky Attachment Type")
        out.append((4, _s(f"Finally, it carries {v(a.get('filename'), 40)}, {what}.", {"finding": k} if k is not None else {"field": "forensics.attachments[0]"})))
    if len(out) > MAX_SENTENCES:                      # drop the delivery hop first: the sender, auth, tricks and attachment matter more
        out = out[1:]
    return [s for _, s in out]


def _unfolded_reputation(result, claimed):
    out = []
    for key, r in _sources(result):
        if ("source", key) in claimed or len(out) >= MAX_SENTENCES - 1:
            continue
        st = _source_state(r)
        src = v(r.get("source") or key, 30)
        if st == "clear":
            out.append(_s(f"{src} answered: {v(r.get('detail') or 'not flagged', 60)}.", {"field": f"intel_sources.{key}"}))
        elif st == "pending":
            out.append(_s(f"{src} accepted the submission, but its verdict was not ready.", {"field": f"intel_sources.{key}"}))
    return out


def _unfolded_url(result):
    tr = result.get("redirect_trace") or {}
    chain = [h for h in tr.get("chain") or [] if isinstance(h, dict)]
    out = []
    if tr.get("hops"):
        hosts = []
        for h in chain:
            for u in (h.get("url"), h.get("location")):
                hh = v(_host(u), 50)
                if hh and (not hosts or hosts[-1] != hh):
                    hosts.append(hh)
        path = ", then ".join(hosts[:-1])
        out.append(_s(_pick(f"The link redirects {_plural(tr['hops'], 'time')}: {path}, landing on {hosts[-1]}.",
                            f"The link redirects {_plural(tr['hops'], 'time')} before landing on {hosts[-1]}."), {"field": "redirect_trace.chain"}))
    if chain:
        last = chain[-1]
        k = len(chain) - 1
        if isinstance(last.get("status"), int) and not last.get("location"):
            out.append(_s(f"The landing page answered with HTTP {last['status']}.", {"field": f"redirect_trace.chain[{k}].status"}))
    return out


# ─── 4. what it means ───────────────────────────────────────────
def _means(result):
    out = []
    verdict = str(result.get("verdict") or "").upper()
    score = result.get("score")
    real = _real(result)
    if isinstance(score, (int, float)):
        if verdict == "MALICIOUS":
            text = f"{_a(score)} {score}% risk score suggests a real attack, so act now."
        elif verdict == "SUSPICIOUS":
            text = f"{_a(score)} {score}% risk score suggests warning signs, not proof, so investigate today."
        else:
            text = f"{_a(score)} {score}% risk score suggests no meaningful threat; routine monitoring is enough."
        out.append(_s(text, {"field": "score"}, "inferred"))
    contrib = [c for c in ((result.get("score_explanation") or {}).get("contributions") or [])
               if isinstance(c, dict) and c.get("points") and not NOT_FACTORS.match(str(c.get("factor") or c.get("label") or ""))]
    if contrib:
        merged = {}
        for c in contrib:
            lab = v(_label(c.get("label") or c.get("factor")), 60)
            merged[lab] = merged.get(lab, 0) + int(c["points"])
        top = sorted(merged.items(), key=lambda x: -x[1])[:3]
        parts = [f"{lab} (+{pts}%)" for lab, pts in top]
        out.append(_s(_pick(f"The score rests on {_join(parts, 3)}.", f"The score rests on {_join(parts[:2], 2)}."),
                      {"field": "score_explanation.contributions"}))
    if real:
        strong = [f for _, f in real if f.get("severity") in ("CRITICAL", "HIGH") and f.get("strength") != "weak"]
        weak = len(real) - len(strong)
        every = lambda n: "The one finding is" if n == 1 else "Both findings are" if n == 2 else f"All {n} findings are"
        intel_weak = any(f.get("strength") == "weak" for _, f in real)
        if strong and weak:
            text = (f"{len(strong)} of {len(real)} findings {'is' if len(strong) == 1 else 'are'} strong (Critical or High); "
                    f"the other {weak} {'is a weaker signal' if weak == 1 else 'are weaker signals'}.")
        elif strong:
            text = f"{every(len(strong))} strong (Critical or High)."
        elif intel_weak and verdict != "BENIGN":
            text = f"{every(weak)} low-count signals, so verify manually before blocking."
        else:
            text = f"{every(weak).replace(' are', ' are weak').replace(' is', ' is a weak')} signal{'s' if weak > 1 else ''} on {'their' if weak > 1 else 'its'} own."
        out.append(_s(text, {"field": "findings"}))
    if isinstance(score, (int, float)):
        if verdict == "MALICIOUS":
            text = "The scoring rules suggest it stays MALICIOUS unless the top findings turn out to be authorised testing."
        elif verdict == "SUSPICIOUS":
            text = (f"The scoring rules suggest about {MALICIOUS_THRESHOLD - int(score)} more points, such as a strong second source, "
                    "would make it MALICIOUS.")
        else:
            text = f"The scoring rules suggest about {BENIGN_THRESHOLD + 1 - int(score)} more points of evidence would make it SUSPICIOUS."
        out.append(_s(_pick(text), {"field": "score"}, "inferred"))
    return out[:MAX_SENTENCES]


# ─── 5. what we couldn't check ──────────────────────────────────
def _limits(result, claimed):
    out = []
    states = {}
    for key, r in _sources(result):
        st = _source_state(r)
        if st in ("not configured", "rate-limited", "unavailable", "pending"):
            states.setdefault(st, []).append(v(r.get("source") or key, 30))
    if states:
        word = {"not configured": ("was not configured", "were not configured"), "rate-limited": ("was rate-limited", "were rate-limited"),
                "unavailable": ("was unavailable", "were unavailable"), "pending": ("had no verdict yet", "had no verdict yet")}
        parts = [f"{_join(names, 4)} {word[st][0] if len(names) == 1 else word[st][1]}" for st, names in states.items()]
        out.append(_s(_pick(_join(parts, 4)[0].upper() + _join(parts, 4)[1:] + ".", parts[0][0].upper() + parts[0][1:] + "."), {"field": "intel_sources"}))
    skipped = (result.get("enrichment") or {}).get("skipped_private") or []
    if skipped and not states:
        are = "it is a private or reserved address" if len(skipped) == 1 else "they are private or reserved addresses"
        out.append(_s(_pick(f"Reputation was not checked for {_join([v(i, 45) for i in skipped], 2)} because {are}.",
                            "Reputation was not checked because the addresses are private or reserved."), {"field": "enrichment.skipped_private"}))
    src_names = {str((r or {}).get("source")) for _, r in _sources(result)}
    cant = [v(c.get("name"), 30) for c in result.get("checks") or [] if isinstance(c, dict) and c.get("outcome") == "unavailable"
            and c.get("name") not in src_names and not (c.get("name") == "Domain age" and "domain_age" in claimed)]
    if cant:
        out.append(_s(_pick(f"The result of the {_join(cant, 3)} {'check' if len(cant) == 1 else 'checks'} {UNKNOWN}."), {"field": "checks"}, "unknown"))
    tr = result.get("redirect_trace") or {}
    chain = tr.get("chain") or []
    if result.get("mode") == "url" and (tr.get("error") or tr.get("blocked") or (chain and chain[-1].get("status") == "ERR")):
        out.append(_s(f"Where the link finally leads {UNKNOWN}; the landing page did not answer.", {"field": "redirect_trace"}, "unknown"))
    qs, seen = [], set()
    for i, f in sorted(_real(result), key=lambda x: (-SEV_RANK.get(x[1].get("severity"), 0), x[0])):
        n = f.get("name", "")
        q = OPEN_Q.get(n) or next((t for p, t in OPEN_Q_PREFIX.items() if n.startswith(p)), None)
        if q and is_intel_name(n) and f.get("strength") != "weak" and not f.get("severity") in ("MEDIUM", "LOW"):
            q = ("What the file does on a machine could not be determined from reputation data alone." if result.get("mode") == "hash"
                 else "What this indicator did in your environment could not be determined from reputation data alone.")
        if q and q not in seen:
            seen.add(q)
            qs.append(_s(q, {"finding": i}, "unknown"))
    out += qs[:2]
    return out[:MAX_SENTENCES]


# ─── assembly ───────────────────────────────────────────────────
def _norm(s):
    return set(re.findall(r"[a-z0-9]+", str(s).lower()))


def _similar(a, b) -> bool:
    A, B = _norm(a), _norm(b)
    return bool(A and B) and len(A & B) / len(A | B) >= 0.8


def _apply_glossary(story):
    terms, used = glossary(), set()
    for sec in story:
        for s in sec["sentences"]:
            for term, definition in terms.items():
                if term not in used and re.search(r"(?<![\w-])" + re.escape(term) + r"(?![\w-])", s["text"], re.I):
                    s.setdefault("define", []).append({"term": term, "definition": definition})
                    used.add(term)


def story_words(story) -> int:
    return sum(_words(s["text"]) for sec in story for s in sec["sentences"])


def build_story(result: dict, headline: str = "", do_now=(), defang: bool = False) -> list:
    result = result if isinstance(result, dict) else {}
    claimed = set()
    mode = result.get("mode", "")
    secs = {"artifact": _artifact(result, claimed)}
    secs["found"] = _found(result, claimed)
    secs["unfolded"] = (_unfolded_logs(result) if mode == "logs" else _unfolded_network(result) if mode == "network"
                        else _unfolded_email(result) if mode == "email" else _unfolded_url(result) if mode == "url"
                        else _unfolded_reputation(result, claimed) if mode in ("hash", "ip") else [])
    secs["means"] = _means(result)
    secs["limits"] = _limits(result, claimed)
    # seen-registry: a fact appears once across headline, story and do_now
    seen = [headline] + [a.get("action", "") for a in do_now or [] if isinstance(a, dict)]
    story = []
    for key, title in SECTIONS:
        kept = []
        for s in secs.get(key) or []:
            if not s or not s.get("text") or any(_similar(s["text"], x) for x in seen):
                continue
            seen.append(s["text"])
            kept.append(s)
        if kept:
            story.append({"section": key, "title": title, "sentences": kept[:MAX_SENTENCES]})
    # visible budget: trim the tail of the least essential sections first
    for key in ("limits", "artifact", "found", "unfolded"):
        while story_words(story) > WORD_MAX:
            sec = next((x for x in story if x["section"] == key and len(x["sentences"]) > 1), None)
            if not sec:
                break
            sec["sentences"].pop()
    _apply_glossary(story)
    if defang:
        for sec in story:
            for s in sec["sentences"]:
                s["text"] = defang_text(s["text"])
    return story


def first_sentence(story, section) -> str:
    sec = next((x for x in story if x["section"] == section), None)
    return sec["sentences"][0]["text"] if sec and sec["sentences"] else ""
