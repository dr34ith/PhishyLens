"""
PhishyLens: deterministic executive summary (no LLM; same result in → same text out).

    build_exec_summary(result, defang=False) -> {headline, what_happened[], why_it_matters, do_now[], key_facts[], story[]}

"story" (utils/story.py) is the data-driven narrative; what_happened and why_it_matters are derived from it so older
renderers and exports keep working.

Every sentence is a fixed template filled with values read from the result (via utils.artifacts). When the data a
template needs is missing, that sentence is skipped. Secrets quoted in evidence are masked; IOCs are defanged only
when defang=True (exports / UI toggle); API values stay live.
"""
import re

from utils.artifacts import (SEV_RANK, ip_inventory, mask_secrets, parse_cleartext, parse_scan, parse_suspicious_port,
                             prioritized_actions, real_findings, top_severity)
from utils.defang import defang_text
from utils.story import build_story, first_sentence, hedged, intel_only

HEADLINE_MAX_WORDS = 25
BULLET_MAX_WORDS = 19
NO_PATTERN = {"No Attack Pattern Identified", "Unmapped Suspicious Activity", ""}

WEB_ATTACKS = {"SQL Injection": "SQL injection", "Cross-Site Scripting (XSS)": "XSS", "Path Traversal / LFI": "path traversal",
               "Command Injection": "command injection", "Log4Shell / JNDI Injection": "Log4Shell", "Server-Side Request Forgery": "SSRF",
               "Web Shell / Sensitive File Probe": "sensitive-file probing", "Scanner / Attack-Tool User-Agent": "attack-tool scanning",
               "Directory / Vulnerability Scanning": "directory scanning"}
STAGE_MEANING = {"Reconnaissance": "the attacker is mapping targets", "Delivery": "malicious content reached the target",
                 "Exploitation": "attack code ran or credentials were abused", "Persistence": "access may survive reboots",
                 "Command & Control": "a remote-control channel may be open", "Actions on Objectives": "data theft or damage may be under way"}
URGENCY = {"MALICIOUS": "act now", "SUSPICIOUS": "investigate today", "BENIGN": "no urgent action is needed"}


def _words(s: str) -> int:
    return len(s.split())


def _join(items: list) -> str:
    items = [i for i in items if i]
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1] if items else ""


def _fit(s: str, limit: int) -> str:
    """Hard cap (only reached by evidence-quoting fallbacks): cut at the limit and mark the cut."""
    w = s.split()
    return s if len(w) <= limit else " ".join(w[:limit - 1]) + " …"


def _host(url: str) -> str:
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", str(url or ""), re.I)
    return m.group(1) if m else str(url or "")


def _by_name(result: dict) -> dict:
    out = {}
    for f in real_findings(result):
        out.setdefault(f.get("name", ""), []).append(f)
    return out


# ─── per-mode templates: (headline parts, bullets) ──────────────
def _network(result, F):
    parts, bullets = [], []
    scans = [parse_scan(f["evidence"]) for f in F.get("TCP Port Scan Detected", []) if parse_scan(f["evidence"])]
    if scans:
        s, d, n = scans[0]
        parts.append(f"port scan from {s} against {d}" + (f" (+{len(scans) - 1} more)" if len(scans) > 1 else ""))
        bullets.append(f"{s} probed {n} ports on {d} (a port scan: mapping open services).")
    creds = [parse_cleartext(f["evidence"]) for f in F.get("Cleartext Credentials on the Wire", []) if parse_cleartext(f["evidence"])]
    if creds:
        protos = sorted({c[0] for c in creds})
        parts.append(f"cleartext {'/'.join(protos)} login captured")
        p, s, d, _ = creds[0]
        bullets.append(f"{p} login from {s} to {d} crossed the network in cleartext (readable by anyone listening).")
    sus = [parse_suspicious_port(f["evidence"]) for f in F.get("Traffic to Suspicious Port", []) if parse_suspicious_port(f["evidence"])]
    if sus:
        ports = sorted({str(x[2]) for x in sus})
        parts.append(f"traffic to suspicious port {'/'.join(ports)}")
        s, d, port, _ = sus[0]
        bullets.append(f"{s} contacted {d} on port {port} (a default port for reverse shells and C2 tools).")
    risky = F.get("Risky Port Open", []) + [f for n, fs in F.items() if n.startswith("Risky Port Open:") for f in fs]
    vuln = [f for n, fs in F.items() if n.startswith(("Vulnerable Service:", "NSE Finding:")) for f in fs]
    if risky:
        hosts = sorted({f["evidence"].split(":")[0] for f in risky})
        services = [re.sub(r"^Risky Port Open: \d+/", "", f["name"]) for f in risky]
        parts.append(f"{_join(hosts[:2])} expose{'s' if len(hosts) == 1 else ''} {len(risky)} risky services")
        bullets.append(_fit(f"{_join(hosts[:2])} expose{'s' if len(hosts) == 1 else ''} {len(risky)} risky services, e.g. "
                            f"{', '.join(services[:3])} (common attack entry points).", BULLET_MAX_WORDS))
    if vuln:
        names = [re.sub(r"^(Vulnerable Service|NSE Finding): ", "", f["name"]) for f in vuln]
        crit = [n for f, n in zip(vuln, names) if f.get("severity") == "CRITICAL"]
        parts.append(f"{len(vuln)} known-vulnerable services" + (f" incl. {crit[0]}" if crit else ""))
        bullets.append(_fit(f"Service banners match known-vulnerable builds: {', '.join((crit or names)[:2])} (public exploits exist).", BULLET_MAX_WORDS))
    if F.get("End-of-Life Operating System"):
        h = F["End-of-Life Operating System"][0]["evidence"].split(":")[0]
        bullets.append(f"{h} runs an end-of-life operating system (no security updates).")
    if F.get("Possible DNS Tunnelling"):
        parts.append("possible DNS tunnelling")
        bullets.append("Oversized DNS queries suggest DNS tunnelling (hiding data inside DNS lookups).")
    if F.get("ICMP Ping Sweep"):
        src = F["ICMP Ping Sweep"][0]["evidence"].split(" ")[0]
        parts.append(f"ping sweep from {src}")
        bullets.append(f"{src} pinged many hosts (a ping sweep: finding live machines).")
    return parts, bullets


def _logs(result, F):
    parts, bullets = [], []
    ls = result.get("log_stats") or {}
    sev_of = {h.get("type"): h.get("severity") for h in ls.get("sample_hits") or []}
    web = sorted((n for n in (ls.get("attack_counts") or {}) if n in WEB_ATTACKS), key=lambda n: -SEV_RANK.get(sev_of.get(n), 0))
    web_ips = sorted({ip for n in web for f in F.get(n, []) for ip in f.get("sources") or []})
    if web:
        shown = [WEB_ATTACKS[n] for n in web[:2]]
        listed = (", ".join(shown) + f" and {len(web) - 2} more attack types") if len(web) > 2 else _join(shown)
        parts.append(listed + (f" from {_join(web_ips[:2])}" if web_ips else ""))
        bullets.append(_fit(f"{_join(web_ips[:2]) or 'A client'} sent web attacks: {', '.join(WEB_ATTACKS[n] for n in web[:3])} "
                            f"(attempts to break into the web app).", BULLET_MAX_WORDS))
    brute = F.get("SSH / Login Brute Force", [])
    for f in brute[:1]:
        m = re.match(r"^(\S+): (\d+) failed logins(?: \(\d+ distinct user\(s\): ([^)]*)\))?", f.get("evidence", ""))
        if m:
            users = ", ".join(u.strip() for u in (m.group(3) or "").split(",")[:3] if u.strip())
            bullets.append(f"{m.group(1)} made {m.group(2)} failed logins" + (f" as {users}" if users else "") + " (password guessing).")
    succ = F.get("Successful Login After Failures", [])
    for f in succ[:1]:
        m = re.match(r"^(\S+): Accepted login for '([^']*)'", f.get("evidence", ""))
        if m:
            parts.append(f"{m.group(1)} logged in after brute force")
            bullets.append(f"{m.group(1)} then logged in successfully as '{m.group(2)}' (possible account compromise).")
    if not succ and brute:
        m = re.match(r"^(\S+):", brute[0].get("evidence", ""))
        if m:
            parts.append(f"brute force from {m.group(1)}, no successful login seen")
    ps = [n for n in F if n.startswith("PowerShell") or n in ("AMSI / Defender Tampering", "Reflection / In-Memory Loader", "LOLBin Proxy Execution")]
    if ps:
        ip = next((s for n in ps for f in F[n] for s in f.get("sources") or []), "")
        cradle = any("Download Cradle" in n for n in ps)
        parts.append("encoded PowerShell" + (" download cradle" if cradle else "") + (f" from {ip}" if ip else ""))
        bullets.append(f"{ip + ' ran' if ip else 'Logs show'} hidden, encoded PowerShell "
                       f"({'obfuscated commands that download code' if cradle else 'obfuscated script commands'}).")
    return parts, bullets


def _email(result, F):
    parts, bullets = [], []
    order = ["SPF", "DKIM", "DMARC"]
    fails = sorted({n.split(" ")[0] for n in F if re.match(r"^(SPF|DKIM|DMARC) Authentication Failed$", n)}, key=order.index)
    notpass = sorted({n.split(" ")[0] for n in F if re.match(r"^(SPF|DKIM|DMARC) Not Passing$", n)} - set(fails), key=order.index)
    if fails or notpass:
        parts.append(", ".join(x for x in (f"{_join(fails)} failed" if fails else "", f"{_join(notpass)} not passing" if notpass else "") if x))
        detail = "; ".join(x for x in (f"{_join(fails)} failed" if fails else "", f"{_join(notpass)} did not pass" if notpass else "") if x)
        bullets.append(f"Sender checks: {detail} (they verify the sender is genuine).")
    for name in ("Double-Extension Attachment", "Risky Attachment Type", "Attachment Hash Known Malicious"):
        if F.get(name):
            ev = re.split(r" \(sha256", F[name][0].get("evidence", ""))[0]
            note = {"Double-Extension Attachment": "an executable disguised as a document",
                    "Risky Attachment Type": "a file type often used for malware",
                    "Attachment Hash Known Malicious": "threat intel knows this exact file"}[name]
            parts.append(f"risky attachment {ev}")
            bullets.append(f"Attachment {ev} is dangerous ({note}).")
            break
    mism = (result.get("forensics") or {}).get("html_link_mismatches") or []
    if F.get("Link Text / Destination Mismatch") and mism:
        shown, actual = _host(mism[0].get("shown")), _host(mism[0].get("actual"))
        parts.append(f"link shows {shown} but opens {actual}")
        bullets.append(f"A link displays {shown} but opens {actual} (a disguised link).")
    for f in F.get("Reply-To Hijack", [])[:1]:
        m = re.match(r"^From @(\S+) vs Reply-To @(\S+)", f.get("evidence", ""))
        if m:
            bullets.append(f"Replies go to {m.group(2)}, not the sender domain {m.group(1)} (reply hijacking).")
    if F.get("Display Name Brand Spoofing") and len(bullets) < 4:
        bullets.append(_fit(f"Display name impersonates a brand: {F['Display Name Brand Spoofing'][0].get('evidence', '')}.", BULLET_MAX_WORDS))
    return parts, bullets


def _url(result, F):
    parts, bullets = [], []
    tr = result.get("redirect_trace") or {}
    final = _host(tr.get("final_url") or result.get("final_url") or result.get("input"))
    hops = tr.get("hops") or 0
    if hops:
        parts.append(f"redirects {hops} time{'s' if hops != 1 else ''} to {final}")
        bullets.append(f"The link redirects {hops} time{'s' if hops != 1 else ''} before landing on {final}.")
    elif final:
        parts.append(f"URL on {final}")
    if F.get("Shortened URL"):
        bullets.append(f"It starts at the URL shortener {F['Shortened URL'][0].get('evidence', '')} (hides the real destination).")
    if F.get("Newly Registered Domain"):
        age = (result.get("domain_info") or {}).get("domain_age_days")
        parts.append("newly registered domain")
        bullets.append(f"{final} is newly registered" + (f" ({age} days old)" if isinstance(age, int) else "") + " (common for phishing sites).")
    ti = [n for n in F if n.startswith("[")]
    if ti:
        srcs = sorted({re.match(r"^\[([^\]]+)\]", n).group(1) for n in ti})
        parts.append(f"flagged by {len(srcs)} intel source{'s' if len(srcs) != 1 else ''}")
        bullets.append(f"Threat intelligence flags it: {_join(srcs)}.")
    if F.get("Brand Impersonation") and len(bullets) < 4:
        bullets.append("The address imitates a well-known brand (brand impersonation).")
    if F.get("Suspicious Redirect Destination") and len(bullets) < 4:
        bullets.append(_fit(f"The final destination looks risky: {F['Suspicious Redirect Destination'][0].get('evidence', '')}.", BULLET_MAX_WORDS))
    if F.get("IP Address in URL") and len(bullets) < 4:
        bullets.append("The URL uses a raw IP address instead of a domain name.")
    return parts, bullets


def _reputation(result, F, what):
    parts, bullets = [], []
    src = result.get("intel_sources") or {}
    checked = [s for s in src.values() if isinstance(s, dict) and s.get("available")]
    flagged = [s for s in checked if s.get("flagged")]
    if src:
        if flagged:
            parts.append(f"{what} flagged by {len(flagged)} of {len(checked)} reputation sources checked")
        elif checked:
            parts.append(f"{what} not flagged by {len(checked)} reputation source{'s' if len(checked) != 1 else ''} checked")
        else:
            parts.append(f"{what} not checked; no reputation source available")
    for s in flagged[:3]:
        bullets.append(_fit(f"{s.get('source')}: {mask_secrets(s.get('detail') or 'flagged as malicious')}.", BULLET_MAX_WORDS))
    for name, note in (("Proxy/VPN Detected", "traffic may be relayed to hide its origin"), ("Hosting/Datacenter IP", "a rented server, not a home user")):
        if F.get(name) and len(bullets) < 4:
            bullets.append(f"{name.replace('/', ' or ')} ({note}).")
    if checked and not flagged:
        bullets.append(f"Checked sources: {_join([s.get('source') for s in checked])}. None flagged it.")
    return parts, bullets


def _fallback(result, F):
    fs = sorted(real_findings(result), key=lambda f: -SEV_RANK.get(f.get("severity"), 0))
    return ([f.get("name", "") for f in fs[:2]],
            [_fit(f"{f.get('name')}: {mask_secrets(f.get('evidence', ''))}.", BULLET_MAX_WORDS) for f in fs[:3] if f.get("evidence")])


# ─── assembly ───────────────────────────────────────────────────
def _headline(result, parts):
    cls = (result.get("classification") or {}).get("primary", "")
    verdict = str(result.get("verdict") or "").upper()
    prefix = cls if cls not in NO_PATTERN else (f"{verdict.title()} activity" if verdict in ("MALICIOUS", "SUSPICIOUS") else "")
    if hedged(result) and real_findings(result):       # not MALICIOUS, or intel flags only: never state a technique as fact
        prefix = f"Possible {prefix[0].lower() + prefix[1:] if prefix.startswith(('Suspicious', 'Malicious', 'Benign')) else prefix}".strip() \
            if prefix else "Possible"
    parts = [p for p in parts if p]
    if not parts:
        if verdict == "BENIGN" or not real_findings(result):
            return f"No significant threat found{'; ' + cls.lower() if cls in ('No Attack Pattern Identified',) else ''}."
        parts = [f.get("name", "") for f in real_findings(result)[:2]]
    while parts:
        body = "; ".join(parts)
        s = (f"{prefix}: {body}." if prefix else body[0].upper() + body[1:] + ".")
        if _words(s) <= HEADLINE_MAX_WORDS:
            return s
        parts = parts[:-1]
    return _fit(f"{prefix}.", HEADLINE_MAX_WORDS)


def _why(result):
    sev = top_severity(result)
    verdict = str(result.get("verdict") or "").upper()
    urgency = URGENCY.get(verdict, "review the findings")
    stage = (result.get("kill_chain") or {}).get("furthest_stage", "")
    if not sev:
        return "No risk factors were found, so no action is needed."
    if stage:
        return f"{sev.title()}-severity evidence maps as far as the {stage} stage ({STAGE_MEANING.get(stage, 'see the kill chain')}), so {urgency}."
    return f"{sev.title()}-severity findings were raised but no attack stage was evidenced, so {urgency}."


CONFIDENCE_TIP = "How complete the evidence is, not how likely it is malicious"


def _own_host_only(result, inv) -> bool:
    """URL mode: the only host counted is the URL's own (resolved) host, which is not an extra fact."""
    if result.get("mode") != "url":
        return False
    di = result.get("domain_info") or {}
    own = {str(di.get("resolved_ip") or ""), _host(result.get("input")), _host(result.get("final_url"))}
    return all((i.get("ip") if isinstance(i, dict) else str(i)) in own for i in inv)


def _facts(result):
    real = real_findings(result)
    techs = (result.get("mitre") or {}).get("techniques") or []
    inv = ip_inventory(result)
    facts = [("Risk score", f"{result['score']}%" if result.get("score") else "", ""),
             ("Analysis confidence", f"{result['confidence']}%" if result.get("confidence") else "", CONFIDENCE_TIP),
             ("Findings", len(real), ""), ("ATT&CK techniques", len(techs), ""),
             ("Hosts involved", 0 if _own_host_only(result, inv) else len(inv), "")]
    return [{"label": k, "value": str(v), **({"title": t} if t else {})} for k, v, t in facts if v not in ("", 0, None)]   # numbers only; zeros hidden


# ─── do now: matches the verdict, one action per intent ─────────
INTENTS = [("contain", re.compile(r"\b(block|quarantine|isolate|contain|take .{0,20}offline|do not (?:visit|click|interact|execute|open|enter|reply))\b", re.I)),
           ("credentials", re.compile(r"\b(reset|rotate|mfa|key-based auth|password)\b", re.I)),
           ("patch", re.compile(r"\b(patch|upgrade|update|remediate|close)\b", re.I)),
           ("verify", re.compile(r"\b(verify|corroborate|review|check|inspect|analy[sz]e|detonate|sandbox|confirm)\b", re.I)),
           ("investigate", re.compile(r"\b(investigate|search|audit|hunt|identify)\b", re.I)),
           ("report", re.compile(r"\b(report|escalate|notify)\b", re.I)),
           ("monitor", re.compile(r"\b(monitor|watch|hygiene|caution)\b", re.I))]
PRIORITIES = ["Now", "Today", "This week"]
SUSPICIOUS_DEFAULT = "Verify the findings with a second source and escalate to the security team if they hold."
MALICIOUS_DEFAULT = "Contain affected systems and block the indicators listed in this report."
BENIGN_DEFAULT = "No action needed; keep monitoring for new activity."


def _intent(action: str) -> str:
    return next((name for name, rx in INTENTS if rx.search(action or "")), "other")


def _do_now(result):
    verdict = str(result.get("verdict") or "").upper()
    if verdict == "BENIGN" or not real_findings(result):
        return [{"priority": "This week", "action": BENIGN_DEFAULT}]
    acts, seen = [], set()
    for a in prioritized_actions(result):
        text = a["action"]
        intent = _intent(text)
        if verdict != "MALICIOUS" and (intent == "contain" or re.search(r"\bimmediately\b", text, re.I)):
            continue                                   # SUSPICIOUS: verify and escalate, never "block immediately"
        if intent in seen:
            continue
        seen.add(intent)
        acts.append({"priority": a["priority"] if verdict == "MALICIOUS" or a["priority"] != "Now" else "Today", "action": text})
    if verdict == "MALICIOUS" and "contain" not in seen:
        acts.insert(0, {"priority": "Now", "action": MALICIOUS_DEFAULT})
    if verdict != "MALICIOUS" and not seen & {"verify", "report"}:
        acts.insert(0, {"priority": "Today", "action": SUSPICIOUS_DEFAULT})
    acts.sort(key=lambda a: PRIORITIES.index(a["priority"]) if a["priority"] in PRIORITIES else 9)
    return acts[:3]


def _derive_bullets(story, fallback):
    """what_happened (backward compatible): leading sentences of "found" and "unfolded", short ones only, no duplicates."""
    get = lambda key: [s["text"] for sec in story if sec["section"] == key for s in sec["sentences"] if not s.get("clear")]
    found, unfolded = get("found"), get("unfolded")
    order = found[:1] + unfolded[:3] + found[1:] + unfolded[3:]
    out = []
    for t in order:
        if len(t.split()) <= BULLET_MAX_WORDS and t not in out:
            out.append(t)
        if len(out) == 4:
            break
    return out or fallback[:4]


# ─── highlighting (key phrases for easy scanning) ───────────────
# Computed from the FINAL sentences, so the same rules work on live and defanged text.
_HL_RULES = [
    ("urgent", re.compile(r"\b(?:act now|investigate today|possible account compromise|logged in successfully|logged in after brute force|"
                          r"(?:Critical|High)-severity|public exploits exist|readable by anyone listening)\b", re.I)),
    ("ioc", re.compile(r"(?<![\w.\[])\d{1,3}(?:(?:\[\.\]|\.)\d{1,3}){3}(?![\w.\]])")),                                  # IPv4, plain or defanged
    ("ioc", re.compile(r"\b[\w-]+(?:(?:\[\.\]|\.)[\w-]+)*(?:\[\.\]|\.)(?:exe|pdf|zip|docm?|xlsm?|js|vbs|ps1|bat|scr|iso|lnk|hta)\b", re.I)),
    ("ioc", re.compile(r"\b(?:[a-z0-9][a-z0-9-]*(?:\[\.\]|\.))+[a-z]{2,24}\b(?!\.\d)", re.I)),                            # domains / hosts
    ("ioc", re.compile(r"'[^'\s]{1,32}'")),                                                                               # 'root'
    ("num", re.compile(r"\b\d+ (?:distinct )?(?:ports?|failed logins?|risky services|known-vulnerable services|more attack types|times|"
                       r"engines|reports|reputation sources?|intel sources?)\b|\bports? \d+\b|\b\d+%", re.I)),
    ("term", re.compile(r"\b(?:SQL injection|XSS|path traversal|command injection|Log4Shell|SSRF|sensitive-file probing|attack-tool scanning|"
                        r"password guessing|brute force|port scan|ping sweep|cleartext|encoded PowerShell|download code|reverse shells|C2 tools|"
                        r"DNS tunnelling|double extension|disguised link|disguised as a document|reply hijacking|end-of-life operating system|known-vulnerable builds|"
                        r"URL shortener|newly registered|brand impersonation|risky attachment|SPF|DKIM|DMARC|"
                        r"Reconnaissance|Delivery|Exploitation|Persistence|Command & Control|Actions on Objectives)\b")),
]
_NOT_DOMAINS = {"e.g", "i.e"}


def highlight_spans(text: str) -> list:
    """Non-overlapping (start, end, kind) spans; earlier rules win, then longer matches."""
    found = []
    for prio, (kind, rx) in enumerate(_HL_RULES):
        for m in rx.finditer(text or ""):
            if m.group(0).lower().rstrip(".") in _NOT_DOMAINS:
                continue
            found.append((m.start(), m.end(), kind, prio))
    found.sort(key=lambda s: (s[3], -(s[1] - s[0]), s[0]))
    taken, out = [], []
    for s, e, kind, _ in found:
        if all(e <= a or s >= b for a, b in taken):
            taken.append((s, e)); out.append((s, e, kind))
    return sorted(out)


def _highlights(texts: list) -> list:
    seen, out = set(), []
    for t in texts:
        for s, e, kind in highlight_spans(t):
            phrase = t[s:e]
            if phrase not in seen:
                seen.add(phrase); out.append({"text": phrase, "kind": kind})
    return out


def build_exec_summary(result: dict, defang: bool = False) -> dict:
    result = result if isinstance(result, dict) else {}
    F = _by_name(result)
    builder = {"network": _network, "logs": _logs, "email": _email, "url": _url,
               "hash": lambda r, f: _reputation(r, f, "hash"), "ip": lambda r, f: _reputation(r, f, "IP")}.get(result.get("mode"), _fallback)
    parts, bullets = builder(result, F)
    if not bullets and real_findings(result):
        _, bullets = _fallback(result, F)
    clean = (lambda s: defang_text(mask_secrets(s))) if defang else mask_secrets
    headline = _headline(result, parts)
    actions = _do_now(result)
    story = build_story(result, headline=headline, do_now=actions, defang=defang)
    why = first_sentence(story, "means") or _why(result)
    out = {
        "headline": clean(headline),
        "what_happened": [clean(_fit(b, BULLET_MAX_WORDS)) for b in _derive_bullets(story, bullets)],
        "why_it_matters": clean(why),
        "do_now": [{"priority": a["priority"], "action": clean(a["action"])} for a in actions],
        "key_facts": [{**k, "value": clean(k["value"])} for k in _facts(result)],
        "story": story,
    }
    # key phrases (IOCs, counts, attack terms, urgent wording) for renderers to emphasise
    out["highlights"] = _highlights([out["headline"], *out["what_happened"], out["why_it_matters"]])
    return out


def attach_exec_summary(result: dict) -> dict:
    try:
        result["exec_summary"] = build_exec_summary(result)
    except Exception as e:
        from utils.logger import get_logger
        get_logger("summary").error("exec summary failed: %s", e)
    return result


# ─── Show details (exec_summary["details"]) ─────────────────────
def build_summary_details(result: dict, defang: bool = False) -> dict:
    """Detailed, non-repetitive details for the Executive Summary (see utils/summary_details.py)."""
    from utils.summary_details import build_details
    result = result if isinstance(result, dict) else {}
    summary = result.get("exec_summary") if isinstance(result.get("exec_summary"), dict) and result["exec_summary"].get("headline") else None
    if summary is None:
        try:
            summary = build_exec_summary(result)
        except Exception:                        # partial / old results: details still build, nothing to de-duplicate against
            summary = {"headline": "", "what_happened": [], "why_it_matters": "", "do_now": []}
    return build_details(result, {k: summary.get(k) for k in ("headline", "what_happened", "why_it_matters", "do_now", "story")}, defang=defang)


def attach_exec_details(result: dict) -> dict:
    """Adds result['exec_summary']['details'] (never raises; the short summary keys are untouched)."""
    try:
        if isinstance(result.get("exec_summary"), dict):
            result["exec_summary"]["details"] = build_summary_details(result)
    except Exception as e:
        from utils.logger import get_logger
        get_logger("summary").error("summary details failed: %s", e)
    return result
