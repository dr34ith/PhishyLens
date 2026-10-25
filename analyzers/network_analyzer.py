"""
PhishyLens: Network Artifact Triage (Phase 1)

Analyzes TEXT-based network artifacts:
  * Nmap normal output (-oN / console), grepable output (-oG)
  * Wireshark / tshark text or CSV exports (columns: No., Time, Source, Destination, Protocol, Length, Info)
and flags risky exposed services, known-vulnerable banners, scan behaviour, cleartext credentials,
suspicious ports and DNS-tunnelling indicators. Offline; public IPs are optionally enriched.
"""
import csv
import io
import re
import time
import uuid
from collections import Counter, defaultdict

from utils.scoring import calculate_score, score_to_verdict, attach_explanation, build_risk_breakdown, correlate_evidence
from utils.logger import get_logger

log = get_logger("network")
MAX_BYTES, MAX_LINES = 4_000_000, 30000

# port -> (service, severity, why)
RISKY_PORTS = {
    21:    ("FTP", "MEDIUM", "Cleartext file transfer; anonymous login and old daemons (vsftpd 2.3.4) are common CTF footholds."),
    23:    ("Telnet", "HIGH", "Cleartext remote shell: credentials sniffable; default creds common on IoT."),
    69:    ("TFTP", "MEDIUM", "Unauthenticated file transfer."),
    111:   ("RPCbind", "MEDIUM", "Exposes RPC/NFS services; used for enumeration."),
    135:   ("MS-RPC", "MEDIUM", "Windows RPC endpoint mapper: lateral movement surface."),
    139:   ("NetBIOS-SSN", "MEDIUM", "Legacy SMB over NetBIOS; null sessions / enumeration."),
    445:   ("SMB", "HIGH", "SMB exposure: EternalBlue (MS17-010), relay and null-session attacks."),
    512:   ("rexec", "HIGH", "Legacy r-services with trust-based auth."),
    513:   ("rlogin", "HIGH", "Legacy r-services with trust-based auth."),
    514:   ("rsh/syslog", "HIGH", "Legacy remote shell."),
    1099:  ("Java RMI", "HIGH", "Exposed RMI registry is frequently exploitable (deserialization)."),
    1433:  ("MSSQL", "MEDIUM", "Database exposed to the network; brute-force / xp_cmdshell risk."),
    1521:  ("Oracle TNS", "MEDIUM", "Database listener exposure."),
    2049:  ("NFS", "MEDIUM", "Network file share: check for world-readable exports."),
    2375:  ("Docker API (unencrypted)", "CRITICAL", "Unauthenticated Docker daemon = remote root on host."),
    3306:  ("MySQL", "MEDIUM", "Database exposed to the network."),
    3389:  ("RDP", "HIGH", "Internet-exposed RDP is a top ransomware entry point (BlueKeep, brute force)."),
    4444:  ("Metasploit default / reverse shell", "CRITICAL", "Default Metasploit/netcat listener port: strong C2 / bind-shell indicator."),
    5432:  ("PostgreSQL", "MEDIUM", "Database exposed to the network."),
    5555:  ("ADB / Android debug", "HIGH", "Unauthenticated Android Debug Bridge."),
    5900:  ("VNC", "HIGH", "Remote desktop often with weak or no password."),
    5985:  ("WinRM (HTTP)", "MEDIUM", "Remote management; lateral movement channel."),
    6379:  ("Redis", "HIGH", "Often unauthenticated: RCE via config/SSH-key write."),
    6667:  ("IRC", "MEDIUM", "Classic botnet C2 channel (also UnrealIRCd backdoor)."),
    8009:  ("AJP13", "HIGH", "Apache JServ: Ghostcat (CVE-2020-1938)."),
    9200:  ("Elasticsearch", "HIGH", "Frequently unauthenticated, leaks data / RCE in old versions."),
    1337:  ("'Leet' backdoor port", "HIGH", "Commonly used by backdoors and CTF challenges."),
    31337: ("Back Orifice / elite backdoor port", "CRITICAL", "Historic backdoor port: rarely legitimate."),
    27017: ("MongoDB", "HIGH", "Frequently unauthenticated."),
    11211: ("Memcached", "HIGH", "Exposed memcached enables data leaks and amplification DDoS."),
    161:   ("SNMP", "MEDIUM", "Default community strings ('public') leak system info."),
}
SUSPICIOUS_C2_PORTS = {4444, 1337, 31337, 5555, 6667, 8888, 9001, 12345, 54321}
# risky services that live on UDP (514/udp is plain syslog, so UDP is only flagged for these)
UDP_RISKY = {69, 111, 161, 2049, 11211}

# banner regex -> (name, severity, CVE / note)
VULN_BANNERS = [
    (re.compile(r"vsftpd\s+2\.3\.4", re.I), "vsftpd 2.3.4 Backdoor", "CRITICAL", "CVE-2011-2523: smiley-face backdoor opens shell on 6200/tcp"),
    (re.compile(r"UnrealIRCd\s+3\.2\.8\.1|unrealircd.*3\.2\.8", re.I), "UnrealIRCd 3.2.8.1 Backdoor", "CRITICAL", "CVE-2010-2075"),
    (re.compile(r"ProFTPD\s+1\.3\.3[a-c]", re.I), "ProFTPD 1.3.3c Backdoor", "CRITICAL", "Backdoored release (2010)"),
    (re.compile(r"Samba(?:\s+smbd)?\s+3\.[0-5]\.", re.I), "Old Samba (usermap_script)", "CRITICAL", "CVE-2007-2447"),
    (re.compile(r"distccd", re.I), "distcc Daemon", "HIGH", "CVE-2004-2687: unauthenticated command execution"),
    (re.compile(r"Apache httpd 2\.[0-3]\.|Apache/2\.[0-3]\.", re.I), "Outdated Apache httpd", "MEDIUM", "End-of-life Apache branch"),
    (re.compile(r"OpenSSH\s+[1-6]\.|OpenSSH_[1-6]\.", re.I), "Outdated OpenSSH", "MEDIUM", "OpenSSH < 7: user enumeration / weak crypto"),
    (re.compile(r"Microsoft Windows (?:XP|2000|Server 2003|7(?!\s*-\s*1\d)|Server 2008)", re.I), "End-of-Life Windows", "HIGH", "No security patches: likely EternalBlue-class exposure"),
    (re.compile(r"Apache Tomcat(?:/|\s)(?:[1-8]\.)", re.I), "Apache Tomcat (check manager)", "MEDIUM", "Default creds / manager deploy → WAR shell"),
    (re.compile(r"Jenkins", re.I), "Jenkins Exposed", "MEDIUM", "Script console → RCE if unauthenticated"),
    (re.compile(r"ms17-010|VULNERABLE:\s*\n?.*MS17-010", re.I), "MS17-010 (EternalBlue) Vulnerable", "CRITICAL", "NSE smb-vuln-ms17-010 reports vulnerable"),
    (re.compile(r"shellshock|CVE-2014-6271", re.I), "Shellshock", "CRITICAL", "CVE-2014-6271"),
    (re.compile(r"Anonymous FTP login allowed", re.I), "Anonymous FTP Allowed", "HIGH", "Unauthenticated file read/write"),
    (re.compile(r"(?:Server|banner):\s*Microsoft-IIS/[1-6]\.", re.I), "Outdated IIS", "HIGH", "IIS ≤ 6: WebDAV buffer overflow"),
    (re.compile(r"State:\s*VULNERABLE", re.I), "NSE Script Reports VULNERABLE", "HIGH", "A Nmap vulnerability script confirmed exposure"),
]

OPEN_NMAP_RE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+(open|open\|filtered|filtered|closed)\s+(\S+)?\s*(.*)$")
GREP_PORT_RE = re.compile(r"(\d{1,5})/(open|closed|filtered)/(tcp|udp)//([^/]*)//([^/]*)/")
IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _parse_nmap(text: str):
    hosts, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^Nmap scan report for\s+(?:(\S+)\s+\(([\d.]+)\)|(\S+))", line)
        if m:
            name, ip, solo = m.groups()
            cur = ip or solo
            hosts[cur] = {"hostname": name or "", "ports": [], "os": "", "scripts": []}
            continue
        g = re.match(r"^Host:\s+([\d.]+)\s+\(([^)]*)\)\s+Ports:\s+(.*)$", line)
        if g:
            ip = g.group(1)
            hosts.setdefault(ip, {"hostname": g.group(2), "ports": [], "os": "", "scripts": []})
            for pm in GREP_PORT_RE.finditer(g.group(3)):
                if pm.group(2) == "open":
                    hosts[ip]["ports"].append({"port": int(pm.group(1)), "proto": pm.group(3), "state": "open",
                                               "service": pm.group(4), "version": pm.group(5).strip()})
            continue
        if cur is None:
            continue
        pm = OPEN_NMAP_RE.match(line)
        if pm and pm.group(3).startswith("open"):
            hosts[cur]["ports"].append({"port": int(pm.group(1)), "proto": pm.group(2), "state": pm.group(3),
                                        "service": pm.group(4) or "", "version": (pm.group(5) or "").strip()})
        elif re.match(r"^\s*(?:OS details|Running|Service Info|Aggressive OS guesses):", line):
            hosts[cur]["os"] += line.strip() + " "
        elif line.startswith("|") or line.startswith("|_"):
            hosts[cur]["scripts"].append(line.strip("| _").strip())
    return {ip: h for ip, h in hosts.items() if h["ports"] or h["scripts"] or h["os"]}


def _parse_packets(text: str):
    """Parse Wireshark/tshark text or CSV exports into [{no,time,src,dst,proto,info}]."""
    pkts = []
    first = text.lstrip()[:300].lower()
    if "source" in first and "destination" in first and "," in first:
        try:
            for row in csv.DictReader(io.StringIO(text)):
                r = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
                pkts.append({"no": r.get("no.", r.get("no", "")), "time": r.get("time", ""), "src": r.get("source", ""),
                             "dst": r.get("destination", ""), "proto": r.get("protocol", ""), "info": r.get("info", "")})
            return pkts
        except Exception as e:
            log.warning("csv packet parse failed: %s", e)
    rx = re.compile(r"^\s*(\d+)\s+([\d.]+)\s+(\S+)\s+(?:→|->|<-)?\s*(\S+)\s+(\w[\w/.-]*)\s+(\d+)\s+(.*)$")
    for line in text.splitlines():
        m = rx.match(line)
        if m:
            pkts.append({"no": m.group(1), "time": m.group(2), "src": m.group(3), "dst": m.group(4), "proto": m.group(5), "info": m.group(7)})
    return pkts


def _f(sev, name, evidence, desc, why, rec, ref, conf=80, fp="Low–Medium."):
    return {"severity": sev, "name": name, "evidence": evidence[:300], "description": desc, "confidence": conf,
            "why_it_matters": why, "recommendation": rec, "false_positive_possibility": fp, "reference": ref}


def analyze_network(text) -> dict:
    start = time.time()
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8", errors="replace")
    text = text[:MAX_BYTES]
    lines = text.splitlines()[:MAX_LINES]
    text = "\n".join(lines)

    hosts = _parse_nmap(text)
    pkts = _parse_packets(text) if not hosts or "Source" in text[:400] else []
    findings, port_table = [], []

    # ─── Nmap host triage ──────────────────────────────────────
    for ip, h in hosts.items():
        open_ports = h["ports"]
        for p in open_ports:
            port_table.append({"host": ip, **p})
            info = RISKY_PORTS.get(p["port"])
            if info and (p["proto"] == "tcp" or p["port"] in UDP_RISKY):
                svc, sev, why = info
                findings.append(_f(sev, f"Risky Port Open: {p['port']}/{svc}", f"{ip}:{p['port']}/{p['proto']} {p['service']} {p['version']}".strip(),
                                   f"{svc} is reachable on {ip}.", why, "Restrict with firewall/VPN; disable if unused; require strong auth + patching.", "MITRE ATT&CK T1046 / T1021",
                                   conf=82, fp="Medium: may be intentional on internal hosts."))
            banner = f"{p['service']} {p['version']}"
            for rx, name, sev, ref in VULN_BANNERS:
                if rx.search(banner):
                    findings.append(_f(sev, f"Vulnerable Service: {name}", f"{ip}:{p['port']} ({banner.strip()})", f"Banner matches a known-vulnerable build ({ref}).",
                                       "Known exploits exist and are trivially weaponised (often in Metasploit).", "Patch/replace immediately; isolate host.", ref, conf=90, fp="Low: banners can be spoofed."))
        if len(open_ports) >= 15:
            findings.append(_f("MEDIUM", "Large Attack Surface", f"{ip}: {len(open_ports)} open ports", "Host exposes an unusually high number of services.",
                               "Each service is another exploitable entry point; indicates poor hardening or a honeypot.", "Reduce exposed services to the minimum.", "MITRE ATT&CK T1046", 70))
        susp = [p for p in open_ports if p["port"] in SUSPICIOUS_C2_PORTS]
        if susp and not any(f["name"].startswith(f"Risky Port Open: {susp[0]['port']}") for f in findings):
            findings.append(_f("HIGH", "Suspicious Listener Port", f"{ip}: {', '.join(str(p['port']) for p in susp)}", "Ports commonly used by backdoors / reverse shells are open.",
                               "Unexpected high-numbered listeners often indicate compromise.", "Identify the owning process (netstat/lsof) and investigate.", "MITRE ATT&CK T1571", 75))
        blob = "\n".join(h["scripts"])
        for rx, name, sev, ref in VULN_BANNERS:
            if rx.search(blob) and not any(name in f["name"] and f["evidence"].startswith(f"{ip}") for f in findings):
                findings.append(_f(sev, f"NSE Finding: {name}", f"{ip}", f"Nmap script output matches: {name}.", "Script output confirms an exploitable condition.",
                                   "Remediate and re-scan.", ref, 88))
        if re.search(r"Windows\s*(?:XP|2000|7|Server 2003|Server 2008)|Linux\s+2\.[0-6]\.", h["os"], re.I):
            findings.append(_f("HIGH", "End-of-Life Operating System", f"{ip}: {h['os'][:120]}", "OS fingerprint indicates an unsupported release.",
                               "No security updates; public exploits abound.", "Upgrade or isolate.", "MITRE ATT&CK T1190", 72))

    # ─── packet-capture triage ─────────────────────────────────
    pkt_stats = {}
    if pkts:
        syn_ports, syn_count = defaultdict(set), Counter()
        icmp_targets, arp_count, dns_long, creds = defaultdict(set), Counter(), [], []
        talkers = Counter()
        for p in pkts:
            info, proto, src, dst = p["info"], p["proto"].upper(), p["src"], p["dst"]
            talkers[src] += 1
            if "[SYN]" in info and "[ACK]" not in info:
                m = re.search(r"(?:→|->|>)\s*(\d+)\s*\[SYN\]", info)
                if m:
                    syn_ports[(src, dst)].add(int(m.group(1)))
                    syn_count[src] += 1
            if re.search(r"\[RST, ACK\]|\[RST\]", info):
                pass
            if proto == "ICMP" and "Echo (ping) request" in info:
                icmp_targets[src].add(dst)
            if proto == "ARP" and ("Who has" in info or "is at" in info):
                arp_count[src] += 1
            if proto == "DNS" and (len(info) > 110 or re.search(r"TXT|NULL", info)):
                dns_long.append(info[:120])
            if re.search(r"\b(USER|PASS)\s+\S+", info) and proto in ("FTP", "TELNET", "POP", "IMAP", "SMTP"):
                creds.append((proto, src, dst, info[:80]))
            if re.search(r"Authorization:\s*Basic|password=|passwd=|pwd=", info, re.I) and proto in ("HTTP", "TCP"):
                creds.append((proto, src, dst, info[:80]))
        for (src, dst), ports in syn_ports.items():
            if len(ports) >= 10:
                findings.append(_f("HIGH" if len(ports) < 100 else "CRITICAL", "TCP Port Scan Detected", f"{src} → {dst}: SYN to {len(ports)} distinct ports (e.g. {sorted(ports)[:8]})",
                                   "One source probed many ports on one target with bare SYN packets.", "Classic reconnaissance preceding exploitation (nmap -sS).", "Block/rate-limit the source; review target exposure.",
                                   "MITRE ATT&CK T1046", 90, "Low: authorised scanners look identical."))
        for src, tgts in icmp_targets.items():
            if len(tgts) >= 10:
                findings.append(_f("MEDIUM", "ICMP Ping Sweep", f"{src} pinged {len(tgts)} hosts", "Host-discovery sweep across many addresses.", "Attackers map live hosts before port scanning.", "Block ICMP echo from untrusted sources.", "MITRE ATT&CK T1018", 78))
        for src, n in arp_count.items():
            if n >= 50:
                findings.append(_f("HIGH", "ARP Flood / Possible Spoofing", f"{src}: {n} ARP packets", "Excessive ARP traffic from one host.", "Typical of ARP poisoning (MITM) or network scanning.", "Enable dynamic ARP inspection; investigate source MAC/IP.", "MITRE ATT&CK T1557.002", 72))
        if len(dns_long) >= 3:
            findings.append(_f("HIGH", "Possible DNS Tunnelling", f"{len(dns_long)} oversized/TXT DNS queries, e.g. {dns_long[0]}", "Long or TXT-heavy DNS queries detected.", "DNS tunnelling exfiltrates data / carries C2 inside DNS.", "Inspect query names for encoded payloads; block the domain.", "MITRE ATT&CK T1071.004", 70))
        for proto, src, dst, info in creds[:5]:
            findings.append(_f("HIGH", "Cleartext Credentials on the Wire", f"{proto} {src}→{dst}: {info}", "Credentials observed unencrypted in the capture.", "Anyone on-path can read them; also a gift in forensics challenges.", "Migrate to TLS/SSH variants; rotate exposed credentials.", "MITRE ATT&CK T1040", 90, "Low."))
        c2 = Counter()
        for p in pkts:
            m = re.search(r"(?:→|->|>)\s*(\d+)\s", p["info"])
            if m and int(m.group(1)) in SUSPICIOUS_C2_PORTS:
                c2[(p["src"], p["dst"], int(m.group(1)))] += 1
        for (src, dst, port), n in c2.most_common(3):
            findings.append(_f("HIGH", "Traffic to Suspicious Port", f"{src} → {dst}:{port} ({n} packets)", f"Connection to commonly abused port {port}.", "Reverse shells and C2 frameworks default to these ports.", "Identify the process behind the connection; consider containment.", "MITRE ATT&CK T1571", 75))
        pkt_stats = {"packets": len(pkts), "top_talkers": talkers.most_common(8), "protocols": dict(Counter(p["proto"] for p in pkts).most_common(8)),
                     "scan_sources": sorted(s for (s, _), pts in syn_ports.items() if len(pts) >= 10)}

    # dedupe by (name, evidence)
    seen, uniq = set(), []
    for f in findings:
        k = (f["name"], f["evidence"])
        if k not in seen:
            seen.add(k); uniq.append(f)
    findings = uniq

    # enrich public hosts/sources
    ips = list(hosts.keys()) + pkt_stats.get("scan_sources", [])
    enrichment = {"ips": [], "hashes": [], "skipped_private": []}
    try:
        from utils.threat_intel import enrich_indicators
        enrichment = enrich_indicators(ips, [])
        findings.extend(enrichment.pop("findings", []))
    except Exception as e:
        log.error("network enrichment failed: %s", e)

    if not findings:
        findings.append({"severity": "LOW", "name": "No Indicators Detected", "evidence": f"{len(hosts)} host(s), {len(pkts)} packet(s) parsed",
                         "description": "No risky services, vulnerable banners or scan behaviour detected.", "confidence": 15, "why_it_matters": "Absence of findings is not proof of safety.",
                         "recommendation": "Corroborate with deeper scans.", "false_positive_possibility": "N/A", "reference": ""})
    real = [f for f in findings if f["name"] != "No Indicators Detected"]
    score = calculate_score(findings) if real else 5
    verdict = score_to_verdict(score)
    result = {
        "verdict": verdict, "score": score, "mode": "network",
        "input": f"{len(hosts)} host(s), {sum(len(h['ports']) for h in hosts.values())} open port(s), {len(pkts)} packet(s)",
        "scan_id": str(uuid.uuid4())[:8].upper(), "findings": findings,
        "timeline": [{"step": "Artifact Parsing", "status": "complete", "detail": f"{len(hosts)} nmap host(s), {len(pkts)} packet(s)"},
                     {"step": "Service & Banner Triage", "status": "complete", "detail": f"{len(real)} issue(s) flagged"},
                     {"step": "Risk Assessment", "status": "complete", "detail": f"Risk score: {score}% ({verdict})"}],
        "risk_breakdown": build_risk_breakdown(findings), "evidence_correlation": correlate_evidence(findings, "network"),
        "summary": f"Triaged {len(hosts)} host(s) and {len(pkts)} packet(s); {len(real)} suspicious item(s) found.",
        "recommended_action": {"MALICIOUS": "Isolate affected hosts, close/patch exposed services and investigate scan sources.",
                               "SUSPICIOUS": "Review flagged services and harden or restrict them.", "BENIGN": "No significant exposure detected."}[verdict],
        "confidence": min(95, 55 + 4 * len(real)), "duration_ms": int((time.time() - start) * 1000),
        "iocs": {"ips": list(hosts.keys()) + pkt_stats.get("scan_sources", []), "urls": [], "emails": [], "domains": [], "hashes": []},
        "network_stats": {"hosts": [{"ip": ip, "hostname": h["hostname"], "os": h["os"].strip(), "open_ports": len(h["ports"])} for ip, h in hosts.items()],
                          "ports": port_table[:200], "packets": pkt_stats},
        "enrichment": enrichment,
    }
    return attach_explanation(result)
