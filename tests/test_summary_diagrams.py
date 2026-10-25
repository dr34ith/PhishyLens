"""
Executive summary, diagrams and write-up structure; mixed-mode fixtures (logs, Nmap, Wireshark, email, URL).
Run:  python -m unittest tests.test_summary_diagrams -v      (network access is mocked)

The HARD RULE under test: every sentence, node, edge and label comes from the analysis result.
"""
import json, os, re, sys, tempfile, unittest
import xml.etree.ElementTree as ET
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "phishylens_test.db"))
os.environ["PHISHYLENS_SKIP_DOTENV"] = "1"

import requests
from utils.artifacts import mask_secrets, timeline_events, ip_scope
from utils.summary import build_exec_summary, HEADLINE_MAX_WORDS, BULLET_MAX_WORDS
from utils.diagrams import build_diagram, build_killchain_svg, MAX_NODES
from utils.report import build_report, slug

FIX = os.path.join(ROOT, "tests", "fixtures")
SECRET = "hunter2"                                  # FTP password inside phishylens_wireshark_test.csv
SVG_NS = "{http://www.w3.org/2000/svg}"


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _fake_head(url, *a, **kw):
    """Deterministic 2-hop redirect chain for the URL fixture: bit.ly → tracker → final phishing page."""
    hops = {"http://bit.ly/3xYz": "http://track.example-redirect.top/r?id=1",
            "http://track.example-redirect.top/r?id=1": "http://paypa1-login.xyz/verify"}
    resp = mock.Mock(status_code=301 if url in hops else 200, headers={"Location": hops.get(url, "")}, url=url)
    resp.close = lambda: None
    return resp


class Fixtures(unittest.TestCase):
    results = {}

    @classmethod
    def setUpClass(cls):
        patches = [mock.patch(f"requests.{fn}", side_effect=requests.ConnectionError("offline")) for fn in ("get", "post")]
        patches.append(mock.patch("requests.head", side_effect=_fake_head))
        patches.append(mock.patch("analyzers.url_analyzer.socket.getaddrinfo",
                                  return_value=[(2, 1, 6, "", ("93.184.216.34", 0))], create=True))
        for p in patches:
            p.start()
        try:
            import app as app_module
            c = app_module.app.test_client()
            for key, ep, body in (("logs", "/api/analyze/logs", {"logs": read(os.path.join(FIX, "phishylens_test.log"))}),
                                  ("nmap", "/api/analyze/network", {"data": read(os.path.join(FIX, "phishylens_nmap_test.txt"))}),
                                  ("pcap", "/api/analyze/network", {"data": read(os.path.join(FIX, "phishylens_wireshark_test.csv"))}),
                                  ("email", "/api/analyze/email", {"raw": read(os.path.join(ROOT, "samples", "phishing.eml"))}),
                                  ("url", "/api/analyze/url", {"url": "http://bit.ly/3xYz"})):
                r = c.post(ep, json=body)
                assert r.status_code == 200, r.get_data(as_text=True)[:300]
                cls.results[key] = r.get_json()["result"]
        finally:
            for p in patches:
                p.stop()


# ─── executive summary ──────────────────────────────────────────
class TestExecSummary(Fixtures):
    def test_shape_and_limits(self):
        for key, r in self.results.items():
            with self.subTest(fixture=key):
                s = r["exec_summary"]
                self.assertEqual(set(s) - {"details", "story"}, {"headline", "what_happened", "why_it_matters", "do_now", "key_facts", "highlights"})   # + "story", optional "details"
                self.assertLessEqual(len(s["headline"].split()), HEADLINE_MAX_WORDS, s["headline"])
                self.assertLessEqual(len(s["what_happened"]), 4)
                for b in s["what_happened"]:
                    self.assertLessEqual(len(b.split()), BULLET_MAX_WORDS, b)
                self.assertEqual(s["why_it_matters"].count(". "), 0, "why_it_matters must be one sentence")
                self.assertLessEqual(len(s["do_now"]), 3)
                for a in s["do_now"]:
                    self.assertIn(a["priority"], ("Now", "Today", "This week"))

    def test_two_to_four_bullets_when_findings_exist(self):
        for key in ("logs", "nmap", "pcap", "email"):
            self.assertGreaterEqual(len(self.results[key]["exec_summary"]["what_happened"]), 2, key)

    def test_no_zero_counts(self):
        for key, r in self.results.items():
            for f in r["exec_summary"]["key_facts"]:
                self.assertNotIn(f["value"], ("0", "0%", ""), f"{key}: {f}")
        s = build_exec_summary({"verdict": "BENIGN", "score": 5, "mode": "url", "findings": [], "mitre": {"techniques": []}})
        self.assertNotIn("Findings", [f["label"] for f in s["key_facts"]])
        self.assertNotIn("ATT&CK techniques", [f["label"] for f in s["key_facts"]])

    def test_no_raw_secrets(self):
        dumped = json.dumps(self.results["pcap"]["exec_summary"])
        self.assertNotIn(SECRET, dumped)
        self.assertIn(SECRET, json.dumps(self.results["pcap"]["findings"]))   # proves the fixture really contains it
        self.assertEqual(mask_secrets("Request: PASS hunter2"), "Request: PASS ********")
        self.assertEqual(mask_secrets("GET /login?user=a&password=s3cr3t&x=1"), "GET /login?user=a&password=********&x=1")
        self.assertEqual(mask_secrets("cleartext FTP login captured"), "cleartext FTP login captured")    # prose untouched
        self.assertEqual(mask_secrets("union select username,password from users"), "union select username,password from users")

    def test_mode_specific_content_is_grounded(self):
        logs = self.results["logs"]["exec_summary"]
        self.assertIn("203.0.113.50", logs["headline"])
        self.assertIn("198.51.100.7 logged in after brute force", logs["headline"])
        self.assertTrue(any("logged in successfully as 'root'" in b for b in logs["what_happened"]))
        pcap = self.results["pcap"]["exec_summary"]
        self.assertIn("port scan from 10.0.0.99 against 10.10.10.5", pcap["headline"])
        self.assertIn("cleartext FTP login", pcap["headline"])
        self.assertIn("4444", pcap["headline"])
        self.assertIn("vsftpd 2.3.4 Backdoor", self.results["nmap"]["exec_summary"]["headline"])
        email = self.results["email"]["exec_summary"]
        self.assertIn("invoice.pdf.exe", email["headline"])
        self.assertIn("paypa1-secure.xyz", email["headline"])
        url = self.results["url"]["exec_summary"]
        self.assertIn("paypa1-login.xyz", url["headline"])
        self.assertIn("redirects 2 times", url["headline"])
        # every IP mentioned in any summary text exists in that result
        for key, r in self.results.items():
            text = json.dumps(r["exec_summary"])
            for ip in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
                self.assertIn(ip, json.dumps({k: v for k, v in r.items() if k != "exec_summary"}), f"{key}: {ip} not in result")

    def test_defang_flag(self):
        s = build_exec_summary(self.results["pcap"], defang=True)
        self.assertIn("10[.]0[.]0[.]99", s["headline"])
        self.assertNotIn("10.0.0.99", json.dumps(s))
        self.assertIn("10.0.0.99", self.results["pcap"]["exec_summary"]["headline"])     # API value stays live

    def test_highlights_come_from_the_text(self):
        for key, r in self.results.items():
            s = r["exec_summary"]
            text = " ".join([s["headline"], *s["what_happened"], s["why_it_matters"]])
            with self.subTest(fixture=key):
                self.assertTrue(s["highlights"])
                for h in s["highlights"]:
                    self.assertIn(h["text"], text)
                    self.assertIn(h["kind"], ("ioc", "num", "term", "urgent"))
        hl = {h["text"]: h["kind"] for h in self.results["logs"]["exec_summary"]["highlights"]}
        self.assertEqual(hl.get("203.0.113.50"), "ioc")
        self.assertEqual(hl.get("SQL injection"), "term")
        self.assertEqual(hl.get("5 failed logins"), "num")
        self.assertEqual(hl.get("possible account compromise"), "urgent")
        self.assertEqual(hl.get("act now"), "urgent")
        defanged = {h["text"] for h in build_exec_summary(self.results["pcap"], defang=True)["highlights"]}
        self.assertIn("10[.]0[.]0[.]99", defanged)

    def test_highlighted_writeup_is_escaped(self):
        from utils.report import _md_hl, _h_hl
        self.assertEqual(_md_hl("10.0.0.99 sent SQL injection to <b>x</b>"), "`10.0.0.99` sent **SQL injection** to &lt;b&gt;x&lt;/b&gt;")
        self.assertEqual(_h_hl("act now <script>"), '<span class="hl hl-urgent">act now</span> &lt;script&gt;')
        html = build_report(self.results["logs"], "html")
        self.assertIn('<span class="hl hl-ip">203[.]0[.]113[.]50</span>', html)
        self.assertIn("`203[.]0[.]113[.]50`", build_report(self.results["logs"], "md"))

    def test_no_em_dashes_in_any_output(self):
        for key, r in self.results.items():
            with self.subTest(fixture=key):
                for out in (json.dumps(r["exec_summary"], ensure_ascii=False), build_diagram(r)["svg"], build_diagram(r)["mermaid"],
                            build_killchain_svg(r), build_report(r, "md"), build_report(r, "html"),
                            json.dumps({k: v for k, v in r.items() if k not in ("mitre",)}, ensure_ascii=False)):
                    self.assertNotIn("\u2014", out)          # em dash

    def test_deterministic(self):
        r = self.results["logs"]
        self.assertEqual(build_exec_summary(r), build_exec_summary(r))


# ─── diagrams ───────────────────────────────────────────────────
class TestDiagrams(Fixtures):
    def _in_result(self, value, r):
        """Node/edge value must be a (secret-masked) value present in the result."""
        blob = mask_secrets(json.dumps(r, ensure_ascii=False))
        if mask_secrets(value) in blob or json.dumps(mask_secrets(value), ensure_ascii=False)[1:-1] in blob:
            return True
        m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)", value)               # host:port from network_stats.ports
        return bool(m and any(p.get("host") == m.group(1) and str(p.get("port")) == m.group(2)
                              for p in (r.get("network_stats") or {}).get("ports") or []))

    def test_every_node_and_edge_maps_to_the_result(self):
        for key, r in self.results.items():
            d = build_diagram(r)
            with self.subTest(fixture=key):
                self.assertNotEqual(d["type"], "none")
                ids = {n["id"] for n in d["nodes"]}
                for n in d["nodes"]:
                    if n["kind"] != "more":
                        self.assertTrue(self._in_result(n["value"], r), f"{key}: node {n['id']} value {n['value']!r} not in result")
                        self.assertTrue(n["field"], n)
                for e in d["edges"]:
                    self.assertIn(e["from"], ids); self.assertIn(e["to"], ids)
                    self.assertTrue(self._in_result(e["value"], r), f"{key}: edge {e['from']}->{e['to']} value {e['value']!r}")
                self.assertNotIn(SECRET, json.dumps(d))

    def test_network_roles_edges_and_scope(self):
        d = build_diagram(self.results["pcap"])
        roles = {n["label"]: n["role"] for n in d["nodes"]}
        self.assertEqual(roles, {"10.0.0.99": "scan source", "10.10.10.5": "target", "10.0.0.50": "client", "10.0.0.77": "destination"})
        labels = {(e["from"], e["to"]): e["label"] for e in d["edges"]}
        self.assertEqual(labels[("ip:10.0.0.99", "ip:10.10.10.5")], "SYN × 25 ports")
        self.assertEqual(labels[("ip:10.0.0.50", "ip:10.10.10.5")], "cleartext FTP login")
        self.assertEqual(labels[("ip:10.10.10.5", "ip:10.0.0.77")], ":4444 callback")
        self.assertNotIn("8.8.8.8", json.dumps(d))           # only in the raw capture, never in the result → not drawn
        self.assertTrue(all("internal" in n["sub"][0] for n in d["nodes"]))
        self.assertEqual((ip_scope("10.0.0.5"), ip_scope("8.8.8.8"), ip_scope("203.0.113.50")), ("internal", "public", "reserved"))

    def test_nmap_ports(self):
        d = build_diagram(self.results["nmap"])
        ports = [n for n in d["nodes"] if n["kind"] == "port"]
        self.assertEqual(len(ports), 12)
        crit = next(n for n in ports if n["label"] == "21/ftp")
        self.assertEqual(crit["severity"], "CRITICAL")
        self.assertIn("vsftpd 2.3.4 Backdoor", crit["sub"])

    def test_email_path(self):
        d = build_diagram(self.results["email"])
        ids = [n["id"] for n in d["nodes"]]
        self.assertEqual(ids[:4], ["from", "rpath", "hop1", "rcpt"])
        rcpt = next(n for n in d["nodes"] if n["id"] == "rcpt")
        self.assertEqual(dict(rcpt["badges"]), {"SPF": "fail", "DKIM": "none", "DMARC": "fail"})
        rt = next(e for e in d["edges"] if e["to"] == "replyto")
        self.assertTrue(rt["dashed"]); self.assertEqual(rt["label"], "Reply-To mismatch")

    def test_url_chain(self):
        d = build_diagram(self.results["url"])
        hops = [n for n in d["nodes"] if n["kind"] in ("hop", "final")]
        self.assertEqual([n["label"] for n in hops], ["bit.ly", "track.example-redirect.top", "paypa1-login.xyz"])
        self.assertIn("URL shortener", hops[0]["sub"])
        self.assertTrue(hops[-1]["highlight"])
        self.assertEqual([e["label"] for e in d["edges"] if e["label"].endswith("redirect")], ["301 redirect", "301 redirect"])

    def test_logs_timeline_markers(self):
        d = build_diagram(self.results["logs"])
        labels = [n["label"] for n in d["nodes"]]
        self.assertIn("Login succeeded after failures", labels)
        self.assertIn("Decoded PowerShell", labels)
        self.assertEqual([n["label"] for n in d["nodes"] if n["kind"] == "lane"], ["203.0.113.50", "198.51.100.7"])
        self.assertEqual(d["edges"][0]["label"], "after 5 failures")

    def test_svg_well_formed_responsive_both_themes(self):
        for key, r in self.results.items():
            for theme in ("dark", "print"):
                with self.subTest(fixture=key, theme=theme):
                    root = ET.fromstring(build_diagram(r, theme)["svg"])
                    self.assertEqual(root.tag, SVG_NS + "svg")
                    self.assertEqual(root.get("width"), "100%")
                    self.assertRegex(root.get("viewBox"), r"^0 0 \d+ \d+$")
                    self.assertEqual(root.findall(f".//{SVG_NS}script"), [])
                    ET.fromstring(build_killchain_svg(r, theme))

    def test_cap_and_escaping(self):
        evil = "<script>alert(1)</script>&\"'"
        r = {"mode": "network", "verdict": "MALICIOUS", "findings": [
            {"name": f"Risky Port Open: {p}/svc", "severity": "HIGH", "evidence": f"10.9.9.9:{p}/tcp {evil}"} for p in range(1000, 1030)],
             "network_stats": {"hosts": [{"ip": "10.9.9.9", "hostname": evil, "open_ports": 30, "os": ""}], "ports": []}}
        d = build_diagram(r)
        self.assertLessEqual(len(d["nodes"]), MAX_NODES)
        more = [n for n in d["nodes"] if n["kind"] == "more"]
        self.assertEqual(len(more), 1)
        self.assertEqual(more[0]["label"], f"+{30 + 1 - (MAX_NODES - 1)} more")
        root = ET.fromstring(d["svg"])                          # still well-formed with hostile text
        self.assertEqual(root.findall(f".//{SVG_NS}script"), [])
        self.assertIn("&lt;script&gt;", d["svg"])

    def test_empty_when_nothing_to_draw(self):
        self.assertEqual(build_diagram({"mode": "logs", "findings": []})["type"], "none")
        self.assertEqual(build_killchain_svg({}), "")

    def test_api(self):
        import app as app_module
        c = app_module.app.test_client()
        r = c.post("/api/diagram", json={"result": self.results["pcap"], "theme": "print"})
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        ET.fromstring(d["svg"]); ET.fromstring(d["killchain_svg"])
        self.assertIn("flowchart LR", d["mermaid"])
        self.assertNotIn(SECRET, r.get_data(as_text=True))
        self.assertEqual(c.post("/api/diagram", json={}).status_code, 400)


# ─── write-up structure ─────────────────────────────────────────
class TestWriteupSections(Fixtures):
    ALWAYS = ["Executive Summary", "Findings", "Appendix"]

    def _ids(self, html):
        return set(re.findall(r'<h2 id="([^"]+)"', html))

    def test_sections_present_when_data_exists(self):
        expect = {
            "logs":  ["Visual Map", "Timeline of Events", "Classification and Kill Chain", "MITRE ATT&CK Techniques", "Why This Score",
                      "Indicators of Compromise", "Recommended Actions", "Detection Rules (Sigma)", "Related Resources"],
            "nmap":  ["Visual Map", "Classification and Kill Chain", "MITRE ATT&CK Techniques", "Indicators of Compromise", "Recommended Actions"],
            "pcap":  ["Visual Map", "MITRE ATT&CK Techniques", "Indicators of Compromise", "Detection Rules (Sigma)"],
            "email": ["Visual Map", "Timeline of Events", "MITRE ATT&CK Techniques", "Indicators of Compromise", "Recommended Actions"],
            "url":   ["Visual Map", "Indicators of Compromise"],
        }
        for key, sections in expect.items():
            html = build_report(self.results[key], "html")
            with self.subTest(fixture=key):
                ids = self._ids(html)
                for s in self.ALWAYS + sections:
                    self.assertIn(slug(s), ids, f"{key}: missing {s}")
                for s in self.ALWAYS + sections:                         # TOC links to every present section
                    self.assertIn(f'href="#{slug(s)}"', html)
                self.assertIn("How to read this report", html)
                self.assertIn("page-break", html)
                self.assertNotIn(SECRET, html)
                self.assertNotIn(SECRET, build_report(self.results[key], "md"))

    def test_sections_omitted_without_data(self):
        for key in ("nmap", "pcap", "url"):                              # no timestamps survive in these results
            self.assertEqual(timeline_events(self.results[key]), [])
            self.assertNotIn(slug("Timeline of Events"), self._ids(build_report(self.results[key], "html")), key)
        bare = {"verdict": "BENIGN", "score": 5, "mode": "url", "findings": []}
        ids = self._ids(build_report(bare, "html"))
        self.assertEqual(ids, {slug(s) for s in self.ALWAYS})

    def test_order_and_formats(self):
        md = build_report(self.results["logs"], "md")
        order = ["Executive Summary", "Visual Map", "Timeline of Events", "Classification and Kill Chain", "MITRE ATT&CK Techniques",
                 "Why This Score", "Findings", "Indicators of Compromise", "Recommended Actions", "Detection Rules (Sigma)",
                 "Related Resources", "Appendix"]
        idx = [md.index(f"## {s}\n") for s in order]
        self.assertEqual(idx, sorted(idx))
        self.assertIn("```mermaid", md)
        self.assertIn("- [ ] ", md)                                     # checklist
        for prio in ("**Now**",):
            self.assertIn(prio, md)
        html = build_report(self.results["logs"], "html")
        self.assertEqual(len(re.findall(r"<figure><svg", html)), 2)       # attack diagram + kill chain inline
        self.assertIn("@media print", html)

    def test_findings_merged_and_iocs_complete(self):
        md = build_report(self.results["pcap"], "md")
        self.assertEqual(md.count("#### Cleartext Credentials on the Wire"), 1)        # two findings merged
        section = md.split("## Indicators of Compromise")[1].split("\n## ")[0]
        for ip in ("10[.]0[.]0[.]99", "10[.]10[.]10[.]5", "10[.]0[.]0[.]50", "10[.]0[.]0[.]77"):
            self.assertIn(ip, section)
        self.assertIn("scan source", section)
        self.assertIn("internal", section)


if __name__ == "__main__":
    unittest.main()
