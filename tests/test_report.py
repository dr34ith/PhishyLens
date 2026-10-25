"""Write-up export tests: run:  python -m unittest tests.test_report -v"""
import os, re, sys, tempfile, unittest
from html.parser import HTMLParser
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "phishylens_test.db"))
os.environ["PHISHYLENS_SKIP_DOTENV"] = "1"

import requests
import yaml
from utils.report import build_report, build_blocks, render_markdown, render_html, report_filename

SECTIONS = ["Executive Summary", "Visual Map", "Timeline of Events", "Classification and Kill Chain", "MITRE ATT&CK Techniques",
            "Why This Score", "Findings", "Indicators of Compromise", "Recommended Actions", "Detection Rules (Sigma)",
            "Related Resources", "Appendix"]
FENCE3 = "`" * 3


def sample(name):
    with open(os.path.join(ROOT, "samples", name), encoding="utf-8") as fh:
        return fh.read()


class ActiveContentFinder(HTMLParser):
    """Collects anything in the HTML that could execute: script-ish tags, on* handlers, non-http(s) hrefs."""
    def __init__(self):
        super().__init__()
        self.bad = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "iframe", "img", "object", "embed", "foreignobject"):
            self.bad.append(tag)
        for k, v in attrs:
            if k.startswith("on") or (k == "href" and v and not v.startswith(("http://", "https://", "#"))):
                self.bad.append(f"{tag}[{k}={v}]")


class ReportCase(unittest.TestCase):
    def setUp(self):
        for fn in ("get", "post", "head"):
            p = mock.patch(f"requests.{fn}", side_effect=requests.ConnectionError("offline"))
            p.start(); self.addCleanup(p.stop)
        import app as app_module
        self.client = app_module.app.test_client()

    def result(self, endpoint="/api/analyze/logs", body=None):
        body = body or {"logs": sample("web_attack.log")}
        return self.client.post(endpoint, json=body).get_json()["result"]


class TestReportContent(ReportCase):
    def test_markdown_has_every_section(self):
        r = self.result()
        md = build_report(r, "md")
        self.assertTrue(md.startswith(f"# PhishyLens Write-up: {r['verdict']} ({r['score']}%)"))
        for s in SECTIONS:
            self.assertIn(f"## {s}", md, s)
        self.assertIn("Attacker reached:", md)
        self.assertLess(md.index("## Executive Summary"), md.index("## Visual Map"))
        self.assertLess(md.index("## Findings"), md.index("## Indicators of Compromise"))
        self.assertIn("```mermaid", md)
        self.assertIn("| ID | Name | Tactic | Confidence | Link |", md)
        self.assertIn("(https://attack.mitre.org/techniques/T1190/)", md)
        self.assertIn("| Factor | Points | Severity | Evidence |", md)
        self.assertRegex(md.split("## Appendix")[1], r"\*\*Generated:\*\* \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC")
        self.assertIn("Built only from the analysis result", md)

    def test_sigma_blocks_parse(self):
        md = build_report(self.result(), "md")
        blocks = re.findall(FENCE3 + r"`*yaml\n(.*?)\n" + FENCE3, md, re.S)
        self.assertGreaterEqual(len(blocks), 3)
        for b in blocks:
            self.assertEqual(list(yaml.safe_load_all(b))[0]["status"], "experimental")
        self.assertNotIn("## Detection Rules (Sigma)", build_report(self.result(), "md", include_sigma=False))

    def test_iocs_always_defanged_and_text_defang_optional(self):
        r = self.result()
        md_live = build_report(r, "md", defang=False)
        ioc_section = md_live.split("## Indicators of Compromise")[1].split("\n## ")[0]
        self.assertNotRegex(ioc_section, r"(?<![\d.\[])(?:\d{1,3}\.){3}\d{1,3}(?![\d.\]])")
        self.assertRegex(ioc_section, r"\d+\[\.\]\d+")
        md = build_report(r, "md", defang=True)
        self.assertNotRegex(md, r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
        self.assertIn("(https://attack.mitre.org/techniques/", md)          # links stay clickable

    def test_only_result_data_no_fabrication(self):
        r = {"verdict": "BENIGN", "score": 5, "mode": "url", "findings": [{"name": "No Indicators Detected", "severity": "LOW"}]}
        md = build_report(r, "md")
        self.assertIn("No findings beyond informational checks.", md)
        self.assertNotIn("Malware family", md)
        for absent in ("MITRE ATT&CK Techniques", "Detection Rules (Sigma)", "Timeline of Events", "Visual Map", "Why This Score"):
            self.assertNotIn(f"## {absent}", md)

    def test_malware_family_section(self):
        r = {"verdict": "MALICIOUS", "score": 94, "findings": [], "malware_family": {
            "name": "AgentTesla", "source": "MalwareBazaar", "first_seen": "2024-03-01", "tags": ["exe"], "indicator": "abc"}}
        md = build_report(r, "md")
        self.assertIn("## Indicators of Compromise", md)
        self.assertIn("**Malware family:** AgentTesla", md)


class TestReportEscaping(unittest.TestCase):
    EVIL = {"verdict": "MALICIOUS", "score": 90, "mode": "logs", "input": "<script>alert(1)</script> `x` | y",
            "findings": [{"name": "<img src=x onerror=alert(1)>", "severity": "HIGH", "evidence": "a " + FENCE3 + " b <b>bold</b> | c",
                          "description": "<iframe src=javascript:alert(1)>", "recommendation": "do <svg onload=alert(1)>"}],
            "mitre": {"techniques": [{"id": "T1190", "name": "x", "tactic": "Initial Access", "confidence": 50,
                                      "url": "javascript:alert(document.cookie)"}]},
            "iocs": {"urls": ["http://evil.com/<script>"]}}

    def test_html_has_no_active_content(self):
        page = build_report(self.EVIL, "html")
        finder = ActiveContentFinder()
        finder.feed(page)
        self.assertEqual(finder.bad, [])
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn('href="javascript:', page)

    def test_markdown_neutralises_html_and_links(self):
        md = build_report(self.EVIL, "md")
        # user-controlled values may keep '<' only inside code spans, which Markdown renders as literal text
        outside_code = re.sub(r"(`+)(?:(?!\1).)+?\1", "", md)
        self.assertNotRegex(outside_code, r"<[A-Za-z/!]")
        self.assertNotIn("](javascript:", md)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", md)
        self.assertIn("`" * 4, md)                     # evidence containing ``` gets a longer code-span fence

    def test_filename_sanitised(self):
        self.assertEqual(report_filename({"scan_id": '../../etc/passwd"x'}, "html"), "phishylens_writeup_etcpasswdx.html")
        self.assertEqual(report_filename({}, "md"), "phishylens_writeup_report.md")

    def test_same_sections_in_both_formats(self):
        blocks = build_blocks(self.EVIL)
        md, page = render_markdown(blocks), render_html(blocks)
        for blk in blocks:
            if blk[0] == "h2":
                self.assertIn(blk[1].replace("&", "&amp;"), page)
                self.assertIn(blk[1], md)


class TestReportApi(ReportCase):
    def test_markdown_and_html_downloads(self):
        r = self.result("/api/analyze/email", {"raw": sample("phishing.eml")})
        md = self.client.post("/api/report", json={"result": r, "format": "md"})
        self.assertEqual(md.status_code, 200)
        self.assertEqual(md.mimetype, "text/markdown")
        self.assertIn("attachment;", md.headers["Content-Disposition"])
        self.assertIn(".md", md.headers["Content-Disposition"])
        page = self.client.post("/api/report", json={"result": r, "format": "html"})
        self.assertEqual(page.mimetype, "text/html")
        self.assertIn("@media print", page.get_data(as_text=True))
        self.assertEqual(page.headers["X-Content-Type-Options"], "nosniff")

    def test_documented_examples_work_and_docs_in_sync(self):
        import json
        from utils.api_spec import ROUTES, build_openapi, build_postman
        bodies = {path: body for _m, path, _s, _t, body, _q in ROUTES if path in ("/api/sigma", "/api/report", "/api/diagram")}
        self.assertEqual(set(bodies), {"/api/sigma", "/api/report", "/api/diagram"})
        r = self.client.post("/api/diagram", json=bodies["/api/diagram"])
        self.assertEqual(r.status_code, 200)
        self.assertIn("<svg", r.get_json()["svg"])
        self.assertIn("/api/diagram", self.client.get("/api/openapi.json").get_json()["paths"])
        r = self.client.post("/api/sigma", json=bodies["/api/sigma"])
        self.assertEqual(r.status_code, 200)
        self.assertIn("status: experimental", r.get_json()["yaml"])
        r = self.client.post("/api/report", json=bodies["/api/report"])
        self.assertEqual(r.status_code, 200)
        self.assertIn("# PhishyLens Write-up", r.get_data(as_text=True))
        for path, data in (("openapi.json", build_openapi()), ("PhishyLens.postman_collection.json", build_postman())):
            with open(os.path.join(ROOT, "docs", path), encoding="utf-8") as fh:
                self.assertEqual(json.load(fh), data, f"docs/{path} is stale; regenerate from utils/api_spec.py")
        spec = self.client.get("/api/openapi.json").get_json()
        self.assertIn("422", spec["paths"]["/api/sigma"]["post"]["responses"])
        self.assertIn("text/html", spec["paths"]["/api/report"]["post"]["responses"]["200"]["content"])

    def test_validation(self):
        self.assertEqual(self.client.post("/api/report", json={}).status_code, 400)
        self.assertEqual(self.client.post("/api/report", json={"result": "x"}).status_code, 400)
        self.assertEqual(self.client.post("/api/report", json={"result": {"verdict": "BENIGN"}, "format": "pdf"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
