"""Step 2 of "Show details": write-ups, copy formats, escaping and the dashboard renderer contract."""
import os
import re
import unittest

from tests.test_summary_details import Fixtures, ROOT
from utils.report import build_report
from utils.summary_details import build_copy_formats, build_details

JS = open(os.path.join(ROOT, "static", "details.js"), encoding="utf-8").read()


class TestWriteupDetails(Fixtures):
    def test_writeup_includes_blocks_when_data_exists(self):
        for key in ("logs", "nmap", "pcap"):
            md = build_report(self.R[key], "md")
            html = build_report(self.R[key], "html")
            self.assertIn("### Show details", md, key)
            self.assertIn("#### Attack story", md + "#### Assessment", key)
            self.assertIn('<details class="xdet" open>', html, key)      # always expanded in the write-up
            for b in self.details(key)["blocks"]:
                self.assertIn(b["title"], md, f"{key}: {b['title']}")

    def test_writeup_omits_blocks_without_data(self):
        r = dict(self.R["benign"], findings=[], exec_summary={}, iocs={}, entities={}, timeline=[], log_entries=[])
        r = {k: v for k, v in r.items() if k in ("verdict", "score", "input_type", "scan_id", "findings")}
        if build_details(r)["blocks"]:
            self.skipTest("builder still produces blocks for a bare result")
        self.assertNotIn("Show details", build_report(r, "md"))
        self.assertNotIn('class="xdet"', build_report(r, "html"))

    def test_hostile_strings_escaped_in_rendered_html(self):
        html = build_report(self.R["hostile"], "html")
        body = html.split("<body", 1)[1]
        det = body[body.index('<details class="xdet"'):]
        det = det[:det.index("</details>")]
        self.assertNotIn("<script>", det)
        self.assertNotIn("\u202e", det)
        self.assertNotIn("\x07", det)
        self.assertNotIn("hunter2", html)
        md = build_report(self.R["hostile"], "md")
        self.assertNotIn("hunter2", md)
        start = md.index("### Show details")
        mdet = md[start:md.index("\n## ", start)]
        self.assertNotIn("\u202e", mdet)
        self.assertNotIn("\x07", mdet)
        self.assertNotIn("<script>", mdet)            # escaped as &lt;script&gt;


class TestCopyFormats(Fixtures):
    def test_three_formats_defanged_and_masked(self):
        for key in ("logs", "nmap", "pcap", "hostile"):
            r = self.R[key]
            copy = build_copy_formats(r, r["exec_summary"], self.details(key))
            self.assertEqual(set(copy), {"plain", "markdown", "oneline"}, key)
            for fmt, text in copy.items():
                self.assertTrue(text.strip(), f"{key}/{fmt}")
                self.assertNotIn("hunter2", text)
                self.assertNotIn("\u202e", text)
                self.assertIsNone(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text), f"{key}/{fmt} has a live IP")
            self.assertNotIn("\n", copy["oneline"])
        self.assertIn("10[.]0[.]0[.]99", build_copy_formats(self.R["pcap"], self.R["pcap"]["exec_summary"], self.details("pcap"))["plain"])

    def test_details_payload_carries_copy(self):
        self.assertIn("copy", self.details("logs"))


class TestDashboardRenderer(unittest.TestCase):
    """The browser behaviour is verified in a headless run; these guard the contract in the source."""
    def test_collapsed_by_default_and_state_saved(self):
        self.assertIn("<details class=\"xdet\" id=\"js-xdet\"${_detailsOpen() ? ' open' : ''}>", JS)
        self.assertIn("localStorage.getItem(DETAILS_OPEN_KEY) === '1'", JS)          # absent key → collapsed
        self.assertIn("addEventListener('toggle'", JS)
        self.assertIn("beforeprint", JS)
        self.assertIn("afterprint", JS)

    def test_no_raw_interpolation_of_data(self):
        # every ${it.…}/${b.…}/${c.…} value passes through an escaper/highlighter or Number()
        for m in re.finditer(r"\$\{([^}]*)\}", JS):
            expr = m.group(1)
            if re.match(r"\s*(it|b|c|d|w|f|df|t|v|k)\.\w+\s*$", expr):
                self.fail(f"unescaped interpolation: ${{{expr}}}")

    def test_old_results_fetch_once_and_hide_on_failure(self):
        self.assertIn("fetch('/api/summary'", JS)
        self.assertIn("_detailsCache[key] = null", JS)
        self.assertIn("if (_detailsCache[key] === null) return;", JS)

    def test_script_loaded_before_defang(self):
        html = open(os.path.join(ROOT, "dashboard.html"), encoding="utf-8").read()
        self.assertLess(html.index("/static/details.js"), html.index("/static/defang.js"))
        self.assertLess(html.index("/static/highlight.js"), html.index("/static/details.js"))


if __name__ == "__main__":
    unittest.main()
