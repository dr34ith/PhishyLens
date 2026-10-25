"""Defang tests: run:  python -m unittest tests.test_defang -v"""
import os, sys, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "phishylens_test.db"))
os.environ["PHISHYLENS_SKIP_DOTENV"] = "1"

import requests
from utils.defang import defang_text, defang_obj


class TestDefang(unittest.TestCase):
    def test_urls_domains_ips_emails(self):
        self.assertEqual(defang_text("http://evil.com/login.php"), "hxxp://evil[.]com/login.php")
        self.assertEqual(defang_text("https://a.b.paypa1.xyz/x?y=1"), "hxxps://a[.]b[.]paypa1[.]xyz/x?y=1")
        self.assertEqual(defang_text("ftp://files.example.org/"), "fxp://files[.]example[.]org/")
        self.assertEqual(defang_text("visit evil.com now"), "visit evil[.]com now")
        self.assertEqual(defang_text("from 185.220.101.4 and [10.0.0.5]"), "from 185[.]220[.]101[.]4 and [10[.]0[.]0[.]5]")
        self.assertEqual(defang_text("user@example.com"), "user[@]example[.]com")
        self.assertEqual(defang_text("www.google.co.uk"), "www[.]google[.]co[.]uk")
        self.assertEqual(defang_text("sent from @paypa1-secure.xyz"), "sent from @paypa1-secure[.]xyz")

    def test_leaves_non_iocs_alone(self):
        for s in ("README.md", "exploit.py", "exploit.pl", "cmd.exe", "index.html", "T1059.001", "v19.2", "2.3.4", "e.g. i.e.",
                  "user.id", "999.1.1.1", "10.0.0.256", "1.2.3.4.5"):
            self.assertEqual(defang_text(s), s, s)

    def test_idempotent_and_safe_inputs(self):
        once = defang_text("http://evil.com 1.2.3.4 a@b.com evil.com")
        self.assertEqual(defang_text(once), once)
        self.assertEqual(defang_text(None), "")
        self.assertEqual(defang_text(42), "42")

    def test_defang_obj_is_a_copy(self):
        original = {"input": "http://evil.com", "iocs": {"ips": ["1.2.3.4"]}, "score": 90, "nested": [{"e": "a@evil.com"}]}
        out = defang_obj(original)
        self.assertEqual(out["input"], "hxxp://evil[.]com")
        self.assertEqual(out["iocs"]["ips"], ["1[.]2[.]3[.]4"])
        self.assertEqual(out["score"], 90)
        self.assertEqual(out["nested"][0]["e"], "a[@]evil[.]com")
        self.assertEqual(original["input"], "http://evil.com")          # untouched

    def test_api_values_stay_live(self):
        """Defanging is display/export-only: analysis responses must keep the real indicators."""
        for fn in ("get", "post", "head"):
            p = mock.patch(f"requests.{fn}", side_effect=requests.ConnectionError("offline"))
            p.start(); self.addCleanup(p.stop)
        import app as app_module
        r = app_module.app.test_client().post("/api/analyze/url", json={"url": "http://paypal-login-verify.xyz/secure"})
        res = r.get_json()["result"]
        self.assertIn("http://paypal-login-verify.xyz", res["input"])
        self.assertNotIn("[.]", str(res.get("iocs", "")))


if __name__ == "__main__":
    unittest.main()
