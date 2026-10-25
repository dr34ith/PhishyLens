"""
Sigma generator tests: every generated rule is parsed with PyYAML and checked for the required fields.
Run:  python -m unittest tests.test_sigma -v
"""
import os, sys, tempfile, unittest, uuid
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "phishylens_test.db"))
os.environ["PHISHYLENS_SKIP_DOTENV"] = "1"

import requests
import yaml
from utils.sigma_gen import generate_rule, generate_rules, supported_finding_names, UnsupportedFinding

LEVELS = {"informational", "low", "medium", "high", "critical"}
REQUIRED = ("title", "id", "status", "description", "references", "logsource", "detection", "falsepositives", "level", "tags")


def finding(name, severity="HIGH", evidence="1 hit(s); first at line 3: sample", fp="Low–Medium: pentests look identical."):
    return {"name": name, "severity": severity, "evidence": evidence, "false_positive_possibility": fp, "confidence": 80}


class TestSigmaRules(unittest.TestCase):
    def assertValidRule(self, text, name):
        docs = list(yaml.safe_load_all(text))
        self.assertGreaterEqual(len(docs), 1)
        rule = docs[0]
        for k in REQUIRED:
            self.assertIn(k, rule, f"{name}: missing {k}")
        self.assertEqual(uuid.UUID(rule["id"]).version, 4)
        self.assertEqual(rule["status"], "experimental")
        self.assertIn(rule["level"], LEVELS)
        self.assertTrue(rule["logsource"])
        det = rule["detection"]
        self.assertIn("condition", det)
        self.assertTrue([k for k in det if k != "condition"], f"{name}: no selection")
        self.assertTrue(any(r.startswith("https://attack.mitre.org/techniques/") for r in rule["references"]), name)
        self.assertTrue(any(t.startswith("attack.t") for t in rule["tags"]), name)
        self.assertIsInstance(rule["falsepositives"], list)
        # every selection the condition names must exist
        for word in det["condition"].replace("1 of ", "").replace("all of ", "").split():
            if word not in ("and", "or", "not") and not word.endswith("*"):
                self.assertIn(word, det, f"{name}: condition references missing '{word}'")
        for corr in docs[1:]:
            self.assertEqual(uuid.UUID(corr["id"]).version, 4)
            self.assertIn(rule["name"], corr["correlation"]["rules"])
            self.assertIn(corr["correlation"]["type"], ("event_count", "value_count"))
            self.assertIn("timespan", corr["correlation"])
        return docs

    def test_every_supported_finding_produces_valid_yaml(self):
        names = supported_finding_names()
        self.assertGreaterEqual(len(names), 18)
        for name in names:
            with self.subTest(name=name):
                out = generate_rule(finding(name), "logs")
                self.assertValidRule(out["yaml"], name)

    def test_required_examples_supported(self):
        for name in ("SSH / Login Brute Force", "PowerShell Encoded Command", "PowerShell Execution Policy Bypass",
                     "SQL Injection", "TCP Port Scan Detected", "Cleartext Credentials on the Wire"):
            self.assertIn(name, supported_finding_names())

    def test_field_mapping(self):
        r = list(yaml.safe_load_all(generate_rule(finding("SSH / Login Brute Force", "CRITICAL", fp="Low–Medium."), "logs")["yaml"]))[0]
        self.assertEqual(r["level"], "critical")
        self.assertEqual(r["falsepositives"], ["Low–Medium."])
        self.assertIn("attack.t1110", r["tags"])
        self.assertIn("attack.credential-access", r["tags"])
        self.assertIn("https://attack.mitre.org/techniques/T1110/", r["references"])
        self.assertEqual(r["logsource"], {"product": "linux", "service": "sshd"})
        self.assertEqual(generate_rule(finding("SQL Injection", "LOW"))["rules"][0]["level"], "low")
        self.assertEqual(generate_rule({**finding("SQL Injection"), "false_positive_possibility": "N/A"})["rules"][0]["falsepositives"], ["Unknown"])

    def test_powershell_regex_matches_analyzer(self):
        from analyzers.log_analyzer import PS_SIGS
        r = generate_rule(finding("PowerShell Encoded Command"))["rules"][0]
        self.assertEqual(r["detection"]["selection"]["CommandLine|re"], "(?i)" + PS_SIGS[0][2].pattern)
        enc = generate_rule(finding("PowerShell Download Cradle (inside encoded payload)"))["rules"][0]
        self.assertEqual(enc["logsource"]["category"], "ps_script")

    def test_count_based_rules_have_correlation(self):
        for name, ctype in (("TCP Port Scan Detected", "value_count"), ("Directory / Vulnerability Scanning", "event_count")):
            docs = list(yaml.safe_load_all(generate_rule(finding(name), "network")["yaml"]))
            self.assertEqual(len(docs), 2)
            self.assertEqual(docs[1]["correlation"]["type"], ctype)

    def test_cleartext_creds_protocol_from_evidence(self):
        ftp = generate_rule(finding("Cleartext Credentials on the Wire", evidence="FTP 10.0.0.2→10.0.0.5: USER admin"))["rules"][0]
        self.assertEqual(ftp["detection"]["selection"]["dst_port"], [21])
        http = generate_rule(finding("Cleartext Credentials on the Wire", evidence="HTTP 10.0.0.2→10.0.0.5: GET /?password=x"))["rules"][0]
        self.assertEqual(http["logsource"]["category"], "webserver")

    def test_user_text_cannot_break_yaml(self):
        nasty = finding("SQL Injection", evidence="x' : - {evil: [1]} # not a comment\n---\nlevel: low", fp="a: b\n- c")
        docs = list(yaml.safe_load_all(generate_rule(nasty)["yaml"]))
        self.assertEqual(len(docs), 1)
        self.assertEqual(docs[0]["level"], "high")
        self.assertEqual(docs[0]["falsepositives"], ["a: b\n- c"])

    def test_unsupported_raises(self):
        for bad in ({"name": "Brand Impersonation"}, {"name": ""}, {}, "x"):
            with self.assertRaises(UnsupportedFinding):
                generate_rule(bad)

    def test_generate_rules_skips_and_dedupes(self):
        out = generate_rules([finding("SQL Injection"), finding("SQL Injection"), finding("Brand Impersonation"), "junk"], "logs")
        self.assertEqual([r["finding"] for r in out["rules"]], ["SQL Injection"])
        self.assertEqual(len(out["skipped"]), 2)
        self.assertTrue(list(yaml.safe_load_all(out["yaml"])))


class TestSigmaApi(unittest.TestCase):
    def setUp(self):
        for fn in ("get", "post", "head"):
            p = mock.patch(f"requests.{fn}", side_effect=requests.ConnectionError("offline"))
            p.start(); self.addCleanup(p.stop)
        import app as app_module
        self.client = app_module.app.test_client()

    def test_single_finding(self):
        r = self.client.post("/api/sigma", json={"finding": finding("SQL Injection"), "mode": "logs"})
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(len(d["rules"]), 1)
        self.assertEqual(yaml.safe_load(d["yaml"])["status"], "experimental")

    def test_unsupported_is_422_with_message(self):
        r = self.client.post("/api/sigma", json={"finding": {"name": "Brand Impersonation"}})
        self.assertEqual(r.status_code, 422)
        d = r.get_json()
        self.assertIn("Brand Impersonation", d["error"])
        self.assertIn("SQL Injection", d["supported"])
        r = self.client.post("/api/sigma", json={"findings": [{"name": "Brand Impersonation"}]})
        self.assertEqual(r.status_code, 422)

    def test_bad_request(self):
        self.assertEqual(self.client.post("/api/sigma", json={}).status_code, 400)
        self.assertEqual(self.client.post("/api/sigma", json={"findings": []}).status_code, 400)

    def test_all_findings_from_real_analysis(self):
        with open(os.path.join(ROOT, "samples", "web_attack.log"), encoding="utf-8") as fh:
            res = self.client.post("/api/analyze/logs", json={"logs": fh.read()}).get_json()["result"]
        r = self.client.post("/api/sigma", json={"findings": res["findings"], "mode": "logs"})
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertGreaterEqual(len(d["rules"]), 3)
        for rule in d["rules"]:
            self.assertTrue(list(yaml.safe_load_all(rule["yaml"])))


if __name__ == "__main__":
    unittest.main()
