"""
Tests for result insights (classification, kill chain, technique confidence, malware family).
Run:  python -m unittest tests.test_insights -v     ; all network access is mocked.
"""
import os, sys, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "phishylens_test.db"))
os.environ["PHISHYLENS_SKIP_DOTENV"] = "1"

import requests
from utils.mitre_map import build_mitre, technique_confidence
from utils.insights import build_classification, build_kill_chain, build_malware_family, KILL_CHAIN_STAGES
from utils.threat_intel import malware_family_from_sources

BRUTE = [{"name": "SSH / Login Brute Force", "severity": "HIGH", "confidence": 80},
         {"name": "Successful Login After Failures", "severity": "CRITICAL", "confidence": 80}]


def sample(name):
    with open(os.path.join(ROOT, "samples", name), encoding="utf-8") as fh:
        return fh.read()


def result_for(findings, mode="logs", verdict="MALICIOUS"):
    return {"findings": findings, "verdict": verdict, "mode": mode, "confidence": 70, "mitre": build_mitre(findings, mode)}


class OfflineApi(unittest.TestCase):
    def setUp(self):
        for fn in ("get", "post", "head"):
            p = mock.patch(f"requests.{fn}", side_effect=requests.ConnectionError("offline"))
            p.start(); self.addCleanup(p.stop)
        import app as app_module
        self.client = app_module.app.test_client()

    def analyze(self, endpoint, body):
        r = self.client.post(endpoint, json=body)
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True)[:300])
        return r.get_json()["result"]


class TestClassification(unittest.TestCase):
    def test_brute_force(self):
        c = build_classification(result_for(BRUTE))
        self.assertEqual(c["primary"], "Credential Access - Brute Force")
        self.assertIn("Initial Access - Valid Accounts", c["secondary"])
        self.assertLessEqual(c["confidence"], 95)
        self.assertIn("SSH / Login Brute Force", c["rationale"])
        self.assertNotIn("\n", c["rationale"])

    def test_phishing_email_groups_sub_techniques(self):
        f = [{"name": "Link Text / Destination Mismatch", "severity": "HIGH", "confidence": 85},
             {"name": "Urgency / Pressure Manipulation", "severity": "MEDIUM", "confidence": 60},
             {"name": "SPF Authentication Failed", "severity": "MEDIUM", "confidence": 70}]
        c = build_classification(result_for(f, "email"))
        self.assertEqual(c["primary"], "Initial Access - Phishing")      # T1566 + T1566.002 grouped by family

    def test_no_mapping(self):
        c = build_classification(result_for([{"name": "No Indicators Detected", "severity": "LOW"}], verdict="BENIGN"))
        self.assertEqual(c["primary"], "No Attack Pattern Identified")
        c = build_classification(result_for([{"name": "AbuseIPDB: Abuse History Confirmed", "severity": "HIGH", "confidence": 80}],
                                            "ip", verdict="SUSPICIOUS"))
        self.assertEqual(c["primary"], "Unmapped Suspicious Activity")
        self.assertEqual(c["confidence"], 80)


class TestKillChain(unittest.TestCase):
    def test_six_stages_in_order(self):
        k = build_kill_chain(result_for(BRUTE))
        self.assertEqual([s["name"] for s in k["stages"]], KILL_CHAIN_STAGES)
        self.assertEqual(len(k["stages"]), 6)
        for s in k["stages"]:
            self.assertEqual(set(s) >= {"name", "hit", "evidence"}, True)

    def test_brute_force_reaches_exploitation(self):
        k = build_kill_chain(result_for(BRUTE))
        hit = {s["name"]: s for s in k["stages"] if s["hit"]}
        self.assertEqual(set(hit), {"Delivery", "Exploitation"})   # T1078 → Initial Access, T1110 → Credential Access
        self.assertIn("SSH / Login Brute Force", hit["Exploitation"]["evidence"])
        self.assertEqual(k["furthest_stage"], "Exploitation")

    def test_email_stealth_counts_as_delivery(self):
        f = [{"name": "SPF Authentication Failed", "severity": "MEDIUM", "confidence": 70}]   # T1684.002 (Stealth)
        self.assertEqual(build_kill_chain(result_for(f, "email"))["furthest_stage"], "Delivery")
        self.assertEqual(build_kill_chain(result_for(f, "logs"))["furthest_stage"], "Exploitation")

    def test_c2_and_empty(self):
        k = build_kill_chain(result_for([{"name": "Possible DNS Tunnelling", "severity": "HIGH", "confidence": 70}], "network"))
        self.assertEqual(k["furthest_stage"], "Command & Control")
        k = build_kill_chain(result_for([], verdict="BENIGN"))
        self.assertEqual(k["furthest_stage"], "")
        self.assertFalse(any(s["hit"] for s in k["stages"]))


class TestTechniqueConfidence(unittest.TestCase):
    def test_single_finding_uses_its_confidence(self):
        c, why = technique_confidence([{"name": "SQL Injection", "severity": "CRITICAL", "confidence": 85}])
        self.assertEqual(c, 85)
        self.assertIn("SQL Injection (85%)", why)
        self.assertIn("no boost", why)

    def test_independent_findings_boost_and_cap(self):
        c, why = technique_confidence([{"name": "A", "confidence": 80}, {"name": "B", "confidence": 70}])
        self.assertEqual(c, 85)
        self.assertIn("+5 for 1 more independent finding (B)", why)
        c, _ = technique_confidence([{"name": n, "confidence": 70} for n in "ABCDEF"])
        self.assertEqual(c, 85)                                   # boost capped at +15
        c, why = technique_confidence([{"name": "A", "confidence": 93}, {"name": "B", "confidence": 90}])
        self.assertEqual(c, 95)
        self.assertIn("Capped at 95", why)

    def test_repeats_of_same_detector_do_not_boost(self):
        c, _ = technique_confidence([{"name": "A", "confidence": 60}, {"name": "A", "confidence": 75}])
        self.assertEqual(c, 75)

    def test_missing_confidence_uses_severity_default(self):
        c, why = technique_confidence([{"name": "X", "severity": "HIGH"}])
        self.assertEqual(c, 70)
        self.assertIn("severity default", why)
        self.assertEqual(technique_confidence([])[0], 0)

    def test_attached_to_every_technique_and_used_by_classification(self):
        r = result_for(BRUTE)
        t1110 = next(t for t in r["mitre"]["techniques"] if t["id"] == "T1110")
        self.assertEqual(t1110["confidence"], 85)              # 80 + 5 (two independent findings)
        self.assertTrue(t1110["confidence_explanation"])
        self.assertEqual(build_classification(r)["confidence"], 85)


MB_HIT = {"source": "MalwareBazaar", "available": True, "flagged": True, "malware_name": "AgentTesla",
          "tags": ["exe", "AgentTesla"], "first_seen": "2024-03-01 10:00:00"}
TF_HIT = {"source": "ThreatFox", "available": True, "flagged": True, "malware": "Cobalt Strike", "tags": ["c2"],
          "first_seen": "2024-05-02 08:00:00 UTC"}


class TestMalwareFamily(unittest.TestCase):
    def test_from_sources_prefers_malwarebazaar_and_never_guesses(self):
        self.assertEqual(malware_family_from_sources({"malwarebazaar": MB_HIT, "threatfox": TF_HIT})["name"], "AgentTesla")
        self.assertEqual(malware_family_from_sources({"threatfox": TF_HIT})["source"], "ThreatFox")
        self.assertIsNone(malware_family_from_sources({}))
        self.assertIsNone(malware_family_from_sources({"malwarebazaar": {**MB_HIT, "malware_name": "Unknown"}}))
        self.assertIsNone(malware_family_from_sources({"threatfox": {**TF_HIT, "flagged": False}}))
        self.assertIsNone(malware_family_from_sources({"threatfox": {**TF_HIT, "available": False}}))

    def test_build_from_direct_lookup_and_enrichment(self):
        m = build_malware_family({"input": "abc123", "intel_sources": {"malwarebazaar": MB_HIT}})
        self.assertEqual((m["name"], m["source"], m["first_seen"], m["indicator"]), ("AgentTesla", "MalwareBazaar", "2024-03-01 10:00:00", "abc123"))
        self.assertEqual(m["tags"], ["exe", "AgentTesla"])
        fam = malware_family_from_sources({"threatfox": TF_HIT})
        m = build_malware_family({"enrichment": {"ips": [{"indicator": "185.220.101.4", "malware_family": fam}], "hashes": []}})
        self.assertEqual((m["name"], m["indicator"]), ("Cobalt Strike", "185.220.101.4"))
        self.assertIsNone(build_malware_family({"intel_sources": {}, "enrichment": {"ips": [{"indicator": "1.2.3.4", "malware_family": None}]}}))


class TestInsightsApi(OfflineApi):
    def test_phishing_email_sample(self):
        res = self.analyze("/api/analyze/email", {"raw": sample("phishing.eml")})
        self.assertEqual(res["classification"]["primary"], "Initial Access - Phishing")
        self.assertEqual(res["kill_chain"]["furthest_stage"], "Delivery")      # lure delivered; nothing shows it was opened

    def test_every_endpoint_has_classification(self):
        cases = [("/api/analyze/logs", {"logs": sample("web_attack.log")}),
                 ("/api/analyze/network", {"data": sample("nmap_scan.txt")}),
                 ("/api/analyze/email", {"raw": sample("phishing.eml")}),
                 ("/api/analyze/url", {"url": "http://paypal-login-verify.xyz/secure"}),
                 ("/api/analyze/hash", {"hash": "44d88612fea8a8f36de82e1278abb02f"}),
                 ("/api/analyze/ip", {"ip": "8.8.8.8"})]
        for endpoint, body in cases:
            with self.subTest(endpoint=endpoint):
                res = self.analyze(endpoint, body)
                c = res["classification"]
                for k in ("primary", "secondary", "confidence", "rationale"):
                    self.assertIn(k, c)
                self.assertTrue(0 <= c["confidence"] <= 100)
                k = res["kill_chain"]
                self.assertEqual(len(k["stages"]), 6)
                self.assertTrue(k["furthest_stage"] == "" or k["furthest_stage"] in KILL_CHAIN_STAGES)
                self.assertIn("malware_family", res)
                self.assertIsNone(res["malware_family"])          # offline: no source answered → nothing shown

    def test_hash_family_from_mocked_abusech(self):
        def fake_post(url, *a, **kw):
            resp = mock.Mock(ok=True, status_code=200)
            if "mb-api" in url:
                resp.json.return_value = {"query_status": "ok", "data": [{"signature": "AgentTesla", "file_type": "exe",
                                          "tags": ["AgentTesla", "exe"], "first_seen": "2024-03-01 10:00:00"}]}
            else:
                resp.json.return_value = {"query_status": "no_result"}
            return resp
        with mock.patch.dict(os.environ, {"ABUSECH_API_KEY": "test"}), mock.patch("requests.post", side_effect=fake_post):
            res = self.analyze("/api/analyze/hash", {"hash": "a" * 64})
        m = res["malware_family"]
        self.assertEqual((m["name"], m["source"], m["first_seen"]), ("AgentTesla", "MalwareBazaar", "2024-03-01 10:00:00"))
        self.assertEqual(m["tags"], ["AgentTesla", "exe"])


if __name__ == "__main__":
    unittest.main()
