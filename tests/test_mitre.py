"""
ATT&CK mapping tests: run with:  python -m unittest tests.test_mitre -v   (or: pytest)

Fails when:
  * a technique ID in utils/mitre_map.py does not exist in static/mitre.json (typo / revoked in a new ATT&CK release)
  * an analyzer can emit a finding name that utils/mitre_map.py does not cover (mapped or deliberately [])
"""
import ast, glob, json, os, re, sys, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "phishylens_test.db"))
os.environ["PHISHYLENS_SKIP_DOTENV"] = "1"

import requests
from utils import mitre_map
from utils.mitre_map import techniques_for, build_mitre, all_mapped_ids, load_mitre

TECH_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
FINDING_SOURCES = glob.glob(os.path.join(ROOT, "analyzers", "*.py")) + [os.path.join(ROOT, "utils", "threat_intel.py")]


def literal_finding_names() -> set:
    """Every constant finding name in the analyzers: {"name": "..."}, _f(sev, "...", ...), SIGS tuples, behaviour tuples."""
    names = set()
    for path in FINDING_SOURCES:
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and k.value == "name" and isinstance(v, ast.Constant) and isinstance(v.value, str):
                        names.add(v.value)
            elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_f" and len(node.args) > 1 \
                    and isinstance(node.args[1], ast.Constant):
                names.add(node.args[1].value)
            elif isinstance(node, ast.Assign) and any(getattr(t, "id", "") in ("SIGS", "PS_SIGS") for t in node.targets):
                for tup in node.value.elts:
                    names.add(tup.elts[0].value)
            elif isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "append" \
                    and getattr(node.func.value, "id", "") == "behaviour" and isinstance(node.args[0], ast.Tuple):
                first = node.args[0].elts[0]
                if isinstance(first, ast.Constant):
                    names.add(first.value)
    # dict keys in helpers like {"name": "X-API-Key"} (api spec) are not findings; only analyzers are scanned
    return names


# representative values for the f-string finding names
DYNAMIC_EXAMPLES = [
    ("SPF Not Passing", "email"), ("DMARC Authentication Failed", "email"),
    ("Risky Port Open: 3389/RDP", "network"), ("Risky Port Open: 6379/Redis", "network"),
    ("Vulnerable Service: vsftpd 2.3.4 Backdoor", "network"), ("NSE Finding: Old Samba (usermap_script)", "network"),
    ("Hash Type Identified: SHA-256", "hash"), ("[MalwareBazaar] Hash Confirmed Malicious", "hash"),
    ("[VirusTotal] Flagged as Malicious", "hash"), ("[VirusTotal] Flagged as Malicious", "url"),
    ("[urlscan.io] Flagged as Malicious", "url"), ("[VirusTotal] Low Detection Count", "url"),
    ("VirusTotal: Flagged by 1 Engine", "ip"), ("VirusTotal: Flagged by 12 Engines", "ip"),
    ("PowerShell Download Cradle (inside encoded payload)", "logs"), ("AMSI / Defender Tampering (inside encoded payload)", "logs"),
]


class TestMitreData(unittest.TestCase):
    def test_mitre_json_is_well_formed(self):
        data = load_mitre()
        meta = data["_meta"]
        self.assertTrue(meta["attack_version"])
        self.assertEqual(meta["tactics"][0]["name"], "Reconnaissance")
        self.assertEqual(meta["tactics"][-1]["name"], "Impact")
        techs = {k: v for k, v in data.items() if k != "_meta"}
        self.assertGreater(len(techs), 500)
        for tid, t in techs.items():
            self.assertRegex(tid, TECH_ID)
            for field in ("name", "tactics", "description", "detection", "mitigations", "platforms", "url"):
                self.assertIn(field, t, f"{tid} missing {field}")
            base, _, sub = tid.partition(".")
            self.assertEqual(t["url"], f"https://attack.mitre.org/techniques/{base}/{sub + '/' if sub else ''}")
            self.assertNotIn("(Citation:", t["description"])

    def test_every_mapped_id_exists(self):
        data = load_mitre()
        unknown = sorted(i for i in all_mapped_ids() if i not in data)
        self.assertEqual(unknown, [], f"technique IDs not in static/mitre.json (typo or revoked): {unknown}")
        for i in all_mapped_ids():
            self.assertRegex(i, TECH_ID)

    def test_build_rejects_unknown_ids(self):
        """A bad ID must be reported, not silently rendered as a blank card."""
        with mock.patch.dict(mitre_map.FINDING_TECHNIQUES, {"SQL Injection": ["T9999"]}):
            self.assertIn("T9999", all_mapped_ids() - set(load_mitre()))
            m = build_mitre([{"name": "SQL Injection", "severity": "HIGH"}], "logs")
            self.assertEqual(m["techniques"], [])


class TestMitreCoverage(unittest.TestCase):
    def test_all_literal_finding_names_are_covered(self):
        names = literal_finding_names()
        self.assertGreater(len(names), 60, "AST scan found too few names; the extractor is broken")
        missing = sorted(n for n in names if techniques_for(n) is None)
        self.assertEqual(missing, [], f"finding names with no ATT&CK mapping entry: {missing}")

    def test_dynamic_finding_names_are_covered(self):
        for name, mode in DYNAMIC_EXAMPLES:
            self.assertIsNotNone(techniques_for(name, mode), name)
        self.assertEqual(techniques_for("[VirusTotal] Flagged as Malicious", "hash"), ["T1204.002"])
        self.assertIn("T1566.002", techniques_for("[VirusTotal] Flagged as Malicious", "url"))
        self.assertIn("T1021.001", techniques_for("Risky Port Open: 3389/RDP"))
        self.assertEqual(techniques_for("Risky Port Open: 6379/Redis"), ["T1190"])
        self.assertEqual(techniques_for("PowerShell Download Cradle (inside encoded payload)"), ["T1105", "T1059.001", "T1027.010"])
        self.assertIsNone(techniques_for("Made Up Finding (inside encoded payload)"))


class TestMitreResults(unittest.TestCase):
    def setUp(self):
        for fn in ("get", "post", "head"):
            p = mock.patch(f"requests.{fn}", side_effect=requests.ConnectionError("offline"))
            p.start(); self.addCleanup(p.stop)
        import app as app_module
        self.client = app_module.app.test_client()

    def _check_shape(self, m):
        for k in ("techniques", "tactics_hit", "kill_chain_stage", "attack_summary"):
            self.assertIn(k, m)
        for t in m["techniques"]:
            for k in ("id", "name", "tactic", "description", "detection", "mitigations", "url", "evidence_findings"):
                self.assertIn(k, t)
            self.assertTrue(t["evidence_findings"])
            self.assertIn(t["tactic"], m["tactics_hit"])
        self.assertEqual(m["unmapped_findings"], [])

    def test_brute_force_summary(self):
        m = build_mitre([{"name": "SSH / Login Brute Force", "severity": "HIGH"},
                         {"name": "Successful Login After Failures", "severity": "CRITICAL"}], "logs")
        self.assertEqual([t["id"] for t in m["techniques"]], ["T1110", "T1078"])
        self.assertEqual(m["attack_summary"], "Credential Access via brute force, followed by Initial Access via valid accounts")
        self.assertEqual(m["techniques"][0]["evidence_findings"], ["SSH / Login Brute Force", "Successful Login After Failures"])
        self.assertEqual(m["techniques"][0]["max_severity"], "CRITICAL")
        self.assertEqual(m["kill_chain_stage"], "Credential Access")   # T1078 also spans Persistence…Stealth, CA is furthest

    def test_every_endpoint_returns_mitre(self):
        def sample(name):
            with open(os.path.join(ROOT, "samples", name), encoding="utf-8") as fh:
                return fh.read()
        cases = [
            ("/api/analyze/logs", {"logs": sample("web_attack.log")}),
            ("/api/analyze/network", {"data": sample("nmap_scan.txt")}),
            ("/api/analyze/email", {"raw": sample("phishing.eml")}),
            ("/api/analyze/url", {"url": "http://paypal-login-verify.xyz/secure/account"}),
            ("/api/analyze/hash", {"hash": "44d88612fea8a8f36de82e1278abb02f"}),
            ("/api/analyze/ip", {"ip": "8.8.8.8"}),
        ]
        for endpoint, body in cases:
            with self.subTest(endpoint=endpoint):
                r = self.client.post(endpoint, json=body)
                self.assertEqual(r.status_code, 200, r.get_data(as_text=True)[:300])
                m = r.get_json()["result"]["mitre"]
                self._check_shape(m)
                if endpoint in ("/api/analyze/logs", "/api/analyze/network", "/api/analyze/email", "/api/analyze/url"):
                    self.assertTrue(m["techniques"], f"{endpoint} sample should map to at least one technique")
                    self.assertTrue(m["attack_summary"])


if __name__ == "__main__":
    unittest.main()
