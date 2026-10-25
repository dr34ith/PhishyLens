"""
Executive Summary "Show details" (exec_summary["details"]) — Step 1 backend tests.
Run:  python -m unittest tests.test_summary_details -v      (network access is mocked)
"""
import copy, json, os, re, sys, tempfile, unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "phishylens_test.db"))
os.environ["PHISHYLENS_SKIP_DOTENV"] = "1"

import requests
from utils.summary import build_summary_details
from utils.summary_details import (build_details, QUESTIONS, NOT_DETERMINED, STATUSES, MAX_VISIBLE, MAX_STORY, WORD_BUDGET,
                                   REPUTATION_STATES, GENERAL_GUIDANCE, clean)

FIX = os.path.join(ROOT, "tests", "fixtures")
GENERATED = ("text", "basis", "why", "question")          # generated prose (evidence / code / header values are quoted data)
FORBIDDEN = re.compile(r"\bconfirmed\b|\bcompromised\b|\bbreach(?:ed)?\b", re.I)


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def analyze(client, endpoint, body):
    r = client.post(endpoint, json=body)
    assert r.status_code == 200, r.get_data(as_text=True)[:300]
    return r.get_json()["result"]


def iter_items(details):
    for b in details["blocks"]:
        for it in b["items"]:
            yield b, it


def ref_exists(result, ref) -> bool:
    if "finding" in ref:
        return isinstance(ref["finding"], int) and 0 <= ref["finding"] < len(result.get("findings") or [])
    if "line" in ref:
        ls = result.get("log_stats") or {}
        lines = {x.get("line") for k in ("sample_hits", "auth_events", "powershell_decoded", "login_after_failures") for x in ls.get(k) or []}
        return ref["line"] in lines
    if "ts" in ref:
        return ref["ts"] in json.dumps(result, ensure_ascii=False) or json.dumps(ref["ts"])[1:-1] in json.dumps(result)
    if "field" in ref:
        cur = result
        for part in re.findall(r"[^.\[\]]+|\[\d+\]", ref["field"]):
            if part.startswith("["):
                i = int(part[1:-1])
                if not isinstance(cur, list) or i >= len(cur):
                    return False
                cur = cur[i]
            else:
                if not isinstance(cur, dict) or part not in cur:
                    return False
                cur = cur[part]
        return True
    return False


def sentences(text):
    return [s for s in re.split(r"(?<=[.!?])\s+", text or "") if s.strip()]


class Fixtures(unittest.TestCase):
    R = {}

    @classmethod
    def setUpClass(cls):
        ps = [mock.patch(f"requests.{fn}", side_effect=requests.ConnectionError("offline")) for fn in ("get", "post", "head")]
        for p in ps:
            p.start()
        try:
            import app as app_module
            cls.client = app_module.app.test_client()
            c = cls.client
            cls.R["logs"] = analyze(c, "/api/analyze/logs", {"logs": read(os.path.join(FIX, "phishylens_test.log"))})
            cls.R["nmap"] = analyze(c, "/api/analyze/network", {"data": read(os.path.join(FIX, "phishylens_nmap_test.txt"))})
            cls.R["pcap"] = analyze(c, "/api/analyze/network", {"data": read(os.path.join(FIX, "phishylens_wireshark_test.csv"))})
            cls.R["email"] = analyze(c, "/api/analyze/email", {"raw": read(os.path.join(ROOT, "samples", "phishing.eml"))})
            cls.R["benign"] = analyze(c, "/api/analyze/logs", {"logs": "\n".join(
                f'192.168.1.{i} - - [03/Oct/2026:09:00:0{i} +0800] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"' for i in range(1, 6))})
            cls.R["single"] = analyze(c, "/api/analyze/network", {"data": "No.,Time,Source,Destination,Protocol,Length,Info\n" + "\n".join(
                f'{i},0.0{i},10.0.0.99,10.10.10.5,TCP,60,"44000 → {1000 + i} [SYN] Seq=0 Win=1024 Len=0"' for i in range(1, 13))})
            hostile_ua = "sqlmap/1.0 " + "A" * 5000
            cls.R["hostile"] = analyze(c, "/api/analyze/logs", {"logs": "\n".join([
                f'203.0.113.9 - - [03/Oct/2026:09:01:10 +0800] "GET /x?q=<script>alert(1)</script>‮exe.pdf HTTP/1.1" 200 1 "-" "{hostile_ua}"',
                f'203.0.113.9 - - [03/Oct/2026:09:01:11 +0800] "GET /login?user=a&password=hunter2&id=1%27%20UNION%20SELECT%20a HTTP/1.1" 200 1 "-" "x"',
            ] + [f"Oct  3 09:05:0{i} web sshd[9]: Failed password for <script>‮root\x07 from 198.51.100.9 port 40{i} ssh2" for i in range(1, 7)])})
        finally:
            for p in ps:
                p.stop()
            import app as app_module
            app_module._RATE.clear()         # test hygiene: don't spend the per-minute limiter budget of later test modules

    def details(self, key):
        return self.R[key]["exec_summary"]["details"]


class TestContent(Fixtures):
    def test_logs_fixture(self):
        d = self.details("logs")
        B = {b["key"]: b for b in d["blocks"]}
        self.assertEqual([a["ip"] for a in B["actors_and_targets"]["items"]], ["203.0.113.50", "198.51.100.7"])
        st = {i["question"]: i["status"] for i in B["assessment"]["items"]}
        self.assertEqual(st["Did a login succeed after failed attempts?"], "Observed")
        self.assertEqual(st["Was a payload downloaded or run?"], "Observed")
        self.assertEqual(st["Did a web attack succeed?"], "Not evidenced")
        techs = {t for i in B["attack_story"]["items"] for t in i["technique_ids"]}
        self.assertTrue({"T1190", "T1110", "T1078", "T1059.001", "T1105"} <= techs)
        self.assertEqual(B["attack_story"]["ordered_by"], "time")
        self.assertIn("when", B["attack_story"]["items"][0])
        self.assertNotIn("duration", B["overview"]["window"])               # mixed CLF / syslog / ISO timestamps
        self.assertTrue(any(i.get("kind") == "code" and "DownloadString" in i["code"] for i in B["mode_extras"]["items"]))

    def test_nmap_fixture(self):
        d = self.details("nmap")
        B = {b["key"]: b for b in d["blocks"]}
        self.assertEqual(B["assessment"]["items"][0]["status"], "Observed")
        self.assertIn("10.10.10.5:21/ftp", B["actors_and_targets"]["targets"]["services"])
        self.assertIn("T1190", {t for i in B["attack_story"]["items"] for t in i["technique_ids"]})
        self.assertEqual(B["attack_story"]["ordered_by"], "kill-chain stage")
        self.assertTrue(all("when" not in i for i in B["attack_story"]["items"]))
        self.assertIn("Vulnerability rests on version banners only.", [i["text"] for i in B["confidence_and_limits"]["items"]])

    def test_wireshark_fixture(self):
        d = self.details("pcap")
        B = {b["key"]: b for b in d["blocks"]}
        actors = {a["ip"]: a for a in B["actors_and_targets"]["items"]}
        self.assertEqual(actors["10.0.0.99"]["role"], "scan source")
        self.assertEqual(actors["10.0.0.99"]["reputation_state"], "Not checked (private/reserved range)")
        self.assertEqual({i["status"] for i in B["assessment"]["items"]}, {"Possible"})
        self.assertEqual([t for i in B["attack_story"]["items"] for t in i["technique_ids"]], ["T1046", "T1040", "T1571"])
        self.assertIn("admin", B["actors_and_targets"]["targets"]["accounts"])

    def test_reputation_vocabulary_and_never_clean(self):
        for key in self.R:
            for b, it in iter_items(self.details(key)):
                if it.get("kind") == "actor":
                    rs = it["reputation_state"]
                    self.assertTrue(rs in REPUTATION_STATES or rs.startswith("Flagged by "), rs)
                    self.assertNotIn("clean", rs.lower())


class TestRules(Fixtures):
    def test_every_ref_exists(self):
        for key, r in self.R.items():
            d = self.details(key)
            for b, it in iter_items(d):
                with self.subTest(fixture=key, block=b["key"], text=it["text"][:40]):
                    self.assertTrue(ref_exists(r, it["ref"]), it["ref"])
            for b in d["blocks"]:
                if b.get("targets_ref"):
                    self.assertTrue(ref_exists(r, b["targets_ref"]), b["targets_ref"])

    def test_single_placement_and_no_repeat_of_short_summary(self):
        for key, r in self.R.items():
            d, s = self.details(key), r["exec_summary"]
            owner = {}
            for b, it in iter_items(d):
                for f in it["facts"]:
                    k = json.dumps(f)
                    self.assertNotIn(k, owner, f"{key}: fact {f} in {owner.get(k)} and {b['key']}")
                    owner[k] = b["key"]
            norm = lambda x: re.sub(r"[^a-z0-9]+", " ", x.lower()).strip()
            short = {norm(x) for t in [s["headline"], *s["what_happened"], s["why_it_matters"]] for x in sentences(t)}
            dn = {norm(a["action"]) for a in s["do_now"]}
            for b, it in iter_items(d):
                for field in GENERATED:
                    for sent in sentences(it.get(field, "")):
                        self.assertNotIn(norm(sent), short, f"{key}: repeats summary: {sent}")
                        words = set(norm(sent).split())
                        for ss in short:
                            sw = set(ss.split())
                            if words and sw:
                                self.assertLess(len(words & sw) / len(words | sw), 0.8, f"{key}: near-repeat of summary: {sent}")
                if it.get("kind") == "respond":
                    self.assertNotIn(norm(it["text"]), dn)

    def test_sentences_short_and_vocabulary(self):
        for key in self.R:
            d = self.details(key)
            for b, it in iter_items(d):
                for field in GENERATED:
                    for sent in sentences(it.get(field, "")):
                        self.assertLess(len(sent.split()), 20, f"{key}/{b['key']}: {sent}")
                for df in it.get("define", []):
                    self.assertLess(len(df["definition"].split()), 13)
                if "status" in it:
                    self.assertIn(it["status"], STATUSES)
                if it.get("kind") == "investigate":
                    self.assertEqual(it["label"], GENERAL_GUIDANCE)
            text = json.dumps(d, ensure_ascii=False)
            self.assertIsNone(FORBIDDEN.search(json.dumps([{k: it.get(k) for k in GENERATED} for _, it in iter_items(d)])), key)

    def test_budgets(self):
        for key in self.R:
            d = self.details(key)
            self.assertLessEqual(d["visible_words"], WORD_BUDGET, key)
            for b in d["blocks"]:
                self.assertLessEqual(b["visible"], MAX_VISIBLE)
                self.assertEqual(b["more"], len(b["items"]) - b["visible"])
                for k, v in (b.get("targets_visible") or {}).items():
                    self.assertLessEqual(v, MAX_VISIBLE)
                if b["key"] == "attack_story":
                    self.assertLessEqual(len(b["items"]), MAX_STORY)

    def test_completeness_contract(self):
        for key, r in self.R.items():
            cov = self.details(key)["coverage"]
            self.assertEqual([c["question"] for c in cov], QUESTIONS[r["mode"]], key)
            blocks = {b["key"] for b in self.details(key)["blocks"]} | {"short summary"}
            for c in cov:
                self.assertTrue(c["answered_by"] == NOT_DETERMINED or c["answered_by"] in blocks, f"{key}: {c}")
        nmap = {c["question"]: c["answered_by"] for c in self.details("nmap")["coverage"]}
        self.assertEqual(nmap["Cleartext credentials seen?"], NOT_DETERMINED)
        logs = {c["question"]: c["answered_by"] for c in self.details("logs")["coverage"]}
        self.assertNotIn(NOT_DETERMINED, logs.values())

    def test_glossary_defined_once(self):
        for key in self.R:
            seen = []
            for b, it in iter_items(self.details(key)):
                for df in it.get("define", []):
                    self.assertNotIn(df["term"], seen)
                    seen.append(df["term"])


class TestCalmAndSafe(Fixtures):
    def test_benign_and_single_finding_are_calm_and_short(self):
        for key, limit in (("benign", 80), ("single", 220)):
            d = self.details(key)
            statuses = [it.get("status") for _, it in iter_items(d) if it.get("status")]
            self.assertNotIn("Observed", statuses, key)
            self.assertLessEqual(d["visible_words"], limit, key)
            gen = " ".join(it.get(f, "") for _, it in iter_items(d) for f in GENERATED).lower()
            for alarm in ("act now", "critical", "immediately", "urgent"):
                self.assertNotIn(alarm, gen, f"{key}: {alarm}")

    def test_hostile_strings_sanitized(self):
        d = self.details("hostile")
        blob = json.dumps(d, ensure_ascii=False)
        self.assertNotIn("‮", blob)
        self.assertNotIn("\x07", blob)
        self.assertNotIn("hunter2", blob)
        for b, it in iter_items(d):
            for k in ("text", "evidence", "code", "basis"):
                self.assertLessEqual(len(it.get(k, "")), 200, f"{b['key']}.{k}")
        for b in d["blocks"]:
            for vals in (b.get("targets") or {}).values():
                for v in vals:
                    self.assertLessEqual(len(v), 200)
                    self.assertNotIn("‮", v)
        self.assertEqual(clean("a‮b\x00c​d " + "x" * 300)[:5], "abcd ")
        self.assertLessEqual(len(clean("x" * 5000)), 200)

    def test_no_raw_secrets(self):
        self.assertNotIn("hunter2", json.dumps(self.details("pcap")))

    def test_missing_fields_do_not_error(self):
        for r in ({}, {"verdict": "MALICIOUS", "findings": [{"name": "SQL Injection", "severity": "HIGH"}], "mode": "logs"},
                  {"mode": "network", "findings": [None, "x", {"name": "TCP Port Scan Detected"}]}, {"mode": "url", "verdict": "BENIGN"}):
            d = build_summary_details(r)
            self.assertIn("blocks", d)

    def test_deterministic(self):
        r = copy.deepcopy(self.R["logs"])
        r.pop("exec_summary", None)
        self.assertEqual(build_summary_details(r), build_summary_details(copy.deepcopy(r)))

    def test_defang_option(self):
        d = build_summary_details(self.R["pcap"], defang=True)
        blob = json.dumps(d)
        self.assertIn("10[.]0[.]0[.]99", blob)
        self.assertNotIn('"10.0.0.99 ', blob)

    def test_api_summary_upgrades_old_results(self):
        old = copy.deepcopy(self.R["logs"])
        old.pop("exec_summary", None)
        r = self.client.post("/api/summary", json={"result": old})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn("headline", body["exec_summary"])
        self.assertEqual([b["key"] for b in body["details"]["blocks"]][0], "overview")
        self.assertEqual(self.client.post("/api/summary", json={}).status_code, 400)
        from utils.api_spec import ROUTES
        body = next(b for _m, path, _s, _t, b, _q in ROUTES if path == "/api/summary")      # documented example works
        self.assertEqual(self.client.post("/api/summary", json=body).status_code, 200)
        self.assertIn("/api/summary", self.client.get("/api/openapi.json").get_json()["paths"])


if __name__ == "__main__":
    unittest.main()
