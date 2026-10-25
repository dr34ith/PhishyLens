"""
Executive Summary story (exec_summary["story"]), checks, verdict consistency and weak-intel handling.
Run:  python -m unittest tests.test_story -v      (network access is mocked)
"""
import json
import re
import unittest
from unittest import mock

import requests

from tests.story_fixtures import intel_results
from tests.test_summary_details import Fixtures, ref_exists, read, FIX, ROOT
from utils.report import build_report
from utils.story import CERTAINTIES, FORBIDDEN, INFER_RX, MAX_SENTENCES, MAX_WORDS, WORD_MAX, build_story, story_words
from utils.summary import build_exec_summary, BENIGN_DEFAULT, CONFIDENCE_TIP, _intent
from utils.threat_intel import WEAK_FALSE_POSITIVE, WEAK_RECOMMENDATION

OUTCOMES = {"flagged", "clear", "unavailable"}


def _fake_head(url, *a, **kw):
    hops = {"http://bit.ly/3xYz": "http://track.example-redirect.top/r?id=1",
            "http://track.example-redirect.top/r?id=1": "http://paypa1-login.xyz/verify"}
    resp = mock.Mock(status_code=301 if url in hops else 200, headers={"Location": hops.get(url, "")}, url=url)
    resp.close = lambda: None
    return resp


def sentences_of(story):
    for sec in story:
        for s in sec["sentences"]:
            yield sec, s


def _jaccard(a, b):
    A, B = set(re.findall(r"[a-z0-9]+", a.lower())), set(re.findall(r"[a-z0-9]+", b.lower()))
    return len(A & B) / len(A | B) if A and B else 0.0


class StoryFixtures(Fixtures):
    R = {}                                   # own dict: never leaks extra fixtures into the Show-details tests

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import app as app_module
        c = app_module.app.test_client()
        cls.R.update(intel_results(c))
        ps = [mock.patch(f"requests.{fn}", side_effect=requests.ConnectionError("offline")) for fn in ("get", "post")]
        ps += [mock.patch("requests.head", side_effect=_fake_head),
               mock.patch("analyzers.url_analyzer.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))], create=True)]
        for p in ps:
            p.start()
        try:
            r = c.post("/api/analyze/url", json={"url": "http://bit.ly/3xYz"})
            cls.R["url"] = r.get_json()["result"]
        finally:
            for p in ps:
                p.stop()
            app_module._RATE.clear()

    def story(self, key):
        return self.R[key]["exec_summary"]["story"]

    def text(self, key):
        return " ".join(s["text"] for _, s in sentences_of(self.story(key)))


class TestStoryContract(StoryFixtures):
    def test_sections_in_order_and_present(self):
        order = ["artifact", "found", "unfolded", "means", "limits"]
        for key in self.R:
            secs = [s["section"] for s in self.story(key)]
            self.assertEqual(secs, [o for o in order if o in secs], key)
            self.assertIn("means", secs, key)
            for sec in self.story(key):
                self.assertTrue(sec["sentences"], f"{key}/{sec['section']}: empty section kept")

    def test_every_sentence_has_a_real_ref(self):
        for key, r in self.R.items():
            for sec, s in sentences_of(self.story(key)):
                if s.get("clear"):
                    continue                               # explicit "nothing else flagged" sentences
                self.assertIsInstance(s["ref"], dict, f"{key}: {s['text']}")
                self.assertTrue(ref_exists(r, s["ref"]), f"{key}/{sec['section']}: ref {s['ref']} missing for: {s['text']}")

    def test_certainty_values_and_wording(self):
        for key in self.R:
            for _, s in sentences_of(self.story(key)):
                self.assertIn(s["certainty"], CERTAINTIES)
                if s["certainty"] == "inferred":
                    self.assertRegex(s["text"], INFER_RX, f"{key}: inferred without 'suggests'/'consistent with': {s['text']}")
                if s["certainty"] == "unknown":
                    self.assertIn("could not be determined", s["text"], key)

    def test_forbidden_words_never_appear(self):
        for key, r in self.R.items():
            s = r["exec_summary"]
            blob = " ".join([s["headline"], *s["what_happened"], s["why_it_matters"], self.text(key), *[a["action"] for a in s["do_now"]]])
            self.assertIsNone(FORBIDDEN.search(blob), f"{key}: {FORBIDDEN.search(blob)}")
            self.assertIsNone(FORBIDDEN.search(r.get("classification", {}).get("rationale", "")) if r.get("classification") else None)

    def test_lengths_and_budget(self):
        for key in self.R:
            st = self.story(key)
            self.assertLessEqual(story_words(st), WORD_MAX, key)
            for sec in st:
                self.assertLessEqual(len(sec["sentences"]), MAX_SENTENCES, f"{key}/{sec['section']}")
                for s in sec["sentences"]:
                    self.assertLessEqual(len(s["text"].split()), MAX_WORDS, f"{key}: {s['text']}")
        for key in ("logs", "email", "nmap"):                      # data-rich MALICIOUS stories are full, not stubs
            self.assertGreaterEqual(story_words(self.story(key)), 170, key)

    def test_no_fact_repeats_across_blocks(self):
        for key, r in self.R.items():
            s = r["exec_summary"]
            others = [s["headline"]] + [a["action"] for a in s["do_now"]] + [f"{k['label']} {k['value']}" for k in s["key_facts"]]
            texts = [x["text"] for _, x in sentences_of(self.story(key))]
            for i, t in enumerate(texts):
                for o in others + texts[:i]:
                    self.assertLess(_jaccard(t, o), 0.8, f"{key}: repeats '{o}' as '{t}'")

    def test_glossary_defined_once(self):
        for key in self.R:
            terms = [d["term"] for _, s in sentences_of(self.story(key)) for d in s.get("define", [])]
            self.assertEqual(len(terms), len(set(terms)), key)

    def test_backward_compatible_keys_derive_from_story(self):
        for key, r in self.R.items():
            s = r["exec_summary"]
            texts = [x["text"] for _, x in sentences_of(self.story(key))]
            for b in s["what_happened"]:
                self.assertIn(b, texts, key)
            self.assertLessEqual(len(s["what_happened"]), 4)
            self.assertEqual(len(set(s["what_happened"])), len(s["what_happened"]))
            means = next(sec for sec in self.story(key) if sec["section"] == "means")
            self.assertEqual(s["why_it_matters"], means["sentences"][0]["text"], key)

    def test_deterministic(self):
        for key in ("logs", "email", "url_weak", "hash"):
            r = {k: v for k, v in self.R[key].items() if k != "exec_summary"}
            self.assertEqual(json.dumps(build_exec_summary(r), sort_keys=True), json.dumps(build_exec_summary(r), sort_keys=True), key)


class TestStoryContent(StoryFixtures):
    def test_weak_url_intel(self):
        r = self.R["url_weak"]
        s, txt = r["exec_summary"], self.text("url_weak")
        self.assertIn("1 of 90 engines", txt)
        self.assertIn("1 threat pulse", txt)
        self.assertIn("low-confidence signal that needs manual verification", txt)
        self.assertTrue(s["headline"].startswith("Possible"), s["headline"])
        self.assertNotIn("block immediately", json.dumps(s).lower())
        self.assertTrue(r["classification"]["rationale"].startswith("Possible"))
        otx = next(f for f in r["findings"] if f["name"] == "[AlienVault OTX] Flagged as Malicious")
        self.assertEqual((otx["severity"], otx["strength"], otx["recommendation"], otx["false_positive_possibility"]),
                         ("MEDIUM", "weak", WEAK_RECOMMENDATION, WEAK_FALSE_POSITIVE))

    def test_unknown_domain_age_is_not_zero_days(self):
        for key in ("url_weak", "url"):
            art = next(sec for sec in self.story(key) if sec["section"] == "artifact")
            age = [x for x in art["sentences"] if "registration age" in x["text"]]
            self.assertTrue(age, key)
            self.assertIn("could not be determined", age[0]["text"])
            self.assertEqual(age[0]["certainty"], "unknown")
            self.assertNotIn("0 days", self.text(key))

    def test_benign_is_short_calm_and_names_clear_checks(self):
        for key in ("url_clean", "benign"):
            txt = self.text(key).lower()
            self.assertLessEqual(story_words(self.story(key)), 160, key)
            for alarm in ("act now", "immediately", "urgent", "critical"):
                self.assertNotIn(alarm, txt, f"{key}: {alarm}")
            self.assertEqual(self.R[key]["exec_summary"]["do_now"], [{"priority": "This week", "action": BENIGN_DEFAULT}])
        clear = " ".join(x["text"] for _, x in sentences_of(self.story("url_clean")) if x.get("clear"))
        self.assertIn("HTTPS", clear)
        self.assertIn("VirusTotal and AlienVault OTX did not flag it", clear)

    def test_malicious_is_direct(self):
        for key in ("logs", "nmap", "pcap", "email"):
            self.assertIn("act now", self.R[key]["exec_summary"]["why_it_matters"], key)

    def test_fixture_coverage(self):
        expect = {
            "logs": ["203.0.113.50", "198.51.100.7", "5 failed logins", "logged in successfully as 'root'", "encoded PowerShell",
                     "http://evil.example/a.ps1", "T1190", "T1110", "T1059.001", "line 12"],
            "nmap": ["10.10.10.5", "vsftpd 2.3.4 Backdoor", "8 risky services", "T1190", "end-of-life"],
            "pcap": ["10.0.0.99", "25 ports", "cleartext", "4444", "T1046", "T1040", "T1571", "29 packets"],
            "email": ["paypa1-secure.xyz", "mailer.badhost.ru", "gmail-support.top", "SPF fail", "DMARC fail", "invoice.pdf.exe", "paypal.com"],
            "url": ["bit.ly", "redirects 2 times", "paypa1-login.xyz"],
            "hash": ["SHA-256", "AgentTesla", "41 of 70 engines"],
            "ip": ["185.220.101.4", "Germany", "517 reports", "12 threat pulses"],
        }
        for key, needles in expect.items():
            txt = self.text(key)
            for n in needles:
                self.assertIn(n, txt, f"{key}: missing {n!r}")

    def test_hostile_strings_sanitized(self):
        txt = json.dumps(self.story("hostile"), ensure_ascii=False)
        for bad in ("‮", "\x07", "hunter2", "A" * 300):
            self.assertNotIn(bad, txt)
        html = build_report(self.R["hostile"], "html")
        start = html.index('<p class="story">')
        region = html[start:html.index("<details", start)]
        self.assertNotIn("<script>", region)
        self.assertNotIn("‮", region)

    def test_no_raw_secrets(self):
        self.assertIn("hunter2", json.dumps(self.R["pcap"]["findings"]))      # the fixture really carries it
        for key in self.R:
            self.assertNotIn("hunter2", json.dumps(self.R[key]["exec_summary"]), key)

    def test_old_results_without_new_keys(self):
        for key in ("logs", "url", "email"):
            r = {k: v for k, v in self.R[key].items() if k not in ("exec_summary", "checks", "score_explanation", "kill_chain", "classification")}
            s = build_exec_summary(r)
            self.assertTrue(s["story"])
            old = dict(self.R[key], exec_summary={k: v for k, v in self.R[key]["exec_summary"].items() if k not in ("story", "details")})
            old.pop("checks", None)
            for fmt in ("md", "html"):
                self.assertTrue(build_report(old, fmt))
        self.assertIsInstance(build_story({}), list)
        self.assertIsInstance(build_story({"mode": "logs", "findings": [None, 3, "x"], "log_stats": {"sample_hits": [None]}}), list)


class TestChecksAndConsistency(StoryFixtures):
    def test_checks_shape_and_never_clear_without_running(self):
        for key in ("url", "url_weak", "url_clean", "email", "hash", "ip"):
            checks = self.R[key]["checks"]
            self.assertTrue(checks, key)
            for c in checks:
                self.assertEqual(set(c), {"name", "outcome"})
                self.assertIn(c["outcome"], OUTCOMES)
        by = {c["name"]: c["outcome"] for c in self.R["url"]["checks"]}          # offline: no intel, RDAP failed
        for src in ("VirusTotal", "AlienVault OTX", "urlscan.io", "ThreatFox"):
            self.assertEqual(by[src], "unavailable")
        self.assertEqual(by["Domain age"], "unavailable")
        self.assertEqual(by["Redirect chain"], "flagged")
        self.assertEqual({c["name"]: c["outcome"] for c in self.R["url_weak"]["checks"]}["Domain age"], "unavailable")
        em = {c["name"]: c["outcome"] for c in self.R["email"]["checks"]}
        self.assertEqual((em["SPF"], em["DKIM"], em["DMARC"], em["Attachments"]), ("flagged", "flagged", "flagged", "flagged"))
        self.assertEqual({c["name"]: c["outcome"] for c in self.R["hash"]["checks"]}["ThreatFox"], "clear")

    def test_do_now_matches_verdict(self):
        for key, r in self.R.items():
            acts, verdict = r["exec_summary"]["do_now"], r["verdict"]
            self.assertLessEqual(len(acts), 3)
            prios = [a["priority"] for a in acts]
            self.assertEqual(prios, sorted(prios, key=["Now", "Today", "This week"].index), key)
            intents = [_intent(a["action"]) for a in acts]
            self.assertEqual(len(intents), len(set(intents)), f"{key}: duplicate intent {intents}")
            if verdict == "MALICIOUS":
                self.assertIn("contain", intents, key)
            elif verdict == "SUSPICIOUS":
                self.assertNotIn("contain", intents, key)
                self.assertNotIn("immediately", json.dumps(acts).lower(), key)
            else:
                self.assertEqual(acts, [{"priority": "This week", "action": BENIGN_DEFAULT}], key)

    def test_key_facts_numbers_only_and_renamed(self):
        for key, r in self.R.items():
            facts = r["exec_summary"]["key_facts"]
            labels = [f["label"] for f in facts]
            self.assertNotIn("Confidence", labels)
            self.assertNotIn("Affected hosts/IPs", labels)
            self.assertNotIn("Verdict", labels)
            for f in facts:
                self.assertRegex(f["value"], r"^\d+%?$", f"{key}: {f}")
                if f["label"] == "Analysis confidence":
                    self.assertEqual(f["title"], CONFIDENCE_TIP)
        self.assertNotIn("Hosts involved", [f["label"] for f in self.R["url_clean"]["exec_summary"]["key_facts"]])

    def test_headline_hedged_unless_malicious_first_hand(self):
        for key, r in self.R.items():
            s = r["exec_summary"]
            from utils.story import hedged
            if hedged(r) and str(r["verdict"]) != "BENIGN":
                self.assertTrue(s["headline"].startswith("Possible"), f"{key}: {s['headline']}")
                rat = (r.get("classification") or {}).get("rationale", "")
                if "map to" in rat or "consistent with" in rat:
                    self.assertTrue(rat.startswith("Possible"), f"{key}: {rat}")
        self.assertFalse(self.R["logs"]["exec_summary"]["headline"].startswith("Possible"))
        self.assertTrue(self.R["hash"]["exec_summary"]["headline"].startswith("Possible"))      # intel flags only


if __name__ == "__main__":
    unittest.main()
