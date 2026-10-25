"""Single source of truth for the API contract: feeds /api/openapi.json and the Postman collection."""

SAMPLE_EML = ("From: \"PayPal Support\" <support@paypa1-secure.xyz>\\nReturn-Path: <bounce@mailer.badhost.ru>\\n"
              "Reply-To: help@gmail-support.top\\nX-Originating-IP: [185.220.101.4]\\n"
              "Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=badhost.ru; dkim=none; dmarc=fail\\n"
              "Subject: URGENT: verify your account\\n\\nYour account will be suspended. Click http://paypa1-secure.xyz/login now")

SAMPLE_FINDING = {"name": "SSH / Login Brute Force", "severity": "HIGH", "evidence": "203.0.113.50: 12 failed logins (2 distinct user(s): admin, root)",
                  "false_positive_possibility": "Low–Medium.", "confidence": 80}
SAMPLE_RESULT = {"verdict": "MALICIOUS", "score": 88, "mode": "logs", "input": "12 log lines (syslog)", "summary": "Example result.",
                 "recommended_action": "Block the source and enforce MFA.", "findings": [SAMPLE_FINDING],
                 "iocs": {"ips": ["203.0.113.50"], "urls": [], "emails": [], "domains": [], "hashes": []}}

SAMPLE_NETWORK_RESULT = {"verdict": "MALICIOUS", "score": 90, "mode": "network", "input": "0 host(s), 0 open port(s), 26 packet(s)",
                         "findings": [{"name": "TCP Port Scan Detected", "severity": "HIGH",
                                       "evidence": "10.0.0.99 → 10.10.10.5: SYN to 25 distinct ports (e.g. [1000, 1001])"},
                                      {"name": "Traffic to Suspicious Port", "severity": "HIGH", "evidence": "10.10.10.5 → 10.0.0.77:4444 (1 packets)"}],
                         "iocs": {"ips": ["10.0.0.99"]}}

# (method, path, summary, tag, body_example | None, query_params | None)
ROUTES = [
    ("GET",  "/api/health",                 "Liveness probe",                              "System",  None, None),
    ("GET",  "/api/system/status",          "Uptime, config flags, external-API health",   "System",  None, None),
    ("GET",  "/api/system/logs",            "Recent internal log records",                 "System",  None, {"limit": "100", "level": "ERROR"}),
    ("GET",  "/api/system/errors",          "Recent errors / failed API calls (bug tracker)", "System", None, {"limit": "50"}),
    ("POST", "/api/analyze/url",            "Analyze a URL (heuristics + intel + redirect trace)", "Analyze", {"url": "http://bit.ly/3example"}, None),
    ("POST", "/api/analyze/redirects",      "Trace HTTP 301/302 redirect chain only",      "Analyze", {"url": "http://bit.ly/3example"}, None),
    ("POST", "/api/analyze/email",          "Analyze raw email (JSON) or .eml upload (multipart field 'file')", "Analyze", {"raw": SAMPLE_EML}, None),
    ("POST", "/api/analyze/email/upload",   "Analyze an uploaded .eml file (multipart field 'file')", "Analyze", "FILE", None),
    ("POST", "/api/analyze/hash",           "Analyze MD5/SHA1/SHA256",                     "Analyze", {"hash": "44d88612fea8a8f36de82e1278abb02f"}, None),
    ("POST", "/api/analyze/ip",             "Reputation of an IP address",                 "Analyze", {"ip": "185.220.101.4"}, None),
    ("POST", "/api/analyze/logs",           "Detect SQLi/XSS/PowerShell/brute force in logs (JSON {logs} or multipart 'file')", "Analyze",
        {"logs": "10.0.0.5 - - [10/Oct/2026:13:55:36 +0000] \\\"GET /item?id=1' UNION SELECT user,pass FROM users-- HTTP/1.1\\\" 200 512 \\\"-\\\" \\\"sqlmap/1.7\\\""}, None),
    ("POST", "/api/analyze/network",        "Triage Nmap / Wireshark text exports (JSON {data} or multipart 'file')", "Analyze",
        {"data": "Nmap scan report for 10.10.10.5\\nPORT   STATE SERVICE VERSION\\n21/tcp open  ftp     vsftpd 2.3.4\\n445/tcp open  microsoft-ds Samba 3.0.20"}, None),
    ("POST", "/api/enrich",                 "Enrich IPs / hashes with VirusTotal + AbuseIPDB", "Intel", {"ips": ["185.220.101.4"], "hashes": []}, None),
    ("GET",  "/api/case/{case_id}",         "Fetch a saved case",                          "Cases",   None, None),
    ("GET",  "/api/cases/stats",            "Case statistics",                             "Cases",   None, None),
    ("GET",  "/api/cases/recent",           "Recent cases",                                "Cases",   None, {"limit": "10"}),
    ("GET",  "/api/cases/search",           "Search cases",                                "Cases",   None, {"q": "", "type": "url", "verdict": "MALICIOUS", "limit": "20"}),
    ("POST", "/api/tools/decode",           "Decode Base64/Hex/URL/ROT13",                 "Tools",   {"text": "SGVsbG8gV29ybGQ="}, None),
    ("POST", "/api/tools/extract",          "Extract IOCs from text",                      "Tools",   {"text": "Visit http://evil.example.com from 8.8.8.8"}, None),
    ("POST", "/api/tools/flagscan",         "Find CTF flags in text",                      "Tools",   {"text": "flag{example_flag}"}, None),
    ("POST", "/api/tools/hashcrack",        "Reverse a hash via public DB",                "Tools",   {"hash": "5f4dcc3b5aa765d61d8327deb882cf99"}, None),
    ("POST", "/api/ai/analyze",             "LLM narrative (falls back to local explanation)", "AI",
        {"mode": "url", "input": "http://evil.example.com", "findings": [], "verdict": "SUSPICIOUS", "score": 50}, None),
    ("POST", "/api/sigma",                  "Generate Sigma rule(s) (YAML) from one finding {finding} or many {findings}; 422 for unsupported finding types",
        "Detection", {"finding": SAMPLE_FINDING, "mode": "logs"}, None),
    ("POST", "/api/summary",                "Upgrade a stored result: short Executive Summary (rebuilt if missing) + detailed 'Show details' blocks",
        "Reporting", {"result": SAMPLE_RESULT, "defang": False}, None),
    ("POST", "/api/diagram",                "Attack diagram (pure SVG + Mermaid) and kill-chain SVG built only from an analysis result",
        "Reporting", {"result": SAMPLE_NETWORK_RESULT, "theme": "dark", "defang": False}, None),
    ("POST", "/api/report",                 "Markdown (format=md) or print-ready HTML (format=html) write-up built only from an analysis result",
        "Reporting", {"result": SAMPLE_RESULT, "format": "md", "defang": True, "include_sigma": True}, None),
]

# per-route extras: additional responses (OpenAPI) and Postman test scripts
ROUTE_RESPONSES = {
    "/api/sigma": {
        "200": {"description": "Success: {rules: [{finding, title, id, yaml, rules}], skipped: [{finding, reason}], yaml}",
                "content": {"application/json": {"schema": {"type": "object", "properties": {
                    "rules": {"type": "array", "items": {"type": "object"}}, "skipped": {"type": "array", "items": {"type": "object"}},
                    "yaml": {"type": "string", "description": "All rules as multi-document Sigma YAML"}}}}}},
        "422": {"description": "No Sigma template for the finding type(s): {error, supported[], request_id}"},
    },
    "/api/summary": {
        "200": {"description": "Success: {exec_summary: {headline, what_happened[], why_it_matters, do_now[], key_facts[], highlights[], "
                               "story[{section, title, sentences[{text, ref, certainty: observed|inferred|unknown}]}]}, "
                               "details: {version, blocks[overview, actors_and_targets, assessment, attack_story, confidence_and_limits, "
                               "next_steps, mode_extras], coverage[], glossary[], visible_words, word_budget}}",
                "content": {"application/json": {"schema": {"type": "object", "properties": {
                    "exec_summary": {"type": "object"}, "details": {"type": "object"}}}}}},
    },
    "/api/diagram": {
        "200": {"description": "Success: {type, title, nodes[], edges[], svg, mermaid, killchain_svg, grouped[]}; type 'none' when the result has nothing to draw",
                "content": {"application/json": {"schema": {"type": "object", "properties": {
                    "type": {"type": "string"}, "nodes": {"type": "array", "items": {"type": "object"}},
                    "edges": {"type": "array", "items": {"type": "object"}}, "svg": {"type": "string"},
                    "mermaid": {"type": "string"}, "killchain_svg": {"type": "string"}}}}}},
    },
    "/api/report": {
        "200": {"description": "The write-up as an attachment (Content-Disposition). IOC table always defanged; other text defanged when defang=true.",
                "content": {"text/markdown": {"schema": {"type": "string"}}, "text/html": {"schema": {"type": "string"}}}},
    },
}
POSTMAN_TESTS = {
    "/api/sigma": ["pm.test('status is 200', () => pm.response.to.have.status(200));",
                   "pm.test('has rules', () => pm.expect(pm.response.json().rules).to.be.an('array').that.is.not.empty);",
                   "pm.test('rule is experimental YAML', () => pm.expect(pm.response.json().yaml).to.include('status: experimental'));"],
    "/api/summary": ["pm.test('status is 200', () => pm.response.to.have.status(200));",
                     "pm.test('has details blocks', () => pm.expect(pm.response.json().details.blocks).to.be.an('array'));",
                     "pm.test('has coverage', () => pm.expect(pm.response.json().details.coverage).to.be.an('array').that.is.not.empty);"],
    "/api/diagram": ["pm.test('status is 200', () => pm.response.to.have.status(200));",
                     "pm.test('has svg', () => pm.expect(pm.response.json().svg).to.include('<svg'));",
                     "pm.test('nodes capped at 20', () => pm.expect(pm.response.json().nodes.length).to.be.at.most(20));"],
    "/api/report": ["pm.test('status is 200', () => pm.response.to.have.status(200));",
                    "pm.test('markdown attachment', () => pm.expect(pm.response.headers.get('Content-Disposition')).to.include('attachment'));",
                    "pm.test('has title', () => pm.expect(pm.response.text()).to.include('# PhishyLens Write-up'));"],
}


def build_openapi(server: str = "") -> dict:
    paths = {}
    for method, path, summary, tag, body, query in ROUTES:
        op = {"summary": summary, "tags": [tag],
              "responses": {"200": {"description": "Success"}, "400": {"description": "Bad request: {error, request_id}"},
                            "429": {"description": "Rate limited"}, "500": {"description": "Internal error: {error, request_id}"}}}
        if "{case_id}" in path:
            op["parameters"] = [{"name": "case_id", "in": "path", "required": True, "schema": {"type": "string"}}]
        if query:
            op.setdefault("parameters", []).extend({"name": k, "in": "query", "schema": {"type": "string"}} for k in query)
        if body == "FILE":
            op["requestBody"] = {"content": {"multipart/form-data": {"schema": {"type": "object", "properties": {"file": {"type": "string", "format": "binary"}}}}}}
        elif body:
            op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object"}, "example": body}}}
        op["responses"].update(ROUTE_RESPONSES.get(path, {}))
        paths.setdefault(path, {})[method.lower()] = op
    return {"openapi": "3.0.3",
            "info": {"title": "PhishyLens API", "version": "3.0.0", "description": "Threat intel & digital forensics workbench. Errors: {error, request_id}. Optional header X-API-Key when PHISHYLENS_API_KEY + REQUIRE_API_KEY=1 are set."},
            "servers": [{"url": server or "/"}],
            "components": {"securitySchemes": {"ApiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
            "paths": paths}


def build_postman(base: str = "{{baseUrl}}") -> dict:
    import json
    folders = {}
    for method, path, summary, tag, body, query in ROUTES:
        url_path = path.replace("{case_id}", "{{caseId}}")
        item = {"name": f"{method} {path}", "request": {"method": method, "header": [{"key": "X-API-Key", "value": "{{apiKey}}", "disabled": True}],
                "url": {"raw": base + url_path, "host": ["{{baseUrl}}"], "path": [p for p in url_path.split("/") if p]}}, "description": summary}
        if query:
            item["request"]["url"]["query"] = [{"key": k, "value": v} for k, v in query.items()]
        if body == "FILE":
            item["request"]["body"] = {"mode": "formdata", "formdata": [{"key": "file", "type": "file"}]}
        elif body:
            item["request"]["header"].append({"key": "Content-Type", "value": "application/json"})
            item["request"]["body"] = {"mode": "raw", "raw": json.dumps(body, indent=2), "options": {"raw": {"language": "json"}}}
        if method == "POST" and tag == "Analyze" and body != "FILE":
            item["event"] = [{"listen": "test", "script": {"type": "text/javascript", "exec": [
                "pm.test('status is 200', () => pm.response.to.have.status(200));",
                "pm.test('has result', () => pm.expect(pm.response.json()).to.have.property('result'));",
                "pm.test('score 0-100', () => { const s = pm.response.json().result.score; pm.expect(s).to.be.within(0,100); });",
                "pm.test('verdict valid', () => pm.expect(['BENIGN','SUSPICIOUS','MALICIOUS']).to.include(pm.response.json().result.verdict));"]}}]
        if path in POSTMAN_TESTS:
            item["event"] = [{"listen": "test", "script": {"type": "text/javascript", "exec": POSTMAN_TESTS[path]}}]
        folders.setdefault(tag, []).append(item)
    return {"info": {"name": "PhishyLens API", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
            "variable": [{"key": "baseUrl", "value": "http://localhost:5000"}, {"key": "apiKey", "value": ""}, {"key": "caseId", "value": "CASE-2026-00001"}],
            "item": [{"name": k, "item": v} for k, v in folders.items()]}
