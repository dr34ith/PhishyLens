# PhisyLens

PhishyLens is a personal project inspired by VirusTotal: which is a lens that analyzes suspicious emails, URLs, logs, and network data to detect phishing and explain why something is risky. I hate phishing, so I built this in the hope that it helps others spot and stop it.

<p align="center">
  <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" alt="Flask" />
  <img src="https://img.shields.io/badge/Vanilla%20JS-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black" alt="Vanilla JavaScript" />
</p>
<p align="center">
  Flask + vanilla-JS workbench for phishing, malware, and incident triage.<br/>
  <b>by dreaith · 2026</b>
</p>


<img width="1280" height="720" alt="Untitled design" src="https://github.com/user-attachments/assets/066ebf7f-7242-4476-918a-c7d013d9f319" />


## Features

| Area | What it does |
|---|---|
| **Email** | `.eml` upload or paste. Parses Return-Path, Reply-To, Received chain, SPF/DKIM/DMARC (from `Authentication-Results`), attachment hashes, double extensions, link mismatches, display-name spoofing |
| **Logs** | Syslog/auth.log, Nginx/Apache, JSON/NDJSON. Detects SQLi, XSS, LFI, command injection, Log4Shell, SSRF, scanners, SSH brute force, and encoded PowerShell (auto-decoded) |
| **Network** | Nmap and Wireshark/tshark output. Flags risky ports, vulnerable banners, SYN scans, ping sweeps, cleartext creds, DNS tunnelling |
| **URLs** | Redirect tracing (≤10 hops, SSRF-guarded) and newly-registered-domain check via RDAP |
| **Enrichment** | VirusTotal, AbuseIPDB, OTX, ThreatFox, MalwareBazaar with TTL cache and failure tracking |
| **Scoring** | Explainable score: contributions sum exactly to the total |
| **MITRE ATT&CK** | Technique cards, tactic heatmap, Navigator layer export, kill-chain bar, attack classification, malware family chip |
| **Sigma** | Per-finding Sigma YAML generation, with correlation rules for count-based detections |
| **Reports** | Executive summary, Markdown/print-PDF write-up, Visual Map (SVG/Mermaid/PNG export), IOC defanging |
| **API** | OpenAPI 3, Postman collection, request IDs, optional API key, rate limiting |
| **Ops** | System Health tab: internal logs, bug tracker, external-API status |

## Quick start

```bash
pip install -r requirements.txt
# add keys to .env (or set env vars in Vercel)
python app.py                              # http://localhost:5000
python -m unittest discover -s tests -v    # offline tests (network mocked)
```

Sample inputs are in `samples/` (`phishing.eml`, `web_attack.log`, `nmap_scan.txt`).

## API

Import `docs/PhishyLens.postman_collection.json` into Postman, or open `/api/openapi.json`.

Success: `{"result": {...}}` · Error: `{"error": "...", "request_id": "..."}` (also in the `X-Request-ID` header)

| Endpoint | Body |
|---|---|
| `POST /api/analyze/url` · `/redirects` | `{"url": "..."}` |
| `POST /api/analyze/email` | `{"raw": "..."}` or multipart `file` |
| `POST /api/analyze/logs` | `{"logs": "..."}` or multipart `file` |
| `POST /api/analyze/network` | `{"data": "..."}` or multipart `file` |
| `POST /api/analyze/hash` · `/ip` | `{"hash": ...}` · `{"ip": ...}` |
| `POST /api/enrich` | `{"ips": [...], "hashes": [...]}` |
| `POST /api/sigma` | `{"finding": {...}}` or `{"findings": [...]}`. Returns 422 if no honest template exists |
| `POST /api/diagram` | `{"result": {...}, "theme": "dark"\|"print", "defang": false}` |
| `POST /api/report` | `{"result": {...}, "format": "md"\|"html", "defang": true}` |
| `GET /api/system/status · /logs · /errors` | Monitoring |

Every analysis result includes `mitre`, `classification`, `kill_chain`, and `malware_family` (null unless ThreatFox/MalwareBazaar names one).

## Configuration

| Variable | Purpose |
|---|---|
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | Core enrichment |
| `ABUSECH_API_KEY` | Free key from auth.abuse.ch (required for MalwareBazaar/ThreatFox) |
| `URLSCAN_API_KEY`, `OTX_API_KEY` | Optional enrichment |
| `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY` | AI narratives, tried in that order with failover |
| `AI_PROVIDER` | Which provider to try first |
| `REQUIRE_API_KEY=1` + `PHISHYLENS_API_KEY` | Require `X-API-Key` on `/api/*` (for API-only deployments) |
| `RATE_LIMIT_PER_MIN` | Default 60; `0` disables |
| `LOG_LEVEL`, `INTEL_CACHE_TTL` | Logging level; cache seconds (default 900) |

Keys load from `.env`; real environment variables take precedence.

## Updating ATT&CK data

```bash
python scripts/build_mitre.py             # fetches MITRE's STIX bundle
python -m unittest tests.test_mitre -v    # fails on revoked/renamed technique IDs
```

If a test reports an unknown ID, update `utils/mitre_map.py`.

## Vercel notes

- Request bodies are capped at 4 MB. Redirect tracing has a 7 s budget (3 s per hop).
- SQLite and in-memory buffers are per instance (ephemeral). Use the Vercel log viewer for history.
- VirusTotal free tier is 4 req/min. Results are cached.
- Only HTTP redirects are followed (no meta-refresh or JS).
- Detection is heuristic. It supports analyst judgement and doesn't replace it.


## Contributing

PhishyLens is open for editing and enhancement. Ideas, bug fixes, new detections, and improvements are all welcome.

1. Fork the repo and create a branch (`git checkout -b feature/your-idea`)
2. Make your changes and run the tests: `python -m unittest discover -s tests -v`
3. Open a pull request describing what you changed and why

  <img src="https://img.shields.io/badge/PRs-welcome-brightgreen?style=for-the-badge" alt="PRs welcome" />
Thanks!
