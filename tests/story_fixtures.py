"""Mocked intel fixtures for the story tests (no network): URL flagged by two low-count sources, hash, IP, BENIGN URL."""
import json
import os
from unittest import mock

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resp(status, payload):
    r = mock.Mock(status_code=status, ok=200 <= status < 300)
    r.json = lambda: payload
    r.headers = {}
    r.close = lambda: None
    return r


def _get_router(table):
    def get(url, *a, **kw):
        for key, (status, payload) in table.items():
            if key in url:
                return _resp(status, payload)
        return _resp(404, {})
    return get


VT_LOW = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 29}}}}
VT_HIGH = {"data": {"attributes": {"last_analysis_stats": {"malicious": 41, "suspicious": 2, "harmless": 0, "undetected": 27}}}}
OTX_LOW = {"pulse_info": {"count": 1}, "validation": []}
OTX_HIGH = {"pulse_info": {"count": 12}, "validation": []}
IPAPI = {"status": "success", "country": "Germany", "countryCode": "DE", "isp": "Example Hosting GmbH", "org": "Example Hosting",
         "as": "AS64500 Example Hosting GmbH", "proxy": False, "hosting": True, "query": "185.220.101.4"}
ABUSE = {"data": {"abuseConfidenceScore": 100, "totalReports": 517, "isWhitelisted": False, "countryCode": "DE", "usageType": "Data Center"}}
MB_HIT = {"query_status": "ok", "data": [{"signature": "AgentTesla", "file_type": "exe", "tags": ["stealer"], "first_seen": "2026-09-01"}]}


def _head(url, *a, **kw):
    return _resp(200, {})


def run(client, endpoint, body, env, get_table, post=None):
    from utils import threat_intel
    threat_intel._CACHE.clear()
    patches = [mock.patch.dict(os.environ, env),
               mock.patch("requests.get", side_effect=_get_router(get_table)),
               mock.patch("requests.post", side_effect=post or (lambda *a, **k: _resp(404, {}))),
               mock.patch("requests.head", side_effect=_head),
               mock.patch("analyzers.url_analyzer.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 0))], create=True),
               mock.patch("socket.gethostbyname", return_value="93.184.216.34")]
    for p in patches:
        p.start()
    try:
        r = client.post(endpoint, json=body)
        assert r.status_code == 200, r.get_data(as_text=True)[:300]
        return r.get_json()["result"]
    finally:
        for p in patches:
            p.stop()


def intel_results(client) -> dict:
    out = {}
    # URL flagged by two LOW-count sources (VirusTotal 1/90, OTX 1 pulse); RDAP fails → domain age Unknown
    out["url_weak"] = run(client, "/api/analyze/url", {"url": "https://shop.example-store.net/account/update"},
                          {"VIRUSTOTAL_API_KEY": "k", "OTX_API_KEY": "k", "URLSCAN_API_KEY": "", "ABUSECH_API_KEY": ""},
                          {"virustotal.com": (200, VT_LOW), "otx.alienvault.com": (200, OTX_LOW), "ip-api.com": (200, {**IPAPI, "hosting": False}),
                           "rdap.org": (503, {})})
    # BENIGN URL: sources answer clean
    out["url_clean"] = run(client, "/api/analyze/url", {"url": "https://docs.example.org/guide"},
                           {"VIRUSTOTAL_API_KEY": "k", "OTX_API_KEY": "k", "URLSCAN_API_KEY": "", "ABUSECH_API_KEY": ""},
                           {"virustotal.com": (200, {"data": {"attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 70}}}}),
                            "otx.alienvault.com": (200, {"pulse_info": {"count": 0}, "validation": []}), "ip-api.com": (200, {**IPAPI, "hosting": False}),
                            "rdap.org": (200, {"events": [{"eventAction": "registration", "eventDate": "2015-03-01T00:00:00Z"}],
                                               "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc."]]]}]})})
    # hash: VirusTotal 41/70 + MalwareBazaar AgentTesla
    out["hash"] = run(client, "/api/analyze/hash", {"hash": "a" * 64},
                      {"VIRUSTOTAL_API_KEY": "k", "ABUSECH_API_KEY": "k"},
                      {"virustotal.com": (200, VT_HIGH)},
                      post=lambda url, *a, **k: _resp(200, MB_HIT) if "mb-api" in url else _resp(200, {"query_status": "no_result"}))
    # IP: AbuseIPDB 100% / 517 reports, OTX 12 pulses, hosting provider
    out["ip"] = run(client, "/api/analyze/ip", {"ip": "185.220.101.4"},
                    {"ABUSEIPDB_API_KEY": "k", "OTX_API_KEY": "k", "VIRUSTOTAL_API_KEY": "", "ABUSECH_API_KEY": ""},
                    {"abuseipdb.com": (200, ABUSE), "otx.alienvault.com": (200, OTX_HIGH), "ip-api.com": (200, IPAPI)})
    return out
