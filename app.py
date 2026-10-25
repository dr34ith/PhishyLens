from flask import Flask, request, jsonify, send_from_directory, g
from werkzeug.exceptions import HTTPException
from datetime import datetime, timezone
from contextlib import contextmanager
import os, re, json, sqlite3, time, hmac, ipaddress
from collections import defaultdict, deque

# load .env BEFORE importing modules that read config at import time (cache TTL, rate limit, API keys)
from utils.env import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env'))

from analyzers.url_analyzer     import analyze_url, trace_redirects
from analyzers.email_analyzer   import analyze_email
from analyzers.hash_analyzer    import analyze_hash
from analyzers.log_analyzer     import analyze_logs
from analyzers.network_analyzer import analyze_network
from utils.scoring              import attach_explanation, build_risk_breakdown, correlate_evidence
from utils.mitre_map            import attach_mitre
from utils.insights             import attach_classification, attach_kill_chain, attach_malware_family
from utils.sigma_gen            import (generate_rule as generate_sigma_rule, generate_rules as generate_sigma_rules,
                                        supported_finding_names, UnsupportedFinding)
from utils.report               import build_report, report_filename
from utils.summary              import attach_exec_summary, attach_exec_details, build_summary_details, build_exec_summary
from utils.diagrams             import build_diagram, build_killchain_svg
from utils.threat_intel         import lookup_ip, enrich_indicators, is_public_ip
from utils.logger               import (get_logger, new_request_id, recent_logs, recent_errors,
                                        api_stats, uptime_seconds)
from utils.api_spec             import build_openapi, build_postman
from utils.hash_reverse         import reverse_hash, hash_type, COMMON_PLAINTEXTS
from utils.ai_analysis          import configured_providers, generate_analysis, local_explanation

APP_VERSION = '3.0.1'
log = get_logger('app')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, static_folder=os.path.join(BASE_DIR, 'static'), template_folder=BASE_DIR)
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024      # Vercel body limit is ~4.5 MB

# ─── CROSS-CUTTING: request id, logging, auth, rate limit, errors ───
_PUBLIC_API = ('/api/health', '/api/openapi.json', '/api/postman.json')
_RATE = defaultdict(deque)
RATE_LIMIT_PER_MIN = int(os.getenv('RATE_LIMIT_PER_MIN', '60'))

def _client_ip() -> str:
    return (request.headers.get('X-Forwarded-For', request.remote_addr or '') or '').split(',')[0].strip()

@app.before_request
def _before():
    g.rid, g.t0 = new_request_id(), time.time()
    path = request.path
    if not path.startswith('/api/'):
        return None
    # optional API-key auth (off by default so the bundled dashboard keeps working)
    if os.getenv('REQUIRE_API_KEY') == '1' and path not in _PUBLIC_API:
        expected = os.getenv('PHISHYLENS_API_KEY', '')
        given = request.headers.get('X-API-Key', '')
        if not expected or not hmac.compare_digest(expected, given):
            log.warning('[%s] auth rejected %s %s from %s', g.rid, request.method, path, _client_ip())
            return jsonify({'error': 'Unauthorized: send a valid X-API-Key header', 'request_id': g.rid}), 401
    # simple per-IP sliding-window limiter on heavy endpoints (per warm instance)
    if RATE_LIMIT_PER_MIN and path.startswith(('/api/analyze/', '/api/enrich', '/api/ai/')):
        q, now = _RATE[_client_ip()], time.time()
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE_LIMIT_PER_MIN:
            return jsonify({'error': 'Rate limit exceeded', 'request_id': g.rid}), 429
        q.append(now)
    return None

@app.after_request
def _after(resp):
    rid = getattr(g, 'rid', '-')
    resp.headers['X-Request-ID'] = rid
    if request.path.startswith('/api/'):
        ms = int((time.time() - getattr(g, 't0', time.time())) * 1000)
        lvl = log.warning if resp.status_code >= 400 else log.info
        lvl('[%s] %s %s -> %s (%d ms)', rid, request.method, request.path, resp.status_code, ms)
    return resp

@app.errorhandler(HTTPException)
def _http_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': e.description if e.code < 500 else 'Server error', 'request_id': getattr(g, 'rid', '-')}), e.code
    return e

@app.errorhandler(Exception)
def _unhandled(e):
    rid = getattr(g, 'rid', '-')
    log.exception('[%s] unhandled error on %s %s: %s', rid, request.method, request.path, e)   # full trace stays in server logs
    return jsonify({'error': 'Internal server error', 'request_id': rid}), 500

def _bad(msg: str, code: int = 400):
    return jsonify({'error': msg, 'request_id': getattr(g, 'rid', '-')}), code

def _get_text_input(*json_keys: str, exts=()) -> str:
    """Return text from a multipart 'file' upload OR from JSON/form fields."""
    f = request.files.get('file')
    if f and f.filename:
        if exts and not f.filename.lower().endswith(tuple(exts)):
            raise ValueError(f"Unsupported file type: expected {', '.join(exts)}")
        return f.read().decode('utf-8', errors='replace')
    data = request.get_json(silent=True) or {}
    for k in json_keys:
        v = data.get(k) or request.form.get(k)
        if v:
            return v
    return ''

def _get_bytes_input(*json_keys: str) -> bytes:
    f = request.files.get('file')
    if f and f.filename:
        return f.read()
    data = request.get_json(silent=True) or {}
    for k in json_keys:
        v = data.get(k) or request.form.get(k)
        if v:
            return v.encode('utf-8', errors='replace')
    return b''

def _int_arg(name: str, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(int(request.args.get(name, default)), hi))
    except (TypeError, ValueError):
        return default

DB_PATH = os.getenv('DB_PATH', '/tmp/cases.db' if os.getenv('VERCEL') else os.path.join(BASE_DIR, 'cases.db'))

# ─── DATABASE ────────────────────────────────────────────────
@contextmanager
def get_db():
    """Connection that commits on success, rolls back on error and is ALWAYS closed."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS cases (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT    UNIQUE,
                type        TEXT    NOT NULL,
                input       TEXT    NOT NULL,
                score       INTEGER NOT NULL,
                verdict     TEXT    NOT NULL,
                action      TEXT    NOT NULL,
                findings    TEXT    NOT NULL,
                created_at  TEXT    NOT NULL
            )
        ''')

def generate_case_number(last_id: int) -> str:
    return f"CASE-{datetime.now().year}-{last_id:05d}"

# ─── ROUTES ──────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory(BASE_DIR, 'dashboard.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_folder, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/api/health')
def health():
    return jsonify({'status': 'operational', 'service': 'PhishyLens Threat Intelligence Workbench', 'version': APP_VERSION, 'timestamp': datetime.now(timezone.utc).isoformat()})

# ─── ANALYZE ENDPOINTS ───────────────────────────────────────
def _finish(kind: str, input_val: str, result: dict):
    """Attach explainable score + ATT&CK mapping, persist case (never fails the request), return JSON."""
    findings = result.get('findings', [])
    result.setdefault('risk_breakdown', build_risk_breakdown(findings))
    result.setdefault('evidence_correlation', correlate_evidence(findings, kind))
    attach_explanation(result)
    attach_mitre(result, kind)
    attach_classification(result)
    attach_kill_chain(result)
    attach_malware_family(result)
    attach_exec_summary(result)
    attach_exec_details(result)
    try:
        _save_case(kind, input_val, result)
    except Exception as e:
        log.error('[%s] case persistence failed: %s', getattr(g, 'rid', '-'), e)
    return jsonify({'result': result})

@app.route('/api/analyze/url', methods=['POST'])
def analyze_url_route():
    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()
    if not url:
        return _bad('No URL provided')
    if len(url) > 4096:
        return _bad('URL too long (max 4096 chars)')
    return _finish('url', url, analyze_url(url))

@app.route('/api/analyze/redirects', methods=['POST'])
def analyze_redirects_route():
    data = request.get_json(silent=True) or {}
    url  = (data.get('url') or '').strip()
    if not url:
        return _bad('No URL provided')
    if len(url) > 4096:
        return _bad('URL too long (max 4096 chars)')
    if not re.match(r'^https?://', url, re.I):
        url = 'http://' + url
    return jsonify({'result': trace_redirects(url)})

@app.route('/api/analyze/email', methods=['POST'])
@app.route('/api/analyze/email/upload', methods=['POST'])
def analyze_email_route():
    try:
        raw = _get_bytes_input('raw')
    except ValueError as e:
        return _bad(str(e))
    if not raw.strip():
        return _bad('No email content provided (JSON {"raw": ...} or multipart "file" .eml)')
    label = (request.files['file'].filename if request.files.get('file') else raw.decode('utf-8', 'replace')[:200])
    return _finish('email', label, analyze_email(raw))

@app.route('/api/analyze/hash', methods=['POST'])
def analyze_hash_route():
    data = request.get_json(silent=True) or {}
    h    = (data.get('hash') or '').strip()
    if not h:
        return _bad('No hash value provided')
    return _finish('hash', h, analyze_hash(h))

@app.route('/api/analyze/ip', methods=['POST'])
def analyze_ip_route():
    data = request.get_json(silent=True) or {}
    ip   = (data.get('ip') or '').strip()
    if not ip:
        return _bad('No IP address provided')
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return _bad('Invalid IP address')
    return _finish('ip', ip, lookup_ip(ip))

@app.route('/api/analyze/logs', methods=['POST'])
def analyze_logs_route():
    try:
        text = _get_text_input('logs', 'data', 'text')
    except ValueError as e:
        return _bad(str(e))
    if not text.strip():
        return _bad('No log data provided (JSON {"logs": ...} or multipart "file")')
    return _finish('logs', f'{len(text.splitlines())} log lines', analyze_logs(text))

@app.route('/api/analyze/network', methods=['POST'])
def analyze_network_route():
    try:
        text = _get_text_input('data', 'text', 'scan')
    except ValueError as e:
        return _bad(str(e))
    if not text.strip():
        return _bad('No network artifact provided (JSON {"data": ...} or multipart "file")')
    return _finish('network', text[:80].replace('\n', ' '), analyze_network(text))

@app.route('/api/enrich', methods=['POST'])
def enrich_route():
    data   = request.get_json(silent=True) or {}
    ips    = [str(i).strip() for i in (data.get('ips') or [])][:10]
    hashes = [str(h).strip() for h in (data.get('hashes') or []) if re.fullmatch(r'[a-fA-F0-9]{32,64}', str(h).strip())][:10]
    if not ips and not hashes:
        return _bad('Provide "ips" and/or "hashes" arrays')
    out = enrich_indicators(ips, hashes, max_ips=10, max_hashes=10)
    return jsonify({'result': out})

# ─── DETECTION ENGINEERING / REPORTING ───────────────────────
SIGMA_MAX_FINDINGS = 100

@app.route('/api/sigma', methods=['POST'])
def sigma_route():
    """Body: {"finding": {...}, "mode": "logs"} → one rule, or {"findings": [...], "mode": ...} → every supported finding.
    Unsupported finding types get 422 with the supported list; never a placeholder rule."""
    data = request.get_json(silent=True) or {}
    mode = str(data.get('mode') or '')[:20]
    if isinstance(data.get('finding'), dict):
        try:
            rule = generate_sigma_rule(data['finding'], mode)
        except UnsupportedFinding:
            name = str(data['finding'].get('name') or '')[:200]
            return jsonify({'error': f"No Sigma rule can be generated for '{name}'; only log-based and network findings with a "
                                     f"detectable pattern are supported.", 'supported': supported_finding_names(),
                            'request_id': getattr(g, 'rid', '-')}), 422
        return jsonify({'rules': [rule], 'skipped': [], 'yaml': rule['yaml']})
    findings = data.get('findings')
    if not isinstance(findings, list) or not findings:
        return _bad('Provide "finding" (object) or "findings" (non-empty array)')
    out = generate_sigma_rules(findings[:SIGMA_MAX_FINDINGS], mode)
    if not out['rules']:
        return jsonify({'error': 'None of the supplied findings has a Sigma template.', 'skipped': out['skipped'],
                        'supported': supported_finding_names(), 'request_id': getattr(g, 'rid', '-')}), 422
    return jsonify(out)

@app.route('/api/summary', methods=['POST'])
def summary_route():
    """Body: {"result": <stored analysis result>, "defang": false}. Upgrades old saved results: returns the short
    summary (rebuilt only if missing) and the detailed, non-repetitive "Show details" blocks."""
    data = request.get_json(silent=True) or {}
    result = data.get('result')
    if not isinstance(result, dict) or not (isinstance(result.get('findings'), list) or result.get('verdict')):
        return _bad('Provide "result": an analysis result object (with "findings" / "verdict")')
    summary = result.get('exec_summary') if isinstance(result.get('exec_summary'), dict) and result['exec_summary'].get('headline')         else build_exec_summary(result)
    details = build_summary_details({**result, 'exec_summary': summary}, defang=data.get('defang') is True)
    return jsonify({'exec_summary': {k: v for k, v in summary.items() if k != 'details'}, 'details': details})

@app.route('/api/diagram', methods=['POST'])
def diagram_route():
    """Body: {"result": <analysis result>, "theme": "dark"|"print", "defang": false}.
    Returns {type, title, nodes[], edges[], svg, mermaid, killchain_svg} built only from the supplied result."""
    data = request.get_json(silent=True) or {}
    result = data.get('result')
    if not isinstance(result, dict) or not result.get('mode'):
        return _bad('Provide "result": an analysis result object (with "mode")')
    theme = data.get('theme') if data.get('theme') in ('dark', 'print') else 'dark'
    out = build_diagram(result, theme, defang=data.get('defang') is True)
    out['killchain_svg'] = build_killchain_svg(result, theme)
    return jsonify(out)

@app.route('/api/report', methods=['POST'])
def report_route():
    """Body: {"result": <analysis result>, "format": "md"|"html", "defang": true, "include_sigma": true}.
    Returns the write-up as a downloadable document built only from the supplied result."""
    data = request.get_json(silent=True) or {}
    result = data.get('result')
    if not isinstance(result, dict) or not (isinstance(result.get('findings'), list) or result.get('verdict')):
        return _bad('Provide "result": an analysis result object (with "findings" / "verdict")')
    fmt = str(data.get('format') or 'md').lower()
    if fmt not in ('md', 'markdown', 'html'):
        return _bad('"format" must be "md" or "html"')
    fmt = 'html' if fmt == 'html' else 'md'
    body = build_report(result, fmt, defang=data.get('defang', True) is not False,
                        include_sigma=data.get('include_sigma', True) is not False, app_version=APP_VERSION)
    resp = app.response_class(body, mimetype='text/html' if fmt == 'html' else 'text/markdown')
    resp.headers['Content-Disposition'] = f'attachment; filename="{report_filename(result, fmt)}"'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp

# ─── SYSTEM / QA ENDPOINTS ───────────────────────────────────
@app.route('/api/system/status')
def system_status():
    return jsonify({
        'version': APP_VERSION, 'uptime_seconds': uptime_seconds(), 'db_path': DB_PATH,
        'keys_configured': {k: bool(os.getenv(k)) for k in ('VIRUSTOTAL_API_KEY', 'ABUSEIPDB_API_KEY', 'ABUSECH_API_KEY', 'URLSCAN_API_KEY', 'OTX_API_KEY', 'DEEPSEEK_API_KEY', 'GEMINI_API_KEY', 'OPENROUTER_API_KEY')},
        'ai_providers': configured_providers(),
        'auth_required': os.getenv('REQUIRE_API_KEY') == '1', 'rate_limit_per_min': RATE_LIMIT_PER_MIN,
        'external_api_stats': api_stats(), 'recent_error_count': len(recent_errors(200)),
    })

@app.route('/api/system/logs')
def system_logs():
    return jsonify({'logs': recent_logs(_int_arg('limit', 100, 1, 500), request.args.get('level', ''))})

@app.route('/api/system/errors')
def system_errors():
    return jsonify({'errors': recent_errors(_int_arg('limit', 50, 1, 200)), 'external_api_stats': api_stats()})

@app.route('/api/openapi.json')
def openapi_spec():
    return jsonify(build_openapi())

@app.route('/api/postman.json')
def postman_collection():
    return jsonify(build_postman())

# ─── CASE RETRIEVAL ──────────────────────────────────────────
@app.route('/api/case/<case_id>')
def get_case(case_id):
    with get_db() as conn:
        row = conn.execute(
            'SELECT * FROM cases WHERE case_number = ?', (case_id,)
        ).fetchone()
    if not row:
        return _bad('Analysis not found', 404)
    case = dict(row)
    try:
        case['findings'] = json.loads(case['findings'])
    except (TypeError, ValueError):
        pass
    return jsonify(case)

@app.route('/api/cases/stats')
def case_stats():
    with get_db() as conn:
        rows = conn.execute('SELECT verdict, COUNT(*) as cnt FROM cases GROUP BY verdict').fetchall()
        total = conn.execute('SELECT COUNT(*) as cnt FROM cases').fetchone()['cnt']
        today = conn.execute(
            "SELECT COUNT(*) as cnt FROM cases WHERE DATE(created_at) = DATE('now')"
        ).fetchone()['cnt']
    stats = {r['verdict']: r['cnt'] for r in rows}
    return jsonify({
        'total':      total,
        'malicious':  stats.get('MALICIOUS', 0) + stats.get('GUILTY', 0),
        'suspicious': stats.get('SUSPICIOUS', 0) + stats.get('PERSON OF INTEREST', 0),
        'benign':     stats.get('BENIGN', 0) + stats.get('CLEARED', 0),
        'today':      today,
    })

@app.route('/api/cases/recent')
def recent_cases():
    limit = _int_arg('limit', 10, 1, 50)
    with get_db() as conn:
        rows = conn.execute(
            'SELECT case_number, type, input, score, verdict, created_at FROM cases ORDER BY id DESC LIMIT ?',
            (limit,)
        ).fetchall()
    return jsonify({'cases': [dict(r) for r in rows]})

@app.route('/api/cases/search')
def search_cases():
    q       = request.args.get('q', '').strip()
    kind    = request.args.get('type', '').strip()
    verdict = request.args.get('verdict', '').strip()
    limit   = _int_arg('limit', 20, 1, 100)

    sql    = 'SELECT case_number, type, input, score, verdict, created_at FROM cases WHERE 1=1'
    params = []
    if q:
        sql    += ' AND input LIKE ?'
        params.append(f'%{q}%')
    if kind:
        sql    += ' AND type = ?'
        params.append(kind)
    if verdict:
        sql    += ' AND (verdict = ? OR verdict = ?)'
        legacy = {'MALICIOUS': 'GUILTY', 'SUSPICIOUS': 'PERSON OF INTEREST', 'BENIGN': 'CLEARED'}.get(verdict, verdict)
        params.extend([verdict, legacy])
    sql += ' ORDER BY id DESC LIMIT ?'
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(sql, params).fetchall()
    return jsonify({'cases': [dict(r) for r in rows]})

# ─── ANALYST TOOLS ───────────────────────────────────────────
def _readable(raw: bytes) -> str | None:
    """Decode bytes as text only if genuinely readable (UTF-8, or UTF-16LE as used by PowerShell), ≥90% printable."""
    for enc in ('utf-8', 'utf-16le'):
        if enc == 'utf-16le' and (len(raw) % 2 or b'\x00' not in raw):
            continue
        try:
            txt = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        if txt and sum(c.isprintable() or c in '\r\n\t' for c in txt) / len(txt) >= 0.9:
            return txt
    return None


@app.route('/api/tools/decode', methods=['POST'])
def tool_decode():
    """Cipher chain decoder: Base64 → Hex → URL → ROT13."""
    import base64, binascii, urllib.parse
    data  = request.get_json(silent=True) or {}
    text  = (data.get('text') or '').strip()
    if not text:
        return _bad('No text provided')
    if len(text) > 100_000:
        return _bad('Text too long (max 100,000 chars)')

    results = []

    # Base64 (standard or URL-safe). Strict alphabet + validation, so ordinary words are not "decoded" into noise.
    b64 = re.sub(r'\s', '', text)
    if len(b64) >= 4 and re.fullmatch(r'[A-Za-z0-9+/_\-]+={0,2}', b64):
        body = b64.rstrip('=').replace('-', '+').replace('_', '/')
        try:
            decoded = _readable(base64.b64decode(body + '=' * (-len(body) % 4), validate=True))
            if decoded:
                results.append({'method': 'BASE64', 'result': decoded})
        except (binascii.Error, ValueError):
            pass

    # Hex (tolerates 0x / \x prefixes and space, colon, comma or dash separators)
    hex_clean = re.sub(r'(?i)0x|\\x|[\s:,\-]', '', text)
    if re.fullmatch(r'[0-9a-fA-F]+', hex_clean) and len(hex_clean) % 2 == 0:
        decoded = _readable(bytes.fromhex(hex_clean))
        if decoded:
            results.append({'method': 'HEX', 'result': decoded})

    # URL decode
    url_decoded = urllib.parse.unquote(text)
    if url_decoded != text:
        results.append({'method': 'URL', 'result': url_decoded})

    # ROT13 (always reversible, so it is a candidate to eyeball rather than a confirmed encoding)
    rot13 = text.translate(str.maketrans(
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
        'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
    ))
    if rot13 != text:
        results.append({'method': 'ROT13', 'result': rot13})

    return jsonify({'results': results or [{'method': 'NONE', 'result': 'No decoding possible'}]})


# extensions that look like TLDs in "invoice.pdf" / "payload.exe" but are file names, not domains
_FILE_EXTS = {'exe', 'dll', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt', 'zip', 'rar', '7z', 'js', 'vbs',
              'ps1', 'bat', 'cmd', 'jpg', 'jpeg', 'png', 'gif', 'html', 'htm', 'php', 'py', 'sh', 'log', 'csv', 'json',
              'xml', 'eml', 'msi', 'iso', 'lnk', 'hta', 'scr', 'jar', 'tmp', 'dat', 'bin', 'docm', 'xlsm', 'svg', 'ini', 'cfg'}


@app.route('/api/tools/extract', methods=['POST'])
def tool_extract():
    """IOC extractor from raw text blob (deduplicated, validated)."""
    data = request.get_json(silent=True) or {}
    text = data.get('text') or ''
    if not text:
        return _bad('No text provided')
    text = text[:1_000_000]
    uniq = lambda xs: list(dict.fromkeys(xs))

    urls   = uniq(u.rstrip('.,;:!?)]}>\'"') for u in re.findall(r'(?:https?|hxxps?)://[^\s<>"\']+', text, re.I))
    emails = uniq(e.lower() for e in re.findall(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b', text))
    ips = []
    for cand in re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])', text):
        try:
            ipaddress.IPv4Address(cand)          # rejects 999.1.1.1 / leading-zero octets
            ips.append(cand)
        except ValueError:
            pass
    hashes = [h.lower() for h in re.findall(r'\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b', text)]
    email_domains = {e.split('@', 1)[1] for e in emails}
    domains = []
    for d in re.findall(r'(?<![@\w.\-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b', text):
        d = d.lower()
        if d.rsplit('.', 1)[-1] not in _FILE_EXTS and d not in email_domains:
            domains.append(d)
    return jsonify({'iocs': {'urls': urls, 'ips': uniq(ips), 'emails': emails, 'hashes': uniq(hashes), 'domains': uniq(domains)}})


@app.route('/api/tools/flagscan', methods=['POST'])
def tool_flagscan():
    """CTF flag pattern finder."""
    data  = request.get_json(silent=True) or {}
    text  = data.get('text') or ''
    if not text:
        return _bad('No text to search')

    patterns = [
        r'\b[A-Z][A-Z0-9_]{1,15}\{[^}\s]+\}',     # FLAG{..}, CTF{..}, picoCTF{..}, HTB{..}, THM{..}, XYZ_CTF{..}
        r'flag\{[^}]+\}',
    ]
    found = []
    for p in patterns:
        found.extend(re.findall(p, text, re.IGNORECASE))

    unique = list(dict.fromkeys(found))
    return jsonify({'flags': unique, 'count': len(unique)})


@app.route('/api/tools/hashcrack', methods=['POST'])
def tool_hashcrack():
    """Reverse MD5/SHA1/SHA256 digests of common passwords using an offline dictionary."""
    data     = request.get_json(silent=True) or {}
    hash_val = (data.get('hash') or '').strip().lower()
    if not hash_val:
        return _bad('No hash submitted')
    htype = hash_type(hash_val)
    if htype == 'unknown':
        return _bad('Not an MD5 (32), SHA-1 (40) or SHA-256 (64) hex digest')
    plaintext = reverse_hash(hash_val)
    return jsonify({
        'hash':      hash_val,
        'hash_type': htype,
        'found':     plaintext is not None,
        'plaintext': plaintext,
        'source':    f'offline dictionary of {len(COMMON_PLAINTEXTS)} common passwords',
    })

# ─── HELPERS ─────────────────────────────────────────────────
def _save_case(kind: str, input_val: str, result: dict):
    with get_db() as conn:
        cursor = conn.execute('''
            INSERT INTO cases
              (case_number, type, input, score, verdict, action, findings, created_at)
            VALUES (?,?,?,?,?,?,?,?)
        ''', (
            None,          # NULL until the id-based number is known (NULLs never collide on UNIQUE)
            kind,
            input_val,
            result.get('score', result.get('risk_score', 0)),
            result.get('verdict', result.get('classification', 'CLEARED')),
            result.get('recommended_action') or result.get('suggested_action', 'SAFE'),
            json.dumps(result.get('findings', [])),
            datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
        ))
        case_num = generate_case_number(cursor.lastrowid)
        conn.execute('UPDATE cases SET case_number=? WHERE id=?', (case_num, cursor.lastrowid))
    result['case_number'] = case_num
    
@app.route('/api/ai/analyze', methods=['POST'])
def ai_analyze():
    data     = request.get_json(silent=True) or {}
    mode     = str(data.get('mode', ''))
    input_val= data.get('input', '')
    findings = data.get('findings') if isinstance(data.get('findings'), list) else []
    verdict  = str(data.get('verdict', ''))
    try:
        score = int(data.get('score', 0) or 0)
    except (TypeError, ValueError):
        return _bad('score must be a number')

    if not input_val:
        return _bad('No input provided')

    out = generate_analysis(mode, input_val, findings, verdict, score)
    if not out['analysis']:
        # graceful offline fallback: deterministic explanation built from the score breakdown
        analysis = local_explanation({'findings': findings, 'verdict': verdict, 'score': score})
        return jsonify({'analysis': analysis, 'source': 'local', 'provider': '', 'errors': out['errors']})

    return jsonify({'analysis': out['analysis'], 'source': 'llm', 'provider': out['provider'],
                    'provider_label': out['provider_label'], 'errors': out['errors']})

# ─── MAIN ────────────────────────────────────────────────────
# init_db() must run on import too, not just when run directly -
# Vercel (and other serverless platforms) import `app` without
# ever executing the __main__ block below.
init_db()

if __name__ == '__main__':
    port  = int(os.getenv('PORT', 5003))
    debug = os.getenv('FLASK_DEBUG', '0') == '1'
    print(f"[PhishyLens] Threat Intelligence Workbench: http://localhost:{port}")
    app.run(debug=debug, host='0.0.0.0', port=port)
