'use strict';
// PhishyLens: Phase 1-3 UI additions (loaded after script.js; does not replace existing logic)

// pipeline labels for the new modes
PIPELINE_STEPS.logs    = ['Input Validation','Format Detection','Signature Scan','Behavioural Analysis','Risk Assessment','Final Report'];
PIPELINE_STEPS.network = ['Input Validation','Artifact Parsing','Service Triage','Scan Detection','Risk Assessment','Final Report'];

// ─── shared submit helper (JSON or multipart) ──────────────────
async function submitAnalysis(mode, endpoint, jsonBody, file, label) {
  const btnId = { logs: 'logs-btn', network: 'network-btn', email: 'email-btn' }[mode];
  const btn = btnId && document.getElementById(btnId);
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Analyzing…'; }
  addActivity('blue', `Starting ${mode.toUpperCase()} analysis: ${activityLabel(label)}`, { module: mode });
  const pipelinePromise = animatePipeline(mode);
  try {
    let res;
    if (file) {
      const fd = new FormData(); fd.append('file', file);
      res = await fetch(endpoint, { method: 'POST', body: fd });
    } else {
      res = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(jsonBody) });
    }
    const json = await res.json().catch(() => ({ error: 'Invalid server response' }));
    await pipelinePromise;
    if (!res.ok) {
      const rid = json.request_id ? ` (ref ${json.request_id})` : '';
      toast('Error: ' + (json.error || 'Analysis failed') + rid);
      addActivity('red', 'Analysis error: ' + (json.error || 'Unknown') + rid, { module: mode });
      return;
    }
    currentResult = json.result;
    renderResult(currentResult);
    saveHistory(mode, label, currentResult);
    loadStats(); loadHistory();
    const v = currentResult.verdict, sc = currentResult.score;
    addActivity(v === 'MALICIOUS' ? 'red' : v === 'SUSPICIOUS' ? 'yellow' : 'green', `${mode.toUpperCase()} analysis complete: ${v} (${sc}%) · ${activityLabel(label)}`,
                { module: mode, result: currentResult });
    document.getElementById('js-scan-id-label').textContent = currentResult.scan_id ? 'Scan ID: ' + currentResult.scan_id : '';
  } catch (e) {
    toast('Network error: ' + e.message);
    addActivity('red', 'Network error: ' + e.message, { module: mode });
  } finally {
    if (btn) { btn.disabled = false; btn.innerHTML = '<span class="btn-text">Analyze</span>'; }
  }
}

async function runForensics(mode) {
  const ta = document.getElementById(mode + '-input');
  const fileEl = document.getElementById(mode + '-file');
  const file = fileEl && fileEl.files && fileEl.files[0];
  const val = ta.value.trim();
  if (!val && !file) { toast('Paste data or choose a file to analyze.'); return; }
  if (file && file.size > 4 * 1024 * 1024) { toast('File too large (max 4 MB).'); fileEl.value = ''; return; }
  const endpoint = mode === 'logs' ? '/api/analyze/logs' : '/api/analyze/network';
  const body = mode === 'logs' ? { logs: val } : { data: val };
  await submitAnalysis(mode, endpoint, body, file, file ? file.name : val.substring(0, 60).replace(/\s+/g, ' '));
  if (fileEl) fileEl.value = '';
}

async function runEmailFile(inputEl) {
  const file = inputEl.files && inputEl.files[0];
  if (!file) return;
  if (file.size > 4 * 1024 * 1024) { toast('File too large (max 4 MB).'); inputEl.value = ''; return; }
  await submitAnalysis('email', '/api/analyze/email/upload', null, file, file.name);
  inputEl.value = '';
}

// ─── extra result sections (appended after the original renderResult) ───
const _origRenderResult = renderResult;
renderResult = function (r) {
  _origRenderResult(r);
  const el = document.getElementById('js-results');
  el.insertAdjacentHTML('afterbegin', exportBar());
  const extra = [
    scoreExplainSection(r.score_explanation),
    redirectSection(r.redirect_trace),
    emailForensicsSection(r.forensics),
    logSection(r.log_stats),
    networkSection(r.network_stats),
    enrichmentSection(r.enrichment),
  ].join('');
  // place new sections right after the "Risk Assessment" card (3rd .section-card) when possible
  const cards = el.querySelectorAll('.section-card');
  if (cards[2]) cards[2].insertAdjacentHTML('afterend', extra); else el.insertAdjacentHTML('beforeend', extra);
};

function sec(title, bodyHtml, badge = '', collapsed = false) {
  return `<div class="section-card ${collapsed ? 'collapsed' : ''}">
    <div class="section-header" onclick="toggleSection(this)"><span class="section-icon"></span>
      <span class="section-title">${escHtml(title)}</span>${badge ? `<span class="section-count">${escHtml(badge)}</span>` : ''}
      <span class="section-chevron">›</span></div>
    <div class="section-body">${bodyHtml}</div></div>`;
}
function kv(rows) {
  return `<table class="kv-table">${rows.filter(r => r[1]).map(r => `<tr><th>${escHtml(r[0])}</th><td>${richText(String(r[1]))}</td></tr>`).join('')}</table>`;
}
function authPill(v) {
  if (!v) return '<span class="pill na">not present</span>';
  const cls = v === 'pass' ? 'pass' : (['fail', 'permerror', 'temperror'].includes(v) ? 'fail' : 'warn');
  return `<span class="pill ${cls}">${escHtml(v)}</span>`;
}

function scoreExplainSection(x) {
  if (!x || !x.contributions || !x.contributions.length) return '';
  const max = Math.max(...x.contributions.map(c => c.points), 1);
  const rows = x.contributions.map(c => `
    <div class="xs-row" title="${escHtml(c.why || '')}">
      <div class="xs-label">${escHtml(c.label)}<small>${escHtml(c.evidence || c.severity)}</small></div>
      <div class="xs-track"><div class="xs-fill ${c.severity}" style="width:${Math.round(c.points / max * 100)}%"></div></div>
      <div class="xs-pts">+${c.points}%</div>
    </div>`).join('');
  return sec('Why This Score? (Explainable Breakdown)',
    rows + `<div class="xs-sum">${escHtml(x.contributions.map(c => '+' + c.points + '% ' + c.label).join('  ').substring(0, 400))}<br>= ${x.score}% total (contributions sum exactly to the final score)</div>`,
    `${x.contributions.length} factors`);
}

function redirectSection(t) {
  if (!t || !t.chain) return '';
  let body;
  if (t.blocked) body = `<p style="color:var(--warning)">⚠ ${escHtml(t.blocked)}</p>`;
  else if (!t.chain.length) body = '<p style="color:var(--text3)">No hops recorded.</p>';
  else body = `<div class="chain">${t.chain.map((h, i) =>
    `<div class="hop">#${i + 1} <strong>${escHtml(String(h.status))}</strong> ${escHtml(h.url)}${h.location ? `<div class="arrow">↳ Location: ${escHtml(h.location)}</div>` : ''}</div>`).join('')}</div>
    <p style="margin-top:8px"><strong>Final destination:</strong> ${richText(t.final_url)}</p>
    ${t.loop ? '<p style="color:var(--danger)">Redirect loop detected.</p>' : ''}${t.error ? `<p style="color:var(--text3)">Note: ${escHtml(t.error)}</p>` : ''}
    <p style="font-size:var(--fs-xs);color:var(--text3)">${escHtml(t.notes || '')}</p>`;
  return sec('URL Deep-Dive: Redirect Chain', body, `${t.hops} hop${t.hops !== 1 ? 's' : ''}`);
}

function emailForensicsSection(f) {
  if (!f || !f.parsed) return '';
  const a = f.auth || {};
  let b = `<div class="sub-title">Authentication Results</div>
    <p>SPF ${authPill(a.spf)} &nbsp; DKIM ${authPill(a.dkim)} &nbsp; DMARC ${authPill(a.dmarc)} ${a.arc ? '&nbsp; ARC ' + authPill(a.arc) : ''}</p>
    ${a.raw ? `<div class="raw-block" style="max-height:80px">${escHtml(a.raw)}</div>` : ''}
    <div class="sub-title">Header Artifacts</div>${kv(Object.entries(f.headers || {}).map(([k, v]) => [k, v]))}`;
  if ((f.origin_ips || []).length) b += `<div class="sub-title">Origin IPs</div><p>${f.origin_ips.map(ip => richText(ip)).join(', ')}</p>`;
  if ((f.received_chain || []).length) b += `<div class="sub-title">Received Chain (oldest → newest)</div><div class="chain">${f.received_chain.map((h, i) =>
    `<div class="hop">#${i + 1} ${escHtml(h.hop)}${h.ips.length ? `<div class="arrow">IPs: ${h.ips.map(escHtml).join(', ')}</div>` : ''}</div>`).join('')}</div>`;
  if ((f.attachments || []).length) b += `<div class="sub-title">Attachments</div><table class="kv-table"><tr><th>File</th><th>Type</th><th>Size</th><th>SHA-256</th></tr>${f.attachments.map(x =>
    `<tr><td>${escHtml(x.filename)} ${x.double_extension ? '<span class="pill fail">double ext</span>' : x.dangerous_ext ? '<span class="pill warn">risky</span>' : ''}</td><td>${escHtml(x.content_type)}</td><td>${x.size}</td><td>${escHtml(x.sha256)}</td></tr>`).join('')}</table>`;
  if ((f.html_link_mismatches || []).length) b += `<div class="sub-title">Link Text ≠ Destination</div>${kv(f.html_link_mismatches.map(m => [m.shown, m.actual]))}`;
  return sec('Email Forensics', b, a.spf || a.dkim || a.dmarc ? 'auth parsed' : '');
}

function logSection(s) {
  if (!s) return '';
  let b = `<p>Parsed <strong>${s.parsed_lines}</strong> of ${s.total_lines} lines; formats: ${Object.entries(s.formats || {}).map(([k, v]) => `${escHtml(k)} (${v})`).join(', ') || 'unknown'}${s.truncated ? ' <span class="pill warn">truncated</span>' : ''}</p>`;
  if (Object.keys(s.attack_counts || {}).length) b += `<div class="sub-title">Attack Types</div>${kv(Object.entries(s.attack_counts))}`;
  if ((s.top_sources || []).length) b += `<div class="sub-title">Top Sources</div><table class="kv-table"><tr><th>IP</th><th>Reqs</th><th>Attack hits</th><th>Failed logins</th><th>Types</th></tr>${s.top_sources.map(t =>
    `<tr><td>${richText(t.ip)}</td><td>${t.requests}</td><td>${t.attack_hits}</td><td>${t.failed_logins}</td><td>${escHtml((t.attack_types || []).join(', '))}</td></tr>`).join('')}</table>`;
  if ((s.powershell_decoded || []).length) b += `<div class="sub-title">Decoded PowerShell (-EncodedCommand)</div>${s.powershell_decoded.map(d => `<div class="cmd-block"><span class="cmd-line">line ${d.line}</span> ${escHtml(d.decoded)}</div>`).join('')}`;
  if ((s.sample_hits || []).length) b += `<div class="sub-title">Flagged Lines</div><table class="kv-table"><tr><th>Line</th><th>Sev</th><th>Type</th><th>Evidence</th></tr>${s.sample_hits.map(h =>
    `<tr><td>${h.line}</td><td>${richText(h.severity)}</td><td>${escHtml(h.type)}</td><td><code class="logline">${markLogLine(h.evidence, h.type)}</code></td></tr>`).join('')}</table>`;
  return sec('Log Analysis Dashboard', b, `${(s.sample_hits || []).length} hits`);
}

function networkSection(n) {
  if (!n) return '';
  let b = '';
  if ((n.hosts || []).length) b += `<div class="sub-title">Hosts</div><table class="kv-table"><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Open ports</th></tr>${n.hosts.map(h =>
    `<tr><td>${richText(h.ip)}</td><td>${richText(h.hostname)}</td><td>${escHtml(h.os)}</td><td>${h.open_ports}</td></tr>`).join('')}</table>`;
  if ((n.ports || []).length) b += `<div class="sub-title">Open Ports</div><table class="kv-table"><tr><th>Host</th><th>Port</th><th>Service</th><th>Version</th></tr>${n.ports.map(p =>
    `<tr><td>${richText(p.host)}</td><td>${p.port}/${escHtml(p.proto)}</td><td>${escHtml(p.service)}</td><td>${escHtml(p.version)}</td></tr>`).join('')}</table>`;
  const pk = n.packets || {};
  if (pk.packets) b += `<div class="sub-title">Packet Capture</div><p>${pk.packets} packets; protocols: ${Object.entries(pk.protocols || {}).map(([k, v]) => `${escHtml(k)} (${v})`).join(', ')}</p>
    ${(pk.top_talkers || []).length ? kv(pk.top_talkers.map(t => [t[0], t[1] + ' packets'])) : ''}`;
  return sec('Network Artifact Triage', b || '<p style="color:var(--text3)">No structured data parsed.</p>');
}

function enrichmentSection(e) {
  if (!e || (!(e.ips || []).length && !(e.hashes || []).length)) return '';
  const rows = [...(e.ips || []), ...(e.hashes || [])].map(x => `<tr><td>${richText(x.indicator)}</td><td>${x.type}</td>
    <td>${x.reputation_score == null ? 'n/a' : x.reputation_score}</td><td>${escHtml(x.verdict === 'UNKNOWN' ? 'UNKNOWN (no reputation source available)' : x.verdict || '')}</td>
    <td>${x.abuseipdb_score != null ? 'AbuseIPDB ' + x.abuseipdb_score + '% (' + (x.abuseipdb_reports || 0) + ' reports)' : ''} ${x.vt_total ? 'VT ' + x.vt_malicious + '/' + x.vt_total : ''} ${escHtml(x.country || '')}</td></tr>`).join('');
  return sec('Automated Indicator Enrichment (VirusTotal · AbuseIPDB · OTX · abuse.ch)',
    `<table class="kv-table"><tr><th>Indicator</th><th>Type</th><th>Reputation</th><th>Verdict</th><th>Detail</th></tr>${rows}</table>` +
    ((e.skipped_private || []).length ? `<p style="font-size:var(--fs-xs);color:var(--text3)">Private/non-routable IPs not queried: ${e.skipped_private.map(escHtml).join(', ')}</p>` : ''),
    `${(e.ips || []).length + (e.hashes || []).length} indicators`);
}

// ─── report export (JSON / Markdown) ───────────────────────────
function exportBar() {
  return `<div class="export-bar"><button class="btn-mini" onclick="exportReport('json')">⬇ Export JSON</button>
    <button class="btn-mini" onclick="exportReport('md')">⬇ Export Markdown</button></div>`;
}
function exportReport(kind) {
  const r = currentResult; if (!r) return;
  const stamp = (r.scan_id || r.mode || 'report') + '_' + Date.now();
  let blob, name;
  if (kind === 'json') { blob = new Blob([JSON.stringify(r, null, 2)], { type: 'application/json' }); name = `phishylens_${stamp}.json`; }
  else {
    const md = [`# PhishyLens Report: ${r.verdict} (${r.score}%)`, '', `- **Mode:** ${r.mode}`, `- **Input:** \`${String(r.input || '').substring(0, 200)}\``,
      `- **Scan ID:** ${r.scan_id || 'n/a'}`, `- **Generated:** ${new Date().toISOString()}`, '',
      ...(r.exec_summary && r.exec_summary.headline
        ? ['## Executive Summary', `**${r.exec_summary.headline}**`, '',
           ...((r.exec_summary.story || []).length
             ? r.exec_summary.story.flatMap(sec => [`### ${sec.title}`, sec.sentences.map(s => s.text).join(' '), ''])
             : [...(r.exec_summary.what_happened || []).map(b => `- ${b}`), '', r.exec_summary.why_it_matters || '', '']),
           ...(r.exec_summary.do_now || []).map(a => `- [ ] **${a.priority}:** ${a.action}`), '']
        : [`## Summary`, r.summary || '', '']),
      `## Score Breakdown`, ...((r.score_explanation && r.score_explanation.contributions) || []).map(c => `- +${c.points}% ${c.label} (${c.severity})`), '',
      `## Findings`, ...(r.findings || []).map(f => `### [${f.severity}] ${f.name}\n- Evidence: ${f.evidence || ''}\n- ${f.description || ''}\n- Fix: ${f.recommendation || ''}\n- Ref: ${f.reference || ''}\n`),
      `## Recommended Action`, r.recommended_action || ''].join('\n');
    blob = new Blob([md], { type: 'text/markdown' }); name = `phishylens_${stamp}.md`;
  }
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click(); URL.revokeObjectURL(a.href);
}

// ─── System Health view (Phase 3 QA) ───────────────────────────
async function showSystem(btn) {
  setActiveNav(btn || document.getElementById('nav-system'));
  const el = document.getElementById('js-results');
  el.innerHTML = '<div class="empty-state"><div class="empty-title">Loading system health…</div></div>';
  try {
    const getJson = url => fetch(url).then(r => r.json().then(j => { if (!r.ok) throw new Error(j.error || 'HTTP ' + r.status); return j; }));
    const [st, er] = await Promise.all([getJson('/api/system/status'), getJson('/api/system/errors?limit=30')]);
    const keys = Object.entries(st.keys_configured || {}).map(([k, v]) => `<tr><td>${escHtml(k)}</td><td>${v ? '<span class="pill pass">configured</span>' : '<span class="pill na">missing</span>'}</td></tr>`).join('');
    const api = Object.entries(st.external_api_stats || {}).map(([k, v]) => `<tr><td>${escHtml(k)}</td><td>${v.ok}</td><td>${v.fail}</td><td>${v.last_ms} ms</td><td>${escHtml(v.last_error || '')}</td></tr>`).join('');
    const errs = (er.errors || []).map(e => `<tr><td>${escHtml(e.ts)}</td><td>${escHtml(e.level)}</td><td>${escHtml(e.message)}</td></tr>`).join('');
    el.innerHTML =
      sec('System Status', kv([['Version', st.version], ['Uptime', st.uptime_seconds + ' s'], ['Auth required', st.auth_required], ['Rate limit / min', st.rate_limit_per_min], ['Recent errors', st.recent_error_count],
        ['AI providers (try order)', (st.ai_providers || []).join(' → ') || 'none: offline explanations only']]) +
        `<div class="sub-title">API Keys</div><table class="kv-table">${keys}</table>`) +
      sec('External API Health', api ? `<table class="kv-table"><tr><th>Service</th><th>OK</th><th>Failed</th><th>Last latency</th><th>Last error</th></tr>${api}</table>` : '<p style="color:var(--text3)">No external calls recorded yet on this instance.</p>') +
      sec('Error / Bug Tracker', errs ? `<table class="kv-table"><tr><th>Time (UTC)</th><th>Level</th><th>Message</th></tr>${errs}</table>` : '<p style="color:var(--success)">No errors recorded on this instance.</p>') +
      `<p style="font-size:var(--fs-xs);color:var(--text3)">Buffers are per serverless instance; use Vercel logs for long-term history. API docs: <a href="/api/openapi.json">/api/openapi.json</a> · Postman: <a href="/api/postman.json">/api/postman.json</a></p>`;
  } catch (e) { el.innerHTML = `<div class="empty-state"><div class="empty-title">Could not load system status</div><div class="empty-sub">${escHtml(e.message)}</div></div>`; }
}
