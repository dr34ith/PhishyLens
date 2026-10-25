'use strict';
// PhishyLens v2: Threat Intelligence Workbench

// ─── STATE ─────────────────────────────────────────────────────
let currentTab   = 'url';
let currentResult = null;

// ─── TAB SWITCHING ─────────────────────────────────────────────
function switchTab(tab, btn) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-' + tab).classList.add('active');
}

// ─── PIPELINE STEPS ────────────────────────────────────────────
const PIPELINE_STEPS = {
  url:   ['Input Validation','URL Normalization','Threat Intelligence','Detection Engine','Risk Assessment','Final Report'],
  email: ['Input Validation','Header Parsing','URL Extraction','Threat Assessment','Risk Assessment','Final Report'],
  hash:  ['Input Validation','Hash Type Detection','Threat Intelligence','Database Lookup','Risk Assessment','Final Report'],
  ip:    ['Input Validation','IP Geolocation','Threat Intelligence','Reputation Check','Risk Assessment','Final Report'],
};

function showPipeline(mode) {
  const steps = PIPELINE_STEPS[mode] || PIPELINE_STEPS.url;
  const bar   = document.getElementById('js-pipeline');
  const stepsEl = document.getElementById('js-pipeline-steps');
  bar.classList.add('visible');

  stepsEl.innerHTML = steps.map((s, i) =>
    `<div class="pipeline-step" id="ps-${i}">
      <div class="step-dot"></div>${s}
     </div>${i < steps.length - 1 ? '<span class="step-arrow">›</span>' : ''}`
  ).join('');
}

async function animatePipeline(mode) {
  showPipeline(mode);
  const steps = PIPELINE_STEPS[mode] || PIPELINE_STEPS.url;
  for (let i = 0; i < steps.length; i++) {
    const el = document.getElementById('ps-' + i);
    if (el) el.classList.add('active');
    await sleep(300);
    if (el) { el.classList.remove('active'); el.classList.add('done'); }
  }
}

function hidePipeline() {
  document.getElementById('js-pipeline').classList.remove('visible');
}

// ─── ANALYSIS RUNNER ────────────────────────────────────────────
async function runAnalysis(mode) {
  const inputMap = { url: 'url-input', email: 'email-input', hash: 'hash-input', ip: 'ip-input' };
  const btnMap   = { url: 'url-btn',   email: 'email-btn',   hash: 'hash-btn',   ip: 'ip-btn'   };
  const fieldMap = { url: 'url',       email: 'raw',         hash: 'hash',       ip: 'ip'       };
  const endpointMap = { url: '/api/analyze/url', email: '/api/analyze/email', hash: '/api/analyze/hash', ip: '/api/analyze/ip' };

  const val = document.getElementById(inputMap[mode]).value.trim();
  if (!val) { toast('Please enter a value to analyze.'); return; }

  const btn = document.getElementById(btnMap[mode]);
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Analyzing…';

  setTicker('Running ' + mode.toUpperCase() + ' analysis on: ' + val.substring(0, 60) + '…');
  addActivity('blue', 'Starting ' + mode.toUpperCase() + ' analysis: ' + activityLabel(val), { module: mode });

  const pipelinePromise = animatePipeline(mode);

  try {
    const body = {};
    body[fieldMap[mode]] = val;
    const res  = await fetch(endpointMap[mode], {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    const json = await res.json();
    await pipelinePromise;

    if (!res.ok) {
      toast('Error: ' + (json.error || 'Analysis failed'));
      addActivity('red', 'Analysis error: ' + (json.error || 'Unknown error'), { module: mode });
      return;
    }

    currentResult = json.result;
    renderResult(currentResult);
    saveHistory(mode, val, currentResult);
    loadStats();
    loadHistory();

    const verdict = currentResult.verdict;
    const score   = currentResult.score;
    const dotColor = verdict === 'MALICIOUS' ? 'red' : verdict === 'SUSPICIOUS' ? 'yellow' : 'green';
    addActivity(dotColor, `${mode.toUpperCase()} analysis complete: ${verdict} (${score}%) · ${activityLabel(val)}`,
                { module: mode, result: currentResult });
    setTicker(`Last scan: ${val.substring(0,40)} · ${verdict} at ${score}%`);

    document.getElementById('js-scan-id-label').textContent =
      currentResult.scan_id ? 'Scan ID: ' + currentResult.scan_id : '';

  } catch (e) {
    toast('Network error: ' + e.message);
    addActivity('red', 'Network error: ' + e.message, { module: mode });
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span class="btn-text">Analyze</span>';
  }
}

// ─── RESULT RENDERING ────────────────────────────────────────────
function renderResult(r) {
  setActiveNav(document.getElementById('nav-main'));
  const el = document.getElementById('js-results');
  const verdict = normalizeVerdict(r.verdict);
  const score   = r.score || 0;
  const now     = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  const actionLabel = verdict === 'MALICIOUS' ? 'BLOCK'
                    : verdict === 'SUSPICIOUS' ? 'INVESTIGATE'
                    : 'SAFE';
  const actionClass = verdict === 'MALICIOUS' ? 'block'
                    : verdict === 'SUSPICIOUS' ? 'monitor'
                    : 'safe';

  const critCount = (r.findings || []).filter(f => f.severity === 'CRITICAL').length;
  const highCount = (r.findings || []).filter(f => f.severity === 'HIGH').length;
  const findCountClass = critCount > 0 ? 'red' : highCount > 0 ? 'yellow' : '';

  el.innerHTML = `
    <!-- Overview -->
    <div class="overview-card">
      <div class="risk-gauge">
        <div class="risk-circle ${verdict}">
          <span class="risk-score-num">${score}</span>
          <span class="risk-score-pct">/ 100</span>
        </div>
        <div class="risk-label ${verdict}">${verdict}</div>
      </div>
      <div class="overview-meta">
        <div class="overview-input">${escHtml(r.input || '')}</div>
        <div class="meta-grid">
          <div class="meta-item"><div class="meta-key">Mode</div><div class="meta-val">${r.mode?.toUpperCase() || ''}</div></div>
          <div class="meta-item"><div class="meta-key">Risk Score</div><div class="meta-val">${score}%</div></div>
          <div class="meta-item"><div class="meta-key">Confidence</div><div class="meta-val">${r.confidence != null ? r.confidence + '%' : 'n/a'}</div></div>
          <div class="meta-item"><div class="meta-key">Duration</div><div class="meta-val">${r.duration_ms != null ? r.duration_ms + ' ms' : 'n/a'}</div></div>
          <div class="meta-item"><div class="meta-key">Timestamp</div><div class="meta-val">${now}</div></div>
          ${r.scan_id ? `<div class="meta-item"><div class="meta-key">Scan ID</div><div class="meta-val">${escHtml(r.scan_id)}</div></div>` : ''}
          ${r.case_number ? `<div class="meta-item"><div class="meta-key">Case</div><div class="meta-val">${escHtml(r.case_number)}</div></div>` : ''}
        </div>
      </div>
      <div class="overview-action">
        <div class="action-badge ${actionClass}">${actionLabel}</div>
        <div class="action-text">${escHtml(r.recommended_action || '')}</div>
      </div>
    </div>

    <!-- Executive Summary -->
    <div class="section-card">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-icon"></span>
        <span class="section-title">Executive Summary</span>
        <span class="section-chevron">›</span>
      </div>
      <div class="section-body">
        <div class="exec-summary">${renderExecSummary(r)}</div>
      </div>
    </div>

    <!-- Detection Results -->
    <div class="section-card">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-icon"></span>
        <span class="section-title">Detection Results</span>
        <span class="section-count ${findCountClass}">${(r.findings||[]).length} finding${(r.findings||[]).length !== 1 ? 's' : ''}</span>
        <span class="section-chevron">›</span>
      </div>
      <div class="section-body">
        ${renderFindings(r.findings || [])}
      </div>
    </div>

    <!-- Risk Assessment / Score Breakdown -->
    <div class="section-card">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-icon"></span>
        <span class="section-title">Risk Assessment</span>
        <span class="section-chevron">›</span>
      </div>
      <div class="section-body">
        ${renderScoreBreakdown(r.risk_breakdown || [], score)}
      </div>
    </div>

    <!-- Evidence Correlation -->
    ${renderCorrelationSection(r.evidence_correlation || [])}

    <!-- Domain / Target Intelligence -->
    ${renderDomainSection(r.domain_info, r.mode)}

    <!-- Threat Intelligence Sources -->
    ${renderThreatIntelSection(r.intel_sources)}

    <!-- IOC Extraction -->
    ${renderIOCSection(r.iocs)}

    <!-- Analysis Timeline -->
    ${renderTimelineSection(r.timeline || [])}

    <!-- Raw Technical Data -->
    <div class="section-card collapsed">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-icon"></span>
        <span class="section-title">Raw Technical Data</span>
        <span class="section-chevron">›</span>
      </div>
      <div class="section-body">
        <div class="raw-block">${escHtml(JSON.stringify(r, null, 2))}</div>
      </div>
    </div>
  `;
}


function renderExecSummary(r) {
  if (r.exec_summary && r.exec_summary.headline) return renderStructuredSummary(r.exec_summary, r.verdict) + aiSectionHtml();
  // fallback for results saved before exec_summary existed
  const verdict  = normalizeVerdict(r.verdict);
  const score    = r.score || 0;
  const findings = r.findings || [];
  const critical = findings.filter(f => f.severity === 'CRITICAL');
  const high     = findings.filter(f => f.severity === 'HIGH');
  const medium   = findings.filter(f => f.severity === 'MEDIUM');
  const low      = findings.filter(f => f.severity === 'LOW');
  const mode     = (r.mode || '').toUpperCase();
  const input    = r.input || '';

  const verdictColor = verdict === 'MALICIOUS' ? 'var(--danger)'
                     : verdict === 'SUSPICIOUS' ? 'var(--warning)'
                     : 'var(--success)';

  let html = '';

  // Overview paragraph
  html += `<p>
    This analysis examined <strong class="mono">${escHtml(input)}</strong>
    as a <strong>${mode}</strong> indicator.
    The detection engine completed ${findings.length} check(s) and assigned a
    <strong style="color:${verdictColor}">${score}% risk score</strong>,
    resulting in a verdict of <strong style="color:${verdictColor}">${verdict}</strong>.
    ${verdict === 'MALICIOUS'
      ? 'This score places the indicator in the <strong style="color:var(--danger)">high-risk</strong> category: immediate action is warranted.'
      : verdict === 'SUSPICIOUS'
      ? 'This score places the indicator in the <strong style="color:var(--warning)">medium-risk</strong> category: further investigation is recommended.'
      : 'This score places the indicator in the <strong style="color:var(--success)">low-risk</strong> category: no immediate threat detected.'}
  </p>`;

  // Critical findings
  if (critical.length) {
    html += `<p><strong style="color:var(--danger)">⚠ Critical Findings (${critical.length})</strong><br>`;
    html += critical.map(f => {
      let d = `<strong>${escHtml(f.name)}</strong>`;
      if (f.evidence)       d += `; <span style="color:var(--text2)">${escHtml(f.evidence)}</span>`;
      if (f.description)    d += `. ${escHtml(f.description)}`;
      if (f.why_it_matters) d += ` <em style="color:var(--text3)">${escHtml(f.why_it_matters)}</em>`;
      return d;
    }).join('<br><br>');
    html += `</p>`;
  }

  // High findings
  if (high.length) {
    html += `<p><strong style="color:var(--warning)">▲ High-Severity Findings (${high.length})</strong><br>`;
    html += high.map(f => {
      let d = `<strong>${escHtml(f.name)}</strong>`;
      if (f.evidence)       d += `; <span style="color:var(--text2)">${escHtml(f.evidence)}</span>`;
      if (f.description)    d += `. ${escHtml(f.description)}`;
      if (f.why_it_matters) d += ` <em style="color:var(--text3)">${escHtml(f.why_it_matters)}</em>`;
      return d;
    }).join('<br><br>');
    html += `</p>`;
  }

  // Medium / Low
  if (medium.length || low.length) {
    const others = [...medium, ...low];
    html += `<p><strong>Additional Indicators (${others.length})</strong><br>`;
    html += others.map(f =>
      `<span style="color:var(--text3)">• ${escHtml(f.name)}${f.evidence ? ` (${escHtml(f.evidence)})` : ''}: ${escHtml(f.description || '')}</span>`
    ).join('<br>');
    html += `</p>`;
  }

  // Threat scenario
  const corr = (r.evidence_correlation || [])[0];
  if (corr) {
    html += `<p>
      <strong>Threat Scenario: ${escHtml(corr.scenario)}</strong><br>
      ${escHtml(corr.description)}
      ${corr.indicators && corr.indicators.length
        ? `<br><span style="color:var(--text3);font-size:var(--fs-xs);">Indicators: ${corr.indicators.map(i => escHtml(i)).join(' → ')}</span>`
        : ''}
      ${corr.mitre ? `<br><span style="font-size:var(--fs-xs);color:var(--text3)">${escHtml(corr.mitre)}</span>` : ''}
    </p>`;
  }

  // TI sources
  if (r.intel_sources && Object.keys(r.intel_sources).length) {
    const sources = Object.values(r.intel_sources);
    const active  = sources.filter(s => s.available);
    const failed  = sources.filter(s => !s.available && s.error);
    const noKey   = sources.filter(s => !s.available && !s.error);
    html += `<p><strong>Threat Intelligence Coverage</strong><br>`;
    if (active.length) {
      html += active.map(s => {
        const status = s.flagged ? `<span style="color:var(--danger)">⚠ FLAGGED</span>`
                     : s.pending ? `<span style="color:var(--warning)">… Submitted</span>`
                     : `<span style="color:var(--success)">✓ Not flagged</span>`;
        return `• <strong>${escHtml(s.source)}</strong>: ${status}: ${escHtml(s.detail || '')}`;
      }).join('<br>');
    } else {
      html += `<span style="color:var(--warning)">No threat-intelligence source returned a result; the verdict is based on local heuristics only.</span>`;
    }
    if (failed.length) {
      html += `<br><span style="color:var(--warning);font-size:var(--fs-xs);">Lookup failed: ${failed.map(s => escHtml(s.source + ' (' + s.error + ')')).join(', ')}</span>`;
    }
    if (noKey.length) {
      html += `<br><span style="color:var(--text3);font-size:var(--fs-xs);">Not queried (no API key): ${noKey.map(s => escHtml(s.source)).join(', ')}</span>`;
    }
    html += `</p>`;
  }

  // Recommended action
  if (r.recommended_action) {
    html += `<p style="border-left:3px solid ${verdictColor};padding-left:10px;margin-top:12px;">
      <strong>Recommended Action</strong><br>
      <span style="color:var(--info)">${escHtml(r.recommended_action)}</span>
    </p>`;
  }

  html += aiSectionHtml();
  return html;
}

// Deterministic summary built server-side (utils/summary.py): replaces the generic paragraph when present.
// Wrap the server-chosen key phrases (s.highlights: IOCs, counts, attack terms, urgent wording) in <mark>.
// Text is escaped first and phrases are matched in their escaped form, so nothing user-controlled becomes HTML.
function highlightText(text, highlights) {
  const safe = escHtml(text || '');
  const list = (highlights || []).filter(h => h && h.text).sort((a, b) => b.text.length - a.text.length);
  if (!list.length) return safe;
  const kindOf = {};
  list.forEach(h => { kindOf[escHtml(h.text)] = h.kind; });
  const rx = new RegExp(list.map(h => escHtml(h.text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'g');
  return safe.replace(rx, m => `<mark class="hl hl-${kindOf[m] || 'term'}">${m}</mark>`);
}

// ─── story (exec_summary.story): labelled paragraphs, certainty styling, ref chips ───
const STORY_SECTIONS = [['domain_info', 'Domain Intelligence', 'domain'], ['country', 'IP Intelligence', 'IP'], ['input', null, null],
  ['intel_sources', 'Threat Intelligence', 'intel'], ['score_explanation', 'Why This Score', 'score'], ['score', 'Why This Score', 'score'],
  ['forensics', 'Email Forensics', 'email'], ['log_stats', 'Log Analysis Dashboard', 'log'], ['network_stats', 'Network Artifact Triage', 'network'],
  ['redirect_trace', 'URL Deep-Dive', 'redirects'], ['enrichment', 'Automated Indicator Enrichment', 'enrichment'], ['findings', 'Detection Results', 'findings']];
const CERTAINTY_TITLE = { observed: 'Observed: a value present in the result', inferred: 'Inferred: a rule-based conclusion',
                          unknown: 'Could not be determined from this data' };

function storyRefChip(ref) {
  if (!ref || typeof ref !== 'object') return '';
  if (Number.isInteger(ref.finding)) return `<button type="button" class="st-ref" onclick="jumpStoryRef('finding', ${ref.finding})" aria-label="Go to the related finding">finding</button>`;
  if (Number.isInteger(ref.line)) return `<button type="button" class="st-ref" onclick="jumpStoryRef('line', ${ref.line})" aria-label="Go to log line ${ref.line}">line ${ref.line}</button>`;
  if (ref.ts) return `<button type="button" class="st-ref" onclick="jumpStoryRef('section', 'Log Analysis Dashboard')" aria-label="Go to the log section">log</button>`;
  const root = String(ref.field || '').split(/[.[]/)[0];
  const hit = STORY_SECTIONS.find(([k]) => k === root);           // whitelist: only known section titles reach onclick
  return hit && hit[1] ? `<button type="button" class="st-ref" onclick="jumpStoryRef('section', '${hit[1]}')" aria-label="Go to ${hit[1]}">${hit[2]}</button>` : '';
}

function jumpStoryRef(kind, val) {
  let el = null;
  const cardOf = prefix => [...document.querySelectorAll('#js-results .section-card')]
    .find(c => ((c.querySelector('.section-title') || {}).textContent || '').startsWith(prefix));
  if (kind === 'finding') {
    el = document.querySelector(`#js-results .finding-card[data-finding-index="${Number(val)}"]`);
    if (el) el.classList.add('open');
  } else if (kind === 'line') {
    const card = cardOf('Log Analysis Dashboard');
    if (card) el = [...card.querySelectorAll('tr')].find(tr => (tr.firstElementChild || {}).textContent === String(val))
                || [...card.querySelectorAll('.cmd-block')].find(b => (b.querySelector('.cmd-line') || {}).textContent === 'line ' + val) || card;
  } else {
    el = cardOf(String(val));
  }
  if (!el) return;
  const card = el.closest('.section-card');
  if (card) card.classList.remove('collapsed');
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.remove('st-flash'); void el.offsetWidth; el.classList.add('st-flash');
}

function renderStory(story, highlights) {
  const gloss = (html, s) => (typeof _gloss === 'function' ? _gloss(html, s.define) : html);
  return `<div class="story">${story.map(sec => `
      <section class="story-sec" data-section="${escHtml(sec.section)}">
        <div class="xsum-label">${escHtml(sec.title)}</div>
        <p class="story-p">${(sec.sentences || []).map(s => {
          const c = CERTAINTY_TITLE[s.certainty] ? s.certainty : 'observed';
          return `<span class="st st-${c}" title="${escHtml(CERTAINTY_TITLE[c])}">${gloss(richText(s.text, highlights), s)}${storyRefChip(s.ref)}</span>`;
        }).join(' ')}</p>
      </section>`).join('')}
      <p class="story-key"><span class="st st-observed">Observed</span> · <span class="st st-inferred">Inferred</span> · <span class="st st-unknown">Could not be determined</span></p>
    </div>`;
}

function renderStructuredSummary(s, verdict) {
  const prio = p => (p || '').toLowerCase().replace(/\s+/g, '-');
  const hl = t => richText(t, s.highlights);
  const hasStory = Array.isArray(s.story) && s.story.length;
  return `
    <div class="xsum" data-verdict="${escHtml(normalizeVerdict(verdict || ''))}">
      <p class="xsum-headline">${hl(s.headline)}</p>
      ${(s.key_facts || []).length ? `<div class="xsum-facts">${s.key_facts.map(f =>
        `<div class="xsum-fact"${f.title ? ` title="${escHtml(f.title)}"` : ''}><span>${escHtml(f.label)}</span><b>${escHtml(f.value)}</b></div>`).join('')}</div>` : ''}
      ${hasStory ? renderStory(s.story, s.highlights) : ''}
      ${!hasStory && (s.what_happened || []).length ? `<div class="xsum-label">What happened</div>
        <ul class="xsum-list">${s.what_happened.map(b => `<li>${hl(b)}</li>`).join('')}</ul>` : ''}
      ${!hasStory && s.why_it_matters ? `<div class="xsum-label">Why it matters</div><p class="xsum-why">${hl(s.why_it_matters)}</p>` : ''}
      ${(s.do_now || []).length ? `<div class="xsum-label">Do now</div>
        <ol class="xsum-actions">${s.do_now.map(a =>
          `<li><span class="xsum-prio ${prio(a.priority)}">${escHtml(a.priority)}</span><span>${richText(a.action)}</span></li>`).join('')}</ol>` : ''}
    </div>`;
}

function aiSectionHtml() {
  return `
    <div id="ai-section" style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px;">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
        <span style="font-size:var(--fs-xs);font-weight:600;color:var(--text);">Analyst Narrative</span>
        <button onclick="generateAI()" id="ai-btn"
          style="padding:4px 12px;background:var(--accent);color:#fff;border:none;border-radius:5px;font-size:var(--fs-xs);font-weight:600;cursor:pointer;font-family:inherit;">
          Generate Analysis
        </button>
        <span class="ai-note">AI write-up via DeepSeek / Gemini / OpenRouter (whichever key is set), otherwise an offline score explanation</span>
      </div>
      <div id="ai-result" class="ai-result" style="display:none;"></div>
    </div>`;
}

async function generateAI() {
  if (!currentResult) return;
  const btn = document.getElementById('ai-btn');
  const out  = document.getElementById('ai-result');
  if (!btn || !out) return;

  btn.disabled = true;
  btn.textContent = 'Analyzing…';
  out.style.display = 'block';
  out.textContent = 'Generating analysis…';

  try {
    const r = await fetch('/api/ai/analyze', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode:     currentResult.mode,
        input:    currentResult.input,
        findings: currentResult.findings,
        verdict:  currentResult.verdict,
        score:    currentResult.score,
      }),
    });
    const d = await r.json();
    if (d.analysis) {
      const failed = (d.errors || []).length ? ` Failed: ${d.errors.join('; ')}.` : '';
      out.innerHTML = richText(d.analysis + (d.source === 'local'
        ? `\n\n(Offline explanation: no AI provider answered.${failed} Set DEEPSEEK_API_KEY or GEMINI_API_KEY in .env for a full narrative.)`
        : `\n\nGenerated by ${d.provider_label || 'LLM'}.${failed ? ' Fallback used after:' + failed.replace(' Failed:', '') : ''} AI output can be wrong; verify against the findings above.`));
      btn.textContent = '✓ Done';
    } else {
      out.textContent = 'Error: ' + (d.error || 'AI unavailable');
      btn.disabled = false;
      btn.textContent = 'Retry';
    }
  } catch(e) {
    out.textContent = 'Network error: ' + e.message;
    btn.disabled = false;
    btn.textContent = 'Retry';
  }
}

function renderFindings(findings) {
  if (!findings.length) return '<div class="text-muted">No findings detected.</div>';

  const order  = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const rank   = s => order[s] ?? 3;   // not `|| 3`: CRITICAL's rank is 0, which is falsy
  const sorted = [...findings].sort((a, b) => rank(a.severity) - rank(b.severity));

  return `<div class="findings-list">${sorted.map((f, i) => `
    <div class="finding-card" id="fc-${i}" data-finding-index="${findings.indexOf(f)}">
      <div class="finding-header" onclick="toggleFinding(${i})">
        <span class="sev-badge ${f.severity}">${f.severity}</span>
        <span class="finding-name">${escHtml(f.name || '')}</span>
        ${f.confidence ? `<span class="conf-pill">${f.confidence}% conf.</span>` : ''}
        <span class="finding-chevron">›</span>
      </div>
      <div class="finding-body">
        ${f.evidence ? `<div class="finding-evidence">${evidenceHtml(f)}</div>` : ''}
        ${f.description ? `
          <div class="finding-detail">
            <div class="finding-detail-label">Description</div>
            <div class="finding-detail-text">${richText(f.description)}</div>
          </div>` : ''}
        ${f.why_it_matters ? `
          <div class="finding-detail">
            <div class="finding-detail-label">Why It Matters</div>
            <div class="finding-detail-text">${richText(f.why_it_matters)}</div>
          </div>` : ''}
        ${f.recommendation ? `
          <div class="finding-detail">
            <div class="finding-detail-label">Recommendation</div>
            <div class="finding-detail-text rec">${richText(f.recommendation)}</div>
          </div>` : ''}
        ${f.false_positive_possibility ? `
          <div class="finding-detail">
            <div class="finding-detail-label">False Positive Possibility</div>
            <div class="finding-detail-text">${richText(f.false_positive_possibility)}</div>
          </div>` : ''}
        ${f.reference ? `<div class="finding-ref">${richText(f.reference)}</div>` : ''}
      </div>
    </div>`).join('')}
  </div>`;
}

function renderScoreBreakdown(rows, score) {
  if (!rows.length) return '<div class="text-muted" style="font-size:var(--fs-xs);">No scoring data available.</div>';
  return `
    <table class="breakdown-table">
      <thead><tr>
        <th>Detection</th><th>Severity</th><th>Evidence</th><th>Points</th>
      </tr></thead>
      <tbody>
        ${rows.map(r => `<tr>
          <td>${escHtml(r.source || '')}</td>
          <td><span class="sev-badge ${r.severity}">${r.severity}</span></td>
          <td class="text-mono" style="font-size:var(--fs-xs);color:var(--text3);">${escHtml((r.detail||'').substring(0,40))}</td>
          <td class="breakdown-pts">${escHtml(r.points || '')}</td>
        </tr>`).join('')}
        <tr class="total-score-row">
          <td colspan="3">Final Risk Score (see "Why This Score?" for the exact attribution)</td>
          <td>${score}</td>
        </tr>
      </tbody>
    </table>`;
}

function renderCorrelationSection(correlations) {
  if (!correlations || !correlations.length) return '';
  return `
    <div class="section-card">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-icon"></span>
        <span class="section-title">Evidence Correlation</span>
        <span class="section-count yellow">${correlations.length} scenario${correlations.length !== 1 ? 's' : ''}</span>
        <span class="section-chevron">›</span>
      </div>
      <div class="section-body">
        ${correlations.map(c => `
          <div class="correlation-card">
            <div class="corr-title">
              ${escHtml(c.scenario || '')}
              <span class="corr-conf ${c.confidence}">${c.confidence} CONFIDENCE</span>
            </div>
            <div class="corr-desc">${escHtml(c.description || '')}</div>
            <div class="corr-indicators">
              ${(c.indicators || []).map(ind => `<span class="corr-indicator">${escHtml(ind)}</span>`).join('')}
            </div>
            ${c.mitre ? `<div class="corr-mitre">${escHtml(c.mitre)}</div>` : ''}
          </div>`).join('')}
      </div>
    </div>`;
}

function renderDomainSection(domainInfo, mode) {
  if (!domainInfo) return '';
  const title = mode === 'ip' ? 'IP Intelligence' : 'Domain Intelligence';
  const icon  = mode === 'ip' ? '' : '';

  const items = Object.entries(domainInfo).map(([k, v]) => `
    <div class="domain-item">
      <div class="domain-key">${escHtml(k.replace(/_/g,' '))}</div>
      <div class="domain-val">${escHtml(String(v || 'n/a'))}</div>
    </div>`).join('');

  return `
    <div class="section-card collapsed">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-icon">${icon}</span>
        <span class="section-title">${title}</span>
        <span class="section-chevron">›</span>
      </div>
      <div class="section-body">
        <div class="domain-grid">${items}</div>
      </div>
    </div>`;
}

function renderThreatIntelSection(sources) {
  if (!sources || !Object.keys(sources).length) return '';
  const cards = Object.values(sources).map(s => {
    let statusClass = 'no-key';
    let statusText  = 'Not queried: no API key configured';
    if (s.available && s.flagged)      { statusClass = 'flagged'; statusText = '⚠ Flagged'; }
    else if (s.available && s.pending) { statusClass = 'pending'; statusText = '… Submitted (verdict pending)'; }
    else if (s.available)              { statusClass = 'clean';   statusText = '✓ Not flagged'; }
    else if (s.error)                  { statusClass = 'error';   statusText = '✕ Lookup failed'; }

    const detail = s.detail || (!s.available && s.error ? s.error : '');
    return `<div class="intel-source-card">
      <div class="intel-source-name">${escHtml(s.source || '')}</div>
      <div class="intel-source-status ${statusClass}">${statusText}</div>
      ${detail ? `<div class="intel-source-detail">${escHtml(detail)}</div>` : ''}
      ${/^https:\/\//.test(s.result_url || '') ? `<div class="intel-source-detail"><a href="${escHtml(s.result_url)}" target="_blank" rel="noopener noreferrer">View result</a></div>` : ''}
    </div>`;
  }).join('');

  return `
    <div class="section-card collapsed">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-icon"></span>
        <span class="section-title">Threat Intelligence</span>
        <span class="section-chevron">›</span>
      </div>
      <div class="section-body">
        <div class="intel-sources-grid">${cards}</div>
      </div>
    </div>`;
}

function renderIOCSection(iocs) {
  if (!iocs) return '';
  const groups = Object.entries(iocs).filter(([, v]) => Array.isArray(v) && v.length > 0);
  if (!groups.length) return '';
  const total = groups.reduce((s, [, v]) => s + v.length, 0);

  return `
    <div class="section-card collapsed">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-icon"></span>
        <span class="section-title">Indicators of Compromise</span>
        <span class="section-count">${total} IOC${total !== 1 ? 's' : ''}</span>
        <span class="section-chevron">›</span>
      </div>
      <div class="section-body">
        ${groups.map(([type, items]) => `
          <div class="ioc-group">
            <div class="ioc-group-title">${type.toUpperCase()}</div>
            <div class="ioc-items">
              ${items.map(item => `
                <div class="ioc-item">
                  <span class="ioc-value">${richText(item)}</span>
                  <span class="ioc-copy" data-copy="${escHtml(item)}" onclick="copyText(this.dataset.copy)">⎘ copy</span>
                </div>`).join('')}
            </div>
          </div>`).join('')}
      </div>
    </div>`;
}

function renderTimelineSection(timeline) {
  if (!timeline.length) return '';
  return `
    <div class="section-card collapsed">
      <div class="section-header" onclick="toggleSection(this)">
        <span class="section-icon">⏱</span>
        <span class="section-title">Analysis Timeline</span>
        <span class="section-chevron">›</span>
      </div>
      <div class="section-body">
        <div class="timeline">
          ${timeline.map(t => `
            <div class="timeline-item">
              <div class="timeline-dot"></div>
              <div class="timeline-content">
                <div class="timeline-step">${escHtml(t.step || '')}</div>
                <div class="timeline-detail">${escHtml(t.detail || '')}</div>
              </div>
            </div>`).join('')}
        </div>
      </div>
    </div>`;
}

// ─── UI INTERACTIONS ────────────────────────────────────────────
function toggleSection(header) {
  header.closest('.section-card').classList.toggle('collapsed');
}

function toggleFinding(idx) {
  document.getElementById('fc-' + idx).classList.toggle('open');
}

function normalizeVerdict(v) {
  const map = { 'GUILTY': 'MALICIOUS', 'PERSON OF INTEREST': 'SUSPICIOUS', 'CLEARED': 'BENIGN' };
  return map[v] || v || 'BENIGN';
}

// ─── HISTORY ─────────────────────────────────────────────────────
function saveHistory(mode, val, result) {
  const history = getHistory();
  history.unshift({
    id:      Date.now(),
    mode,
    input:   val,
    verdict: normalizeVerdict(result.verdict),
    score:   result.score,
    ts:      new Date().toISOString(),
    case_number: result.case_number || '',
    result,
  });
  // full results (raw emails, log stats) can exceed the ~5 MB localStorage quota; shrink instead of failing
  for (const keep of [100, 50, 20, 5, 1]) {
    try { localStorage.setItem('pl_history', JSON.stringify(history.slice(0, keep))); return; }
    catch { /* quota exceeded; retry with fewer entries */ }
  }
}

function getHistory() {
  try { return JSON.parse(localStorage.getItem('pl_history') || '[]'); } catch { return []; }
}

function loadHistory() {
  renderHistoryList(getHistory());
}

function filterHistory(query) {
  const history = getHistory();
  if (!query) { renderHistoryList(history); return; }
  const q = query.toLowerCase();
  renderHistoryList(history.filter(h => String(h.input || '').toLowerCase().includes(q) || (h.verdict||'').toLowerCase().includes(q)));
}

function renderHistoryList(items) {
  const el = document.getElementById('js-history-list');
  if (!items.length) {
    el.innerHTML = '<div style="font-size:var(--fs-xs);color:var(--text3);padding:8px 4px;">No scans yet.</div>';
    return;
  }
  el.innerHTML = items.map(h => {
    const verdict = normalizeVerdict(h.verdict);
    const vClass  = verdict.replace(' ', '-');
    const date    = new Date(h.ts).toLocaleString('en-US', {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'});
    return `<div class="history-item" onclick="loadHistoryItem(${h.id})">
      <div class="history-item-top">
        <span class="history-verdict ${vClass}">${verdict}</span>
        <span class="history-input">${escHtml(h.input)}</span>
      </div>
      <div class="history-meta">${(h.mode||'').toUpperCase()} · ${h.score}% · ${date}</div>
    </div>`;
  }).join('');
}

async function loadHistoryItem(id) {
  const h = getHistory().find(x => x.id === id);
  if (!h) return;
  setActiveNav(document.getElementById('nav-main'));
  // entries restored from the server only hold a summary; fetch the saved case for its findings
  if (h.case_number && !(h.result.findings || []).length) {
    try {
      const r = await fetch('/api/case/' + encodeURIComponent(h.case_number));
      if (r.ok) {
        const c = await r.json();
        h.result = { ...h.result, findings: Array.isArray(c.findings) ? c.findings : [], recommended_action: c.action,
                     summary: `Saved case ${c.case_number} (${c.created_at} UTC). Only the findings were stored; re-run the analysis for full detail.` };
      }
    } catch { /* show what we have */ }
  }
  currentResult = h.result;
  renderResult(h.result);
}

// ─── STATS ────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch('/api/cases/stats');
    if (!r.ok) return;
    const d = await r.json();
    const total = d.total || 0;
    document.getElementById('js-stat-total').textContent     = total;
    document.getElementById('js-stat-malicious').textContent  = d.malicious || 0;
    document.getElementById('js-stat-suspicious').textContent = d.suspicious || 0;
    document.getElementById('js-stat-benign').textContent     = d.benign || 0;
    document.getElementById('js-total-count').textContent     = total;
  } catch { /* graceful degradation */ }
}

async function loadServerHistory() {
  try {
    const r = await fetch('/api/cases/recent?limit=30');
    if (!r.ok) return;
    const d = await r.json();
    if (d.cases && d.cases.length) {
      // Merge server history into local if local is empty
      const local = getHistory();
      if (!local.length) {
        const base = Date.now();
        const mapped = d.cases.map((c, i) => ({
          id:      base - i,                       // unique per entry so each one opens its own case
          mode:    c.type,
          input:   c.input,
          verdict: normalizeVerdict(c.verdict),
          score:   c.score,
          ts:      /Z|[+-]\d\d:\d\d$/.test(c.created_at) ? c.created_at : c.created_at + 'Z',   // stored as UTC
          case_number: c.case_number,
          result:  { verdict: c.verdict, score: c.score, mode: c.type, input: c.input, findings: [], case_number: c.case_number },
        }));
        try { localStorage.setItem('pl_history', JSON.stringify(mapped)); } catch { /* storage unavailable */ }
        renderHistoryList(mapped);
      }
    }
  } catch { /* graceful degradation */ }
}

// ─── ANALYST TOOLS ────────────────────────────────────────────────
async function runTool(tool) {
  const inputMap  = { decode: 'decode-input', extract: 'extract-input', hashcrack: 'hashcrack-input' };
  const resultMap = { decode: 'decode-result', extract: 'extract-result', hashcrack: 'hashcrack-result' };
  const endMap    = { decode: '/api/tools/decode', extract: '/api/tools/extract', hashcrack: '/api/tools/hashcrack' };
  const keyMap    = { decode: 'text', extract: 'text', hashcrack: 'hash' };

  const val   = document.getElementById(inputMap[tool]).value.trim();
  const resEl = document.getElementById(resultMap[tool]);
  if (!val) { toast('Please enter a value.'); return; }

  resEl.textContent = 'Processing…';
  resEl.classList.add('visible');

  try {
    const body = {};
    body[keyMap[tool]] = val;
    const r = await fetch(endMap[tool], {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const d = await r.json();

    if (!r.ok) {
      resEl.textContent = 'Error: ' + (d.error || 'Request failed');
    } else if (tool === 'decode' && d.results) {
      resEl.textContent = d.results.map(x => `[${x.method}] ${x.result}`).join('\n');
    } else if (tool === 'extract' && d.iocs) {
      const lines = [];
      for (const [type, items] of Object.entries(d.iocs)) {
        if (items.length) lines.push(`${type.toUpperCase()}: ${items.join(', ')}`);
      }
      resEl.textContent = lines.join('\n') || 'No IOCs found.';
    } else if (tool === 'hashcrack' && d) {
      resEl.textContent = d.found
        ? `[${d.hash_type}] Plaintext: "${d.plaintext}"\n(${d.source})`
        : `[${d.hash_type}] Not a common password; checked ${d.source}.`;
    } else {
      resEl.textContent = JSON.stringify(d, null, 2);
    }
  } catch (e) {
    resEl.textContent = 'Error: ' + e.message;
  }
}

// ─── ACTIVITY FEED ────────────────────────────────────────────────
const ACTIVITY_MAX = 50;
const ACTIVITY_MODULES = { url: 'URL', email: 'EMAIL', logs: 'LOGS', network: 'NET', hash: 'HASH', ip: 'IP' };
let activityEntries = [];   // newest first: { id, color, kind, text, time, module, result }
let activityFilter  = 'all';
let activitySeq     = 0;

// one-line preview of an indicator; raw emails/logs can be huge, so cap it rather than letting CSS clip it
function activityLabel(s, max = 160) {
  const t = String(s || '').replace(/\s+/g, ' ').trim();
  return t.length > max ? t.substring(0, max) + '…' : t;
}

// opts: { module:'url'|'email'|..., result: analysis result (makes the entry clickable) }
function addActivity(color, text, opts = {}) {
  const result  = opts.result || null;
  const verdict = result ? normalizeVerdict(result.verdict) : '';
  const kind = verdict === 'MALICIOUS'  ? 'malicious'
             : verdict === 'SUSPICIOUS' ? 'suspicious'
             : verdict                  ? 'benign'
             : color === 'red'          ? 'error' : 'info';
  activityEntries.unshift({
    id: ++activitySeq,
    color, kind, text, result,
    module: ACTIVITY_MODULES[opts.module] || (opts.module ? String(opts.module).toUpperCase() : ''),
    time: new Date().toLocaleTimeString('en-GB', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
  });
  if (activityEntries.length > ACTIVITY_MAX) activityEntries.length = ACTIVITY_MAX;
  renderActivity(activitySeq);
}

function renderActivity(newId) {
  const feed = document.getElementById('js-activity-feed');
  if (!feed) return;
  document.getElementById('js-activity-count').textContent = activityEntries.length;
  const shown = activityFilter === 'all' ? activityEntries : activityEntries.filter(e => e.kind === activityFilter);
  if (!shown.length) {
    feed.innerHTML = `<div class="activity-empty">${activityEntries.length ? 'No matching activity.' : 'No activity yet.'}</div>`;
    return;
  }
  feed.innerHTML = shown.map(e => `
    <div class="activity-item${e.result ? ' clickable' : ''}${e.id === newId ? ' is-new' : ''}" data-id="${e.id}"
         ${e.result ? `onclick="openActivityResult(${e.id})" role="button" tabindex="0" title="Reload this result"` : ''}>
      <div class="activity-dot ${escHtml(e.color)}"></div>
      <div class="activity-main">
        <div class="activity-meta">
          <span class="activity-time">${e.time}</span>
          ${e.module ? `<span class="activity-badge">${escHtml(e.module)}</span>` : ''}
        </div>
        <div class="activity-text">${escHtml(e.text)}</div>
      </div>
    </div>`).join('');
  if (newId) feed.scrollTop = 0;
}

function openActivityResult(id) {
  const e = activityEntries.find(x => x.id === id);
  if (!e || !e.result) return;
  currentResult = e.result;
  renderResult(e.result);
  const label = document.getElementById('js-scan-id-label');
  if (label) label.textContent = e.result.scan_id ? 'Scan ID: ' + e.result.scan_id : '';
}

function setActivityFilter(filter) {
  activityFilter = filter;
  document.querySelectorAll('.activity-chip').forEach(c => c.classList.toggle('active', c.dataset.filter === filter));
  renderActivity();
}

function clearActivity() {
  activityEntries = [];
  renderActivity();
}

function toggleActivityPanel(force) {
  const section = document.getElementById('js-activity-section');
  if (!section) return;
  const collapsed = typeof force === 'boolean' ? force : !section.classList.contains('collapsed');
  section.classList.toggle('collapsed', collapsed);
  document.getElementById('js-activity-toggle').setAttribute('aria-expanded', String(!collapsed));
  try { localStorage.setItem('pl_activity_collapsed', collapsed ? '1' : '0'); } catch { /* storage unavailable */ }
}

document.addEventListener('DOMContentLoaded', () => {
  try { if (localStorage.getItem('pl_activity_collapsed') === '1') toggleActivityPanel(true); } catch { /* storage unavailable */ }
  const feed = document.getElementById('js-activity-feed');
  if (feed) feed.addEventListener('keydown', ev => {
    const item = ev.target.closest && ev.target.closest('.activity-item.clickable');
    if (item && (ev.key === 'Enter' || ev.key === ' ')) { ev.preventDefault(); openActivityResult(Number(item.dataset.id)); }
  });
  if (!activityEntries.length) addActivity('blue', 'System ready. Submit an indicator to begin analysis.');
});

// ─── MISC VIEWS ─────────────────────────────────────────────────
function setActiveNav(btn) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  if (btn) btn.classList.add('active');
}

const EMPTY_STATE_HTML = `
  <div class="empty-state">
    <div class="empty-icon"></div>
    <div class="empty-title">No active analysis</div>
    <div class="empty-sub">Submit a URL, email, hash, IP address, log or network artifact to begin threat analysis.</div>
  </div>`;

function showMainView(btn) {
  setActiveNav(btn || document.getElementById('nav-main'));
  if (currentResult) renderResult(currentResult);
  else document.getElementById('js-results').innerHTML = EMPTY_STATE_HTML;
}

async function showStats(btn) {
  setActiveNav(btn || document.getElementById('nav-stats'));
  const el = document.getElementById('js-results');
  el.innerHTML = '<div class="empty-state"><div class="empty-title">Loading statistics…</div></div>';
  try {
    const [st, rc] = await Promise.all([
      fetch('/api/cases/stats').then(r => r.json()),
      fetch('/api/cases/recent?limit=25').then(r => r.json()),
    ]);
    const total = st.total || 0;
    const pct = n => total ? Math.round(n / total * 100) + '%' : '0%';
    const rows = (rc.cases || []).map(c => `<tr>
        <td>${escHtml(c.case_number || '')}</td><td>${escHtml((c.type || '').toUpperCase())}</td>
        <td><span class="history-verdict ${escHtml(normalizeVerdict(c.verdict))}">${escHtml(normalizeVerdict(c.verdict))}</span></td>
        <td>${c.score}</td><td>${escHtml(String(c.input || '').substring(0, 70))}</td><td>${escHtml(c.created_at || '')}</td></tr>`).join('');
    el.innerHTML =
      sec('Case Statistics', kv([
        ['Total cases', total], ['Today (UTC)', st.today || 0],
        ['Malicious', `${st.malicious || 0} (${pct(st.malicious || 0)})`],
        ['Suspicious', `${st.suspicious || 0} (${pct(st.suspicious || 0)})`],
        ['Benign', `${st.benign || 0} (${pct(st.benign || 0)})`],
      ]) + '<p style="font-size:var(--fs-xs);color:var(--text3)">Counts come from this server instance\'s case database (ephemeral on serverless hosts).</p>') +
      sec('Recent Cases', rows
        ? `<table class="kv-table"><tr><th>Case</th><th>Type</th><th>Verdict</th><th>Score</th><th>Input</th><th>Created (UTC)</th></tr>${rows}</table>`
        : '<p style="color:var(--text3)">No cases recorded yet.</p>', `${(rc.cases || []).length} shown`);
  } catch (e) {
    el.innerHTML = `<div class="empty-state"><div class="empty-title">Could not load statistics</div><div class="empty-sub">${escHtml(e.message)}</div></div>`;
  }
}

// ─── UTILITIES ───────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function setTicker(text) {
  const el = document.getElementById('js-scan-ticker');
  if (el) el.textContent = text.substring(0, 80);
}

function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 3000);
}

function copyText(text) {
  navigator.clipboard.writeText(text).then(() => toast('Copied to clipboard')).catch(() => toast('Copy failed'));
}

// ─── INIT ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadHistory();
  loadServerHistory();

  // Enter key submits
  ['url-input', 'hash-input', 'ip-input'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('keydown', e => { if (e.key === 'Enter') runAnalysis(currentTab); });
  });
});
