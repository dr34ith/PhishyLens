'use strict';
// PhishyLens: result insights UI: classification badge (loaded after mitre.js; wraps renderResult)

const _preInsightsRenderResult = renderResult;
renderResult = function (r) {
  _preInsightsRenderResult(r);
  const el = document.getElementById('js-results');
  const overview = el.querySelector('.overview-card');
  const badge = classificationBanner(r.classification, r);
  if (badge) {
    if (overview) overview.insertAdjacentHTML('afterend', badge);
    else el.insertAdjacentHTML('afterbegin', badge);
  }
  // kill chain sits right below the Executive Summary card (summary first, then where the attack got to)
  const kc = killChainBar(r.kill_chain);
  if (kc) {
    const summary = [...el.querySelectorAll('.section-card')].find(c => (c.querySelector('.section-title') || {}).textContent === 'Executive Summary');
    const anchor = summary || el.querySelector('#js-insights-top') || overview;
    if (anchor) anchor.insertAdjacentHTML('afterend', `<div class="insights-kc">${kc}</div>`);
    else el.insertAdjacentHTML('afterbegin', kc);
  }
  tagMalwareIocs(r.malware_family);
};

function classificationBanner(c, r) {
  if (!c || !c.primary) return '';
  const verdict = normalizeVerdict(r.verdict);
  const conf = Math.max(0, Math.min(100, Number(c.confidence) || 0));
  return `
  <div class="insights-top" id="js-insights-top">
    <div class="class-badge ${escHtml(verdict)}" title="${escHtml(c.rationale || '')}" tabindex="0" aria-label="Attack classification: ${escHtml(c.primary)}. ${escHtml(c.rationale || '')}">
      <div class="class-label">Attack Classification</div>
      <div class="class-primary">${escHtml(c.primary)}</div>
      <div class="class-meta">
        <span class="class-conf">${conf}% confidence</span>
        ${(c.secondary || []).map(s => `<span class="class-secondary">${escHtml(s)}</span>`).join('')}
      </div>
      <div class="class-rationale">${richText(c.rationale || '')}</div>
    </div>
    ${r.malware_family ? `<div class="mf-row">${malwareChip(r.malware_family, true)}</div>` : ''}
  </div>`;
}

// ─── malware family chip (only when ThreatFox / MalwareBazaar named one) ───
function malwareChip(m, detailed) {
  if (!m || !m.name) return '';
  const tip = `Malware family reported by ${m.source}${m.first_seen ? ', first seen ' + m.first_seen : ''}${m.indicator ? ' for ' + m.indicator : ''}`;
  return `<span class="mf-chip" title="${escHtml(tip)}">
      <span class="mf-icon" aria-hidden="true">☣</span><span class="mf-name">${escHtml(m.name)}</span>
      ${detailed ? `<span class="mf-src">${escHtml(m.source)}${m.first_seen ? ' · first seen ' + escHtml(m.first_seen) : ''}</span>
      ${(m.tags || []).map(t => `<span class="mf-tag">${escHtml(t)}</span>`).join('')}` : ''}
    </span>`;
}

function tagMalwareIocs(m) {
  if (!m || !(m.matches || []).length) return;
  const byIndicator = {};
  m.matches.forEach(x => { if (x.indicator) byIndicator[String(x.indicator).toLowerCase()] = x; });
  // IOC list items and enrichment table rows whose indicator text matches exactly
  document.querySelectorAll('#js-results .ioc-item, #js-results .kv-table td:first-child').forEach(el => {
    const node = el.classList.contains('ioc-item') ? (el.querySelector('.ioc-value') || el.firstChild) : el;
    const text = (node && node.textContent || '').trim().toLowerCase();
    const hit = byIndicator[text];
    if (hit && !el.querySelector('.mf-chip')) el.insertAdjacentHTML(el.classList.contains('ioc-item') ? 'afterbegin' : 'beforeend', ' ' + malwareChip(hit, false));
  });
}

// ─── kill chain bar ────────────────────────────────────────────
function killChainBar(k) {
  if (!k || !(k.stages || []).length) return '';
  const steps = k.stages.map((s, i) => `
    <button type="button" class="kc-step ${s.hit ? 'hit sev-' + escHtml(s.max_severity || 'LOW') : ''} ${s.name === k.furthest_stage ? 'furthest' : ''}"
            data-stage="${i}" onclick="showKillChainStage(${i})" aria-pressed="false"
            title="${escHtml(s.name)}: ${s.hit ? s.evidence.length + ' finding(s)' : 'no evidence'}">
      <span class="kc-num">${i + 1}</span>
      <span class="kc-name">${escHtml(s.name)}</span>
      <span class="kc-count">${s.hit ? s.evidence.length : '0'}</span>
    </button>`).join('');
  return `
  <div class="kc-card" id="js-kill-chain">
    <div class="kc-head">
      <span class="kc-title">Kill Chain</span>
      <span class="kc-reached">${k.furthest_stage ? `Attacker reached: <strong>${escHtml(k.furthest_stage)}</strong>` : 'No kill-chain stage evidenced'}</span>
    </div>
    <div class="kc-bar" role="group" aria-label="Kill chain stages">${steps}</div>
    <div class="kc-detail" id="js-kc-detail" hidden></div>
  </div>`;
}

function showKillChainStage(i) {
  const r = currentResult;
  const s = r && r.kill_chain && r.kill_chain.stages[i];
  const detail = document.getElementById('js-kc-detail');
  if (!s || !detail) return;
  const btns = document.querySelectorAll('#js-kill-chain .kc-step');
  const already = btns[i] && btns[i].getAttribute('aria-pressed') === 'true';
  btns.forEach(b => { b.classList.remove('selected'); b.setAttribute('aria-pressed', 'false'); });
  if (already) { detail.hidden = true; return; }
  btns[i].classList.add('selected'); btns[i].setAttribute('aria-pressed', 'true');
  detail.hidden = false;
  detail.innerHTML = s.hit
    ? `<div class="kc-detail-title">${escHtml(s.name)}: ${s.evidence.length} finding(s) via ${s.techniques.map(t => `<span class="kc-tech">${escHtml(t)}</span>`).join(' ')}</div>
       <div class="corr-indicators">${s.evidence.map(e => `<span class="corr-indicator">${escHtml(e)}</span>`).join('')}</div>`
    : `<div class="kc-detail-title">${escHtml(s.name)}: no findings map to this stage.</div>`;
}
