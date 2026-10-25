'use strict';
// PhishyLens: MITRE ATT&CK mapping UI (loaded after forensics.js; wraps renderResult, does not replace it)
// Data comes from result.mitre (utils/mitre_map.py), whose text is copied from MITRE's STIX bundle.

const ATTACK_SEV_SCORE = { CRITICAL: 100, HIGH: 75, MEDIUM: 50, LOW: 25 };
const ATTACK_SEV_RANK  = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
// compact column headers for the mini matrix (full tactic name stays in the tooltip)
const ATTACK_TACTIC_ABBR = {
  'Reconnaissance': 'Recon', 'Resource Development': 'Resource Dev', 'Initial Access': 'Initial Access',
  'Privilege Escalation': 'Priv Esc', 'Defense Impairment': 'Defense Impair', 'Defense Evasion': 'Defense Evasion',
  'Credential Access': 'Cred Access', 'Lateral Movement': 'Lateral Move', 'Command and Control': 'C2',
  'Exfiltration': 'Exfil', 'Persistence': 'Persist', 'Collection': 'Collect',
};

const _preAttackRenderResult = renderResult;
renderResult = function (r) {
  _preAttackRenderResult(r);
  const html = attackSection(r.mitre);
  if (!html) return;
  const el = document.getElementById('js-results');
  // after Evidence Correlation when present, otherwise after Detection Results
  const cards = [...el.querySelectorAll('.section-card')];
  const title = c => (c.querySelector('.section-title') || {}).textContent || '';
  const anchor = cards.find(c => title(c) === 'Evidence Correlation') || cards.find(c => title(c) === 'Detection Results');
  if (anchor) anchor.insertAdjacentHTML('afterend', html); else el.insertAdjacentHTML('beforeend', html);
};

function attackSection(m) {
  if (!m || !(m.techniques || []).length) return '';
  const techs = m.techniques;
  const body = `
    <div class="attack-head">
      <div class="attack-summary">
        ${m.attack_summary ? `<div class="attack-summary-text">${escHtml(m.attack_summary)}.</div>` : ''}
        <div class="attack-summary-meta">
          ${m.kill_chain_stage ? `<span>Furthest stage reached: <strong>${escHtml(m.kill_chain_stage)}</strong></span>` : ''}
          <span>${(m.tactics_hit || []).length} of ${(m.tactic_order || []).length || 15} tactics</span>
          ${m.attack_version ? `<span>ATT&amp;CK v${escHtml(m.attack_version)}</span>` : ''}
        </div>
      </div>
      <button type="button" class="btn-mini" onclick="exportNavigatorLayer()" title="Open in https://mitre-attack.github.io/attack-navigator/ → Open Existing Layer → Upload from local">
        ⬇ Export ATT&amp;CK Navigator layer (.json)
      </button>
    </div>
    ${attackMatrix(m)}
    <div class="sub-title">Techniques</div>
    <div class="attack-cards">${techs.map(attackCard).join('')}</div>`;
  return sec('ATT&CK Mapping', body, `${techs.length} technique${techs.length !== 1 ? 's' : ''}`)
    .replace('<div class="section-card ', '<div id="js-attack-section" class="section-card ');
}

function attackMatrix(m) {
  const order = (m.tactic_order && m.tactic_order.length) ? m.tactic_order : [...new Set(m.techniques.flatMap(t => t.tactics || [t.tactic]))];
  const byTactic = {};
  m.techniques.forEach(t => (t.tactics || [t.tactic]).forEach(tac => (byTactic[tac] = byTactic[tac] || []).push(t)));
  const cols = order.map(tac => {
    const list = byTactic[tac] || [];
    const worst = list.reduce((w, t) => (ATTACK_SEV_RANK[t.max_severity] || 0) > (ATTACK_SEV_RANK[w] || 0) ? t.max_severity : w, '');
    return `<div class="attack-col ${list.length ? 'hit sev-' + worst : ''}" title="${escHtml(tac)}: ${list.length} technique${list.length !== 1 ? 's' : ''}">
      <div class="attack-col-head">${escHtml(ATTACK_TACTIC_ABBR[tac] || tac)}</div>
      <div class="attack-col-count">${list.length || ''}</div>
      ${list.map(t => `<button type="button" class="attack-cell sev-${escHtml(t.max_severity || 'LOW')}" onclick="focusTechnique('${escHtml(t.id)}')" title="${escHtml(t.id + ' ' + t.name)}">${escHtml(t.id).replace('.', '<wbr>.')}</button>`).join('')}
    </div>`;
  }).join('');
  return `<div class="attack-matrix-wrap"><div class="attack-matrix" style="--cols:${order.length}">${cols}</div></div>
    <div class="attack-legend"><span class="sev-CRITICAL">Critical</span><span class="sev-HIGH">High</span><span class="sev-MEDIUM">Medium</span><span class="sev-LOW">Low</span><span class="muted">Column colour = highest-severity evidence for that tactic</span></div>`;
}

function attackCard(t) {
  const det = (t.detection || []).map(d => `
    <li>${d.url ? `<a href="${escHtml(d.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${escHtml(d.id)}</a> ` : ''}<strong>${escHtml(d.name)}</strong>
      ${(d.analytics || []).length ? `<ul>${d.analytics.map(a => `<li>${escHtml(a)}</li>`).join('')}</ul>` : ''}</li>`).join('');
  const mit = (t.mitigations || []).map(x => `
    <li><a href="${escHtml(x.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${escHtml(x.id)}</a> <strong>${escHtml(x.name)}</strong>${x.description ? `; ${escHtml(x.description)}` : ''}</li>`).join('');
  return `
  <div class="attack-card sev-${escHtml(t.max_severity || 'LOW')}" id="attack-${escHtml(t.id)}" role="button" tabindex="0" aria-expanded="false"
       onclick="toggleAttackCard(this)" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();toggleAttackCard(this)}">
    <div class="attack-card-top">
      <span class="attack-id">${escHtml(t.id)}</span>
      <span class="attack-name">${escHtml(t.name)}</span>
      <span class="section-chevron">›</span>
    </div>
    <div class="attack-chips">
      ${(t.tactics || [t.tactic]).map((tac, i) => `<span class="attack-tactic${i ? ' secondary' : ''}">${escHtml(tac)}</span>`).join('')}
    </div>
    ${confidenceMeter(t)}
    <div class="attack-desc">${richText(t.description || '')}</div>
    <div class="attack-detail">
      <div class="attack-label">Evidence in this scan</div>
      <div class="corr-indicators">${(t.evidence_findings || []).map(f => `<span class="corr-indicator">${escHtml(f)}</span>`).join('')}</div>
      <div class="attack-label">Detection</div>
      ${det ? `<ul class="attack-list">${det}</ul>` : '<p class="attack-none">No detection strategy listed by MITRE for this technique.</p>'}
      <div class="attack-label">Mitigations</div>
      ${mit ? `<ul class="attack-list">${mit}</ul>` : '<p class="attack-none">MITRE lists no mitigations for this technique.</p>'}
    </div>
    <a class="attack-link" href="${escHtml(t.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">Open on MITRE ↗</a>
  </div>`;
}

function confidenceMeter(t) {
  if (t.confidence == null) return '';
  const c = Math.max(0, Math.min(100, Number(t.confidence) || 0));
  const band = c >= 80 ? 'high' : c >= 60 ? 'med' : 'low';
  const tip = `Confidence ${c}/100. ${t.confidence_explanation || ''} Method: strongest supporting finding's confidence, +5 per additional independent finding (max +15), capped at 95.`;
  return `<div class="conf-meter ${band}" title="${escHtml(tip)}" aria-label="${escHtml(tip)}">
      <span class="conf-meter-label">Confidence</span>
      <span class="conf-meter-track"><span class="conf-meter-fill" style="width:${c}%"></span></span>
      <span class="conf-meter-num">${c}</span>
    </div>`;
}

function toggleAttackCard(card, force) {
  const open = typeof force === 'boolean' ? force : !card.classList.contains('open');
  card.classList.toggle('open', open);
  card.setAttribute('aria-expanded', String(open));
}

function focusTechnique(id) {
  const card = document.getElementById('attack-' + id);
  if (!card) return;
  toggleAttackCard(card, true);
  card.scrollIntoView({ behavior: 'smooth', block: 'center' });
  card.classList.remove('flash'); void card.offsetWidth; card.classList.add('flash');
}

// ─── ATT&CK Navigator layer export (layer format 4.5) ──────────
function buildNavigatorLayer(r) {
  const m = r.mitre || {};
  const techs = m.techniques || [];
  const entries = techs.map(t => ({
    techniqueID: t.id,
    score: ATTACK_SEV_SCORE[t.max_severity] || 25,
    color: '',
    comment: 'Evidence: ' + (t.evidence_findings || []).join('; '),
    enabled: true,
    metadata: [{ name: 'Max severity', value: t.max_severity || 'LOW' },
               ...(t.confidence != null ? [{ name: 'Confidence', value: String(t.confidence) }] : [])],
    links: [],
    showSubtechniques: false,
  }));
  // expand parents so sub-techniques are visible when the layer opens
  const parents = new Set(techs.filter(t => t.id.includes('.')).map(t => t.id.split('.')[0]));
  parents.forEach(pid => {
    const existing = entries.find(e => e.techniqueID === pid);
    if (existing) existing.showSubtechniques = true;
    else entries.push({ techniqueID: pid, color: '', comment: '', enabled: true, metadata: [], links: [], showSubtechniques: true });
  });
  return {
    name: `PhishyLens ${String(r.mode || '').toUpperCase()} ${r.scan_id || ''}`.trim(),
    versions: { attack: String(m.attack_version || '').split('.')[0] || undefined, navigator: '5.1.0', layer: '4.5' },
    domain: 'enterprise-attack',
    description: (m.attack_summary || '') + (r.input ? `; input: ${String(r.input).substring(0, 200)}` : ''),
    filters: { platforms: [...new Set(techs.flatMap(t => t.platforms || []))] },
    sorting: 3,
    layout: { layout: 'side', aggregateFunction: 'max', showID: true, showName: true, showAggregateScores: false, countUnscored: false, expandedSubtechniques: 'annotated' },
    hideDisabled: false,
    techniques: entries,
    gradient: { colors: ['#58a6ff', '#d29922', '#f85149'], minValue: 0, maxValue: 100 },
    legendItems: [
      { label: 'Critical evidence', color: '#f85149' }, { label: 'High evidence', color: '#e3742f' },
      { label: 'Medium evidence', color: '#d29922' }, { label: 'Low evidence', color: '#58a6ff' },
    ],
    metadata: [
      { name: 'Generated by', value: 'PhishyLens' },
      { name: 'Verdict', value: `${r.verdict || ''} (${r.score != null ? r.score + '%' : 'n/a'})` },
      { name: 'Generated at', value: new Date().toISOString() },
    ],
    links: [],
    showTacticRowBackground: true,
    tacticRowBackground: '#dddddd',
    selectTechniquesAcrossTactics: true,
    selectSubtechniquesWithParent: false,
    selectVisibleTechniques: false,
  };
}

function exportNavigatorLayer() {
  const r = currentResult;
  if (!r || !r.mitre || !(r.mitre.techniques || []).length) { toast('No ATT&CK techniques to export.'); return; }
  const layer = buildNavigatorLayer(r);
  const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `phishylens_attack_layer_${r.scan_id || r.mode || 'scan'}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast('Layer saved: open it in ATT&CK Navigator via "Open Existing Layer → Upload from local".');
}
