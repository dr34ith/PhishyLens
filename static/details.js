'use strict';
// PhishyLens: "Show details" under the Executive Summary (exec_summary.details from utils/summary_details.py).
// Everything is rendered through the escape-first highlighter (static/highlight.js). Loaded before defang.js.

const DETAILS_OPEN_KEY = 'pl_details_open';
const _detailsCache = {};                      // results saved before details existed: fetched once via /api/summary
const STATUS_CLASS = { 'Observed': 'observed', 'Possible': 'possible', 'Not evidenced': 'not-evidenced' };

const _preDetailsRenderResult = renderResult;
renderResult = function (r) {
  _preDetailsRenderResult(r);
  mountDetails(r);
};

function _detailsKey(r) { return String(r.scan_id || r.case_number || '') + '|' + String(r.input || '').slice(0, 80); }

function mountDetails(r) {
  if (!r) return;
  const det = r.exec_summary && r.exec_summary.details;
  if (det && det.blocks) { renderDetails(r, det); return; }
  const key = _detailsKey(r);
  if (_detailsCache[key]) { renderDetails(r, _detailsCache[key]); return; }
  if (_detailsCache[key] === null) return;                       // failed before: stay hidden
  fetch('/api/summary', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ result: r }) })
    .then(res => (res.ok ? res.json() : Promise.reject(res.status)))
    .then(d => {
      if (!d || !d.details) throw new Error('no details');
      _detailsCache[key] = d.details;
      if (r.exec_summary) r.exec_summary.details = d.details;
      if (currentResult === r) renderDetails(r, d.details);
    })
    .catch(() => { _detailsCache[key] = null; });               // hide silently
}

function _detailsOpen() { try { return localStorage.getItem(DETAILS_OPEN_KEY) === '1'; } catch { return false; } }

// glossary: first occurrence of each defined term gets <abbr title=…> (only in text segments, never inside tags)
function _gloss(html, defines) {
  if (!defines || !defines.length) return html;
  const parts = html.split(/(<[^>]+>)/);
  defines.forEach(df => {
    const rx = new RegExp('(^|[^\\w-])(' + _hlEsc(df.term).replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')(?![\\w-])', 'i');
    for (let i = 0; i < parts.length; i++) {
      if (parts[i].startsWith('<') || !rx.test(parts[i])) continue;
      parts[i] = parts[i].replace(rx, (m, a, b) => `${a}<abbr class="gloss" title="${_hlEsc(df.definition)}">${b}</abbr>`);
      break;
    }
  });
  return parts.join('');
}
const _rt = (text, it) => _gloss(richText(text || ''), it && it.define);
const _defs = it => (it.define || []).map(d => `<div class="xdef"><dfn>${_hlEsc(d.term)}</dfn>: ${_hlEsc(d.definition)}</div>`).join('');

function _moreBtn(b) {
  return b.more > 0 ? `<button type="button" class="xmore" onclick="toggleDetailsMore(this)" aria-expanded="false">+${Number(b.more)} more</button>` : '';
}
const _hid = (b, i) => (i >= b.visible ? ' xhidden' : '');

function _overview(b) {
  const w = b.window || {};
  const chips = Object.entries(b.chips || {}).map(([k, list]) => `<div class="xchips"><span class="xchips-label">${_hlEsc(k)}</span>${
    list.map(c => `<button type="button" class="xchip" onclick="jumpDetails('${_hlEsc(c.target_block)}', ${c.step ? Number(c.step) : 0}, this.textContent)">${richText(c.label)}</button>`).join('')}</div>`).join('');
  return `${w.first ? `<p class="xwindow">${_rt(b.items.find(i => i.kind === 'window')?.text || '', b.items.find(i => i.kind === 'window'))}</p>` : ''}
    ${b.items.filter(i => i.kind !== 'window').map((it, i) => `<p class="xline${_hid(b, i + (w.first ? 1 : 0))}">${_rt(it.text, it)}</p>`).join('')}
    ${chips}${_moreBtn(b)}`;
}

function _actors(b) {
  const cards = b.items.map((it, i) => `
    <div class="xactor${_hid(b, i)}" id="xactor-${_hlEsc(it.ip)}">
      <div class="xactor-head">${richText(it.ip)} <span class="xrole">${_hlEsc(it.role)}</span></div>
      ${Object.keys(it.counts || {}).length ? `<div class="xcounts">${Object.entries(it.counts).filter(([, v]) => v).map(([k, v]) =>
        `<span><b>${Number(v)}</b> ${_hlEsc(k.replace(/_/g, ' '))}</span>`).join('')}</div>` : ''}
      ${(it.tools || []).length ? `<div class="xmeta">Tools: ${it.tools.map(t => `<span class="hl hl-cmd">${_hlEsc(t)}</span>`).join(' ')}</div>` : ''}
      ${(it.attack_types || []).length ? `<div class="xmeta">Attack types: ${_hlEsc(it.attack_types.join(', '))}</div>` : ''}
      <div class="xrep ${/^Flagged/.test(it.reputation_state) ? 'flagged' : ''}">Reputation: ${_rt(it.reputation_state, it)}</div>
      ${_defs(it)}
    </div>`).join('');
  const t = b.targets || {};
  const targets = Object.entries(t).map(([k, vals]) => {
    const vis = (b.targets_visible || {})[k] || vals.length;
    return `<div class="xtargets"><span class="xchips-label">${_hlEsc(k)}</span>${vals.map((v, i) =>
      `<span class="xtarget${i >= vis ? ' xhidden' : ''}">${richText(v)}</span>`).join('')}${vals.length > vis ?
      `<button type="button" class="xmore" onclick="toggleDetailsMore(this)" aria-expanded="false">+${vals.length - vis} more</button>` : ''}</div>`;
  }).join('');
  return `${cards ? `<div class="xactors">${cards}</div>${_moreBtn(b)}` : ''}${targets ? `<div class="xsub">Targets</div>${targets}` : ''}`;
}

function _assessment(b) {
  return `<ul class="xassess">${b.items.map((it, i) => `
    <li class="${_hid(b, i).trim()}"><span class="xbadge ${STATUS_CLASS[it.status] || ''}">${_hlEsc(it.status)}</span>
      <div class="xassess-body"><div class="xq">${_rt(it.question, it)}</div><div class="xbasis">${_rt(it.basis, it)}</div>${_defs(it)}</div></li>`).join('')}</ul>${_moreBtn(b)}`;
}

function _story(b) {
  return `<ol class="xstory">${b.items.map((it, i) => `
    <li class="xstep${_hid(b, i)}" id="xstep-${Number(it.order)}">
      <span class="xstep-num" aria-hidden="true">${Number(it.order)}</span>
      <div class="xstep-body">
        <div class="xstep-meta">${it.when ? `<span class="xwhen">${_hlEsc(it.when)}</span>` : ''}${it.stage ? `<span class="xstage">${_hlEsc(it.stage)}</span>` : ''}${
          (it.technique_ids || []).map(t => `<span class="hl hl-mitre">${_hlEsc(t)}</span>`).join('')}</div>
        <div class="xwhat">${_rt(it.text, it)}</div>
        ${it.evidence ? `<code class="logline">${richText(it.evidence)}</code>` : ''}
        ${it.why ? `<div class="xwhy"><b>Why it matters:</b> ${_rt(it.why, it)}</div>` : ''}
        ${_defs(it)}
      </div></li>`).join('')}</ol>${_moreBtn(b)}<p class="xnote">Ordered by ${_hlEsc(b.ordered_by || 'time')}.</p>`;
}

function _confidence(b) {
  return `<ul class="xlist">${b.items.map((it, i) => `<li class="${_hid(b, i).trim()} xk-${_hlEsc(it.kind || '')}">${_rt(it.text, it)}${
    it.factors ? ` ${it.factors.map(f => `<span class="xfactor">${_hlEsc(f.label)} <b>+${Number(f.points)}</b></span>`).join('')}
      <button type="button" class="xlink" onclick="jumpToSection('Why This Score')">See the full breakdown</button>` : ''}${_defs(it)}</li>`).join('')}</ul>${_moreBtn(b)}`;
}

function _next(b) {
  const respond = b.items.filter(i => i.kind === 'respond'), inv = b.items.filter(i => i.kind === 'investigate');
  const idx = it => b.items.indexOf(it);
  const prio = p => String(p || '').toLowerCase().replace(/\s+/g, '-');
  return `${respond.length ? `<div class="xsub">Respond</div><ul class="xlist">${respond.map(it =>
      `<li class="${_hid(b, idx(it)).trim()}"><span class="xsum-prio ${prio(it.priority)}">${_hlEsc(it.priority)}</span> ${_rt(it.text, it)}</li>`).join('')}</ul>` : ''}
    ${inv.length ? `<div class="xsub">Investigate <span class="xguide">${_hlEsc(b.investigate_label || '')}</span></div><ul class="xlist">${inv.map(it =>
      `<li class="${_hid(b, idx(it)).trim()}">${_rt(it.text, it)}</li>`).join('')}</ul>` : ''}${_moreBtn(b)}`;
}

function _extras(b) {
  return `<ul class="xlist">${b.items.map((it, i) => `<li class="${_hid(b, i).trim()}">${_rt(it.text, it)}${
    it.code ? `<pre class="cmd-block">${_hlEsc(it.code)}</pre>` : ''}${_defs(it)}</li>`).join('')}</ul>${_moreBtn(b)}`;
}

const DETAIL_RENDERERS = { overview: _overview, actors_and_targets: _actors, assessment: _assessment, attack_story: _story,
                           confidence_and_limits: _confidence, next_steps: _next, mode_extras: _extras };

function renderDetails(r, det) {
  const card = [...document.querySelectorAll('#js-results .section-card')].find(c => (c.querySelector('.section-title') || {}).textContent === 'Executive Summary');
  const host = card && (card.querySelector('.xsum') || card.querySelector('.section-body'));
  if (!host) return;
  const old = document.getElementById('js-xdet');
  if (old) old.remove();
  const blocks = (det.blocks || []).filter(b => DETAIL_RENDERERS[b.key]);
  if (!blocks.length) return;
  const nd = (det.coverage || []).filter(c => /^Not determined/.test(c.answered_by)).map(c => c.question);
  const html = `
  <details class="xdet" id="js-xdet"${_detailsOpen() ? ' open' : ''}>
    <summary><span class="xdet-title">Show details</span><span class="xdet-meta">${blocks.length} sections</span></summary>
    <div class="xdet-tools" role="group" aria-label="Copy summary">
      <span class="xchips-label">Copy summary</span>
      <button type="button" class="btn-mini" onclick="copyDetailsFormat('plain')">Plain text</button>
      <button type="button" class="btn-mini" onclick="copyDetailsFormat('markdown')">Markdown</button>
      <button type="button" class="btn-mini" onclick="copyDetailsFormat('oneline')">One line</button>
    </div>
    ${blocks.map(b => `<section class="xblock" data-block="${_hlEsc(b.key)}"><h4 class="xblock-title">${_hlEsc(b.title)}</h4>${DETAIL_RENDERERS[b.key](b)}</section>`).join('')}
    ${nd.length ? `<p class="xnote">Not determined from this data: ${_hlEsc(nd.join('; '))}</p>` : ''}
  </details>`;
  host.insertAdjacentHTML('afterend', html);
  const el = document.getElementById('js-xdet');
  el.addEventListener('toggle', () => { try { localStorage.setItem(DETAILS_OPEN_KEY, el.open ? '1' : '0'); } catch { /* storage unavailable */ } });
}

function toggleDetailsMore(btn) {
  const scope = btn.closest('.xtargets') || btn.closest('.xblock');
  const open = btn.getAttribute('aria-expanded') !== 'true';
  scope.querySelectorAll('.xhidden, .xshown').forEach(n => { n.classList.toggle('xhidden', !open); n.classList.toggle('xshown', open); });
  btn.setAttribute('aria-expanded', String(open));
  btn.textContent = open ? 'Show less' : btn.dataset.label || btn.textContent;
  if (!btn.dataset.label && !open) btn.textContent = 'Show more';
  if (open && !btn.dataset.label) btn.dataset.label = btn.textContent;
}

function jumpDetails(block, step, label) {
  const el = step ? document.getElementById('xstep-' + step) : document.getElementById('xactor-' + String(label || '').trim()) ||
             document.querySelector(`.xblock[data-block="${block}"]`);
  if (!el) return;
  if (el.classList.contains('xhidden')) { const b = el.closest('.xblock').querySelector('.xmore'); if (b) toggleDetailsMore(b); }
  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
  el.classList.remove('flash'); void el.offsetWidth; el.classList.add('flash');
}

function jumpToSection(prefix) {
  const card = [...document.querySelectorAll('#js-results .section-card')].find(c => ((c.querySelector('.section-title') || {}).textContent || '').startsWith(prefix));
  if (card) { card.classList.remove('collapsed'); card.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
}

function copyDetailsFormat(fmt) {
  const r = currentResult;
  const det = (r && r.exec_summary && r.exec_summary.details) || (r && _detailsCache[_detailsKey(r)]);
  const text = det && det.copy && det.copy[fmt];
  if (!text) { toast('Nothing to copy.'); return; }
  copyText(typeof defangText === 'function' ? defangText(text) : text);   // server copy is already defanged + masked
}

// print: expand, then restore the reader's choice
window.addEventListener('beforeprint', () => document.querySelectorAll('details.xdet').forEach(d => { d.dataset.wasOpen = d.open ? '1' : '0'; d.open = true; }));
window.addEventListener('afterprint', () => document.querySelectorAll('details.xdet').forEach(d => { if (d.dataset.wasOpen === '0') d.open = false; }));
