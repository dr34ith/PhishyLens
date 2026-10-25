'use strict';
// PhishyLens: "Visual Map" section: Attack Diagram | Kill Chain tabs, SVG/PNG download, Copy Mermaid.
// Diagrams come from POST /api/diagram (utils/diagrams.py: pure-Python SVG, every label XML-escaped server-side).
// Loaded after report.js and before defang.js, so the defang toggle also applies to diagram text.

const _preVisualRenderResult = renderResult;
let visualState = { diagram: null, token: 0, tab: 'attack' };

renderResult = function (r) {
  _preVisualRenderResult(r);
  const el = document.getElementById('js-results');
  if (!r || !r.mode || !el) return;
  const cards = [...el.querySelectorAll('.section-card')];
  const summary = cards.find(c => (c.querySelector('.section-title') || {}).textContent === 'Executive Summary');
  const anchor = el.querySelector('.insights-kc') || summary || el.querySelector('.overview-card');
  const html = sec('Visual Map', `
    <div class="vm-bar">
      <div class="vm-tabs" role="tablist" aria-label="Visual map views">
        <button type="button" role="tab" class="vm-tab active" id="vm-tab-attack" aria-selected="true" aria-controls="vm-pane-attack" onclick="showVisualTab('attack')">Attack Diagram</button>
        <button type="button" role="tab" class="vm-tab" id="vm-tab-kc" aria-selected="false" aria-controls="vm-pane-kc" onclick="showVisualTab('kc')">Kill Chain</button>
      </div>
      <div class="vm-actions">
        <button type="button" class="btn-mini" onclick="downloadVisual('svg')">⬇ Download SVG</button>
        <button type="button" class="btn-mini" onclick="downloadVisual('png')">⬇ Download PNG</button>
        <button type="button" class="btn-mini" id="vm-copy-mermaid" onclick="copyVisualMermaid()">⎘ Copy Mermaid</button>
      </div>
    </div>
    <div class="vm-pane" id="vm-pane-attack" role="tabpanel" aria-labelledby="vm-tab-attack"><div class="vm-loading">Building diagram…</div></div>
    <div class="vm-pane" id="vm-pane-kc" role="tabpanel" aria-labelledby="vm-tab-kc" hidden></div>
    <div class="vm-caption" id="vm-caption"></div>`).replace('<div class="section-card ', '<div id="js-visual-map" class="section-card ');
  if (anchor) anchor.insertAdjacentHTML('afterend', html); else el.insertAdjacentHTML('beforeend', html);
  loadVisualMap(r);
};

function _isServerSvg(s) {
  return typeof s === 'string' && s.startsWith('<svg xmlns="http://www.w3.org/2000/svg"') && !/<script|foreignobject|\son\w+=/i.test(s);
}

async function loadVisualMap(r) {
  const token = ++visualState.token;
  let d;
  try {
    const res = await fetch('/api/diagram', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ result: r, theme: document.documentElement.dataset.theme === 'light' ? 'print' : 'dark' }) });
    d = await res.json();
    if (!res.ok) throw new Error(d.error || res.status);
  } catch (e) {
    if (token === visualState.token) { const p = document.getElementById('vm-pane-attack'); if (p) p.innerHTML = `<div class="vm-loading">Diagram unavailable: ${escHtml(e.message)}</div>`; }
    return;
  }
  if (token !== visualState.token) return;                 // a newer result was rendered meanwhile
  visualState.diagram = d;
  const section = document.getElementById('js-visual-map');
  if (!section) return;
  const hasAttack = _isServerSvg(d.svg), hasKc = _isServerSvg(d.killchain_svg);
  if (!hasAttack && !hasKc) { section.remove(); return; }  // nothing to draw → skip the section silently
  document.getElementById('vm-pane-attack').innerHTML = hasAttack ? d.svg : '';
  document.getElementById('vm-pane-kc').innerHTML = hasKc ? d.killchain_svg : '';
  // natural size: never scale labels below 12px; wide diagrams scroll inside their own pane
  document.querySelectorAll('#vm-pane-attack svg, #vm-pane-kc svg').forEach(svg => {
    const vb = (svg.getAttribute('viewBox') || '').split(/\s+/).map(Number);
    if (vb[2]) { svg.style.width = vb[2] + 'px'; svg.style.height = 'auto'; }
  });
  document.getElementById('vm-tab-attack').hidden = !hasAttack;
  document.getElementById('vm-tab-kc').hidden = !hasKc;
  document.getElementById('vm-copy-mermaid').hidden = !d.mermaid;
  document.getElementById('vm-caption').textContent = hasAttack
    ? `${d.title}: ${d.nodes.length} nodes, ${d.edges.length} connections${(d.grouped || []).length ? ` (${d.grouped.length} grouped as "+more")` : ''}. Every node and edge comes from this result.`
    : '';
  showVisualTab(hasAttack ? (visualState.tab === 'kc' && hasKc ? 'kc' : 'attack') : 'kc');
}

function showVisualTab(tab) {
  visualState.tab = tab;
  ['attack', 'kc'].forEach(t => {
    const btn = document.getElementById('vm-tab-' + t), pane = document.getElementById('vm-pane-' + t);
    if (!btn || !pane) return;
    btn.classList.toggle('active', t === tab);
    btn.setAttribute('aria-selected', String(t === tab));
    pane.hidden = t !== tab;
  });
}

function _activeSvg() {
  const pane = document.getElementById(visualState.tab === 'kc' ? 'vm-pane-kc' : 'vm-pane-attack');
  return pane && pane.querySelector('svg');
}

function _saveBlob(blob, name) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function downloadVisual(kind) {
  const svg = _activeSvg();
  if (!svg) { toast('No diagram to download.'); return; }
  const r = currentResult || {};
  const base = `phishylens_${visualState.tab === 'kc' ? 'killchain' : 'diagram'}_${String(r.scan_id || r.mode || 'scan').replace(/[^A-Za-z0-9_-]/g, '')}`;
  const clone = svg.cloneNode(true);                      // serialise what is displayed (already defanged when the toggle is on)
  const vb = (clone.getAttribute('viewBox') || '0 0 1000 600').split(/\s+/).map(Number);
  clone.setAttribute('width', vb[2]); clone.setAttribute('height', vb[3]);
  clone.removeAttribute('style');
  const text = '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(clone);
  if (kind === 'svg') { _saveBlob(new Blob([text], { type: 'image/svg+xml' }), base + '.svg'); return; }
  const scale = 2;
  const img = new Image();
  const url = URL.createObjectURL(new Blob([text], { type: 'image/svg+xml' }));
  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = vb[2] * scale; canvas.height = vb[3] * scale;
    const ctx = canvas.getContext('2d');
    ctx.scale(scale, scale);
    ctx.drawImage(img, 0, 0, vb[2], vb[3]);
    URL.revokeObjectURL(url);
    canvas.toBlob(b => b ? _saveBlob(b, base + '.png') : toast('PNG export failed'), 'image/png');
  };
  img.onerror = () => { URL.revokeObjectURL(url); toast('PNG export failed'); };
  img.src = url;
}

function copyVisualMermaid() {
  const d = visualState.diagram;
  if (!d || !d.mermaid) { toast('No Mermaid code for this diagram.'); return; }
  copyText(d.mermaid);                                    // defang.js wraps copyText when the toggle is on
}
