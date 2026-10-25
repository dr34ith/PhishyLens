'use strict';
// PhishyLens: "Generate Sigma rule" on every finding card (loaded after insights.js; wraps renderResult)
// Rules come from POST /api/sigma (utils/sigma_gen.py); unsupported finding types get the server's 422 message.

const _preSigmaRenderResult = renderResult;
renderResult = function (r) {
  _preSigmaRenderResult(r);
  document.querySelectorAll('#js-results .finding-card').forEach(card => {
    const body = card.querySelector('.finding-body');
    if (!body || body.querySelector('.sigma-btn')) return;
    body.insertAdjacentHTML('beforeend',
      `<div class="sigma-actions"><button type="button" class="btn-mini sigma-btn" data-finding-index="${escHtml(card.dataset.findingIndex || '')}"
        onclick="event.stopPropagation(); openSigmaForFinding(this.dataset.findingIndex)">⚙ Generate Sigma rule</button></div>`);
  });
};

let sigmaState = { yaml: '', filename: 'rule.yml' };

function ensureSigmaModal() {
  let m = document.getElementById('js-sigma-modal');
  if (m) return m;
  document.body.insertAdjacentHTML('beforeend', `
    <div class="modal-backdrop" id="js-sigma-modal" hidden onclick="if (event.target === this) closeSigmaModal()">
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="js-sigma-title">
        <div class="modal-head">
          <div class="modal-title" id="js-sigma-title">Sigma rule</div>
          <button type="button" class="modal-close" onclick="closeSigmaModal()" aria-label="Close">×</button>
        </div>
        <div class="modal-sub" id="js-sigma-sub"></div>
        <pre class="modal-code" id="js-sigma-code" tabindex="0"></pre>
        <div class="modal-actions">
          <button type="button" class="btn-mini" id="js-sigma-copy" onclick="copySigma()">⎘ Copy</button>
          <button type="button" class="btn-mini" id="js-sigma-dl" onclick="downloadSigma()">⬇ Download .yml</button>
        </div>
      </div>
    </div>`);
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeSigmaModal(); });
  return document.getElementById('js-sigma-modal');
}

function showSigmaModal(title, sub, code, isError) {
  const m = ensureSigmaModal();
  document.getElementById('js-sigma-title').textContent = title;
  document.getElementById('js-sigma-sub').textContent = sub || '';
  const pre = document.getElementById('js-sigma-code');
  // YAML is rendered through the escape-first highlighter; server error messages stay plain text
  if (isError) pre.textContent = code; else pre.innerHTML = hlYaml(code);
  pre.classList.toggle('error', !!isError);
  document.getElementById('js-sigma-copy').disabled = !!isError;
  document.getElementById('js-sigma-dl').disabled = !!isError;
  m.hidden = false;
  document.getElementById('js-sigma-copy').focus();
}

function closeSigmaModal() {
  const m = document.getElementById('js-sigma-modal');
  if (m) m.hidden = true;
}

async function openSigmaForFinding(idx) {
  const r = currentResult;
  const f = r && (r.findings || [])[Number(idx)];
  if (!f) { toast('Finding not found.'); return; }
  showSigmaModal('Sigma rule: ' + (f.name || ''), 'Generating…', '');
  try {
    const res = await fetch('/api/sigma', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding: f, mode: r.mode || '' }) });
    const d = await res.json().catch(() => ({ error: 'Invalid server response' }));
    if (!res.ok) {
      showSigmaModal('No Sigma rule for this finding', f.name || '',
        (d.error || 'Rule generation failed.') + (d.supported ? '\n\nSupported finding types:\n  • ' + d.supported.join('\n  • ') : ''), true);
      return;
    }
    sigmaState = { yaml: d.yaml, filename: 'phishylens_' + String(f.name || 'rule').toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '') + '.yml' };
    const rule = d.rules[0];
    showSigmaModal('Sigma rule: ' + f.name, `id ${rule.id} · status experimental${rule.rules.length > 1 ? ' · includes a correlation rule' : ''}`, d.yaml);
  } catch (e) {
    showSigmaModal('Sigma generation failed', '', 'Network error: ' + e.message, true);
  }
}

function copySigma() {
  if (!sigmaState.yaml) return;
  navigator.clipboard.writeText(sigmaState.yaml).then(() => toast('Sigma rule copied')).catch(() => toast('Copy failed'));
}

function downloadSigma() {
  if (!sigmaState.yaml) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([sigmaState.yaml], { type: 'application/x-yaml' }));
  a.download = sigmaState.filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
