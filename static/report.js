'use strict';
// PhishyLens: "Export Write-up" (Markdown) + print-ready HTML via POST /api/report (loaded before defang.js).
// The real result is sent; the server defangs according to the current toggle and always defangs the IOC table.

const _preReportRenderResult = renderResult;
renderResult = function (r) {
  _preReportRenderResult(r);
  const bar = document.querySelector('#js-results .export-bar');
  if (!bar || bar.querySelector('.btn-writeup')) return;
  bar.insertAdjacentHTML('beforeend',
    `<button class="btn-mini btn-writeup" type="button" onclick="exportWriteup('md')" title="Markdown write-up: summary, classification, kill chain, ATT&amp;CK, findings, IOCs, Sigma rules">⬇ Export Write-up</button>
     <button class="btn-mini btn-writeup" type="button" onclick="exportWriteup('html')" title="Same write-up as HTML, styled for Print → Save as PDF">⬇ Write-up .html (print/PDF)</button>`);
};

async function exportWriteup(format) {
  const r = currentResult;
  if (!r) { toast('Run an analysis first.'); return; }
  const defang = typeof defangEnabled === 'function' ? defangEnabled() : true;
  toast('Building write-up…');
  try {
    const res = await fetch('/api/report', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ result: r, format, defang, include_sigma: true }),
    });
    if (!res.ok) {
      const d = await res.json().catch(() => ({}));
      toast('Write-up failed: ' + (d.error || res.status));
      return;
    }
    const blob = await res.blob();
    const cd = res.headers.get('Content-Disposition') || '';
    const m = cd.match(/filename="([^"]+)"/);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = m ? m[1] : `phishylens_writeup.${format === 'html' ? 'html' : 'md'}`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast(format === 'html' ? 'HTML write-up saved: open it and use Print → Save as PDF' : 'Markdown write-up saved');
  } catch (e) {
    toast('Write-up failed: ' + e.message);
  }
}
