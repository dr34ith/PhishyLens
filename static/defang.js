'use strict';
// PhishyLens: global "Defang IOCs" toggle (loaded LAST so it post-processes the fully rendered results).
// Defangs what is DISPLAYED, COPIED or EXPORTED; currentResult and every API response keep the real values.
// Mirrors utils/defang.py: keep the TLD list and rules in sync.

const DEFANG_KEY = 'pl_defang';
const DEFANG_TLDS = 'com|net|org|edu|gov|mil|int|io|co|info|biz|xyz|top|ru|su|cn|uk|de|fr|be|nl|es|br|tk|ml|ga|cf|gq|pw|cc|tv|ly|' +
  'gl|gd|online|site|club|shop|store|live|app|dev|cloud|link|click|zip|mov|work|icu|buzz|rest|fun|space|website|tech|pro|' +
  'xin|win|bid|loan|date|stream|download|review|country|kim|men|party|science|trade|vip|cyou|monster|sbs|cfd|lol|' +
  'ir|kp|ua|kz|by|ro|pk|ng|za|au|ca|jp|kr|hk|tw|sg|vn|th|ph|mx|ar|cl|pe|ve|tr|gr|pt|cz|sk|hu|ch|se|dk|fi|ie|il|sa|ae|eg';
const DEFANG_URL_RE    = /\b(https?|ftp):\/\/([^\s/?#<>"'`]+)/gi;
const DEFANG_EMAIL_RE  = /\b([A-Za-z0-9._%+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b/g;
const DEFANG_IPV4_RE   = /(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?!\d|\.\d)/g;
const DEFANG_DOMAIN_RE = new RegExp('(?<![\\w./-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+(?:' + DEFANG_TLDS + '))(?![\\w-]|\\.[A-Za-z0-9])', 'gi');
const DEFANG_SCHEME = { http: 'hxxp', https: 'hxxps', ftp: 'fxp' };

function defangText(value) {
  if (value == null) return '';
  const dots = s => s.replace(/\./g, '[.]');
  return String(value)
    .replace(DEFANG_URL_RE, (m, scheme, host) => `${DEFANG_SCHEME[scheme.toLowerCase()] || scheme}://${dots(host)}`)
    .replace(DEFANG_EMAIL_RE, (m, user, dom) => `${user}[@]${dots(dom)}`)
    .replace(DEFANG_IPV4_RE, (m, ip) => dots(ip))
    .replace(DEFANG_DOMAIN_RE, (m, dom) => dots(dom));
}

function defangObj(v) {
  if (typeof v === 'string') return defangText(v);
  if (Array.isArray(v)) return v.map(defangObj);
  if (v && typeof v === 'object') { const o = {}; for (const k of Object.keys(v)) o[k] = defangObj(v[k]); return o; }
  return v;
}

function defangEnabled() {
  try { return localStorage.getItem(DEFANG_KEY) !== '0'; } catch { return true; }     // default ON
}

function defangIfOn(s) { return defangEnabled() ? defangText(s) : s; }

// ─── DOM pass: text nodes + tooltip/copy attributes; hrefs are left alone so links keep working ───
const DEFANG_SKIP = new Set(['SCRIPT', 'STYLE', 'TEXTAREA', 'INPUT', 'SELECT', 'OPTION']);
function defangDom(root) {
  if (!root || !defangEnabled()) return;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode: n => (n.parentElement && (DEFANG_SKIP.has(n.parentElement.tagName) || n.parentElement.closest('[data-no-defang]')))
      ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT,
  });
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  nodes.forEach(n => { const d = defangText(n.nodeValue); if (d !== n.nodeValue) n.nodeValue = d; });
  const els = root.nodeType === 1 ? [root, ...root.querySelectorAll('[title],[data-copy]')] : [];
  els.forEach(el => ['title', 'data-copy'].forEach(a => {
    if (el.hasAttribute && el.hasAttribute(a)) { const v = el.getAttribute(a); const d = defangText(v); if (d !== v) el.setAttribute(a, d); }
  }));
}

const DEFANG_CONTAINERS = ['js-results', 'js-activity-feed', 'js-history-list'];
const defangObserver = new MutationObserver(muts => {
  if (!defangEnabled()) return;
  muts.forEach(m => m.addedNodes.forEach(n => {
    if (n.nodeType === 1) defangDom(n);
    else if (n.nodeType === 3 && n.parentElement && !DEFANG_SKIP.has(n.parentElement.tagName)) {
      const d = defangText(n.nodeValue); if (d !== n.nodeValue) n.nodeValue = d;
    }
  }));
});

// ─── hooks: render, copy, exports ───────────────────────────────
const _preDefangRenderResult = renderResult;
renderResult = function (r) {
  _preDefangRenderResult(r);
  defangDom(document.getElementById('js-results'));
  addDefangExportButtons();
};

const _origCopyText = copyText;
copyText = function (text) { _origCopyText(defangIfOn(text)); };

// run an export with a defanged COPY of currentResult, then restore the real object
function withDefangedResult(fn) {
  return function (...args) {
    if (!defangEnabled() || !currentResult) return fn.apply(this, args);
    const real = currentResult;
    currentResult = defangObj(real);
    try { return fn.apply(this, args); } finally { currentResult = real; }
  };
}
if (typeof exportReport === 'function') exportReport = withDefangedResult(exportReport);
if (typeof exportNavigatorLayer === 'function') exportNavigatorLayer = withDefangedResult(exportNavigatorLayer);

// ─── "Copy IOCs (defanged)"; always defanged, regardless of the toggle ───
function iocLines(r, defang) {
  const lines = [];
  Object.entries((r && r.iocs) || {}).forEach(([type, items]) => {
    if (!Array.isArray(items) || !items.length) return;
    lines.push(type.toUpperCase());
    [...new Set(items)].forEach(v => lines.push('  ' + (defang ? defangText(v) : String(v))));
  });
  return lines;
}

function copyIocsDefanged() {
  const lines = iocLines(currentResult, true);
  if (!lines.length) { toast('No IOCs in this result.'); return; }
  _origCopyText(lines.join('\n'));                          // bypass the toggle wrapper: this button is always defanged
}

function addDefangExportButtons() {
  const bar = document.querySelector('#js-results .export-bar');
  if (!bar || bar.querySelector('.btn-copy-iocs')) return;
  bar.insertAdjacentHTML('beforeend', '<button class="btn-mini btn-copy-iocs" type="button" onclick="copyIocsDefanged()" title="Copy every IOC in this result, defanged">⎘ Copy IOCs (defanged)</button>');
}

// ─── toggle ─────────────────────────────────────────────────────
function setDefang(on) {
  try { localStorage.setItem(DEFANG_KEY, on ? '1' : '0'); } catch { /* storage unavailable: session-only */ }
  const cb = document.getElementById('js-defang-toggle');
  if (cb) cb.checked = on;
  // re-render from the untouched data so turning it OFF restores the real values
  if (currentResult) renderResult(currentResult);
  if (typeof renderActivity === 'function') renderActivity();
  if (typeof loadHistory === 'function') loadHistory();
  toast(on ? 'IOCs are now shown defanged' : 'IOCs are now shown live: be careful clicking or copying');
}

document.addEventListener('DOMContentLoaded', () => {
  const cb = document.getElementById('js-defang-toggle');
  if (cb) {
    cb.checked = defangEnabled();
    cb.addEventListener('change', () => setDefang(cb.checked));
  }
  DEFANG_CONTAINERS.forEach(id => {
    const el = document.getElementById(id);
    if (el) { defangObserver.observe(el, { childList: true, subtree: true }); defangDom(el); }
  });
});
