'use strict';
// PhishyLens: safe auto-highlighter for reading text (summary, findings, evidence, narrative, IOC values, Sigma YAML).
// Every piece of output is HTML-escaped; matches are only wrapped in <span class="hl-*"> / <mark class="hl-match">.
// The rules below are plain JSON between the markers and are also loaded by utils/highlight.py (write-up export),
// so the UI and the exported HTML highlight exactly the same things. Keep the JSON valid.

const HL_CONFIG = /*RULES-JSON-START*/{
  "rules": [
    {"cls": "hl-secret", "flags": "",  "pattern": "\\*{4,}"},
    {"cls": "hl-url",    "flags": "i", "pattern": "\\b(?:https?|hxxps?|ftp|fxp)://[^\\s<>\"'`]+"},
    {"cls": "hl-domain", "flags": "i", "pattern": "\\b[\\w.+%-]+(?:@|\\[@\\])[\\w-]+(?:(?:\\.|\\[\\.\\])[\\w-]+)+"},
    {"cls": "hl-hash",   "flags": "",  "pattern": "\\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\\b"},
    {"cls": "hl-ip",     "flags": "",  "pattern": "(?<![\\w.\\[])\\d{1,3}(?:(?:\\.|\\[\\.\\])\\d{1,3}){3}(?::\\d{1,5})?(?![\\w\\]])"},
    {"cls": "hl-mitre",  "flags": "",  "pattern": "\\bT\\d{4}(?:\\.\\d{3})?\\b"},
    {"cls": "hl-mitre",  "flags": "i", "pattern": "\\battack\\.t\\d{4}(?:\\.\\d{3})?\\b"},
    {"cls": "hl-cve",    "flags": "",  "pattern": "\\bCVE-\\d{4}-\\d{4,7}\\b"},
    {"cls": "@phrases"},
    {"cls": "hl-domain", "flags": "i", "pattern": "\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.|\\[\\.\\]))+(?:com|net|org|edu|gov|io|co|info|biz|xyz|top|ru|su|cn|uk|de|fr|nl|br|tk|ml|ga|cf|gq|pw|cc|tv|ly|online|site|club|shop|store|live|app|dev|cloud|link|click|zip|mov|work|icu|buzz|rest|fun|space|website|tech|pro|local|example|ir|kp|ua|kz|by|ro|pk|ng|za|au|ca|jp|kr|hk|tw|sg|vn|in|us|me)\\b(?![\\w-])"},
    {"cls": "hl-cmd",    "flags": "i", "pattern": "\\b(?:powershell(?:\\.exe)?|pwsh|cmd\\.exe|IEX|Invoke-Expression|Invoke-WebRequest|DownloadString|DownloadFile|Net\\.WebClient|certutil|mshta|regsvr32|rundll32|bitsadmin|Start-BitsTransfer|FromBase64String)\\b|(?:^|\\s)-(?:EncodedCommand|enc|ExecutionPolicy\\s+Bypass|ep\\s+bypass|NoP|W\\s+Hidden|WindowStyle\\s+Hidden)\\b"},
    {"cls": "@sev",      "flags": "",  "pattern": "\\b(?:CRITICAL|HIGH|MEDIUM|LOW|MALICIOUS|SUSPICIOUS|BENIGN)\\b"},
    {"cls": "hl-num",    "flags": "i", "pattern": "\\b\\d+(?:\\.\\d+)?%|\\b\\d+ (?:distinct )?(?:ports?|failed logins?|hits?|findings?|engines|reports|hosts?|packets?|risky services|lines?|connections)\\b(?!\\()"}
  ],
  "attack_marks": {
    "SQL Injection": "union\\s+(?:all\\s+)?select|'\\s*or\\s*'?1'?\\s*=\\s*'?1|information_schema|sleep\\s*\\(|benchmark\\s*\\(|waitfor\\s+delay|xp_cmdshell|load_file\\s*\\(|extractvalue\\s*\\(|updatexml\\s*\\(",
    "Cross-Site Scripting (XSS)": "<\\s*script[^>]*>|javascript\\s*:|on(?:error|load|click|mouseover|focus)\\s*=|<\\s*iframe|<\\s*svg|document\\.cookie|alert\\s*\\(",
    "Path Traversal / LFI": "(?:\\.\\./){2,}|(?:\\.\\.\\\\){2,}|/etc/passwd|/etc/shadow|/proc/self/environ|win\\.ini|boot\\.ini|php://\\w+",
    "Command Injection": "(?:[;|`]|&&)\\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|ncat|bash|sh)\\b|\\$\\((?:cat|id|whoami|curl|wget|uname)\\b|/bin/(?:ba)?sh",
    "Log4Shell / JNDI Injection": "\\$\\{(?:jndi|lower|upper|\\$\\{)[^\\s]*",
    "Server-Side Request Forgery": "127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254|0\\.0\\.0\\.0|\\[::1\\]",
    "Web Shell / Sensitive File Probe": "/(?:phpmyadmin|\\.git/config|\\.env|\\.aws/credentials|id_rsa|web\\.config|backup\\.sql|shell\\.php|c99\\.php|r57\\.php|cmd\\.php|\\.htpasswd)",
    "Scanner / Attack-Tool User-Agent": "sqlmap|nikto|nmap|masscan|acunetix|nessus|wpscan|dirbuster|gobuster|ffuf|hydra|havij|zgrab|nuclei|metasploit",
    "PowerShell Encoded Command": "-(?:e|en|enc|enco|encod|encode|encoded|encodedcommand)\\s+[A-Za-z0-9+/=]{8,}",
    "PowerShell Execution Policy Bypass": "-(?:ep|exec|executionpolicy)\\s+(?:bypass|unrestricted)|set-executionpolicy\\s+(?:bypass|unrestricted)",
    "PowerShell Hidden Window / No Profile": "-(?:w|win|window|windowstyle)\\s+(?:h|hidden)\\b|-(?:nop|noprofile)\\b|-noni\\b",
    "PowerShell Download Cradle": "(?:iex|invoke-expression)\\b|downloadstring|downloadfile|net\\.webclient|invoke-webrequest|start-bitstransfer|certutil(?:\\.exe)?\\s+-urlcache",
    "AMSI / Defender Tampering": "amsiutils|amsiinitfailed|set-mppreference|add-mppreference",
    "Reflection / In-Memory Loader": "\\[reflection\\.assembly\\]::load|frombase64string|virtualalloc|add-type",
    "LOLBin Proxy Execution": "mshta|regsvr32|rundll32|wmic|bitsadmin"
  }
}/*RULES-JSON-END*/;

const HL_SEV_CLASS = { CRITICAL: 'hl-sev-critical', HIGH: 'hl-sev-high', MEDIUM: 'hl-sev-medium', LOW: 'hl-sev-low',
                       MALICIOUS: 'hl-sev-critical', SUSPICIOUS: 'hl-sev-medium', BENIGN: 'hl-sev-benign' };
const HL_PHRASE_CLASS = { term: 'hl-term', urgent: 'hl-urgent', num: 'hl-num' };     // server summary kinds ('ioc' → auto rules)
const HL_COMPILED = HL_CONFIG.rules.map(r => (r.pattern ? { ...r, rx: new RegExp(r.pattern, (r.flags || '') + 'g') } : r));

function _hlEsc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// Collect non-overlapping spans: rule order is priority, then longer match, then position.
function _hlSpans(text, phrases) {
  const found = [];
  HL_COMPILED.forEach((r, prio) => {
    if (r.cls === '@phrases') {
      (phrases || []).forEach(p => {
        const cls = HL_PHRASE_CLASS[p.kind];
        if (!cls || !p.text) return;
        let i = text.indexOf(p.text);
        while (i !== -1) { found.push([i, i + p.text.length, cls, prio]); i = text.indexOf(p.text, i + p.text.length); }
      });
      return;
    }
    r.rx.lastIndex = 0;
    let m;
    while ((m = r.rx.exec(text)) !== null) {
      if (!m[0]) { r.rx.lastIndex++; continue; }
      let s = m.index, e = s + m[0].length;
      while (s < e && /\s/.test(text[s])) s++;                     // patterns that start with (^|\s)
      const cls = r.cls === '@sev' ? HL_SEV_CLASS[m[0].toUpperCase()] : r.cls;
      found.push([s, e, cls, prio]);
    }
  });
  found.sort((a, b) => a[3] - b[3] || (b[1] - b[0]) - (a[1] - a[0]) || a[0] - b[0]);
  const taken = [];
  for (const f of found) if (taken.every(t => f[1] <= t[0] || f[0] >= t[1])) taken.push(f);
  return taken.sort((a, b) => a[0] - b[0]);
}

// Escape-first rich text: returns safe HTML with technical values / key phrases wrapped in spans.
function richText(text, phrases) {
  const t = String(text == null ? '' : text);
  let out = '', last = 0;
  for (const [s, e, cls] of _hlSpans(t, phrases)) {
    out += _hlEsc(t.slice(last, s)) + `<span class="hl ${cls}">${_hlEsc(t.slice(s, e))}</span>`;
    last = e;
  }
  return out + _hlEsc(t.slice(last));
}

// A log line / evidence snippet: the part the detector matched gets <mark>, the rest stays escaped plain text.
function markLogLine(line, attackType) {
  const t = String(line == null ? '' : line);
  const key = String(attackType || '').replace(/ \(inside encoded payload\)$/, '');
  const pat = HL_CONFIG.attack_marks[key];
  if (!pat) return _hlEsc(t);
  const rx = new RegExp(pat, 'ig');
  let out = '', last = 0, m;
  while ((m = rx.exec(t)) !== null) {
    if (!m[0]) { rx.lastIndex++; continue; }
    out += _hlEsc(t.slice(last, m.index)) + `<mark class="hl-match">${_hlEsc(m[0])}</mark>`;
    last = m.index + m[0].length;
  }
  return out + _hlEsc(t.slice(last));
}

// Finding evidence: "N hit(s); first at line L: <log snippet>" → prose prefix + log line box with the match marked.
function evidenceHtml(f) {
  const ev = String((f && f.evidence) || '');
  const m = ev.match(/^(\d+ hit\(s\); first at line \d+: )([\s\S]*)$/);
  if (m) return `<span class="ev-prefix">${richText(m[1])}</span><code class="logline">${markLogLine(m[2], f.name)}</code>`;
  return richText(ev);
}

// Sigma / YAML: keys muted, technical values coloured; every character escaped.
function hlYaml(yaml) {
  return String(yaml || '').split('\n').map(line => {
    const m = line.match(/^(\s*-?\s*)([A-Za-z0-9_.|-]+)(:)(\s.*|)$/);
    if (m && !/^\s*-\s*$/.test(m[1] + m[2])) return `${_hlEsc(m[1])}<span class="yaml-key">${_hlEsc(m[2])}</span>${_hlEsc(m[3])}${richText(m[4])}`;
    if (/^---\s*$/.test(line)) return `<span class="yaml-doc">${_hlEsc(line)}</span>`;
    return richText(line);
  }).join('\n');
}
