'use strict';
// PhishyLens: display preferences (Reading comfort + Theme) and the colour Legend.
// Loaded in <head> so the saved preference applies before first paint (no flash); purely presentational.

(function () {
  const COMFORT_KEY = 'pl_comfort', THEME_KEY = 'pl_theme';
  const COMFORTS = ['compact', 'comfortable', 'large'];
  const THEMES = ['dark', 'light'];
  const root = document.documentElement;
  const read = (k, ok, dflt) => { try { const v = localStorage.getItem(k); return ok.includes(v) ? v : dflt; } catch { return dflt; } };
  const save = (k, v) => { try { localStorage.setItem(k, v); } catch { /* storage unavailable: session only */ } };

  function apply(comfort, theme) {
    root.setAttribute('data-comfort', comfort);
    root.setAttribute('data-theme', theme);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'light' ? '#ffffff' : '#0d1117');
  }
  apply(read(COMFORT_KEY, COMFORTS, 'comfortable'), read(THEME_KEY, THEMES, 'dark'));

  function syncButtons() {
    document.querySelectorAll('[data-set-comfort]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.setComfort === root.dataset.comfort)));
    document.querySelectorAll('[data-set-theme]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.setTheme === root.dataset.theme)));
  }

  function togglePop(btn, pop, force) {
    const open = typeof force === 'boolean' ? force : pop.hidden;
    document.querySelectorAll('.ui-pop').forEach(p => { if (p !== pop) p.hidden = true; });
    document.querySelectorAll('.ui-btn[aria-controls]').forEach(b => { if (b !== btn) b.setAttribute('aria-expanded', 'false'); });
    pop.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    if (open) { const first = pop.querySelector('button, a'); if (first) first.focus(); }
  }

  document.addEventListener('DOMContentLoaded', () => {
    syncButtons();
    document.querySelectorAll('[data-set-comfort]').forEach(b => b.addEventListener('click', () => {
      save(COMFORT_KEY, b.dataset.setComfort); apply(b.dataset.setComfort, root.dataset.theme); syncButtons();
    }));
    document.querySelectorAll('[data-set-theme]').forEach(b => b.addEventListener('click', () => {
      save(THEME_KEY, b.dataset.setTheme); apply(root.dataset.comfort, b.dataset.setTheme); syncButtons();
      // diagrams are server-rendered SVG: redraw the Visual Map in the matching palette
      if (typeof currentResult !== 'undefined' && currentResult && typeof renderResult === 'function') renderResult(currentResult);
    }));
    document.querySelectorAll('.ui-btn[aria-controls]').forEach(btn => {
      const pop = document.getElementById(btn.getAttribute('aria-controls'));
      if (pop) btn.addEventListener('click', e => { e.stopPropagation(); togglePop(btn, pop); });
    });
    document.addEventListener('click', e => {
      if (!e.target.closest('.ui-pop')) document.querySelectorAll('.ui-pop').forEach(p => { p.hidden = true; });
      document.querySelectorAll('.ui-btn[aria-controls]').forEach(b => { if (!e.target.closest('.ui-pop')) b.setAttribute('aria-expanded', 'false'); });
    });
    document.addEventListener('keydown', e => {
      if (e.key !== 'Escape') return;
      document.querySelectorAll('.ui-pop').forEach(p => {
        if (!p.hidden) { p.hidden = true; const b = document.querySelector(`[aria-controls="${p.id}"]`); if (b) { b.setAttribute('aria-expanded', 'false'); b.focus(); } }
      });
    });
  });
})();
