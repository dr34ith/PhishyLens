"""
UI tokens + safe highlighter tests. Run:  python -m unittest tests.test_ui_tokens -v

* every colour token used for text meets WCAG AA (>= 4.5:1) against the backgrounds it is drawn on, in the dark and
  light UI themes, the write-up export (screen + print) and the diagram palettes;
* the highlighter escapes HTML first (a log line containing <script> renders as text);
* no web fonts and no font size below 12px.
"""
import os, re, sys, unittest
from html.parser import HTMLParser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from utils.highlight import rich_html, evidence_html, mark_log_line, load_config, classify

CSS = open(os.path.join(ROOT, "static", "style.css"), encoding="utf-8").read()
FG_TOKENS = ["--text", "--text2", "--text3", "--accent2", "--sev-critical", "--sev-high", "--sev-medium", "--sev-low",
             "--sev-benign", "--c-ip", "--c-domain", "--c-hash", "--c-mitre", "--c-cmd", "--c-secret", "--c-key"]
BG_TOKENS = ["--bg", "--surface", "--surface2", "--code-bg"]


def luminance(hexv: str) -> float:
    h = hexv.lstrip("#")
    rgb = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def block(css: str, selector_regex: str) -> dict:
    m = re.search(selector_regex + r"\s*\{(.*?)\}", css, re.S)
    assert m, selector_regex
    return dict(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{6})\b", m.group(1)))


class TestContrast(unittest.TestCase):
    def assertPalette(self, tokens, fg, bg, label):
        for f in fg:
            for b in bg:
                with self.subTest(theme=label, fg=f, bg=b):
                    self.assertIn(f, tokens); self.assertIn(b, tokens)
                    ratio = contrast(tokens[f], tokens[b])
                    self.assertGreaterEqual(ratio, 4.5, f"{label}: {f} {tokens[f]} on {b} {tokens[b]} = {ratio:.2f}:1")

    def test_ui_dark_theme(self):
        dark = block(CSS, r":root(?!\[)")
        self.assertPalette(dark, FG_TOKENS, BG_TOKENS, "dark")
        self.assertGreaterEqual(contrast(dark["--on-accent"], dark["--accent"]), 4.5)
        self.assertNotEqual(dark["--text"].lower(), "#ffffff")       # soft off-white, not pure white
        self.assertNotEqual(dark["--bg"].lower(), "#000000")

    def test_ui_light_theme(self):
        light = {**block(CSS, r":root(?!\[)"), **block(CSS, r':root\[data-theme="light"\]')}
        self.assertPalette(light, FG_TOKENS, BG_TOKENS, "light")
        self.assertGreaterEqual(contrast(light["--on-accent"], light["--accent"]), 4.5)

    def test_writeup_export_palettes(self):
        from utils.report import HTML_STYLE
        screen = block(HTML_STYLE, r":root")
        printed = {**screen, **block(HTML_STYLE, r"@media print\{:root")}
        fg = ["--text", "--text2", "--text3", "--accent", "--sev-critical", "--sev-high", "--sev-medium", "--sev-low", "--sev-benign",
              "--c-ip", "--c-domain", "--c-hash", "--c-mitre", "--c-cmd", "--c-secret"]
        self.assertPalette(screen, fg, ["--bg", "--surface", "--code-bg"], "write-up screen")
        self.assertPalette(printed, fg, ["--bg", "--surface", "--code-bg"], "write-up print")

    def test_diagram_palettes(self):
        from utils.diagrams import THEMES
        for name, T in THEMES.items():
            tokens = {"text": T["text"], "muted": T["muted"], "ip": T["ip"], "domain": T["domain"], "hash": T["hash"], "ok": T["ok"],
                      **{f"sev-{k}": v for k, v in T["sev"].items()}, "bg": T["bg"], "node": T["node"], "lane": T["lane"]}
            fg = ["text", "muted", "ip", "domain", "hash", "ok"] + [f"sev-{k}" for k in T["sev"]]
            self.assertPalette(tokens, fg, ["bg", "node", "lane"], f"diagram {name}")


class TestTypography(unittest.TestCase):
    def test_no_web_fonts(self):
        self.assertNotIn("fonts.googleapis", CSS)
        self.assertNotIn("@import", CSS)
        html = open(os.path.join(ROOT, "dashboard.html"), encoding="utf-8").read()
        self.assertNotIn("fonts.googleapis", html)

    def test_no_hardcoded_tiny_fonts(self):
        sizes = [float(x) for x in re.findall(r"font-size:\s*([0-9.]+)px", CSS)]
        self.assertEqual(sizes, [], "use the --fs-* scale instead of px font sizes")
        for f in os.listdir(os.path.join(ROOT, "static")):
            if f.endswith(".js"):
                src = open(os.path.join(ROOT, "static", f), encoding="utf-8").read()
                small = [float(x) for x in re.findall(r"font-size:\s*([0-9.]+)px", src) if float(x) < 12]
                self.assertEqual(small, [], f)
        self.assertIn("--fs-xs:   max(12px", CSS)                       # smallest step never drops below 12px


class AllowedTags(HTMLParser):
    def __init__(self):
        super().__init__(); self.tags = []
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class TestHighlighterEscaping(unittest.TestCase):
    def assertSafe(self, out):
        p = AllowedTags(); p.feed(out)
        for tag, attrs in p.tags:
            self.assertIn(tag, ("span", "mark", "code"), out)
            self.assertTrue(set(attrs) <= {"class"}, out)
        self.assertNotIn("<script", out.lower())
        self.assertNotIn("<img", out.lower())

    def test_log_line_with_script_renders_as_text(self):
        line = "203.0.113.50 GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1"
        out = mark_log_line(line, "Cross-Site Scripting (XSS)")
        self.assertSafe(out)
        self.assertIn('<mark class="hl-match">&lt;script&gt;</mark>', out)
        import html as _html
        self.assertEqual(_html.unescape(re.sub(r"<[^>]+>", "", out)), line)      # same text, only wrapped

    def test_rich_text_escapes_and_classifies(self):
        out = rich_html('<img src=x onerror="alert(1)"> 10.0.0.5 evil.com T1110 PASS ******** flag{x} '
                        'd41d8cd98f00b204e9800998ecf8427e CRITICAL 97% powershell.exe')
        self.assertSafe(out)
        self.assertIn("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;", out)
        for cls, val in (("hl-ip", "10.0.0.5"), ("hl-domain", "evil.com"), ("hl-mitre", "T1110"), ("hl-secret", "********"),
                         ("hl-hash", "d41d8cd98f00b204e9800998ecf8427e"), ("hl-sev-critical", "CRITICAL"),
                         ("hl-num", "97%"), ("hl-cmd", "powershell.exe")):
            self.assertIn(f'<span class="hl {cls}">{val}</span>', out)

    def test_evidence_and_defanged_values(self):
        out = evidence_html({"name": "SQL Injection", "evidence": "1 hit(s); first at line 3: /p?id=1' union select a from b-- <b>x</b>"})
        self.assertSafe(out)
        self.assertIn('<mark class="hl-match">union select</mark>', out)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", out)
        self.assertEqual(classify("10[.]0[.]0[.]99"), "hl-ip")
        self.assertEqual(classify("hxxps://paypal[.]com/secure"), "hl-url")

    def test_ctf_flags_are_plain_escaped_text(self):
        """The flag highlight was removed: flag{...} renders as ordinary escaped text (Flag Scanner tool is unaffected)."""
        out = rich_html("found flag{<b>pwn3d</b>} and CTF{x}")
        self.assertSafe(out)
        self.assertEqual(out, "found flag{&lt;b&gt;pwn3d&lt;/b&gt;} and CTF{x}")
        self.assertNotIn("hl-flag", open(os.path.join(ROOT, "static", "highlight.js"), encoding="utf-8").read())
        self.assertNotIn("hl-flag", CSS)
        self.assertNotIn("CTF flag", open(os.path.join(ROOT, "dashboard.html"), encoding="utf-8").read())

    def test_rules_shared_with_the_ui(self):
        js = open(os.path.join(ROOT, "static", "highlight.js"), encoding="utf-8").read()
        self.assertIn("/*RULES-JSON-START*/", js)
        cfg = load_config()                       # the same JSON block the browser uses
        self.assertGreaterEqual(len(cfg["rules"]), 10)
        self.assertIn("SQL Injection", cfg["attack_marks"])
        # the browser renderer escapes every slice too
        self.assertIn("_hlEsc(t.slice(last, s))", js)
        self.assertIn("_hlEsc(t.slice(s, e))", js)


if __name__ == "__main__":
    unittest.main()
