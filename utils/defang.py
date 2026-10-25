"""
PhishyLens: IOC defanging for display / export (never applied to API values).

    defang_text("see http://evil.com/a.php from 1.2.3.4 or bob@evil.com")
      -> "see hxxp://evil[.]com/a.php from 1[.]2[.]3[.]4 or bob[@]evil[.]com"

Mirrors static/defang.js: keep the TLD list and rules in sync.
"""
import re

# TLDs defanged when they appear as bare domains. Deliberately excludes TLDs that collide with file extensions
# (md, py, sh, pl, rs, ps, so) or with everyday words (id, in, it, at, no, my, me, us), so "README.md",
# "exploit.pl" or "user.id" are left alone.
TLDS = ("com|net|org|edu|gov|mil|int|io|co|info|biz|xyz|top|ru|su|cn|uk|de|fr|be|nl|es|br|tk|ml|ga|cf|gq|pw|cc|tv|ly|"
        "gl|gd|online|site|club|shop|store|live|app|dev|cloud|link|click|zip|mov|work|icu|buzz|rest|fun|space|website|tech|pro|"
        "xin|win|bid|loan|date|stream|download|review|country|kim|men|party|science|trade|vip|cyou|monster|sbs|cfd|lol|"
        "ir|kp|ua|kz|by|ro|pk|ng|za|au|ca|jp|kr|hk|tw|sg|vn|th|ph|mx|ar|cl|pe|ve|tr|gr|pt|cz|sk|hu|ch|se|dk|fi|ie|il|sa|ae|eg")
_URL_RE = re.compile(r"\b(https?|ftp)://([^\s/?#<>\"'`]+)", re.I)
_EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})\b")
_IPV4_RE = re.compile(r"(?<![\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?!\d|\.\d)")
_DOMAIN_RE = re.compile(r"(?<![\w./-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:" + TLDS + r"))(?![\w-]|\.[A-Za-z0-9])", re.I)
_SCHEME = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}


def _dots(s: str) -> str:
    return s.replace(".", "[.]")


def defang_text(value) -> str:
    """Defang every URL scheme/host, e-mail address, IPv4 address and bare domain in a string (idempotent)."""
    if value is None:
        return ""
    s = str(value)
    s = _URL_RE.sub(lambda m: f"{_SCHEME.get(m.group(1).lower(), m.group(1))}://{_dots(m.group(2))}", s)
    s = _EMAIL_RE.sub(lambda m: f"{m.group(1)}[@]{_dots(m.group(2))}", s)
    s = _IPV4_RE.sub(lambda m: _dots(m.group(1)), s)
    s = _DOMAIN_RE.sub(lambda m: _dots(m.group(1)), s)
    return s


def defang_obj(obj):
    """Deep copy of a JSON-like value with every string defanged (the input is not modified)."""
    if isinstance(obj, str):
        return defang_text(obj)
    if isinstance(obj, list):
        return [defang_obj(v) for v in obj]
    if isinstance(obj, dict):
        return {k: defang_obj(v) for k, v in obj.items()}
    return obj
