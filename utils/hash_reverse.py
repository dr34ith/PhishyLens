"""
Offline hash reversal for the analyst "Hash Lookup" tool.

Public reverse-lookup APIs (md5hashing.net, nitrxgen, ...) are unreliable or no longer return JSON, so lookups are
done against a built-in dictionary of very common passwords / CTF strings. A miss only means "not one of these
words"; it says nothing about whether the hash is crackable.
"""
import hashlib

COMMON_PLAINTEXTS = [
    "", "password", "123456", "123456789", "12345678", "12345", "1234567", "1234567890", "1234", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein", "welcome", "monkey", "dragon", "football",
    "iloveyou", "1q2w3e4r", "000000", "qwerty123", "qwertyuiop", "654321", "superman", "sunshine", "princess",
    "master", "shadow", "baseball", "trustno1", "passw0rd", "p@ssw0rd", "P@ssw0rd", "Password", "Password1",
    "Password123", "password123", "admin123", "administrator", "root", "toor", "test", "test123", "guest",
    "changeme", "default", "secret", "hello", "hello123", "login", "access", "pass", "pass123", "starwars",
    "whatever", "freedom", "michael", "jennifer", "hunter2", "batman", "charlie", "ashley", "jordan", "666666",
    "7777777", "121212", "zaq12wsx", "asdfgh", "asdf", "zxcvbnm", "computer", "internet", "summer", "winter",
    "Spring2024", "Summer2024", "Welcome1", "Welcome123", "Qwerty123", "letmein123", "kali", "msfadmin",
    "flag", "ctf", "hackme", "hacker", "secret123", "admin@123", "Admin@123", "root123", "oracle", "postgres",
    "mysql", "raspberry", "ubuntu", "user", "user123", "demo", "a", "abc", "abcd", "abcdef", "test1",
]

_ALGOS = {32: ("MD5", hashlib.md5), 40: ("SHA1", hashlib.sha1), 64: ("SHA256", hashlib.sha256)}
_TABLE: dict = {}


def _table() -> dict:
    if not _TABLE:
        for word in COMMON_PLAINTEXTS:
            for _, fn in _ALGOS.values():
                _TABLE.setdefault(fn(word.encode()).hexdigest(), word)
    return _TABLE


def hash_type(h: str) -> str:
    h = (h or "").strip().lower()
    if all(c in "0123456789abcdef" for c in h) and len(h) in _ALGOS:
        return _ALGOS[len(h)][0]
    return "unknown"


def reverse_hash(h: str) -> str | None:
    """Plaintext if `h` is the MD5/SHA1/SHA256 of a dictionary word, else None."""
    return _table().get((h or "").strip().lower())
