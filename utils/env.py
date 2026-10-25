"""Minimal .env loader (no python-dotenv dependency).

Reads KEY=VALUE lines from the project's .env into os.environ WITHOUT overriding variables that are already set,
so real environment variables (e.g. Vercel project settings) always win. Set PHISHYLENS_SKIP_DOTENV=1 to disable
(the test suite does this so a developer's local keys never leak into tests).
"""
import os


def load_dotenv(path: str) -> int:
    if os.getenv("PHISHYLENS_SKIP_DOTENV") == "1" or not os.path.isfile(path):
        return 0
    loaded = 0
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip().removeprefix("export ").strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            elif " #" in value:                      # inline comment on an unquoted value
                value = value.split(" #", 1)[0].rstrip()
            if key and value and key not in os.environ:
                os.environ[key] = value
                loaded += 1
    return loaded
