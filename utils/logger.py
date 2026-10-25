"""
PhishyLens: internal system logging & bug tracking.

* Logs to stdout (Vercel captures stdout/stderr) in a single-line format.
* Keeps an in-memory ring buffer of recent log records and of errors / failed
  external API calls, exposed through /api/system/logs and /api/system/errors.
  NOTE: on Vercel the buffer is per warm instance (serverless), so use the
  Vercel log viewer for long-term history.
"""
import logging, os, sys, time, threading, traceback, uuid
from collections import deque
from datetime import datetime, timezone

_LOCK        = threading.Lock()
_RECENT      = deque(maxlen=500)
_ERRORS      = deque(maxlen=200)
_API_STATS   = {}          # service -> {"ok": n, "fail": n, "last_error": str, "last_ms": int}
_STARTED     = time.time()


class _BufferHandler(logging.Handler):
    def emit(self, record):
        entry = {
            "ts":      datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "level":   record.levelname,
            "logger":  record.name,
            "message": record.getMessage(),
        }
        with _LOCK:
            _RECENT.append(entry)
            if record.levelno >= logging.ERROR:
                if record.exc_info:
                    entry = dict(entry, traceback="".join(traceback.format_exception(*record.exc_info))[-2000:])
                _ERRORS.append(entry)


def setup_logging() -> logging.Logger:
    root = logging.getLogger("phishylens")
    if root.handlers:
        return root
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"))
    root.addHandler(sh)
    root.addHandler(_BufferHandler())
    root.propagate = False
    return root


def get_logger(name: str = "app") -> logging.Logger:
    setup_logging()
    return logging.getLogger(f"phishylens.{name}")


def new_request_id() -> str:
    return uuid.uuid4().hex[:10]


def track_api_call(service: str, ok: bool, elapsed_ms: int = 0, error: str = ""):
    """Record success/failure of an external API call (VirusTotal, AbuseIPDB, ...)."""
    with _LOCK:
        s = _API_STATS.setdefault(service, {"ok": 0, "fail": 0, "last_error": "", "last_ms": 0})
        s["ok" if ok else "fail"] += 1
        s["last_ms"] = elapsed_ms
        if not ok:
            s["last_error"] = error[:300]
    if not ok:
        get_logger("external").warning("API call failed service=%s ms=%s error=%s", service, elapsed_ms, error[:200])


def recent_logs(limit: int = 100, level: str = "") -> list:
    with _LOCK:
        items = list(_RECENT)
    if level:
        items = [i for i in items if i["level"] == level.upper()]
    return items[-limit:][::-1]


def recent_errors(limit: int = 50) -> list:
    with _LOCK:
        return list(_ERRORS)[-limit:][::-1]


def api_stats() -> dict:
    with _LOCK:
        return {k: dict(v) for k, v in _API_STATS.items()}


def uptime_seconds() -> int:
    return int(time.time() - _STARTED)
