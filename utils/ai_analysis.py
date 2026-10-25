"""
LLM analyst narratives with provider failover.

Providers (each enabled by its API key):
  * DeepSeek  : DEEPSEEK_API_KEY   (model: DEEPSEEK_MODEL, default deepseek-chat)
  * Gemini    : GEMINI_API_KEY     (model: GEMINI_MODEL,   default gemini-2.5-flash)
  * OpenRouter: OPENROUTER_API_KEY (model: AI_MODEL,       default deepseek/deepseek-chat)

AI_PROVIDER picks the first one to try ("deepseek", "gemini", "openrouter"); default "auto" tries them in the
order above. If a provider fails (bad key, quota, timeout) the next configured one is tried, and if none works the
caller falls back to the offline local_explanation().
"""
import os
import re
import time
import requests
from utils.logger import get_logger, track_api_call

log = get_logger('ai')

SYSTEM_PROMPT = """You are a senior SOC analyst and threat intelligence expert.
You analyze cybersecurity indicators and produce detailed, professional threat assessments.
Your analysis must be specific, technical, and actionable, and must stay grounded in the findings provided -
do not invent indicators, threat actors, or intelligence that is not supported by the evidence.
Never be vague. Always explain the threat type, attacker behavior, and real-world impact.
Write in clear paragraphs. No bullet points. No markdown headers. No emojis.
Do not use em dashes; use commas, colons, semicolons or parentheses instead."""

PROVIDER_ORDER = ("deepseek", "gemini", "openrouter")
PROVIDER_KEYS = {"deepseek": "DEEPSEEK_API_KEY", "gemini": "GEMINI_API_KEY", "openrouter": "OPENROUTER_API_KEY"}
PROVIDER_LABELS = {"deepseek": "DeepSeek", "gemini": "Google Gemini", "openrouter": "OpenRouter"}

MAX_INPUT_CHARS = 3000     # raw emails / logs can be megabytes; only a preview goes to the model
MAX_FINDINGS = 25
TIMEOUT = 25


def configured_providers() -> list:
    """Providers with an API key, in the order they will be tried."""
    preferred = os.getenv("AI_PROVIDER", "auto").strip().lower()
    order = list(PROVIDER_ORDER)
    if preferred in order:
        order.remove(preferred)
        order.insert(0, preferred)
    return [p for p in order if os.getenv(PROVIDER_KEYS[p])]


def build_prompt(mode: str, input_val: str, findings: list, verdict: str, score: int) -> str:
    findings_text = ""
    for f in (findings or [])[:MAX_FINDINGS]:
        if not isinstance(f, dict):
            continue
        findings_text += f"\n- [{f.get('severity', '?')}] {f.get('name', '')}: {f.get('evidence', '')}. {f.get('description', '')}"
    if len(findings or []) > MAX_FINDINGS:
        findings_text += f"\n- … {len(findings) - MAX_FINDINGS} more finding(s) omitted"

    indicator = str(input_val or "")
    if len(indicator) > MAX_INPUT_CHARS:
        indicator = indicator[:MAX_INPUT_CHARS] + f"\n[… truncated, {len(str(input_val)) - MAX_INPUT_CHARS} more characters]"

    return f"""Analyze the following cybersecurity indicator as a senior SOC analyst.

Type: {str(mode or '').upper()}
Indicator: {indicator}
Risk Verdict: {verdict}
Risk Score: {score}%

Detected Findings:
{findings_text or '- none'}

Score attribution (how the final score was built; reference it when explaining WHY):
{_score_text(findings, score)}

Write a detailed threat analysis covering ALL of the following:

1. THREAT CLASSIFICATION: What specific type of threat is this? (e.g. botnet node, phishing infrastructure, C2 server, credential harvester, malware dropper, scanner, spam source, etc.) Be specific.

2. ATTACKER BEHAVIOR: What has this indicator been used for? What activities has the attacker conducted? What techniques are being used based on the evidence?

3. THREAT CONTEXT: Why are these specific findings dangerous when combined? Explain the relationship between the indicators and what they reveal about the attacker's intent.

4. POTENTIAL IMPACT: Who are the likely targets? What is the real-world consequence if a user or system interacts with this indicator?

5. ANALYST RECOMMENDATIONS: What should a SOC analyst do right now? Be specific: block, investigate, escalate, monitor, quarantine?

Write 4-6 sentences per section. Be direct and technical. If the evidence is weak or the verdict is BENIGN, say so plainly instead of exaggerating the threat. Assume the reader is a junior SOC analyst who needs to understand both the what and the why."""


# ─── PROVIDER CALLS (each returns text or raises) ─────────────
def _openai_compatible(url: str, key: str, model: str, prompt: str, extra_headers: dict | None = None) -> str:
    r = requests.post(
        url,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json", **(extra_headers or {})},
        json={"model": model,
              "messages": [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
              "max_tokens": 1500, "temperature": 0.3},
        timeout=TIMEOUT,
    )
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:150]}")
    return r.json()["choices"][0]["message"]["content"].strip()


def _call_deepseek(prompt: str) -> str:
    return _openai_compatible("https://api.deepseek.com/chat/completions", os.environ["DEEPSEEK_API_KEY"],
                              os.getenv("DEEPSEEK_MODEL", "deepseek-chat"), prompt)


def _call_openrouter(prompt: str) -> str:
    return _openai_compatible("https://openrouter.ai/api/v1/chat/completions", os.environ["OPENROUTER_API_KEY"],
                              os.getenv("AI_MODEL", "deepseek/deepseek-chat"), prompt,
                              {"HTTP-Referer": "https://phishylens.local", "X-Title": "PhishyLens"})


def _call_gemini(prompt: str) -> str:
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    r = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"], "Content-Type": "application/json"},
        json={"systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
              "contents": [{"role": "user", "parts": [{"text": prompt}]}],
              # 2.5-series models spend part of the output budget on internal reasoning; leave room for the answer
              "generationConfig": {"temperature": 0.3, "maxOutputTokens": 4096}},
        timeout=TIMEOUT,
    )
    if not r.ok:
        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:150]}")
    data = r.json()
    cands = data.get("candidates") or []
    if not cands:
        reason = (data.get("promptFeedback") or {}).get("blockReason", "no candidates returned")
        raise RuntimeError(f"Gemini returned no answer ({reason})")
    text = "".join(p.get("text", "") for p in (cands[0].get("content") or {}).get("parts", []) if not p.get("thought"))
    if not text.strip():
        raise RuntimeError(f"Gemini returned empty text (finishReason={cands[0].get('finishReason')})")
    return text.strip()


_CALLERS = {"deepseek": _call_deepseek, "gemini": _call_gemini, "openrouter": _call_openrouter}


def _no_em_dashes(text: str) -> str:
    """Models still slip em dashes in despite the instruction; swap them for plain punctuation."""
    text = re.sub(r"\s*\u2014\s*", ", ", text or "")
    return text.replace(", ,", ",")


def generate_analysis(mode: str, input_val: str, findings: list, verdict: str, score: int) -> dict:
    """
    Try each configured provider in order. Returns
      {"analysis": str, "provider": "deepseek"|..., "provider_label": str, "errors": [...]}
    with analysis == "" if no provider is configured or all of them failed.
    """
    prompt = build_prompt(mode, input_val, findings, verdict, score)
    errors = []
    for name in configured_providers():
        t0 = time.time()
        try:
            text = _no_em_dashes(_CALLERS[name](prompt))
            track_api_call(name, True, int((time.time() - t0) * 1000))
            return {"analysis": text, "provider": name, "provider_label": PROVIDER_LABELS[name], "errors": errors}
        except Exception as e:
            msg = str(e)[:200]
            track_api_call(name, False, int((time.time() - t0) * 1000), msg)
            log.error("%s analysis failed: %s", PROVIDER_LABELS[name], msg)
            errors.append(f"{PROVIDER_LABELS[name]}: {msg.split(':')[0]}")
    return {"analysis": "", "provider": "", "provider_label": "", "errors": errors}


def get_ai_analysis(mode: str, input_val: str, findings: list, verdict: str, score: int) -> str:
    """Backward-compatible wrapper: narrative text, or "" if no LLM produced one."""
    return generate_analysis(mode, input_val, findings, verdict, score)["analysis"]


def _score_text(findings: list, score: int) -> str:
    """Plain-text score attribution used inside the LLM prompt."""
    from utils.scoring import explain_score
    try:
        exp = explain_score([f for f in (findings or []) if isinstance(f, dict)], int(score or 0))
    except (TypeError, ValueError):
        return "- unavailable"
    return "\n".join(f"- {c['display']} ({c['severity']})" for c in exp["contributions"]) or "- baseline only"


def local_explanation(result: dict) -> str:
    """
    Offline, deterministic 'why' narrative built from the explainable score.
    Used as a fallback when no LLM key is configured, and as an exam-friendly answer key.
    """
    from utils.scoring import explain_score
    findings = [f for f in (result.get("findings") or []) if isinstance(f, dict)]
    exp = result.get("score_explanation") or explain_score(findings, result.get("score"))
    verdict, score = result.get("verdict", "UNKNOWN"), result.get("score", 0)
    if not exp["contributions"]:
        return f"Verdict {verdict} ({score}%). No risk factors were detected, so the score is the baseline value."
    lines = [f"Verdict {verdict} at {score}%. The score is the sum of these factors:"]
    for c in exp["contributions"][:8]:
        why = f"; {c['why']}" if c.get("why") else ""
        lines.append(f"  {c['display']} [{c['severity']}]{why}")
    return "\n".join(lines)
