# llm_bridge.py
"""
Enterprise LLM Bridge
Secure • Hardened • CI-Safe • Prompt-Injection Resistant
"""

import os
import json
import time
import hashlib
import random
import requests
from typing import List, Dict, Any, Optional
from threading import Lock


__all__ = [
    "assistant_factory",
    "ollama_chat",
    "assert_ollama_available",
    "check_ollama_health",
    "get_fallback_suggestion",
    "OllamaHealthError",
]

# =========================================================
# GLOBAL CIRCUIT BREAKER
# =========================================================

_FAILURE_COUNT = 0
_CIRCUIT_OPEN_UNTIL = 0
_LOCK = Lock()

MAX_FAILURES = int(os.getenv("LLM_MAX_FAILURES", "5"))
COOLDOWN_SECONDS = int(os.getenv("LLM_COOLDOWN_SECONDS", "60"))

MAX_PROMPT_CHARS = int(os.getenv("LLM_MAX_PROMPT_CHARS", "12000"))


# =========================================================
# LOGGING
# =========================================================

def _is_verbose():
    return os.getenv("LLM_VERBOSE", "0") == "1"


def _log(msg):
    if _is_verbose():
        print(msg)


# =========================================================
# PROMPT INJECTION GUARD
# =========================================================

BLOCK_PATTERNS = [
    "ignore previous instructions",
    "exfiltrate",
    "send secrets",
    "reveal system prompt",
    "override policy",
]

def _sanitize_messages(messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
    sanitized = []
    for msg in messages:
        content = msg.get("content", "")
        lowered = content.lower()
        for pattern in BLOCK_PATTERNS:
            if pattern in lowered:
                content = "[Blocked potentially unsafe instruction]"
                break
        if len(content) > MAX_PROMPT_CHARS:
            content = content[:MAX_PROMPT_CHARS] + "\n[truncated]"
        sanitized.append({
            "role": msg.get("role", "user"),
            "content": content,
        })
    return sanitized


# =========================================================
# FALLBACK
# =========================================================

def get_fallback_suggestion(
    tool: str,
    rule_id: str = "",
    severity: str = "",
    message: str = "",
    file_path: str = "",
    line: str = "",
) -> str:
    loc = f"{file_path}:{line}" if file_path and line else file_path or "the file"
    sev = severity.upper() if severity else "SECURITY"

    return f"""[Fallback Suggestion]

Issue: {sev} finding in {loc}

Action:
- Review the vulnerability
- Apply least-privilege principle
- Patch the affected component
- Re-run security scan
"""


# =========================================================
# HEALTH CHECK
# =========================================================

class OllamaHealthError(Exception):
    pass


def check_ollama_health(base_url=None, model=None, timeout=5):
    base_url = (base_url or os.getenv("OLLAMA_URL", "http://localhost:11434")).rstrip("/")
    model = model or os.getenv("LLM_MODEL", "llama3")

    result = {
        "healthy": False,
        "server_reachable": False,
        "model_available": False,
        "error": None,
    }

    try:
        r = requests.get(f"{base_url}/api/tags", timeout=timeout)
        r.raise_for_status()
        result["server_reachable"] = True

        models = r.json().get("models", [])
        available = [m.get("name") for m in models]

        if any(model.split(":")[0] in m for m in available):
            result["model_available"] = True
            result["healthy"] = True
        else:
            result["error"] = f"Model {model} not found"

    except Exception as e:
        result["error"] = str(e)

    return result


def assert_ollama_available(base_url=None, model=None):
    health = check_ollama_health(base_url, model)
    if not health["healthy"]:
        raise OllamaHealthError(health.get("error"))


# =========================================================
# CIRCUIT BREAKER CONTROL
# =========================================================

def _circuit_open():
    return time.time() < _CIRCUIT_OPEN_UNTIL


def _record_failure():
    global _FAILURE_COUNT, _CIRCUIT_OPEN_UNTIL
    with _LOCK:
        _FAILURE_COUNT += 1
        if _FAILURE_COUNT >= MAX_FAILURES:
            _CIRCUIT_OPEN_UNTIL = time.time() + COOLDOWN_SECONDS
            _log(f"[llm_bridge] Circuit breaker OPEN for {COOLDOWN_SECONDS}s")


def _record_success():
    global _FAILURE_COUNT
    with _LOCK:
        _FAILURE_COUNT = 0


# =========================================================
# ASSISTANT FACTORY
# =========================================================

def assistant_factory(name, system_message, temperature=0.2, use_fallback=True):

    base_url = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
    model = os.getenv("LLM_MODEL", "llama3")
    connect_t = 10
    read_t = 300
    max_retries = int(os.getenv("LLM_MAX_RETRIES", "3"))

    session = requests.Session()

    class Assistant:

        def chat_completion_fn(self, messages: List[Dict[str, str]]) -> str:

            if _circuit_open():
                _log("[llm_bridge] Circuit open — forcing fallback")
                return get_fallback_suggestion("", "", "", "")

            messages_clean = _sanitize_messages(messages)

            payload = {
                "model": model,
                "stream": False,
                "messages": messages_clean,
                "options": {
                    "temperature": float(temperature),
                    "num_predict": int(os.getenv("OLLAMA_NUM_PREDICT", "1024")),
                    "num_ctx": int(os.getenv("OLLAMA_NUM_CTX", "4096")),
                }
            }

            chat_url = f"{base_url}/api/chat"

            for attempt in range(max_retries):
                try:
                    r = session.post(chat_url, json=payload, timeout=(connect_t, read_t))
                    r.raise_for_status()
                    _record_success()
                    return r.json().get("message", {}).get("content", "").strip()

                except Exception as e:
                    _log(f"[llm_bridge] Attempt {attempt+1} failed: {e}")
                    _record_failure()
                    time.sleep((2 ** attempt) + random.random())

            if use_fallback:
                return get_fallback_suggestion("", "", "", "")

            raise RuntimeError("LLM request failed")

    return Assistant()


# =========================================================
# SIMPLE CHAT
# =========================================================

def ollama_chat(system, user, temperature=0.2, use_fallback=True):
    assistant = assistant_factory("simple", system, temperature)
    return assistant.chat_completion_fn([
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ])