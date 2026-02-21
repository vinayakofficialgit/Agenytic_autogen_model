# from agents.llm_bridge import assert_ollama_available, ollama_chat, assistant_factory

# def main():
#     print("Checking Ollama…")
#     assert_ollama_available()
#     print("✔ Ollama is reachable and model is installed.")

#     agent = assistant_factory("diag", "You are diag assistant.", 0.1)
#     resp = agent.chat_completion_fn([
#         {"role":"system","content": agent.system_message},
#         {"role":"user","content": "Say hello from Ollama in 3 words"}
#     ])
#     print("Response:", resp)

# if __name__ == "__main__":
#     main()





# diag_ollama_check.py

from __future__ import annotations

import os
from agents.llm_bridge import assert_ollama_available, ollama_chat, assistant_factory


def main():
    # Show current config banner (useful in CI/logs)
    url = os.getenv("OLLAMA_URL", "(unset)")
    model = os.getenv("OLLAMA_MODEL", "(unset)")
    strict = os.getenv("LLM_STRICT", "1") == "1"
    temperature = float(os.getenv("OLLAMA_TEMPERATURE", "0.1"))

    print(f"> LLM mode: ollama | Model: {model} | URL: {url} | STRICT={int(strict)} | temp={temperature}")

    print("Checking Ollama…")
    try:
        assert_ollama_available()
        print("✔ Ollama is reachable and model is installed.")
    except Exception as e:
        # If STRICT is off, keep going but warn; else re-raise
        if strict:
            raise
        print(f"⚠ Ollama availability check failed (STRICT=0): {e}")
