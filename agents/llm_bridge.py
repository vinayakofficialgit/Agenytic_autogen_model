# agents/llm_bridge.py
import os
from openai import OpenAI

# =============================
# CONFIG
# =============================
LLM_MODE = os.getenv("LLM_MODE", "openai").lower()


# =============================
# BASIC HELPERS
# =============================
def is_llm_enabled():
    return os.getenv("LLM_ENABLED", "false").lower() == "true"


def get_openai_client():
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        return None
    return OpenAI(api_key=key)


# =============================
# HEALTH CHECK
# =============================
def check_ollama_health():
    # stub for compatibility
    return False


# =============================
# FALLBACK SUGGESTION
# =============================
def get_fallback_suggestion(tool="", rule_id="", severity="", message=""):
    return f"""
Fallback remediation suggestion:

Tool: {tool}
Rule: {rule_id}
Severity: {severity}

Recommendation:
- Review configuration manually
- Apply least privilege principle
- Update dependency or config
- Add validation tests
"""


# =============================
# SIMPLE CHAT (for legacy calls)
# =============================
def generate_ai_summary(prompt):
    client = get_openai_client()
    if not client:
        return {"summary": "LLM disabled"}

    try:
        resp = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return {"summary": resp.choices[0].message.content}
    except Exception as e:
        return {"summary": f"[fallback] {e}"}


# =============================
# ASSISTANT FACTORY (CRITICAL)
# =============================
class SimpleAssistant:
    def __init__(self, name, system_message, temperature=0.2):
        self.name = name
        self.system_message = system_message
        self.temperature = temperature
        self.client = get_openai_client()

    def chat_completion_fn(self, messages):
        if not self.client:
            return "[Fallback] LLM unavailable"

        try:
            resp = self.client.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                messages=messages,
                temperature=self.temperature,
            )
            return resp.choices[0].message.content
        except Exception as e:
            return f"[Fallback] {e}"

    # =============================================
    # FIX: Added generate_patch() method
    # This is called by fixer.py to get a unified
    # diff patch from the LLM for a given prompt.
    # =============================================
    def generate_patch(self, prompt):
        """Generate a unified diff patch using the LLM."""
        messages = [
            {"role": "system", "content": self.system_message},
            {"role": "user", "content": prompt},
        ]
        return self.chat_completion_fn(messages)


def assistant_factory(name="security_fixer", system_message="You are a senior security engineer. Output ONLY unified diff patches.", temperature=0.2):
    """
    FIX: Added default values for name and system_message so callers
    that don't pass arguments (like fixer.py) won't crash with TypeError.
    """
    return SimpleAssistant(name, system_message, temperature)


# =============================
# OLLAMA STUB (compatibility)
# =============================
def ollama_chat(*args, **kwargs):
    return "[Fallback] Ollama disabled"





















# 
# 
# # agents/llm_bridge.py
# import os
# from openai import OpenAI

# # =============================
# # CONFIG
# # =============================
# LLM_MODE = os.getenv("LLM_MODE", "openai").lower()


# # =============================
# # BASIC HELPERS
# # =============================
# def is_llm_enabled():
#     return os.getenv("LLM_ENABLED", "false").lower() == "true"


# def get_openai_client():
#     key = os.getenv("OPENAI_API_KEY")
#     if not key:
#         return None
#     return OpenAI(api_key=key)


# # =============================
# # HEALTH CHECK
# # =============================
# def check_ollama_health():
#     # stub for compatibility
#     return False


# # =============================
# # FALLBACK SUGGESTION
# # =============================
# def get_fallback_suggestion(tool="", rule_id="", severity="", message=""):
#     return f"""
# Fallback remediation suggestion:

# Tool: {tool}
# Rule: {rule_id}
# Severity: {severity}

# Recommendation:
# - Review configuration manually
# - Apply least privilege principle
# - Update dependency or config
# - Add validation tests
# """


# # =============================
# # SIMPLE CHAT (for legacy calls)
# # =============================
# def generate_ai_summary(prompt):
#     client = get_openai_client()
#     if not client:
#         return {"summary": "LLM disabled"}

#     try:
#         resp = client.chat.completions.create(
#             model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
#             messages=[{"role": "user", "content": prompt}],
#             temperature=0.2,
#         )
#         return {"summary": resp.choices[0].message.content}
#     except Exception as e:
#         return {"summary": f"[fallback] {e}"}


# # =============================
# # ASSISTANT FACTORY (CRITICAL)
# # =============================
# class SimpleAssistant:
#     def __init__(self, name, system_message, temperature=0.2):
#         self.name = name
#         self.system_message = system_message
#         self.temperature = temperature
#         self.client = get_openai_client()

#     def chat_completion_fn(self, messages):
#         if not self.client:
#             return "[Fallback] LLM unavailable"

#         try:
#             resp = self.client.chat.completions.create(
#                 model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
#                 messages=messages,
#                 temperature=self.temperature,
#             )
#             return resp.choices[0].message.content
#         except Exception as e:
#             return f"[Fallback] {e}"


# def assistant_factory(name, system_message, temperature=0.2):
#     return SimpleAssistant(name, system_message, temperature)


# # =============================
# # OLLAMA STUB (compatibility)
# # =============================
# def ollama_chat(*args, **kwargs):
#     return "[Fallback] Ollama disabled"


# # import os
# # from openai import OpenAI

# # def is_llm_enabled():
# #     return os.getenv("LLM_ENABLED", "false").lower() == "true"

# # def get_openai_client():
# #     key = os.getenv("OPENAI_API_KEY")
# #     if not key:
# #         return None
# #     return OpenAI(api_key=key)

# # def generate_ai_summary(prompt):
# #     client = get_openai_client()
# #     if not client:
# #         return {"summary": "LLM disabled"}

# #     resp = client.chat.completions.create(
# #         model="gpt-4o-mini",
# #         messages=[{"role": "user", "content": prompt}],
# #         temperature=0.2,
# #     )
# #     return {"summary": resp.choices[0].message.content}