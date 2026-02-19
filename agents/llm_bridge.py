import os
from openai import OpenAI

def is_llm_enabled():
    return os.getenv("LLM_ENABLED", "false").lower() == "true"

def get_openai_client():
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        return None
    return OpenAI(api_key=key)

def generate_ai_summary(prompt):
    client = get_openai_client()
    if not client:
        return {"summary": "LLM disabled"}

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
    )
    return {"summary": resp.choices[0].message.content}