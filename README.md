
# Agentic DevSecOps — Slim 4‑Agents + AutoGen layer

This repo adds an **AutoGen-based multi‑agent layer** on top of the slim 4‑agent pipeline.
- Scanners still run deterministically in **GitHub Actions** (SARIF to Security tab).
- Python orchestrator (Collector → PolicyGate → Fixer → Reporter) remains the **gate**.
- **AutoGen AgentChat** is optional and only enhances **triage & summary** when `llm.enabled: true` and `OPENAI_API_KEY` is present.

> AutoGen is a Microsoft open‑source framework for building single/multi‑agent applications. The project now points new users to the **Microsoft Agent Framework** for the long term; AutoGen remains maintained. We use AutoGen’s **AgentChat** here to keep setup simple during the hackathon.

## Quick start
1. Upload this folder to a new GitHub repo.
2. (Optional) In repo **Settings → Secrets and variables → Actions → Secrets**, add `OPENAI_API_KEY` if you want the AutoGen layer.
3. (Optional) In repo **Variables**, set `POLICY_URL` (remote OPA pack) and `ZAP_TARGET` (authorized URL).
4. Push a commit → pipeline runs. On FAIL, Fixer edits files and an **auto‑PR** is opened.

## AutoGen usage here
We create small agent roles (Triage / PolicyAdvisor / Reporter) via **AgentChat** and produce an additional `agent_output/agentic_summary.md` that’s appended to the default summary.

