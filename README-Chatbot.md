# 🛡️ DevSecOps AI Chatbot

An intelligent, AI-powered chatbot built with Streamlit that connects directly to your GitHub Actions security pipeline — delivering real-time vulnerability analysis, interactive security dashboards, and automated remediation guidance, all powered by **Groq's Llama 3.3 70B** large language model.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Security Tools Integrated](#security-tools-integrated)
- [Application Tabs](#application-tabs)
- [Data Flow](#data-flow)

---

## Overview

Modern DevSecOps pipelines generate vast amounts of security scan data across multiple tools — Semgrep findings, Trivy vulnerability reports, tfsec misconfigurations, leaked secrets from Gitleaks, and policy violations from Conftest. Developers are often left sifting through raw JSON outputs, trying to understand what matters and what to fix first.

The **DevSecOps AI Chatbot** eliminates that friction. It acts as an intelligent layer between your CI/CD security pipeline and your development team by:

1. **Auto-fetching** the latest scan artifacts the moment the application loads — no manual downloads or file hunting
2. **Parsing and normalizing** results from five different security scanners into a single, unified findings model with consistent severity ratings
3. **Injecting full pipeline context** into every AI conversation — so the chatbot knows your exact vulnerabilities, CVE IDs, affected files, and line numbers
4. **Generating targeted remediation** with before/after code examples tailored to each specific finding
5. **Tracking pipeline health** across multiple workflow runs with pass/fail trends and one-click artifact loading from any historical run

The result is a conversational security co-pilot that turns raw scan data into actionable intelligence.

---

## Architecture

The DevSecOps AI Chatbot is designed as a **multi-layered system** where each layer has a distinct responsibility. Data flows from the CI/CD pipeline through processing layers and ultimately reaches the user through an intelligent, context-aware interface.

```
╔══════════════════════════════════════════════════════════════════════════╗
║                        🔒 CI/CD SECURITY LAYER                         ║
║                                                                        ║
║   GitHub Actions Pipeline                                              ║
║   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   ║
║   │ Semgrep  │ │  Trivy   │ │  tfsec   │ │ Gitleaks │ │ Conftest │   ║
║   │  (SAST)  │ │(Vuln+IaC)│ │(Terraform│ │(Secrets) │ │ (Policy) │   ║
║   └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘   ║
║        │             │            │             │             │         ║
║        └──────┬──────┴─────┬──────┴──────┬──────┴─────┬──────┘         ║
║               ▼            ▼             ▼            ▼                ║
║   ┌─────────────────┐ ┌──────────────────────┐ ┌───────────────────┐  ║
║   │  scan-reports   │ │ remediation-suggest.  │ │   ai-results      │  ║
║   │  (JSON files)   │ │ (Markdown + JSON)     │ │ (decision + recs) │  ║
║   └────────┬────────┘ └──────────┬───────────┘ └────────┬──────────┘  ║
║            └─────────────────────┼──────────────────────┘              ║
║                                  ▼                                     ║
║                     GitHub Actions Artifacts (ZIP)                     ║
╚══════════════════════════════════╤═════════════════════════════════════╝
                                   │
                          GitHub REST API
                                   │
╔══════════════════════════════════╧═════════════════════════════════════╗
║                     📡 DATA INGESTION LAYER                           ║
║                                                                        ║
║   ┌──────────────────────────────────────────────────────────────┐     ║
║   │               GitHub API Client Module                       │     ║
║   │                                                              │     ║
║   │  get_workflow_runs()  →  Fetches last 15 runs (all workflows)│     ║
║   │  get_artifacts()      →  Lists artifacts per run             │     ║
║   │  download_artifact()  →  Downloads + extracts ZIP to dict    │     ║
║   │  auto_fetch_pipeline_data()  →  Orchestrates full fetch      │     ║
║   └──────────────────────────────┬───────────────────────────────┘     ║
║                                  │                                     ║
║                     Raw file contents (dict)                           ║
╚══════════════════════════════════╤═════════════════════════════════════╝
                                   │
╔══════════════════════════════════╧═════════════════════════════════════╗
║                    🔄 PROCESSING & PARSING LAYER                      ║
║                                                                        ║
║   ┌────────────────────────┐    ┌─────────────────────────────────┐   ║
║   │   Scan Parser Engine   │    │     Context Builder Engine      │   ║
║   │                        │    │                                 │   ║
║   │  parse_scan_findings() │    │  build_pipeline_context()       │   ║
║   │                        │    │                                 │   ║
║   │  • Semgrep → rules,    │    │  • Aggregates run metadata      │   ║
║   │    severity, snippets  │    │  • Summarizes findings by tool  │   ║
║   │  • Trivy → CVEs,       │───▶│  • Includes severity breakdown  │   ║
║   │    packages, versions  │    │  • Appends remediation content  │   ║
║   │  • tfsec → IaC rules   │    │  • Includes security gate       │   ║
║   │  • Gitleaks → secrets  │    │    decision (pass/fail)         │   ║
║   │  • Conftest → policy   │    │  • Formats as Markdown string   │   ║
║   │    violations          │    │    (~2K-8K chars)               │   ║
║   └────────────┬───────────┘    └──────────────┬──────────────────┘   ║
║                │                               │                       ║
║                ▼                               ▼                       ║
║   ┌────────────────────────────────────────────────────────────────┐  ║
║   │                  Streamlit Session State                       │  ║
║   │                                                                │  ║
║   │  loaded_findings    →  Structured findings per tool            │  ║
║   │  workflow_runs      →  Run history across all workflows        │  ║
║   │  latest_run         →  Most recent run with security data      │  ║
║   │  loaded_scan_files  →  Raw JSON file contents                  │  ║
║   │  loaded_remediation →  Remediation markdown files              │  ║
║   │  loaded_ai_files    →  Decision + LLM recommendations          │  ║
║   │  pipeline_context   →  Aggregated context for LLM              │  ║
║   │  chat_messages      →  Full conversation history               │  ║
║   └────────────────────────────────────────────────────────────────┘  ║
╚══════════════════════════════════╤═════════════════════════════════════╝
                                   │
╔══════════════════════════════════╧═════════════════════════════════════╗
║                      🧠 AI INTELLIGENCE LAYER                         ║
║                                                                        ║
║   ┌──────────────────────────────────────────────────────────────┐    ║
║   │                    AI Chat Engine                             │    ║
║   │                                                              │    ║
║   │  groq_chat(messages, system_prompt, api_key, model)          │    ║
║   │                                                              │    ║
║   │  1. Constructs system prompt with full pipeline context      │    ║
║   │  2. Appends conversation history + latest user message       │    ║
║   │  3. Sends to Groq API (Llama 3.3 70B, temp=0.3)            │    ║
║   │  4. Returns AI response with specific CVEs, file paths,     │    ║
║   │     line numbers, and code fix suggestions                   │    ║
║   └──────────────────────────────┬───────────────────────────────┘    ║
║                                  │                                     ║
║                          Groq Cloud API                                ║
║                    (Llama 3.3 70B Versatile)                           ║
╚══════════════════════════════════╤═════════════════════════════════════╝
                                   │
╔══════════════════════════════════╧═════════════════════════════════════╗
║                      🖥️ PRESENTATION LAYER                            ║
║                                                                        ║
║   Streamlit Web Application (Dark Theme)                               ║
║   ┌──────────────────────────────────────────────────────────────┐    ║
║   │                                                              │    ║
║   │  ┌─────────┐  ┌───────────┐  ┌──────────┐  ┌────────────┐  │    ║
║   │  │ 🤖 AI   │  │ 📊 Pipe-  │  │ 🔍 Scan  │  │ 💡 Remedi- │  │    ║
║   │  │  Chat   │  │  line     │  │ Results  │  │  ation     │  │    ║
║   │  │         │  │ Dashboard │  │          │  │            │  │    ║
║   │  └─────────┘  └───────────┘  └──────────┘  └────────────┘  │    ║
║   │                                                              │    ║
║   │  Quick Prompts  ·  Severity Metrics  ·  Finding Cards       │    ║
║   │  Chat History   ·  Run Expanders     ·  Explain & Fix AI    │    ║
║   └──────────────────────────────────────────────────────────────┘    ║
╚══════════════════════════════════════════════════════════════════════╝
```

### Layer Responsibilities

| Layer | Purpose | Key Components |
|-------|---------|----------------|
| **CI/CD Security Layer** | Runs security scanners inside GitHub Actions and packages results as downloadable artifacts | 5 scanners, 3 artifact types (scan-reports, remediation-suggestions, ai-results) |
| **Data Ingestion Layer** | Connects to GitHub REST API to fetch workflow runs and download artifact ZIPs | GitHub API client functions with authentication and error handling |
| **Processing & Parsing Layer** | Transforms raw JSON scanner outputs into normalized findings and builds a unified context string for the LLM | Scan parser (5 formats), context builder, Streamlit session state |
| **AI Intelligence Layer** | Manages all LLM communication — constructs context-rich prompts and handles Groq API interactions | Chat engine with system prompt injection, conversation history management |
| **Presentation Layer** | Renders the four-tab Streamlit interface with metrics, findings cards, chat, and remediation views | Streamlit components with custom dark-themed CSS |

---

## Features

### 🤖 AI-Powered Chat
- Conversational interface with full pipeline context awareness
- Ask about vulnerabilities, get code fixes, and request security guidance
- 8 quick-prompt buttons for common security queries
- Powered by Groq's Llama 3.3 70B for fast, accurate responses

### 📊 Pipeline Dashboard
- Real-time view of all GitHub Actions workflow runs (across all workflows)
- Pass/fail metrics with trend indicators
- One-click artifact loading from any pipeline run
- Direct links to GitHub for detailed run inspection

### 🔍 Unified Scan Results
- Consolidated view of findings from 5 security scanners
- Severity breakdown (Critical, High, Medium, Low) with color-coded cards
- Per-tool expandable sections with detailed finding information
- "Explain & Fix" AI button for each individual finding
- Manual JSON upload support for offline analysis

### 💡 AI Remediation
- Auto-loaded remediation suggestions from pipeline artifacts
- Per-tool remediation markdown with actionable steps
- Security gate decision status (pass/fail) with reasoning
- "Ask AI" button to prioritize and summarize remediation actions

---

## Tech Stack

| Component              | Technology                            |
|------------------------|---------------------------------------|
| **Frontend**           | Streamlit (Python)                    |
| **AI / LLM**          | Groq API — Llama 3.3 70B Versatile   |
| **CI/CD**             | GitHub Actions                        |
| **Container**          | Docker (Python 3.12-slim)            |
| **Security Scanners** | Semgrep, Trivy, tfsec, Gitleaks, Conftest |
| **Language**           | Python 3.12                          |

---

## Project Structure

```
devsecops-ai-chatbot/
├── App.py                    # Main Streamlit application
├── Dockerfile                # Container build configuration
├── Requirements.txt          # Python dependencies
├── .streamlit/
│   └── config.toml           # Streamlit theme & server configuration
├── README.md                 # Project documentation (this file)
└── DFD.html                  # Data Flow Diagram (visual reference)
```

---

## Security Tools Integrated

The chatbot parses and displays findings from five security scanners that run inside your GitHub Actions pipeline:

| Tool         | Category                     | What It Detects                                        | Report File              |
|--------------|------------------------------|--------------------------------------------------------|--------------------------|
| **Semgrep**  | SAST (Static Analysis)       | Code-level vulnerabilities, insecure patterns, OWASP issues | `semgrep.json`           |
| **Trivy**    | Vulnerability + Misconfiguration | CVEs in OS/library packages, Dockerfile & K8s misconfigs | `trivy_fs.json`, `trivy_image.json` |
| **tfsec**    | Infrastructure as Code       | Terraform security misconfigurations and compliance gaps | `tfsec.json`             |
| **Gitleaks** | Secret Detection             | Hardcoded API keys, tokens, passwords in git history    | `gitleaks.json`          |
| **Conftest** | Policy-as-Code               | OPA/Rego policy violations in Kubernetes manifests      | `conftest.json`          |

### Expected GitHub Actions Artifacts

The chatbot looks for three named artifacts in your workflow runs:

- **`scan-reports`** — Contains JSON outputs from all scanners listed above
- **`remediation-suggestions`** — Contains per-tool `.md` remediation files and a `remediation_summary.json`
- **`ai-results`** — Contains `decision.json` (security gate pass/fail) and `llm_recommendations.md`

---

## Application Tabs

### 1. 🤖 AI Chat

The AI Chat tab is the core of the chatbot. On application startup, it automatically fetches the latest pipeline data and builds a comprehensive context string that gets injected into every Groq API call. This means the AI always knows your current vulnerabilities, affected files, severity levels, and remediation status.

**How it works:**
- The system prompt includes the full pipeline context (run metadata, findings summary per tool, severity breakdown, remediation content, security gate decision)
- Every user message is sent alongside the full conversation history for multi-turn awareness
- The AI references actual CVE IDs, file paths, line numbers, and package versions from your real scan data
- Quick-prompt buttons allow one-click access to common queries like "List all critical vulnerabilities" or "Generate fix for the most severe finding"

### 2. 📊 Pipeline Dashboard

Displays a real-time overview of your CI/CD pipeline health across all workflows:

- **Metrics Row:** Total runs, recent pass/fail ratio, latest run status
- **Run History:** Expandable cards for the last 10 runs showing workflow name, commit SHA, branch, trigger event, and status badge
- **Artifact Loading:** Click "Load Artifacts" on any run to download and parse its scan reports, remediation suggestions, and AI analysis — the chat context automatically rebuilds

### 3. 🔍 Scan Results

A unified security findings dashboard:

- **Severity Counters:** Color-coded metrics for Critical (red), High (orange), Medium (yellow), and Low (green)
- **Per-Tool Sections:** Expandable panels for each scanner with styled finding cards featuring severity-based left border colors
- **AI Explain & Fix:** One-click button on any finding that sends it to the LLM for a detailed explanation and corrected code snippet
- **Manual Upload:** Drag-and-drop JSON files if you want to analyze scan reports outside the pipeline

### 4. 💡 Remediation

Displays AI-generated remediation guidance from the pipeline:

- **Summary Metrics:** Remediation mode, total findings processed, and total suggestions generated
- **Per-Tool Suggestions:** Expandable markdown sections (Semgrep, Trivy, tfsec, Gitleaks, Conftest) with detailed fix instructions
- **Security Gate Decision:** Visual pass/fail badge with the AI's reasoning and full decision JSON
- **Ask AI:** Button that sends the remediation content to the LLM for a prioritized action plan

---

## Data Flow

The data flow describes the complete journey of security data — from scanners generating findings inside the CI/CD pipeline, through the chatbot's processing engine, to the AI-powered responses presented to the developer.

```
┌─────────────────────────────────────────────────────────────────────┐
│                     GITHUB ACTIONS PIPELINE                         │
│                                                                     │
│  Code Push / PR                                                     │
│       │                                                             │
│       ▼                                                             │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐ │
│  │ Semgrep │  │  Trivy  │  │  tfsec  │  │Gitleaks │  │Conftest │ │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘ │
│       │            │            │             │             │       │
│       ▼            ▼            ▼             ▼             ▼       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              Artifact Upload (ZIP archives)                 │   │
│  │  scan-reports  ·  remediation-suggestions  ·  ai-results   │   │
│  └─────────────────────────────┬───────────────────────────────┘   │
└────────────────────────────────┼───────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐
                    │   GitHub REST API       │
                    │   /actions/runs         │
                    │   /artifacts/{id}/zip   │
                    └────────────┬────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │       DATA INGESTION (on startup)    │
              │                                      │
              │  1. Fetch last 15 workflow runs       │
              │  2. Find latest run with security     │
              │     artifacts (scan-reports, etc.)    │
              │  3. Download + extract ZIP files      │
              │  4. Store raw file contents in        │
              │     session state                     │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────▼──────────────────┐
              │        PARSING & PROCESSING          │
              │                                      │
              │  parse_scan_findings()               │
              │  ┌───────────────────────────────┐   │
              │  │ semgrep.json  → rules, sev,   │   │
              │  │                 file, line     │   │
              │  │ trivy_fs.json → CVEs, pkgs,   │   │
              │  │                 versions       │   │
              │  │ tfsec.json   → IaC rules,     │   │
              │  │                 locations      │   │
              │  │ gitleaks.json → secret rules,  │   │
              │  │                 file paths     │   │
              │  │ conftest.json → policy fails   │   │
              │  └───────────────────────────────┘   │
              │                                      │
              │  build_pipeline_context()             │
              │  ┌───────────────────────────────┐   │
              │  │ Aggregates all data into a     │   │
              │  │ single Markdown string:        │   │
              │  │ • Run metadata                 │   │
              │  │ • Findings per tool (top 10)   │   │
              │  │ • Severity breakdown           │   │
              │  │ • Security gate decision       │   │
              │  │ • Remediation summaries        │   │
              │  │ • Recent run history           │   │
              │  └───────────────────────────────┘   │
              └──────────┬──────────┬───────────────┘
                         │          │
          ┌──────────────▼──┐  ┌───▼──────────────────┐
          │  Session State  │  │  Pipeline Context     │
          │  (all findings, │  │  (Markdown string     │
          │   runs, files,  │  │   for LLM system      │
          │   chat history) │  │   prompt injection)   │
          └────────┬────────┘  └───────────┬───────────┘
                   │                       │
              ┌────▼───────────────────────▼────────┐
              │           AI CHAT ENGINE             │
              │                                      │
              │  User message                        │
              │       +                              │
              │  Conversation history                │
              │       +                              │
              │  System prompt (with pipeline        │
              │  context injected)                   │
              │       │                              │
              │       ▼                              │
              │  ┌─────────────────────────┐         │
              │  │     Groq API Call       │         │
              │  │  Llama 3.3 70B         │         │
              │  │  temp=0.3, 4096 tokens │         │
              │  └───────────┬─────────────┘         │
              │              │                       │
              │              ▼                       │
              │  AI Response (with real CVEs,        │
              │  file paths, code fixes)             │
              └──────────────┬──────────────────────┘
                             │
              ┌──────────────▼──────────────────────┐
              │        STREAMLIT UI                  │
              │                                      │
              │  ┌────────┐ ┌──────────┐ ┌────────┐ │
              │  │AI Chat │ │Dashboard │ │ Scans  │ │
              │  ├────────┤ ├──────────┤ ├────────┤ │
              │  │Chat    │ │Metrics   │ │Severity│ │
              │  │bubbles │ │Run cards │ │cards   │ │
              │  │Quick   │ │Artifact  │ │Per-tool│ │
              │  │prompts │ │loader    │ │details │ │
              │  └────────┘ └──────────┘ └────────┘ │
              │  ┌──────────────────────────────┐    │
              │  │        Remediation           │    │
              │  │  Suggestions · Gate Decision │    │
              │  └──────────────────────────────┘    │
              └──────────────────────────────────────┘
                             │
                             ▼
                        👤 Developer
```

### Flow Summary

| Step | What Happens |
|------|-------------|
| **1. Pipeline Trigger** | A code push or PR triggers the GitHub Actions workflow |
| **2. Security Scanning** | Five scanners run in parallel, each producing a JSON report |
| **3. Artifact Packaging** | Reports are grouped into three ZIP artifacts and uploaded to GitHub |
| **4. Auto-Fetch** | On chatbot startup, the GitHub API client fetches the latest runs and downloads artifacts |
| **5. Parsing** | Raw JSON files are parsed into a normalized findings structure per tool |
| **6. Context Building** | All data is aggregated into a Markdown string for LLM prompt injection |
| **7. Session Storage** | Parsed findings, run history, and context are stored in Streamlit session state |
| **8. User Interaction** | Developer asks questions, clicks quick prompts, or browses dashboards |
| **9. AI Processing** | User messages + pipeline context are sent to Groq's Llama 3.3 70B |
| **10. Response Delivery** | AI responses with specific CVEs, file paths, and code fixes are rendered in the chat |

> 📊 A visual Data Flow Diagram is available in `DFD.html`.

---

<p align="center">
  <strong>Built with 🛡️ by the DevSecOps AI Team</strong><br>
  Powered by Groq · GitHub Actions · Streamlit
</p>
