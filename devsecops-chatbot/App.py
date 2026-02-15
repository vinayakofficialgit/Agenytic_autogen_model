"""
🛡️ DevSecOps AI Assistant — Streamlit Chatbot
Powered by Groq (Llama 3.3 70B) + GitHub Actions integration
"""

import streamlit as st
import requests
import json
import zipfile
import io
import os
from datetime import datetime, timezone

# ─── PAGE CONFIG ──────────────────────────────────────────────
st.set_page_config(
    page_title="DevSecOps AI Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── CUSTOM CSS ───────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=DM+Sans:wght@400;500;600;700&display=swap');

/* Global */
.stApp { font-family: 'DM Sans', sans-serif; }
code, pre, .stCode { font-family: 'JetBrains Mono', monospace !important; }

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
}
[data-testid="stSidebar"] * { color: #e2e8f0 !important; }
[data-testid="stSidebar"] .stTextInput input {
    background: #334155 !important;
    border: 1px solid #475569 !important;
    color: #f1f5f9 !important;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #1e293b, #0f172a);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 16px;
}
[data-testid="stMetric"] label { color: #94a3b8 !important; }
[data-testid="stMetric"] [data-testid="stMetricValue"] { color: #f8fafc !important; }

/* Chat messages */
.chat-user {
    background: linear-gradient(135deg, #1d4ed8, #2563eb);
    color: white;
    padding: 12px 18px;
    border-radius: 18px 18px 4px 18px;
    margin: 8px 0;
    max-width: 80%;
    margin-left: auto;
    font-size: 0.95em;
}
.chat-ai {
    background: #1e293b;
    color: #e2e8f0;
    padding: 12px 18px;
    border-radius: 18px 18px 18px 4px;
    margin: 8px 0;
    max-width: 85%;
    border: 1px solid #334155;
    font-size: 0.95em;
}

/* Status badges */
.badge-pass {
    display: inline-block;
    background: #065f46;
    color: #6ee7b7;
    padding: 4px 14px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 0.85em;
}
.badge-fail {
    display: inline-block;
    background: #7f1d1d;
    color: #fca5a5;
    padding: 4px 14px;
    border-radius: 20px;
    font-weight: 600;
    font-size: 0.85em;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] { gap: 8px; }
.stTabs [data-baseweb="tab"] {
    background: #1e293b;
    border-radius: 8px;
    color: #94a3b8;
    border: 1px solid #334155;
    padding: 8px 20px;
}
.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, #1d4ed8, #2563eb) !important;
    color: white !important;
    border-color: #3b82f6 !important;
}

/* Finding cards */
.finding-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 16px;
    margin: 10px 0;
}
.finding-card:hover { border-color: #3b82f6; }
.sev-critical { border-left: 4px solid #ef4444 !important; }
.sev-high { border-left: 4px solid #f97316 !important; }
.sev-medium { border-left: 4px solid #eab308 !important; }
.sev-low { border-left: 4px solid #22c55e !important; }

/* Header */
.main-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
    border: 1px solid #334155;
    border-radius: 16px;
    padding: 24px 32px;
    margin-bottom: 24px;
}
</style>
""", unsafe_allow_html=True)


# ─── GROQ API HELPER ─────────────────────────────────────────
def groq_chat(messages: list, system_prompt: str = "", api_key: str = "") -> str:
    """Send messages to Groq API and return the response."""
    if not api_key:
        return "⚠️ Please enter your Groq API key in the sidebar."

    all_messages = []
    if system_prompt:
        all_messages.append({"role": "system", "content": system_prompt})
    all_messages.extend(messages)

    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": "llama-3.3-70b-versatile",
                "messages": all_messages,
                "temperature": 0.3,
                "max_tokens": 4096,
            },
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except requests.exceptions.HTTPError as e:
        if resp.status_code == 401:
            return "❌ Invalid Groq API key. Please check your key in the sidebar."
        return f"❌ Groq API error: {e}"
    except Exception as e:
        return f"❌ Error: {e}"


# ─── GITHUB API HELPERS ──────────────────────────────────────
def get_workflow_runs(owner: str, repo: str, token: str, limit: int = 10) -> list:
    """Fetch recent workflow runs from GitHub Actions."""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/actions/runs",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"},
            params={"per_page": limit},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("workflow_runs", [])
    except Exception as e:
        st.error(f"GitHub API error: {e}")
        return []


def get_artifacts(owner: str, repo: str, run_id: int, token: str) -> list:
    """Fetch artifacts for a specific workflow run."""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json().get("artifacts", [])
    except Exception as e:
        st.error(f"Artifact fetch error: {e}")
        return []


def download_artifact(owner: str, repo: str, artifact_id: int, token: str) -> dict:
    """Download and extract a GitHub Actions artifact (zip)."""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip",
            headers={"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"},
            timeout=60,
            stream=True,
        )
        resp.raise_for_status()
        files = {}
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for name in zf.namelist():
                with zf.open(name) as f:
                    content = f.read()
                    try:
                        files[name] = content.decode("utf-8")
                    except UnicodeDecodeError:
                        files[name] = f"[Binary file: {len(content)} bytes]"
        return files
    except Exception as e:
        st.error(f"Download error: {e}")
        return {}


def parse_scan_findings(files: dict) -> dict:
    """Parse scan report JSON files into structured findings."""
    findings = {"semgrep": [], "trivy": [], "tfsec": [], "gitleaks": [], "conftest": []}

    # Semgrep
    if "semgrep.json" in files:
        try:
            data = json.loads(files["semgrep.json"])
            for r in data.get("results", []):
                findings["semgrep"].append({
                    "rule": r.get("check_id", ""),
                    "severity": r.get("extra", {}).get("severity", "UNKNOWN"),
                    "message": r.get("extra", {}).get("message", ""),
                    "file": r.get("path", ""),
                    "line": r.get("start", {}).get("line", "?"),
                    "snippet": r.get("extra", {}).get("lines", ""),
                })
        except json.JSONDecodeError:
            pass

    # Trivy FS
    if "trivy_fs.json" in files:
        try:
            data = json.loads(files["trivy_fs.json"])
            for result in data.get("Results", []):
                target = result.get("Target", "")
                for vuln in result.get("Vulnerabilities", []):
                    findings["trivy"].append({
                        "id": vuln.get("VulnerabilityID", ""),
                        "severity": vuln.get("Severity", "UNKNOWN"),
                        "package": vuln.get("PkgName", ""),
                        "installed": vuln.get("InstalledVersion", ""),
                        "fixed": vuln.get("FixedVersion", "N/A"),
                        "title": vuln.get("Title", ""),
                        "target": target,
                    })
                for misconf in result.get("Misconfigurations", []):
                    findings["trivy"].append({
                        "id": misconf.get("ID", ""),
                        "severity": misconf.get("Severity", "UNKNOWN"),
                        "title": misconf.get("Title", ""),
                        "description": misconf.get("Description", ""),
                        "target": target,
                        "type": "misconfiguration",
                    })
        except json.JSONDecodeError:
            pass

    # tfsec
    if "tfsec.json" in files:
        try:
            data = json.loads(files["tfsec.json"])
            for r in data.get("results", []) or []:
                findings["tfsec"].append({
                    "rule": r.get("rule_id", r.get("long_id", "")),
                    "severity": r.get("severity", "UNKNOWN"),
                    "description": r.get("description", ""),
                    "file": r.get("location", {}).get("filename", ""),
                    "line": r.get("location", {}).get("start_line", "?"),
                })
        except json.JSONDecodeError:
            pass

    # Gitleaks
    if "gitleaks.json" in files:
        try:
            data = json.loads(files["gitleaks.json"])
            if isinstance(data, list):
                for r in data:
                    findings["gitleaks"].append({
                        "rule": r.get("RuleID", r.get("rule", "")),
                        "file": r.get("File", r.get("file", "")),
                        "line": r.get("StartLine", r.get("line", "?")),
                    })
        except json.JSONDecodeError:
            pass

    # Conftest
    if "conftest.json" in files:
        try:
            data = json.loads(files["conftest.json"])
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        for fail in entry.get("failures", []):
                            findings["conftest"].append({
                                "file": entry.get("filename", ""),
                                "msg": fail.get("msg", "") if isinstance(fail, dict) else str(fail),
                            })
        except json.JSONDecodeError:
            pass

    return findings


# ─── SIDEBAR ──────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ DevSecOps AI")
    st.markdown("---")

    st.markdown("### 🔑 API Keys")

    # Read from environment variables (set via Docker -e flags)
    env_groq = os.getenv("GROQ_API_KEY", "")
    env_gh = os.getenv("GH_PAT_TOKEN", "")
    env_repo = os.getenv("GITHUB_REPOSITORY", "")

    # Use session state to persist values across rerenders
    if "groq_key" not in st.session_state:
        st.session_state.groq_key = env_groq
    if "github_token" not in st.session_state:
        st.session_state.github_token = env_gh
    if "repo_full" not in st.session_state:
        st.session_state.repo_full = env_repo

    groq_input = st.text_input(
        "Groq API Key",
        value=st.session_state.groq_key,
        type="password",
        help="Get free at console.groq.com",
    )
    gh_input = st.text_input(
        "GitHub Token (PAT)",
        value=st.session_state.github_token,
        type="password",
        help="For fetching pipeline artifacts",
    )

    st.markdown("---")
    st.markdown("### 📦 Repository")
    repo_input = st.text_input(
        "Owner/Repo",
        value=st.session_state.repo_full,
        placeholder="e.g. vinayak/my-repo",
    )

    # Update session state with user input (or keep env var)
    groq_key = groq_input if groq_input else env_groq
    github_token = gh_input if gh_input else env_gh
    repo_full = repo_input if repo_input else env_repo

    st.session_state.groq_key = groq_key
    st.session_state.github_token = github_token
    st.session_state.repo_full = repo_full

    # Show connection status
    st.markdown("---")
    st.markdown("### 📡 Status")
    st.markdown(f"{'✅' if groq_key else '❌'} Groq API Key")
    st.markdown(f"{'✅' if github_token else '❌'} GitHub Token")
    st.markdown(f"{'✅' if repo_full else '❌'} Repository: `{repo_full}`" if repo_full else "❌ Repository")

    st.markdown("---")
    st.markdown("### ⚙️ Settings")
    model_choice = st.selectbox("Groq Model", [
        "llama-3.3-70b-versatile",
        "llama-3.1-8b-instant",
        "mixtral-8x7b-32768",
    ])

    st.markdown("---")
    st.markdown("""
    <div style="text-align:center; opacity:0.5; font-size:0.8em;">
    Powered by Groq + GitHub Actions<br>
    DevSecOps Agentic AI Pipeline
    </div>
    """, unsafe_allow_html=True)


# ─── HEADER ───────────────────────────────────────────────────
st.markdown("""
<div class="main-header">
    <h1 style="margin:0; color:#f8fafc;">🛡️ DevSecOps AI Assistant</h1>
    <p style="margin:4px 0 0 0; color:#94a3b8; font-size:1.1em;">
        Chat with your security pipeline • Analyze vulnerabilities • Get AI-powered remediation
    </p>
</div>
""", unsafe_allow_html=True)


# ─── TABS ─────────────────────────────────────────────────────
tab_chat, tab_dashboard, tab_scans, tab_remediation = st.tabs([
    "🤖 AI Chat",
    "📊 Pipeline Dashboard",
    "🔍 Scan Results",
    "💡 Remediation",
])


# ══════════════════════════════════════════════════════════════
# TAB 1: AI CHAT
# ══════════════════════════════════════════════════════════════
with tab_chat:
    SYSTEM_PROMPT = """You are a senior DevSecOps security engineer and AI assistant.
You have deep expertise in:
- Application security (OWASP Top 10, secure coding)
- Container security (Docker, Kubernetes)
- Infrastructure as Code security (Terraform, CloudFormation)
- CI/CD pipeline security (GitHub Actions, GitLab CI)
- Secrets management, vulnerability remediation
- Tools: Semgrep, Trivy, tfsec, Gitleaks, Conftest, OPA

When users share scan results or findings, you:
1. Explain the vulnerability clearly
2. Assess the severity and impact
3. Provide corrected code snippets
4. Suggest best practices

You also answer general questions like a knowledgeable AI assistant.
Always be clear, concise, and provide actionable advice with code examples."""

    # Initialize chat history
    if "chat_messages" not in st.session_state:
        st.session_state.chat_messages = []

    # Display chat history
    for msg in st.session_state.chat_messages:
        css_class = "chat-user" if msg["role"] == "user" else "chat-ai"
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Chat input
    if prompt := st.chat_input("Ask me anything about security, vulnerabilities, or DevSecOps..."):
        # Add user message
        st.session_state.chat_messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # Build context if scan data is loaded
        context_prefix = ""
        if "loaded_findings" in st.session_state and st.session_state.loaded_findings:
            findings = st.session_state.loaded_findings
            total = sum(len(v) for v in findings.values())
            if total > 0:
                context_prefix = f"\n\n[CONTEXT: The current pipeline has {total} security findings across these tools: "
                for tool, items in findings.items():
                    if items:
                        context_prefix += f"{tool}({len(items)}), "
                context_prefix = context_prefix.rstrip(", ") + "]\n\n"

        messages_for_api = [
            {"role": m["role"], "content": m["content"]}
            for m in st.session_state.chat_messages
        ]
        if context_prefix:
            messages_for_api[-1]["content"] = context_prefix + messages_for_api[-1]["content"]

        # Get AI response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                response = groq_chat(messages_for_api, SYSTEM_PROMPT, groq_key)
                st.markdown(response)

        st.session_state.chat_messages.append({"role": "assistant", "content": response})

    # Quick action buttons
    st.markdown("---")
    st.markdown("**Quick prompts:**")
    cols = st.columns(4)
    quick_prompts = [
        "Explain OWASP Top 10",
        "How to harden a Dockerfile?",
        "Best practices for GitHub Actions secrets",
        "How to fix SQL injection in Python?",
    ]
    for i, qp in enumerate(quick_prompts):
        if cols[i].button(qp, key=f"qp_{i}", use_container_width=True):
            st.session_state.chat_messages.append({"role": "user", "content": qp})
            st.rerun()


# ══════════════════════════════════════════════════════════════
# TAB 2: PIPELINE DASHBOARD
# ══════════════════════════════════════════════════════════════
with tab_dashboard:
    if not github_token or not repo_full:
        st.info("👈 Enter your GitHub token and repository in the sidebar to view pipeline runs.")
    else:
        parts = repo_full.split("/")
        if len(parts) != 2:
            st.error("Repository format should be `owner/repo`")
        else:
            owner, repo = parts

            if st.button("🔄 Refresh Pipeline Data", use_container_width=True):
                st.session_state.pop("workflow_runs", None)

            if "workflow_runs" not in st.session_state:
                with st.spinner("Fetching pipeline runs..."):
                    st.session_state.workflow_runs = get_workflow_runs(owner, repo, github_token)

            runs = st.session_state.get("workflow_runs", [])

            if not runs:
                st.warning("No workflow runs found.")
            else:
                # Summary metrics
                recent = runs[:5]
                passed = sum(1 for r in recent if r.get("conclusion") == "success")
                failed = sum(1 for r in recent if r.get("conclusion") == "failure")

                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Total Runs", len(runs))
                c2.metric("Recent Passed", f"{passed}/5", delta=f"{passed*20}%")
                c3.metric("Recent Failed", f"{failed}/5", delta=f"-{failed*20}%" if failed else "0%")
                c4.metric("Latest", runs[0].get("conclusion", "running").upper() if runs else "N/A")

                st.markdown("### Recent Pipeline Runs")

                for run in runs[:10]:
                    conclusion = run.get("conclusion", "in_progress")
                    status_icon = "✅" if conclusion == "success" else "❌" if conclusion == "failure" else "⏳"
                    badge_class = "badge-pass" if conclusion == "success" else "badge-fail"
                    created = run.get("created_at", "")[:19].replace("T", " ")

                    with st.expander(
                        f"{status_icon} Run #{run.get('run_number', '?')} — {created} — {run.get('head_branch', '')}",
                        expanded=False,
                    ):
                        col_a, col_b = st.columns([3, 1])
                        with col_a:
                            st.markdown(f"**Commit:** `{run.get('head_sha', '')[:8]}`")
                            st.markdown(f"**Branch:** `{run.get('head_branch', '')}`")
                            st.markdown(f"**Trigger:** {run.get('event', '')}")
                            st.markdown(f"**Status:** <span class='{badge_class}'>{conclusion}</span>", unsafe_allow_html=True)
                        with col_b:
                            st.link_button("View on GitHub", run.get("html_url", "#"), use_container_width=True)

                            # Load artifacts button
                            if st.button(f"📥 Load Artifacts", key=f"load_{run['id']}", use_container_width=True):
                                with st.spinner("Fetching artifacts..."):
                                    artifacts = get_artifacts(owner, repo, run["id"], github_token)
                                    for art in artifacts:
                                        files = download_artifact(owner, repo, art["id"], github_token)
                                        if art["name"] == "scan-reports":
                                            st.session_state.loaded_scan_files = files
                                            st.session_state.loaded_findings = parse_scan_findings(files)
                                            st.success(f"✅ Loaded scan reports ({len(files)} files)")
                                        elif art["name"] == "remediation-suggestions":
                                            st.session_state.loaded_remediation_files = files
                                            st.success(f"✅ Loaded remediation suggestions ({len(files)} files)")
                                        elif art["name"] == "ai-results":
                                            st.session_state.loaded_ai_files = files
                                            st.success(f"✅ Loaded AI analysis ({len(files)} files)")


# ══════════════════════════════════════════════════════════════
# TAB 3: SCAN RESULTS
# ══════════════════════════════════════════════════════════════
with tab_scans:
    st.markdown("### 🔍 Security Scan Results")

    # Option to upload manually
    uploaded = st.file_uploader(
        "Upload scan report (JSON)",
        type=["json"],
        accept_multiple_files=True,
        help="Upload semgrep.json, trivy_fs.json, tfsec.json, gitleaks.json, or conftest.json",
    )

    if uploaded:
        manual_files = {}
        for f in uploaded:
            manual_files[f.name] = f.read().decode("utf-8")
        st.session_state.loaded_scan_files = manual_files
        st.session_state.loaded_findings = parse_scan_findings(manual_files)

    findings = st.session_state.get("loaded_findings", {})
    total_findings = sum(len(v) for v in findings.values())

    if total_findings == 0:
        st.info("No scan results loaded. Either load from the Dashboard tab or upload files above.")
    else:
        # Summary
        st.markdown(f"**Total findings: {total_findings}**")

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for tool_findings in findings.values():
            for f in tool_findings:
                sev = f.get("severity", "UNKNOWN").upper()
                if sev in sev_counts:
                    sev_counts[sev] += 1
                else:
                    sev_counts["UNKNOWN"] += 1

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("🔴 Critical", sev_counts["CRITICAL"])
        c2.metric("🟠 High", sev_counts["HIGH"])
        c3.metric("🟡 Medium", sev_counts["MEDIUM"])
        c4.metric("🟢 Low", sev_counts["LOW"])

        # Per-tool breakdown
        for tool_name, tool_findings in findings.items():
            if not tool_findings:
                continue

            tool_icons = {
                "semgrep": "🐍", "trivy": "🔍", "tfsec": "🏗️",
                "gitleaks": "🔑", "conftest": "📋",
            }
            icon = tool_icons.get(tool_name, "📄")

            with st.expander(f"{icon} {tool_name.upper()} — {len(tool_findings)} finding(s)", expanded=True):
                for i, finding in enumerate(tool_findings):
                    sev = finding.get("severity", "UNKNOWN").upper()
                    sev_class = f"sev-{sev.lower()}" if sev.lower() in ["critical", "high", "medium", "low"] else ""

                    st.markdown(f"""<div class="finding-card {sev_class}">
                        <strong>[{sev}]</strong> {finding.get('rule', finding.get('id', finding.get('msg', 'Finding')))}
                        <br><small>{finding.get('file', finding.get('target', ''))} {f"line {finding.get('line', '')}" if finding.get('line') else ''}</small>
                        <br><em>{finding.get('message', finding.get('title', finding.get('description', '')))[:200]}</em>
                    </div>""", unsafe_allow_html=True)

                    # AI explain button
                    if st.button(f"🤖 Explain & Fix", key=f"explain_{tool_name}_{i}", use_container_width=False):
                        explain_prompt = f"Explain this {tool_name} security finding and provide a fix with code:\n\n{json.dumps(finding, indent=2)}"
                        with st.spinner("AI analyzing..."):
                            explanation = groq_chat(
                                [{"role": "user", "content": explain_prompt}],
                                "You are a security expert. Explain the vulnerability clearly and provide a corrected code snippet.",
                                groq_key,
                            )
                            st.markdown(explanation)


# ══════════════════════════════════════════════════════════════
# TAB 4: REMEDIATION
# ══════════════════════════════════════════════════════════════
with tab_remediation:
    st.markdown("### 💡 Remediation Suggestions")

    remed_files = st.session_state.get("loaded_remediation_files", {})
    ai_files = st.session_state.get("loaded_ai_files", {})

    if not remed_files and not ai_files:
        st.info("No remediation data loaded. Go to the Dashboard tab and click 'Load Artifacts' on a pipeline run.")
    else:
        # Show summary if available
        if "remediation_summary.json" in remed_files:
            try:
                summary = json.loads(remed_files["remediation_summary.json"])
                c1, c2, c3 = st.columns(3)
                c1.metric("Mode", summary.get("mode", "unknown").upper())
                c2.metric("Total Findings", summary.get("total_findings", 0))
                c3.metric("Suggestions Generated", summary.get("total_suggestions", 0))
            except json.JSONDecodeError:
                pass

        # Show README
        if "README.md" in remed_files:
            with st.expander("📄 README — Overview", expanded=True):
                st.markdown(remed_files["README.md"])

        # Show per-tool suggestion files
        tool_files = {
            "semgrep_suggestions.md": "🐍 Semgrep Suggestions",
            "trivy_suggestions.md": "🔍 Trivy Suggestions",
            "tfsec_suggestions.md": "🏗️ tfsec Suggestions",
            "gitleaks_suggestions.md": "🔑 Gitleaks Suggestions",
            "conftest_suggestions.md": "📋 Conftest Suggestions",
            "llm_analysis_recommendations.md": "🤖 LLM Analysis Recommendations",
        }

        for filename, label in tool_files.items():
            if filename in remed_files:
                with st.expander(f"{label}", expanded=False):
                    st.markdown(remed_files[filename])

                    # Ask AI about this file
                    if st.button(f"💬 Ask AI about this", key=f"ask_{filename}"):
                        content_preview = remed_files[filename][:3000]
                        with st.spinner("AI analyzing..."):
                            response = groq_chat(
                                [{"role": "user", "content": f"Summarize the key actions I need to take from these remediation suggestions and prioritize them:\n\n{content_preview}"}],
                                "You are a DevSecOps expert. Provide a clear, prioritized action plan.",
                                groq_key,
                            )
                            st.markdown(response)

        # Show decision.json from AI results
        if "decision.json" in ai_files:
            with st.expander("🚦 Pipeline Decision", expanded=True):
                try:
                    decision = json.loads(ai_files["decision.json"])
                    status = decision.get("status", "unknown")
                    badge = "badge-pass" if status == "pass" else "badge-fail"
                    st.markdown(f"**Status:** <span class='{badge}'>{status.upper()}</span>", unsafe_allow_html=True)
                    st.json(decision)
                except json.JSONDecodeError:
                    st.code(ai_files["decision.json"])
