#!/usr/bin/env python3
import os
import subprocess
import pathlib
from typing import Dict, List
from datetime import datetime

from tools.embeddings.retriever import RepoRetriever
from tools.agent.pick_findings import get_findings
from tools.agent.fixers import fixer_k8s, fixer_tf, fixer_java, fixer_docker
from tools.agent.utils.prompt_lib import call_llm_rewrite

REPO_ROOT = pathlib.Path(".").resolve()
OUTPUT_DIR = REPO_ROOT / "agent_output"
OUTPUT_DIR.mkdir(exist_ok=True)


# ============================================================
# Git Helpers
# ============================================================

def ensure_git_identity():
    subprocess.run(["git", "config", "user.email", "ci-bot@example.com"], check=False)
    subprocess.run(["git", "config", "user.name", "CI Bot"], check=False)


def create_branch() -> str:
    branch = f"ai-autofix-{os.urandom(4).hex()}"
    subprocess.run(["git", "checkout", "-b", branch], check=True)
    return branch


def has_changes() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def commit_and_push(branch: str):
    subprocess.run(["git", "add", "-A"], check=True)
    subprocess.run(["git", "commit", "-m", "Agentic AI Autofix"], check=True)
    subprocess.run(["git", "push", "--set-upstream", "origin", branch], check=True)


# ============================================================
# Logging Helpers
# ============================================================

def print_vuln_block(item, file_path, stage, status="RESOLVED"):
    tool = item.get("tool", "unknown")
    severity = item.get("severity", "UNKNOWN")
    rule = item.get("rule", "N/A")
    detail = (item.get("detail", "") or "")[:300]

    print(f"""
----------------------------------------------------
{ "✔" if status=="RESOLVED" else "✖" } {status}
Tool       : {tool}
Severity   : {severity}
Rule / CVE : {rule}
Details    : {detail}
File       : {file_path}
Stage      : {stage}
----------------------------------------------------
""")


def write_markdown_report(summary_rows: List[Dict]):
    report_path = OUTPUT_DIR / "ai_security_report.md"

    lines = []
    lines.append("# 🤖 Agentic AI Security Autofix Report")
    lines.append("")
    lines.append(f"Generated at: {datetime.utcnow().isoformat()} UTC")
    lines.append("")
    lines.append("| Tool | Severity | Rule/CVE | File | Stage | Status |")
    lines.append("|------|----------|----------|------|-------|--------|")

    for row in summary_rows:
        lines.append(
            f"| {row['tool']} | {row['severity']} | {row['rule']} | "
            f"{row['file']} | {row['stage']} | {row['status']} |"
        )

    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n📄 Security report generated: {report_path}")


# ============================================================
# Agent Core
# ============================================================

def collect_file_updates(findings: Dict[str, list], retriever: RepoRetriever):

    fx_map = {
        "k8s": fixer_k8s,
        "tf": fixer_tf,
        "java": fixer_java,
        "docker": fixer_docker,
    }

    resolved_any = False
    summary_rows = []

    for kind, items in findings.items():
        if kind not in fx_map:
            continue

        fx = fx_map[kind]

        for idx, item in enumerate(items, 1):
            print(f"\n--- Processing {kind} finding #{idx} ---")

            result = None
            resolution_stage = None
            file_path = item.get("file", "UNKNOWN")

            # ============================
            # Stage 1 — Deterministic
            # ============================
            result = fx.try_deterministic(item)
            if result:
                resolution_stage = "DETERMINISTIC"
                file_path = result.get("file", file_path)

            # ============================
            # Stage 2 — RAG
            # ============================
            if not result:
                q = fx.query_for(item)
                topk = retriever.search(q) if q else []
                result = fx.try_rag_style(item, topk)
                if result:
                    resolution_stage = "RAG"
                    file_path = result.get("file", file_path)

            # ============================
            # Stage 3 — LLM
            # ============================
            if not result:
                print("→ Falling back to LLM rewrite")

                if not file_path:
                    print("⚠ No file path available")
                    continue

                path_obj = pathlib.Path(file_path)
                if not path_obj.exists():
                    print(f"⚠ File not found: {file_path}")
                    continue

                original = path_obj.read_text(encoding="utf-8")

                new_content = call_llm_rewrite(
                    kind=kind,
                    finding=item,
                    original_content=original
                )

                if not new_content or not new_content.strip():
                    print("⚠ LLM returned empty content")
                    summary_rows.append({
                        **item,
                        "file": file_path,
                        "stage": "LLM",
                        "status": "FAILED"
                    })
                    continue

                if len(new_content) < len(original) * 0.5:
                    print("⚠ LLM output suspiciously small — skipping")
                    summary_rows.append({
                        **item,
                        "file": file_path,
                        "stage": "LLM",
                        "status": "FAILED"
                    })
                    continue

                path_obj.write_text(new_content, encoding="utf-8")
                resolution_stage = "LLM"
                resolved_any = True

                print_vuln_block(item, file_path, resolution_stage)
                summary_rows.append({
                    **item,
                    "file": file_path,
                    "stage": resolution_stage,
                    "status": "RESOLVED"
                })
                continue

            if result:
                resolved_any = True
                print_vuln_block(item, file_path, resolution_stage)
                summary_rows.append({
                    **item,
                    "file": file_path,
                    "stage": resolution_stage,
                    "status": "RESOLVED"
                })
            else:
                print_vuln_block(item, file_path, "NONE", status="NOT RESOLVED")
                summary_rows.append({
                    **item,
                    "file": file_path,
                    "stage": "NONE",
                    "status": "NOT RESOLVED"
                })

    write_markdown_report(summary_rows)

    return resolved_any


# ============================================================
# Main
# ============================================================

def main():
    ensure_git_identity()

    min_sev = os.getenv("MIN_SEVERITY", "HIGH").upper()
    findings = get_findings(min_sev)

    if not findings:
        print("⚠ No findings.")
        return

    branch = create_branch()

    retriever = RepoRetriever(top_k=6)
    print("RAG ready.")

    resolved_any = collect_file_updates(findings, retriever)

    if not resolved_any:
        print("⚠ No patches generated.")
        subprocess.run(["git", "checkout", "-"], check=False)
        subprocess.run(["git", "branch", "-D", branch], check=False)
        return

    if not has_changes():
        print("⚠ No actual file changes detected.")
        subprocess.run(["git", "checkout", "-"], check=False)
        subprocess.run(["git", "branch", "-D", branch], check=False)
        return

    commit_and_push(branch)
    print(f"\n🚀 Branch pushed: {branch}")


if __name__ == "__main__":
    main()











# #!/usr/bin/env python3
# import os
# import subprocess
# import pathlib
# from typing import Dict

# from tools.embeddings.retriever import RepoRetriever
# from tools.agent.pick_findings import get_findings
# from tools.agent.fixers import fixer_k8s, fixer_tf, fixer_java, fixer_docker
# from tools.agent.utils.prompt_lib import call_llm_rewrite

# REPO_ROOT = pathlib.Path(".").resolve()


# # ============================================================
# # Git Helpers
# # ============================================================

# def ensure_git_identity():
#     subprocess.run(["git", "config", "user.email", "ci-bot@example.com"], check=False)
#     subprocess.run(["git", "config", "user.name", "CI Bot"], check=False)


# def create_branch() -> str:
#     branch = f"ai-autofix-{os.urandom(4).hex()}"
#     subprocess.run(["git", "checkout", "-b", branch], check=True)
#     return branch


# def has_changes() -> bool:
#     result = subprocess.run(
#         ["git", "status", "--porcelain"],
#         capture_output=True,
#         text=True,
#     )
#     return bool(result.stdout.strip())


# def commit_and_push(branch: str):
#     subprocess.run(["git", "add", "-A"], check=True)
#     subprocess.run(["git", "commit", "-m", "Agentic AI Autofix"], check=True)
#     subprocess.run(["git", "push", "--set-upstream", "origin", branch], check=True)


# # ============================================================
# # Agent Core
# # ============================================================

# def collect_file_updates(findings: Dict[str, list], retriever: RepoRetriever):

#     fx_map = {
#         "k8s": fixer_k8s,
#         "tf": fixer_tf,
#         "java": fixer_java,
#         "docker": fixer_docker,
#     }

#     resolved_any = False

#     for kind, items in findings.items():
#         if kind not in fx_map:
#             continue

#         fx = fx_map[kind]

#         for idx, item in enumerate(items, 1):
#             print(f"\n--- Processing {kind} finding #{idx} ---")

#             result = None
#             resolution_stage = None

#             # ---------------------------
#             # Stage 1 — Deterministic
#             # ---------------------------
#             result = fx.try_deterministic(item)
#             if result:
#                 resolution_stage = "DETERMINISTIC"

#             # ---------------------------
#             # Stage 2 — RAG
#             # ---------------------------
#             if not result:
#                 q = fx.query_for(item)
#                 topk = retriever.search(q) if q else []
#                 result = fx.try_rag_style(item, topk)
#                 if result:
#                     resolution_stage = "RAG"

#             # ---------------------------
#             # Stage 3 — LLM
#             # ---------------------------
#             if not result:
#                 print("→ Falling back to LLM rewrite")

#                 path = item.get("file")
#                 if not path:
#                     print("⚠ No file path available")
#                     continue

#                 file_path = pathlib.Path(path)
#                 if not file_path.exists():
#                     print(f"⚠ File not found: {path}")
#                     continue

#                 original = file_path.read_text(encoding="utf-8")

#                 new_content = call_llm_rewrite(
#                     kind=kind,
#                     finding=item,
#                     original_content=original
#                 )

#                 if not new_content or not new_content.strip():
#                     print("⚠ LLM returned empty content")
#                     continue

#                 if len(new_content) < len(original) * 0.5:
#                     print("⚠ LLM output suspiciously small — skipping")
#                     continue

#                 file_path.write_text(new_content, encoding="utf-8")
#                 resolution_stage = "LLM"
#                 resolved_any = True

#                 print(f"""
#                 -----------------------------------------
#                 ✔ RESOLVED
#                 File : {path}
#                 Stage: {resolution_stage}
#                 -----------------------------------------
#                 """)
#                 continue

#             if result:
#                 resolved_any = True
#                 print(f"""
#                 -----------------------------------------
#                 ✔ RESOLVED
#                 File : {result['file']}
#                 Stage: {resolution_stage}
#                 -----------------------------------------
#                 """)

#             else:
#                 print(f"""
#                 -----------------------------------------
#                 ✖ NOT RESOLVED
#                 File : {item.get('file')}
#                 Stage: NONE
#                 -----------------------------------------
#                 """)

#     return resolved_any


# # ============================================================
# # Main
# # ============================================================

# def main():
#     ensure_git_identity()

#     min_sev = os.getenv("MIN_SEVERITY", "HIGH").upper()
#     findings = get_findings(min_sev)

#     if not findings:
#         print("⚠ No findings.")
#         return

#     branch = create_branch()

#     retriever = RepoRetriever(top_k=6)
#     print("RAG ready.")

#     resolved_any = collect_file_updates(findings, retriever)

#     if not resolved_any:
#         print("⚠ No patches generated.")
#         subprocess.run(["git", "checkout", "-"], check=False)
#         subprocess.run(["git", "branch", "-D", branch], check=False)
#         return

#     if not has_changes():
#         print("⚠ No actual file changes detected.")
#         subprocess.run(["git", "checkout", "-"], check=False)
#         subprocess.run(["git", "branch", "-D", branch], check=False)
#         return

#     commit_and_push(branch)
#     print(f"\n🚀 Branch pushed: {branch}")


# if __name__ == "__main__":
#     main()