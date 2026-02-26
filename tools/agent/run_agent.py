#!/usr/bin/env python3
import os
import subprocess
import pathlib
import tempfile
from typing import Dict, List

from tools.embeddings.retriever import RepoRetriever
from tools.agent.pick_findings import get_findings
from tools.agent.fixers import fixer_k8s, fixer_tf, fixer_java, fixer_docker
from tools.agent.utils.prompt_lib import call_llm_rewrite

REPO_ROOT = pathlib.Path(".").resolve()
OUTPUT = REPO_ROOT / "agent_output"
OUTPUT.mkdir(parents=True, exist_ok=True)


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


def commit_and_push(branch: str):
    subprocess.run(["git", "add", "-u"], check=True)
    subprocess.run(["git", "commit", "-m", "Agentic AI Autofix"], check=True)
    subprocess.run(["git", "push", "--set-upstream", "origin", branch], check=True)


# ============================================================
# Patch Generator (Enterprise Safe)
# ============================================================

def generate_git_patch(file_path: str, new_content: str) -> str | None:
    original = pathlib.Path(file_path)

    if not original.exists():
        print(f"⚠ File not found: {file_path}")
        return None

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(new_content.encode("utf-8"))
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["git", "diff", "--no-index", file_path, tmp_path],
            capture_output=True,
            text=True,
        )

        patch = result.stdout
        if not patch.strip():
            return None

        # BLOCK destructive diff
        if "+++ /dev/null" in patch:
            print("⚠ Destructive patch detected. Skipping.")
            return None

        return patch
    finally:
        os.unlink(tmp_path)


def apply_patch(patch: str) -> bool:
    patch_file = OUTPUT / "agent_patch.diff"
    patch_file.write_text(patch, encoding="utf-8")

    result = subprocess.run(
        ["git", "apply", "--check", str(patch_file)],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("⚠ Patch validation failed:")
        print(result.stderr)
        return False

    subprocess.run(["git", "apply", str(patch_file)], check=True)
    return True


# ============================================================
# Agent Core
# ============================================================

def collect_file_updates(findings: Dict[str, list], retriever: RepoRetriever):
    file_updates: Dict[str, str] = {}

    fx_map = {
        "k8s": fixer_k8s,
        "tf": fixer_tf,
        "java": fixer_java,
        "docker": fixer_docker,
    }

    for kind, items in findings.items():
        if kind not in fx_map:
            continue

        fx = fx_map[kind]

        for idx, item in enumerate(items, 1):
            print(f"\n--- Processing {kind} finding #{idx} ---")

            result = None
            resolution_stage = None

            # ====================================================
            # Stage 1 — Deterministic
            # ====================================================
            result = fx.try_deterministic(item)
            if result:
                resolution_stage = "DETERMINISTIC"

            # ====================================================
            # Stage 2 — RAG
            # ====================================================
            if not result:
                q = fx.query_for(item)
                topk = retriever.search(q) if q else []
                result = fx.try_rag_style(item, topk)
                if result:
                    resolution_stage = "RAG"

            # ====================================================
            # Stage 3 — LLM Fallback (Enterprise Safe)
            # ====================================================
            if not result:
                print("→ Falling back to LLM rewrite")

                original_path = item.get("file")
                if not original_path:
                    print("⚠ No file path available")
                    continue

                original_file = pathlib.Path(original_path)
                if not original_file.exists():
                    print(f"⚠ File not found: {original_path}")
                    continue

                original_content = original_file.read_text(encoding="utf-8")

                new_content = call_llm_rewrite(
                    kind=kind,
                    finding=item,
                    original_content=original_content
                )

                if not new_content or not new_content.strip():
                    print("⚠ LLM returned empty content")
                    continue

                # Prevent suspicious wipe
                if len(new_content) < len(original_content) * 0.5:
                    print("⚠ LLM output suspiciously small — skipping")
                    continue

                result = {
                    "file": original_path,
                    "content": new_content
                }

                resolution_stage = "LLM"

            if not result:
                print("⚠ No fix generated")
                continue

            path = result["file"]
            content = result["content"]

            print(f"✓ Resolved by: {resolution_stage}")
            file_updates[path] = content

    return file_updates


def main():
    ensure_git_identity()

    min_sev = os.getenv("MIN_SEVERITY", "HIGH").upper()
    findings = get_findings(min_sev)

    retriever = RepoRetriever(top_k=6)
    print("RAG ready.")

    file_updates = collect_file_updates(findings, retriever)

    if not file_updates:
        print("⚠ No patches generated.")
        return

    branch = create_branch()

    applied_any = False

    for path, new_content in file_updates.items():
        print(f"\n📦 Generating patch for {path}")

        patch = generate_git_patch(path, new_content)
        if not patch:
            print("⚠ No diff generated")
            continue

        if apply_patch(patch):
            print("✓ Patch applied")
            applied_any = True
        else:
            print("⚠ Patch skipped")

    if not applied_any:
        print("⚠ No patches successfully applied.")
        subprocess.run(["git", "checkout", "-"], check=False)
        subprocess.run(["git", "branch", "-D", branch], check=False)
        return

    commit_and_push(branch)
    print(f"\n🚀 Branch pushed: {branch}")


if __name__ == "__main__":
    main()