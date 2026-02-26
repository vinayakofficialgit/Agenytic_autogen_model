#!/usr/bin/env python3
import os
import json
import pathlib
import subprocess
from typing import Dict, List

from tools.embeddings.retriever import RepoRetriever
from tools.agent.utils.prompt_lib import build_patch_prompt, call_llm_for_diff
from tools.agent.pick_findings import get_findings
from tools.agent.utils.git_ops import ensure_git_identity

APP_DIR = os.getenv("APP_DIR", "java-pilot-app")
MIN_SEVERITY = os.getenv("MIN_SEVERITY", "high")
RAG_DEBUG = os.getenv("RAG_DEBUG", "false").lower() == "true"


def run(cmd: str, check=True):
    print(f"+ {cmd}")
    return subprocess.run(cmd, shell=True, check=check)


def validate_diff_structure(diff: str) -> bool:
    if not diff.strip().startswith("--- "):
        return False
    if "@@" not in diff:
        return False
    return True


def apply_single_patch(branch: str, diff_text: str, index: int) -> bool:
    tmp_patch = pathlib.Path(f"agent_output/temp_patch_{index}.diff")
    tmp_patch.write_text(diff_text, encoding="utf-8")

    # Dry run
    result = subprocess.run(
        f"git apply --check {tmp_patch}",
        shell=True,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print(f"⚠ Patch {index} failed validation:")
        print(result.stderr)
        return False

    # Apply
    subprocess.check_call(
        f"git apply --whitespace=fix {tmp_patch}",
        shell=True
    )

    return True


def has_git_changes() -> bool:
    result = subprocess.run(
        "git status --porcelain",
        shell=True,
        capture_output=True,
        text=True
    )
    return bool(result.stdout.strip())


def main():
    pathlib.Path("agent_output").mkdir(exist_ok=True)

    findings = get_findings(MIN_SEVERITY)

    if not any(findings.values()):
        print("No findings to fix.")
        return

    retriever = RepoRetriever(top_k=6)

    ensure_git_identity()

    branch = f"ai-autofix-{os.urandom(4).hex()}"
    run(f"git checkout -b {branch}")

    patch_counter = 0
    applied_count = 0

    def handle(kind: str, items: List[Dict]):
        nonlocal patch_counter, applied_count

        for finding in items:
            patch_counter += 1
            print(f"\n--- Processing {kind} finding #{patch_counter} ---")

            context = retriever.search(
                f"{finding.get('file')} {finding.get('rule')} {finding.get('detail')}"
            )

            if RAG_DEBUG:
                print(f"Context chunks: {len(context)}")

            prompt = build_patch_prompt(kind, finding, context)
            diff = call_llm_for_diff(prompt)

            if not validate_diff_structure(diff):
                print("⚠ Invalid diff structure. Skipping.")
                continue

            success = apply_single_patch(branch, diff, patch_counter)

            if success:
                applied_count += 1
                print("✓ Patch applied")
            else:
                print("⚠ Patch skipped due to git apply failure")

    handle("k8s", findings.get("k8s", []))
    handle("tf", findings.get("tf", []))
    handle("java", findings.get("java", []))
    handle("docker", findings.get("docker", []))

    if applied_count == 0:
        print("⚠ No patches successfully applied.")
        run("git checkout -", check=False)
        run(f"git branch -D {branch}", check=False)
        return

    if not has_git_changes():
        print("⚠ No actual file changes detected.")
        run("git checkout -", check=False)
        run(f"git branch -D {branch}", check=False)
        return

    run("git add .")
    run('git commit -m "Agentic AI security autofix"')
    run(f"git push origin {branch}")

    meta = {
        "branch": branch,
        "applied_patches": applied_count
    }

    pathlib.Path("agent_output/agent_meta.json").write_text(
        json.dumps(meta, indent=2),
        encoding="utf-8"
    )

    print(f"\n✓ Branch {branch} pushed with {applied_count} fixes.")


if __name__ == "__main__":
    main()