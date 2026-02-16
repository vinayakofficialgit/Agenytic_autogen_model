# fixer.py
"""
Enhanced Fixer for DevSecOps Agentic AI Pipeline

Key Enhancements:
- Patch-first design: writes git-apply friendly unified diffs to agent_output/patches/*.patch
- Deterministic quick patches for common Semgrep findings (HTML integrity, eval, subprocess shell)
- Deterministic patches for Dockerfile/K8s/Terraform (no in-place edits during Fix job)
- LLM diffs are saved as patches instead of being applied immediately
- Clear diagnostics & audit artifacts
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import re
import yaml
import shutil
from datetime import datetime
import os
import subprocess
import tempfile
import json
import difflib

# Robust imports: work whether llm_bridge/policy_gate are in agents/ or at repo root
try:
    from agents.llm_bridge import (
        assistant_factory,
        ollama_chat,
        get_fallback_suggestion,
        check_ollama_health,
    )
except Exception:
    try:
        from llm_bridge import (
            assistant_factory,
            ollama_chat,
            get_fallback_suggestion,
            check_ollama_health,
        )
    except Exception:
        assistant_factory = None
        ollama_chat = None
        get_fallback_suggestion = None
        check_ollama_health = None

# Optional input policy-gate
try:
    from agents.input_policy_gate import InputPolicyGate, gated_chat_completion
except Exception:
    try:
        from input_policy_gate import InputPolicyGate, gated_chat_completion
    except Exception:
        InputPolicyGate = None
        gated_chat_completion = None


# -------------------------
# Small helpers
# -------------------------

def _llm_banner() -> str:
    """Short banner for LLM artifacts."""
    # Prefer LLM_MODEL first; OLLAMA_MODEL fallback
    model = os.getenv("LLM_MODEL") or os.getenv("OLLAMA_MODEL") or "(unset)"
    url = os.getenv("OLLAMA_URL") or (("http://" + os.getenv("OLLAMA_HOST"))
                                      if os.getenv("OLLAMA_HOST") else "(unset)")
    mode = os.getenv("LLM_MODE", "ollama")
    return f"> LLM mode: {mode} | Model: {model} | URL: {url}\n\n"


def _llm_ask(name: str, system: str, user: str, temperature: float = 0.2) -> Optional[str]:
    """Ask the LLM via assistant_factory; return None on failure."""
    if assistant_factory is None:
        return None
    try:
        agent = assistant_factory(name=name, system_message=system, temperature=temperature)
        messages = [
            {"role": "system", "content": agent.system_message},
            {"role": "user", "content": user},
        ]
        return agent.chat_completion_fn(messages)
    except Exception as e:
        print(f"[fixer] LLM error: {e}")
        return None


def _truncate_any(val: Any, limit: int = 1200) -> str:
    """Truncate arbitrary value to <= limit characters."""
    if isinstance(val, str):
        s = val
    else:
        try:
            s = json.dumps(val, ensure_ascii=False)
        except Exception:
            s = str(val)
    return s if len(s) <= limit else (s[:limit] + "\n... [truncated] ...")


def _build_semgrep_prompt(item: Dict[str, Any]) -> str:
    """Prompt to ask LLM for semgrep-based patch."""
    return (
        "You are a senior application security engineer. Be precise and minimal.\n"
        "Return a valid unified diff (git-apply friendly) when possible.\n\n"
        f"Semgrep finding (severity: {item.get('severity','')})\n"
        f"- rule_id: {item.get('rule_id','')}\n"
        f"- message: {item.get('message','')}\n"
        f"- file: {item.get('file','')}\n"
        f"- line: {item.get('line','')}\n\n"
        "Code context (may be truncated):\n"
        "```python\n"
        f"{_truncate_any(item.get('snippet',''))}\n"
        "```\n\n"
        "Tasks:\n"
        "1) Explain risk in 1–2 lines.\n"
        "2) Provide a minimal unified diff for the file.\n"
        "3) List any follow-up (tests/config)."
    )


def _build_trivy_fs_prompt(item: Dict[str, Any]) -> str:
    """Prompt for trivy filesystem."""
    return (
        "You are a cloud security engineer. Prefer secure defaults and minimal changes.\n"
        "Return a valid unified diff when the target is text-based.\n\n"
        "Trivy-FS finding:\n"
        f"- id: {item.get('id','')}\n"
        f"- severity: {item.get('severity','')}\n"
        f"- file: {item.get('file','')}\n"
        f"- summary: {item.get('summary','')}\n\n"
        "Relevant content (truncated):\n"
        "```\n"
        f"{_truncate_any(item.get('snippet',''))}\n"
        "```\n\n"
        "Tasks:\n"
        "1) Identify insecure setting.\n"
        "2) Provide a minimal unified diff.\n"
        "3) Note policy implications briefly."
    )


def _get_fallback_for_item(item: Dict[str, Any], tool_group: str) -> str:
    """Fallback text via llm_bridge.get_fallback_suggestion."""
    if get_fallback_suggestion is None:
        return "[No fallback available - llm_bridge not loaded]"
    if tool_group == "semgrep":
        return get_fallback_suggestion(
            tool="semgrep",
            rule_id=item.get("rule_id", ""),
            severity=item.get("severity", ""),
            message=item.get("message", ""),
        )
    elif tool_group == "trivy_fs":
        return get_fallback_suggestion(
            tool="trivy_fs",
            rule_id=item.get("id", ""),
            severity=item.get("severity", ""),
            message=item.get("summary", ""),
        )
    else:
        return get_fallback_suggestion(
            tool=tool_group,
            severity=item.get("severity", ""),
            message=str(item)[:200],
        )


def _parse_diff_changed_files(patch_text: str) -> List[str]:
    """Collect target file paths from '+++ ' lines in unified diff."""
    files: List[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+++ "):
            part = line[4:].strip()
            if part.startswith("a/") or part.startswith("b/"):
                part = part[2:]
            if part != "/dev/null" and part not in files:
                files.append(part)
    return files


def _safe_name(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", path)


def _make_unified_diff(old_text: str, new_text: str, repo_rel_path: str) -> str:
    """Create git-apply friendly unified diff."""
    old_lines = (old_text or "").splitlines(keepends=True)
    new_lines = (new_text or "").splitlines(keepends=True)
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{repo_rel_path}",
        tofile=f"b/{repo_rel_path}",
        lineterm=""
    )
    return "\n".join(diff) + "\n"


# ------------------------------------------------------------
# Fixer
# ------------------------------------------------------------

class Fixer:
    """
    Patch-first auto-remediation.

    - Dockerfile: ADD->COPY; ensure non-root USER (configurable)
    - K8s: set runAsNonRoot, drop privileged, add default limits
    - Terraform: replace 0.0.0.0/0 with allowed CIDR
    - Semgrep quick patches:
        * HTML script without integrity -> add integrity/crossorigin (TODO-SRI-HASH)
        * Python eval(...) -> ast.literal_eval(...)
        * Python subprocess shell=True -> shell=False (adds import shlex if needed)
    - LLM: when diffs are returned, save them as patches; don't apply here
    """

    def __init__(self, config: Dict[str, Any], output_dir: Path, repo_root: Optional[Path] = None):
        self.cfg = config or {}
        self.out = Path(output_dir)
        self.repo = Path(repo_root) if repo_root else Path(".")
        self.defaults = (self.cfg.get("remediation") or {}).get("defaults", {})
        # Defaults
        self.docker_nonroot_user = self.defaults.get("docker_nonroot_user", "appuser")
        self.k8s_default_cpu_limit = self.defaults.get("k8s_default_cpu_limit", "250m")
        self.k8s_default_mem_limit = self.defaults.get("k8s_default_mem_limit", "256Mi")
        self.terraform_allowed_cidr = self.defaults.get("terraform_allowed_cidr", "10.0.0.0/24")
        # Patch dir
        self.patch_dir = self.out / "patches"
        self.patch_dir.mkdir(parents=True, exist_ok=True)

    def apply(self, findings: Any) -> Dict[str, Any]:
        """
        Produce patches but do not modify working files in-place.
        Returns metadata for audit.
        """
        emitted_patches: List[str] = []
        notes: List[str] = []
        llm_report_path: Optional[str] = None

        print("[fixer] Starting remediation (patch-first)...")

        # --- Phase 0: Semgrep quick patches (code issues)
        qp_notes, qp_patches = self._apply_semgrep_quick_patches(findings)
        notes.extend(qp_notes)
        emitted_patches.extend(qp_patches)

        # --- Phase 1: Deterministic infra/config patches
        det_notes, det_patches = self._apply_deterministic_patches()
        notes.extend(det_notes)
        emitted_patches.extend(det_patches)

        # --- Phase 2: LLM autofix (optional) -> save diffs as patches
        llm_autofix_enabled = (os.getenv("LLM_AUTOFIX", "").strip() == "1")
        if llm_autofix_enabled:
            print("[fixer] LLM autofix enabled; gathering patches...")
            llm_notes, llm_patches = self._save_llm_autofix_patches(findings)
            notes.extend(llm_notes)
            emitted_patches.extend(llm_patches)

        # Optional LLM explanation (for audit)
        if self.cfg.get("llm", {}).get("enabled", False) or os.getenv("LLM_EXPLAIN", "") == "1":
            llm_report_path = self._maybe_generate_llm_report(emitted_patches, notes, findings)

        # Audit list
        self.out.mkdir(parents=True, exist_ok=True)
        try:
            (self.out / "remediation_changes.txt").write_text(
                "PATCHES EMITTED:\n" +
                "\n".join(emitted_patches if emitted_patches else ["(none)"]) +
                "\n\nNOTES:\n" + "\n".join(notes if notes else ["(none)"]),
                encoding="utf-8"
            )
        except Exception as e:
            print(f"[fixer] Error writing remediation_changes.txt: {e}")

        print(f"[fixer] Completed. Patches generated: {len(emitted_patches)}")
        return {
            "changed": bool(emitted_patches),
            "files": emitted_patches,  # list of patch paths for clarity
            "notes": notes,
            "llm_report": llm_report_path,
            "llm_report_path": llm_report_path,
        }

    # ------------------------------------------------------------
    # Phase 0: Semgrep quick patches (heuristics)
    # ------------------------------------------------------------

    def _normalize_findings_grouped(self, findings: Any) -> Dict[str, List[Dict[str, Any]]]:
        """Normalize into groups."""
        if isinstance(findings, dict) and any(
            k in findings for k in ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap")
        ):
            grouped = {k: list(v) for k, v in findings.items() if isinstance(v, list)}
            for k in ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap"):
                grouped.setdefault(k, [])
            return grouped

        # else try to coerce a flat list
        grouped: Dict[str, List[Dict[str, Any]]] = {k: [] for k in
            ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap")}
        if isinstance(findings, list):
            for f in findings:
                tool = (f.get("tool") or f.get("source") or "").lower()
                if tool == "semgrep" or ("rule_id" in f and "file" in f):
                    grouped["semgrep"].append({
                        "file": f.get("file") or f.get("path") or "(unknown)",
                        "line": f.get("line") or (f.get("location") or {}).get("line"),
                        "severity": (f.get("severity") or "low"),
                        "rule_id": f.get("rule_id") or f.get("id") or f.get("check_id") or "",
                        "message": f.get("message") or f.get("title") or f.get("description") or "",
                        "snippet": f.get("snippet") or f.get("code") or f.get("content") or "",
                    })
                elif tool in ("trivy-fs", "trivy", "trivy_config", "trivy-config", "trivyfs"):
                    grouped["trivy_fs"].append({
                        "file": f.get("file") or f.get("target") or f.get("path") or "(unknown)",
                        "id": f.get("id") or f.get("rule_id") or f.get("vulnerability_id") or f.get("class_id") or "",
                        "severity": (f.get("severity") or "low"),
                        "summary": f.get("summary") or f.get("message") or f.get("title") or f.get("description") or "",
                        "snippet": f.get("snippet") or f.get("code") or f.get("content") or "",
                    })
                else:
                    grouped["conftest"].append(f)
        return grouped

    def _apply_semgrep_quick_patches(self, findings: Any) -> Tuple[List[str], List[str]]:
        """
        Heuristic patchers for common semgrep rules:
        - Missing SRI on <script> (HTML)
        - Python eval(...) -> ast.literal_eval(...)
        - Python subprocess.*(..., shell=True) -> shell=False (+ import shlex)
        Writes patches to agent_output/patches and returns (notes, patch_paths).
        """
        notes: List[str] = []
        emitted: List[str] = []
        grouped = self._normalize_findings_grouped(findings)
        items = grouped.get("semgrep", []) or []

        for it in items:
            repo_rel_file = it.get("file") or ""
            if not repo_rel_file or repo_rel_file.startswith("("):
                continue
            target = (self.repo / repo_rel_file)
            if not target.exists() or not target.is_file():
                continue

            try:
                original = target.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                notes.append(f"Semgrep quick: cannot read {repo_rel_file}: {e}")
                continue

            rule = (it.get("rule_id") or "").lower()
            msg  = (it.get("message") or "").lower()

            # 1) HTML missing integrity
            if repo_rel_file.lower().endswith((".html", ".htm")) and (
                "missing-integrity" in rule or "integrity" in msg
            ):
                new_text, changed = self._patch_html_add_sri(original)
                if changed:
                    diff = _make_unified_diff(original, new_text, repo_rel_file)
                    patch_path = self._write_patch(repo_rel_file, diff, prefix="semgrep_html_")
                    emitted.append(patch_path)
                    notes.append(f"Semgrep quick: added integrity placeholder to <script> in {repo_rel_file}")
                continue

            # 2) Python eval(...) -> ast.literal_eval(...)
            if repo_rel_file.lower().endswith(".py") and ("eval" in msg or "eval" in rule):
                new_text, changed = self._patch_python_eval(original)
                if changed:
                    diff = _make_unified_diff(original, new_text, repo_rel_file)
                    patch_path = self._write_patch(repo_rel_file, diff, prefix="semgrep_eval_")
                    emitted.append(patch_path)
                    notes.append(f"Semgrep quick: replaced eval(...) with ast.literal_eval(...) in {repo_rel_file}")
                continue

            # 3) Python subprocess shell=True -> shell=False (+ import shlex if needed)
            if repo_rel_file.lower().endswith(".py") and (
                "subprocess" in msg or "subprocess" in rule or "shell" in msg or "shell" in rule
            ):
                new_text, changed = self._patch_python_subprocess_shell(original)
                if changed:
                    diff = _make_unified_diff(original, new_text, repo_rel_file)
                    patch_path = self._write_patch(repo_rel_file, diff, prefix="semgrep_subproc_")
                    emitted.append(patch_path)
                    notes.append(f"Semgrep quick: hardened subprocess(shell) usage in {repo_rel_file}")
                continue

        return notes, emitted

    # --- Concrete quick patchers ---

    def _patch_html_add_sri(self, text: str) -> Tuple[str, bool]:
        """
        Add integrity + crossorigin to <script ...> tags that lack integrity.
        We insert placeholder hash 'TODO-SRI-HASH' for review to avoid breaking runtime.
        """
        changed = False

        def repl(m):
            nonlocal changed
            tag = m.group(0)
            if re.search(r'\bintegrity\s*=\s*["\']', tag, flags=re.I):
                return tag  # already has integrity
            changed = True
            # Insert attributes before closing '>'
            tag = re.sub(r'>\s*$', ' integrity="sha384-TODO-SRI-HASH" crossorigin="anonymous">', tag)
            return tag

        new_text = re.sub(r'<script\b[^>]*>', repl, text, flags=re.I)
        return new_text, changed

    def _patch_python_eval(self, text: str) -> Tuple[str, bool]:
        """
        Replace eval(...) with ast.literal_eval(...) and add `import ast` if missing.
        """
        changed = False
        new_text = re.sub(r'\beval\s*\(', 'ast.literal_eval(', text)
        if new_text != text:
            changed = True
            # Ensure import ast at top if not present
            if not re.search(r'^\s*import\s+ast\b', new_text, flags=re.M):
                new_text = "import ast\n" + new_text
        return new_text, changed

    def _patch_python_subprocess_shell(self, text: str) -> Tuple[str, bool]:
        """
        Ensure shell=False when a subprocess call passes shell=True.
        Also add 'import shlex' if missing (developers can refine args).
        """
        changed = False
        # Replace shell=True with shell=False
        new_text = re.sub(r'shell\s*=\s*True', 'shell=False', text)
        if new_text != text:
            changed = True
            if not re.search(r'^\s*import\s+shlex\b', new_text, flags=re.M):
                new_text = "import shlex\n" + new_text
        return new_text, changed

    # ------------------------------------------------------------
    # Phase 1: Deterministic infra/config patches
    # ------------------------------------------------------------

    def _apply_deterministic_patches(self) -> Tuple[List[str], List[str]]:
        """
        Build patches for Dockerfile, k8s, terraform instead of editing files in place.
        """
        notes: List[str] = []
        emitted: List[str] = []

        # Dockerfile
        dockerfile = self.repo / "app" / "Dockerfile"
        if dockerfile.exists():
            try:
                txt = dockerfile.read_text(encoding="utf-8")
                new_txt = self._fix_dockerfile_text(txt, notes)
                if new_txt != txt:
                    diff = _make_unified_diff(txt, new_txt, "app/Dockerfile")
                    p = self._write_patch("app/Dockerfile", diff, prefix="det_docker_")
                    emitted.append(p)
                    notes.append("Dockerfile: patch emitted (ADD->COPY / non-root USER)")
            except Exception as e:
                notes.append(f"Error building Dockerfile patch: {e}")

        # Kubernetes
        kdir = self.repo / "k8s"
        if kdir.exists():
            for p in sorted(list(kdir.glob("*.yaml")) + list(kdir.glob("*.yml"))):
                try:
                    original = p.read_text(encoding="utf-8")
                    docs = list(yaml.safe_load_all(original))
                    if not docs:
                        continue
                    changed_any = False
                    fixed_docs: List[Any] = []
                    for d in docs:
                        if d is None:
                            fixed_docs.append(d)
                            continue
                        fixed, ch = self._fix_k8s_obj(d)
                        fixed_docs.append(fixed)
                        changed_any = changed_any or ch
                    if changed_any:
                        new_text = yaml.safe_dump_all(fixed_docs, sort_keys=False)
                        diff = _make_unified_diff(original, new_text, f"k8s/{p.name}")
                        patch_path = self._write_patch(f"k8s/{p.name}", diff, prefix="det_k8s_")
                        emitted.append(patch_path)
                        notes.append(f"K8s: patch emitted for {p.name}")
                except Exception as e:
                    notes.append(f"Error building K8s patch for {p.name}: {e}")

        # Terraform
        tdir = self.repo / "terraform"
        if tdir.exists():
            for p in sorted(tdir.rglob("*.tf")):
                try:
                    orig = p.read_text(encoding="utf-8")
                    new_tf = self._fix_tf_text(orig, notes)
                    if new_tf != orig:
                        rel = str(p.relative_to(self.repo)).replace("\\", "/")
                        diff = _make_unified_diff(orig, new_tf, rel)
                        path = self._write_patch(rel, diff, prefix="det_tf_")
                        emitted.append(path)
                        notes.append(f"Terraform: patch emitted for {rel}")
                except Exception as e:
                    notes.append(f"Error building Terraform patch for {p}: {e}")

        return notes, emitted

    def _fix_dockerfile_text(self, txt: str, notes: List[str]) -> str:
        """Dockerfile rules: ADD->COPY, enforce non-root USER."""
        out = re.sub(
            r"(?im)^\s*ADD\s+([^\s]+)\s+([^\s]+)\s*$",
            lambda m: (notes.append(f"Dockerfile: ADD→COPY {m.group(1)} → {m.group(2)}") or f"COPY {m.group(1)} {m.group(2)}"),
            txt,
        )
        has_user = re.search(r"(?im)^\s*USER\s+.+$", out) is not None
        is_root_user = re.search(r"(?im)^\s*USER\s+root\s*$", out) is not None

        if (not has_user) or is_root_user:
            user = self.docker_nonroot_user
            block = (
                "\n# Security: create non-root user and switch\n"
                f"RUN (adduser --disabled-password --gecos '' {user}) || (adduser -D {user}) || "
                f"(useradd -m {user} || true)\n"
                f"USER {user}\n"
            )
            m = re.search(r"(?im)^(\s*)(CMD|ENTRYPOINT)\b", out)
            if m:
                out = out[: m.start()] + block + out[m.start():]
            else:
                out = out.rstrip() + "\n" + block
            notes.append(f"Dockerfile: Ensured USER {user} (non-root)")
        return out

    def _fix_k8s_obj(self, obj: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """K8s: runAsNonRoot, unprivileged, default limits."""
        if isinstance(obj, list):
            changed_any = False
            fixed_list = []
            for item in obj:
                if isinstance(item, dict):
                    fixed_item, ch = self._fix_k8s_obj(item)
                    fixed_list.append(fixed_item)
                    changed_any = changed_any or ch
                else:
                    fixed_list.append(item)
            return fixed_list, changed_any

        changed = False
        d = obj
        try:
            kind = (d.get("kind") or "").strip()
            if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
                spec = d.setdefault("spec", {})
                tpl = spec.setdefault("template", {}).setdefault("spec", {})
                sc = tpl.setdefault("securityContext", {})
                if sc.get("runAsNonRoot") is not True:
                    sc["runAsNonRoot"] = True
                    changed = True
                containers = tpl.get("containers") or []
                for c in containers:
                    if not isinstance(c, dict):
                        continue
                    sc2 = c.setdefault("securityContext", {})
                    if sc2.get("privileged") is True:
                        sc2["privileged"] = False
                        changed = True
                    res = c.setdefault("resources", {})
                    lim = res.setdefault("limits", {})
                    if not lim:
                        lim["cpu"] = self.k8s_default_cpu_limit
                        lim["memory"] = self.k8s_default_mem_limit
                        changed = True

            elif kind == "Pod":
                tpl = d.setdefault("spec", {})
                sc = tpl.setdefault("securityContext", {})
                if sc.get("runAsNonRoot") is not True:
                    sc["runAsNonRoot"] = True
                    changed = True
                containers = tpl.get("containers") or []
                for c in containers:
                    if not isinstance(c, dict):
                        continue
                    sc2 = c.setdefault("securityContext", {})
                    if sc2.get("privileged") is True:
                        sc2["privileged"] = False
                        changed = True
                    res = c.setdefault("resources", {})
                    lim = res.setdefault("limits", {})
                    if not lim:
                        lim["cpu"] = self.k8s_default_cpu_limit
                        lim["memory"] = self.k8s_default_mem_limit
                        changed = True

        except Exception as e:
            print(f"[fixer] Warning: error fixing K8s object: {e}")
            return d, changed

        return d, changed

    def _fix_tf_text(self, text: str, notes: List[str]) -> str:
        """Terraform: replace world-open cidrs."""
        n = re.sub(
            r'(?i)cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
            f'cidr_blocks = ["{self.terraform_allowed_cidr}"]',
            text,
        )
        n2 = re.sub(
            r'(?i)ipv6_cidr_blocks\s*=\s*\[\s*"::/0"\s*\]',
            f'ipv6_cidr_blocks = ["{self.terraform_allowed_cidr}"]',
            n,
        )
        if n2 != text:
            notes.append("Terraform: replaced world-open CIDR with allowed CIDR")
        return n2

    # ------------------------------------------------------------
    # Phase 2: LLM diffs -> saved as patches (no apply here)
    # ------------------------------------------------------------

    def _llm_propose_patch_for_item(self, item: Dict[str, Any], tool_group: str, temperature: float = 0.2) -> Tuple[str, bool]:
        """Request LLM suggestion; return (text, used_fallback?)."""
        if assistant_factory is None:
            fallback = _get_fallback_for_item(item, tool_group)
            return f"[Fallback - LLM unavailable]\n\n{fallback}" if fallback else "[LLM unavailable]", True

        if tool_group == "semgrep":
            user = _build_semgrep_prompt(item)
            sys_msg = "You are a senior AppSec engineer. Produce safe, minimal patches."
            name = "semgrep_fixer"
        elif tool_group == "trivy_fs":
            user = _build_trivy_fs_prompt(item)
            sys_msg = "You are a cloud security engineer. Suggest secure config changes."
            name = "trivy_fs_fixer"
        else:
            return f"[Unsupported tool for autofix: {tool_group}]", True

        try:
            agent = assistant_factory(name=name, system_message=sys_msg, temperature=temperature)
            messages = [
                {"role": "system", "content": agent.system_message},
                {"role": "user", "content": user}
            ]
            response = agent.chat_completion_fn(messages)
            if response and "[Fallback" in response:
                return response, True
            return response or "", False
        except Exception as e:
            print(f"[fixer] LLM error for {tool_group}: {e}")
            fallback = _get_fallback_for_item(item, tool_group)
            return f"[Fallback - Error: {e}]\n\n{fallback}" if fallback else f"[LLM error: {e}]", True

    def _save_llm_autofix_patches(self, findings: Any) -> Tuple[List[str], List[str]]:
        """
        Save LLM-returned unified diffs as .patch files (do not apply).
        """
        notes: List[str] = []
        emitted: List[str] = []

        temperature = float(os.getenv("LLM_TEMPERATURE", "0.2") or "0.2")
        enabled_groups = (os.getenv("LLM_AUTOFIX_TOOLS", "semgrep").replace(" ", "").lower()).split(",")
        grouped = self._normalize_findings_grouped(findings)

        suggestions_md: List[str] = [_llm_banner(), "# LLM Autofix Suggestions\n"]
        counter = 0
        fallback_count = 0

        for group in ("semgrep", "trivy_fs"):
            if group not in enabled_groups:
                continue
            items = grouped.get(group, []) or []
            for item in items:
                counter += 1
                resp, used_fallback = self._llm_propose_patch_for_item(item, tool_group=group, temperature=temperature)
                if used_fallback:
                    fallback_count += 1

                suggestions_md.append(f"## {group} – {item.get('file')} ({item.get('id') or item.get('rule_id') or ''})\n")
                suggestions_md.append((resp or "").strip() + "\n")

                if not used_fallback and ("--- " in resp) and ("+++ " in resp):
                    # Save exactly as provided; normalization can be added if needed.
                    p = self._write_patch(f"{group}_{counter}.diff", resp, prefix="llm_")
                    emitted.append(p)
                    notes.append(f"LLM: diff saved: {Path(p).name}")
                else:
                    notes.append(f"LLM: suggestion provided (no diff) for {group} at {item.get('file')}")

        # Write suggestions markdown
        self.out.mkdir(parents=True, exist_ok=True)
        try:
            (self.out / "llm_autofix_suggestions.md").write_text("\n".join(suggestions_md), encoding="utf-8")
        except Exception as e:
            print(f"[fixer] Error writing suggestions md: {e}")

        if fallback_count > 0:
            notes.append(f"Note: {fallback_count} suggestion(s) used fallback (LLM unavailable or declined diff)")

        return notes, emitted

    # ------------------------------------------------------------
    # Optional LLM explanation for audit
    # ------------------------------------------------------------

    def _maybe_generate_llm_report(
        self,
        emitted_patches: List[str],
        notes: List[str],
        findings: Any,
    ) -> Optional[str]:
        """Generate a short narrative of what patches do."""
        system_msg = (
            "You are a DevSecOps assistant. Explain the emitted patches crisply and accurately. "
            "Avoid hallucinations; only use given context."
        )
        context = (
            "Summarize the following patches to be applied. "
            "Explain WHY each change improves security or reliability, and mention trade-offs if any. "
            "Keep it under 250 words.\n\n"
            f"Patches emitted:\n{chr(10).join(emitted_patches) if emitted_patches else '(none)'}\n\n"
            f"Notes:\n{chr(10).join(notes) if notes else '(none)'}\n\n"
            f"Optional findings context (truncated):\n{_truncate_any(findings)}"
        )

        text = _llm_ask(
            name="remediation_reporter",
            system=system_msg,
            user=context,
            temperature=0.2,
        )
        if text:
            self.out.mkdir(parents=True, exist_ok=True)
            md_path = self.out / "remediation_explained.md"
            try:
                md_path.write_text(_llm_banner() + text.strip(), encoding="utf-8")
                return str(md_path)
            except Exception as e:
                print(f"[fixer] Error writing remediation_explained.md: {e}")
        return None

    # ------------------------------------------------------------
    # Patch writing helper
    # ------------------------------------------------------------

    def _write_patch(self, repo_rel_path: str, patch_text: str, prefix: str = "patch_") -> str:
        """
        Write patch_text into agent_output/patches/<prefix><safe_name>.patch
        Returns the written path as string.
        """
        # Derive a stable name from the path OR provided label like group_counter
        safe = _safe_name(repo_rel_path)
        out_path = self.patch_dir / f"{prefix}{safe}.patch"
        out_path.write_text(patch_text, encoding="utf-8")
        print(f"[fixer] patch written: {out_path}")
        return str(out_path)


# -------------------------
# Standalone helper function
# -------------------------

def propose_fixes(log_text: str) -> str:
    """Generate LLM-proposed fixes from a text log."""
    if assistant_factory is None:
        return (
            "LLM bridge not available. Ensure llm_bridge.py is present and configured.\n\n"
            "Generic troubleshooting steps:\n"
            "1. Check errors for file/line references\n"
            "2. Review recent changes to those files\n"
            "3. Verify env vars & configuration\n"
            "4. Check dependency versions"
        )
    try:
        assistant = assistant_factory(
            name="fixer",
            system_message=(
                "You are a pragmatic DevOps/SRE helper. Given logs or errors, "
                "propose 3 actionable fixes with commands."
            ),
            temperature=0.2,
        )
        messages = [
            {"role": "system", "content": assistant.system_message},
            {"role": "user", "content": f"Here is a failure log:\n\n{log_text}\n\nSuggest 3 actionable fixes with commands."},
        ]
        return assistant.chat_completion_fn(messages)
    except Exception as e:
        return f"[LLM error] {e}"