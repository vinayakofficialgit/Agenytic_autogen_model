
 # fixer.py
"""
Enhanced Fixer for DevSecOps Agentic AI Pipeline

Key Enhancements:
- Better LLM integration with fallback suggestions
- Improved error handling and logging
- Support for both LLM-powered and fallback remediation advice
- Safer file operations with backups
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

# Note: PolicyGate for input validation (different from policy_gate.py)
# This is an optional safety layer for LLM inputs
try:
    from agents.input_policy_gate import InputPolicyGate, gated_chat_completion
except Exception:
    try:
        from input_policy_gate import InputPolicyGate, gated_chat_completion
    except Exception:
        InputPolicyGate = None
        gated_chat_completion = None


def _llm_banner() -> str:
    """Small banner to include in artifacts showing which LLM is used."""
    url = os.getenv("OLLAMA_URL", "(unset)")
    model = os.getenv("OLLAMA_MODEL", "(unset)")
    mode = os.getenv("LLM_MODE", "ollama")
    return f"> LLM mode: {mode} | Model: {model} | URL: {url}\n\n"


def _llm_ask(name: str, system: str, user: str, temperature: float = 0.2) -> Optional[str]:
    """
    Convenience helper to ask the LLM through assistant_factory.
    Returns None if llm_bridge is not available or call fails.
    """
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
    """Truncate any value to a string of limited length."""
    if isinstance(val, str):
        s = val
    else:
        try:
            s = json.dumps(val, ensure_ascii=False)
        except Exception:
            s = str(val)
    return s if len(s) <= limit else (s[:limit] + "\n... [truncated] ...")


def _build_semgrep_prompt(item: Dict[str, Any]) -> str:
    """Build the per-finding prompt for Semgrep items."""
    return (
        "You are a senior application security engineer. "
        "Be precise, minimal, and safe. If possible, return a unified diff.\n\n"
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
        "1) Explain the risk in 1–2 lines.\n"
        "2) Propose a minimal unified diff for the file above.\n"
        "3) List any follow-up (tests/config)."
    )


def _build_trivy_fs_prompt(item: Dict[str, Any]) -> str:
    """Build the per-finding prompt for Trivy filesystem items."""
    return (
        "You are a cloud security engineer. Prefer secure defaults and minimal changes. "
        "If applicable, return a unified diff.\n\n"
        "Trivy-FS finding:\n"
        f"- id: {item.get('id','')}\n"
        f"- severity: {item.get('severity','')}\n"
        f"- file: {item.get('file','')}\n"
        f"- summary: {item.get('summary','')}\n\n"
        "Relevant content (may be truncated):\n"
        "```\n"
        f"{_truncate_any(item.get('snippet',''))}\n"
        "```\n\n"
        "Tasks:\n"
        "1) Identify the insecure setting.\n"
        "2) Provide a minimal unified diff for the file (if text-based).\n"
        "3) Note any deployment/policy implications."
    )


def _get_fallback_for_item(item: Dict[str, Any], tool_group: str) -> str:
    """Get fallback suggestion for a finding when LLM is unavailable."""
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
    """
    Extract target file paths from a unified diff by reading +++ lines.
    Returns deduplicated list of file paths (without a/ b/ prefixes).
    """
    files: List[str] = []
    for line in patch_text.splitlines():
        if line.startswith("+++ "):
            part = line[4:].strip()
            # Format may be "a/path" or "b/path" or just "path"
            if part.startswith("a/") or part.startswith("b/"):
                part = part[2:]
            if part != "/dev/null" and part not in files:
                files.append(part)
    return files





def _git_apply_patch(patch_text: str) -> Tuple[bool, str]:
    """
    Try to apply a unified diff using git apply with a dry-run first.
    Returns (success, message).
    """
    if shutil.which("git") is None:
        return False, "git not available on PATH"

    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".patch") as f:
        f.write(patch_text)
        patch_path = f.name

    try:
        # --check first (dry run)
        dry = subprocess.run(
            ["git", "apply", "--check", patch_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        if dry.returncode != 0:
            msg = dry.stderr.strip() or dry.stdout.strip() or "git apply --check failed"
            return False, msg

        # Apply for real
        run = subprocess.run(
            ["git", "apply", patch_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        if run.returncode != 0:
            msg = run.stderr.strip() or run.stdout.strip() or "git apply failed"
            return False, msg

        return True, "applied"
    except subprocess.TimeoutExpired:
        return False, "git apply timed out"
    except Exception as e:
        return False, f"git apply error: {e}"
    finally:
        try:
            os.unlink(patch_path)
        except Exception:
            pass



from openai import OpenAI

def openai_patch(prompt):
    client = OpenAI()
    resp = client.chat.completions.create(
        model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        messages=[{"role":"user","content":prompt}],
        temperature=0.2
    )
    return resp.choices[0].message.content


class Fixer:
    """
    Deterministic auto-remediation for Dockerfile, Kubernetes YAML, and Terraform .tf files.

    - Dockerfile: replaces ADD->COPY; ensures non-root user (configurable)
    - K8s: ensures runAsNonRoot, unsets privileged, sets default limits if missing
    - Terraform: replaces world-open CIDRs with an allowed CIDR (configurable)

    Enhancements:
    - Optional LLM explanation report if cfg['llm']['enabled'] or LLM_EXPLAIN=1
    - Optional LLM AUTOFIX: For semgrep/trivy_fs findings, request unified diffs from the model
      and attempt to apply them safely when LLM_AUTOFIX=1
    - Fallback suggestions when LLM is unavailable
    """

    def __init__(self, config: Dict[str, Any], output_dir: Path, repo_root: Optional[Path] = None):
        self.cfg = config or {}
        self.out = Path(output_dir)
        self.repo = Path(repo_root) if repo_root else Path(".")
        self.defaults = (self.cfg.get("remediation") or {}).get("defaults", {})
        
        # Defaults with sensible fallbacks
        self.docker_nonroot_user = self.defaults.get("docker_nonroot_user", "appuser")
        self.k8s_default_cpu_limit = self.defaults.get("k8s_default_cpu_limit", "250m")
        self.k8s_default_mem_limit = self.defaults.get("k8s_default_mem_limit", "256Mi")
        self.terraform_allowed_cidr = self.defaults.get("terraform_allowed_cidr", "10.0.0.0/24")

    
    
    def load_violations(self):
        decision = self.out / "decision.json"
        if not decision.exists():
            return []
    
        try:
            data = json.loads(decision.read_text())
            return data.get("violations", [])
        except Exception:
            return []

    def apply(self, findings=None):
        violations = self.load_violations()

        if violations:
            print(f"[fixer] Using {len(violations)} violations from gate")
            findings = violations

        if not findings:
            return []

        notes, changed = self._apply_llm_autofixes(findings)

        try:
            (self.out / "patch_manifest.json").write_text(
                json.dumps({"files": changed}, indent=2)
            )
        except Exception:
            pass

        return changed
        
    # -------------------------
    # Internals
    # -------------------------

    def _backup_file(self, path: Path) -> None:
        """Create a timestamped backup alongside the original file."""
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        backup = path.with_suffix(path.suffix + f".bak.{ts}")
        try:
            shutil.copy2(path, backup)
        except Exception:
            try:
                backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
            except Exception as e:
                print(f"[fixer] Warning: Could not create backup for {path}: {e}")

    def _fix_dockerfile(self, txt: str, notes: List[str]) -> str:
        """
        - Replace `ADD` with `COPY` for simple cases
        - Ensure non-root USER exists and switch to it
        """
        # ADD -> COPY (line-by-line)
        out = re.sub(
            r"(?im)^\s*ADD\s+([^\s]+)\s+([^\s]+)\s*$",
            lambda m: (notes.append(f"Dockerfile: ADD→COPY {m.group(1)} → {m.group(2)}") or f"COPY {m.group(1)} {m.group(2)}"),
            txt,
        )

        # Ensure non-root USER block
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
            # Insert before CMD/ENTRYPOINT if present; else append at end
            m = re.search(r"(?im)^(\s*)(CMD|ENTRYPOINT)\b", out)
            if m:
                out = out[: m.start()] + block + out[m.start():]
            else:
                out = out.rstrip() + "\n" + block
            notes.append(f"Dockerfile: Ensured USER {user} (non-root)")

        return out

    def _fix_k8s_obj(self, obj: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """
        Fix a single K8s object. Returns (fixed_obj, changed).
        """
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
            
            # Only address workload types that have Pod templates
            if kind in {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"}:
                spec = d.setdefault("spec", {})
                tpl = spec.setdefault("template", {}).setdefault("spec", {})

                # Pod-level securityContext
                sc = tpl.setdefault("securityContext", {})
                if sc.get("runAsNonRoot") is not True:
                    sc["runAsNonRoot"] = True
                    changed = True

                # Containers
                containers = tpl.get("containers") or []
                for c in containers:
                    if not isinstance(c, dict):
                        continue
                    sc2 = c.setdefault("securityContext", {})
                    if sc2.get("privileged") is True:
                        sc2["privileged"] = False
                        changed = True
                    # Add default limits if none are set
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
            print(f"[fixer] Warning: Error fixing K8s object: {e}")
            return d, changed

        return d, changed

    def _fix_tf(self, text: str, notes: List[str]) -> str:
        """
        Replace world-open IPv4/IPv6 cidr_blocks in Security Group rules with allowed CIDR.
        """
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

    # -------------------------
    # LLM Autofix phase
    # -------------------------

    def _normalize_findings_grouped(self, findings: Any) -> Dict[str, List[Dict[str, Any]]]:
        """
        Accept either grouped findings dict (preferred) or flat list.
        """
        if isinstance(findings, dict) and any(k in findings for k in ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap")):
            grouped = {k: list(v) for k, v in findings.items() if isinstance(v, list)}
            for k in ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap"):
                grouped.setdefault(k, [])
            return grouped

        # Flat list fallback
        grouped: Dict[str, List[Dict[str, Any]]] = {
            "semgrep": [],
            "trivy_fs": [],
            "trivy_image": [],
            "tfsec": [],
            "gitleaks": [],
            "conftest": [],
            "zap": [],
        }
        
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

    def _llm_propose_patch_for_item(self, item: Dict[str, Any], tool_group: str, temperature: float = 0.2) -> Tuple[str, bool]:
        """
        Ask the LLM for a suggestion for a single finding.
        Returns (suggestion_text, used_fallback).
        """
        # if assistant_factory is None:
        #     fallback = _get_fallback_for_item(item, tool_group)
        #     return f"[Fallback - LLM unavailable]\n\n{fallback}" if fallback else "[LLM unavailable]", True
        
        if assistant_factory is None:
            try:
                # ⭐ user var was undefined
                if tool_group == "semgrep":
                    user = _build_semgrep_prompt(item)
                elif tool_group == "trivy_fs":
                    user = _build_trivy_fs_prompt(item)
                else:
                    user = str(item)

                return openai_patch(user), False
            except:
                fallback = _get_fallback_for_item(item, tool_group)
                return fallback, True


        # Choose prompt
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
            
            # Check if response contains fallback marker
            if response and "[Fallback" in response:
                return response, True
            
            return response or "", False
            
        except Exception as e:
            print(f"[fixer] LLM error for {tool_group}: {e}")
            fallback = _get_fallback_for_item(item, tool_group)
            return f"[Fallback - Error: {e}]\n\n{fallback}" if fallback else f"[LLM error: {e}]", True

    def _apply_llm_autofixes(self, findings: Any) -> Tuple[List[str], List[str]]:
        """
        Loop through selected groups, request patches, validate and apply them.
        Returns (notes, changed_files_from_llm).
        """
        notes: List[str] = []
        llm_changed_files: List[str] = []

        temperature = float(os.getenv("LLM_TEMPERATURE", "0.2") or "0.2")
        enabled_groups = (os.getenv("LLM_AUTOFIX_TOOLS", "semgrep").replace(" ", "").lower()).split(",")
        grouped = self._normalize_findings_grouped(findings)

        suggestions_md: List[str] = [_llm_banner(), "# LLM Autofix Suggestions\n"]

        patch_dir = self.out / "llm_autofix_patches"
        # ⭐ patch manifest for PR agent
        try:
            (self.out / "patch_manifest.json").write_text(
                json.dumps({"files": llm_changed_files}, indent=2)
            )
        except Exception:
            pass

        
        patch_dir.mkdir(parents=True, exist_ok=True)

        counter = 0
        fallback_count = 0
        

        for group in ("semgrep", "trivy_fs"):
            if group not in enabled_groups:
                continue
            items = grouped.get(group, [])
            
            for item in items:
                # ⭐ severity guard (enterprise safe autofix)
                if item.get("severity","low").lower() not in ["high","critical"]:
                    continue

                counter += 1
                resp, used_fallback = self._llm_propose_patch_for_item(item, tool_group=group, temperature=temperature)

                # ⭐ diff validation (your confusion point)
                if not resp:
                    notes.append("Empty LLM response")
                    continue

                if "```diff" not in resp and "--- " not in resp:
                    notes.append("LLM response has no valid diff")
                    continue
                
                if used_fallback:
                    fallback_count += 1
                
                fallback_marker = " 🔄" if used_fallback else ""
                suggestions_md.append(f"## {group}{fallback_marker} – {item.get('file')} ({item.get('id') or item.get('rule_id') or ''})\n")
                suggestions_md.append((resp or "").strip() + "\n")

                # Try to detect a unified diff (only if not a fallback)
                if not used_fallback and ("--- " in resp) and ("+++ " in resp):
                    patch_path = patch_dir / f"{counter:03d}_{group}.patch"
                    patch_path.write_text(resp, encoding="utf-8")

                    target_files = _parse_diff_changed_files(resp)
                    ok, msg = _git_apply_patch(resp)
                    if ok:
                        notes.append(f"LLM: applied patch from {group} ({item.get('file')}): {patch_path.name}")
                        for f in target_files:
                            if f not in llm_changed_files:
                                llm_changed_files.append(f)
                    else:
                        notes.append(f"LLM: patch not applied ({patch_path.name}): {msg}")
                else:
                    notes.append(f"LLM: suggestion provided {'(fallback)' if used_fallback else '(no diff)'} for {group} at {item.get('file')}")

        # Write suggestions MD
        self.out.mkdir(parents=True, exist_ok=True)
        try:
            (self.out / "llm_autofix_suggestions.md").write_text("\n".join(suggestions_md), encoding="utf-8")
        except Exception as e:
            print(f"[fixer] Error writing suggestions: {e}")

        if fallback_count > 0:
            notes.append(f"Note: {fallback_count} suggestion(s) used fallback (LLM unavailable)")

        return notes, llm_changed_files

    # -------------------------
    # Optional LLM explanation
    # -------------------------

    def _maybe_generate_llm_report(
        self,
        changed_files: List[str],
        notes: List[str],
        findings: Any,
    ) -> Optional[str]:
        """
        If LLM is enabled and llm_bridge is available, generate a markdown explanation
        of what changed and why.
        """
        system_msg = (
            "You are a DevSecOps assistant. Explain file remediations crisply and accurately. "
            "Avoid hallucinations; only use given context."
        )
        context = (
            "Summarize the following auto-remediations performed by the tool. "
            "Explain WHY each change improves security or reliability, and mention trade-offs if any. "
            "Keep it under 250 words.\n\n"
            f"Changed files:\n{chr(10).join(changed_files) if changed_files else '(none)'}\n\n"
            f"Notes:\n{chr(10).join(notes) if notes else '(none)'}\n\n"
            f"Optional findings context (may be truncated):\n{_truncate_any(findings)}"
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
                print(f"[fixer] Error writing report: {e}")
        
        return None


# -------------------------
# Standalone helper function
# -------------------------

def propose_fixes(log_text: str) -> str:
    """
    Generate LLM-proposed fixes from a text log.
    Returns fallback advice if LLM is unavailable.
    """
    if assistant_factory is None:
        return (
            "LLM bridge not available. Ensure llm_bridge.py is present and configured.\n\n"
            "Generic troubleshooting steps:\n"
            "1. Check the error message for specific file/line references\n"
            "2. Review recent changes to the affected files\n"
            "3. Verify environment variables and configuration\n"
            "4. Check dependencies and their versions"
        )

    try:
        assistant = assistant_factory(
            name="fixer",
            system_message=(
                "You are a pragmatic DevOps/SRE helper. Given logs or error messages, "
                "propose 3 actionable, verifiable fixes with commands."
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