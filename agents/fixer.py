# agents/fixer.py
"""
Patch-first Fixer (targeted, CI-safe)

Fixes included:
- Deterministic patches:
  - Dockerfile: ADD->COPY, enforce non-root USER
  - K8s YAML: runAsNonRoot, privileged=false, allowPrivilegeEscalation=false, default limits
  - Terraform: replace 0.0.0.0/0 and ::/0 with allowed CIDR
- Semgrep quick patches (deterministic):
  - HTML <script> missing integrity -> add placeholder SRI + crossorigin
  - Python eval(...) -> ast.literal_eval(...)
  - subprocess(... shell=True) -> shell=False (+ import shlex)
- Targeted-only mode:
  - If targets list is provided, ONLY those exact files are changed/patch-generated.
  - This prevents ambiguity and prevents touching unrelated files.

Most important bugfix:
- Robust diff extraction for LLM output (handles code fences / extra prose).
- Patch writer only writes true unified diffs (--- / +++).
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Set
import re
import os
import subprocess
import tempfile
import json

import yaml  # required dependency in your workflow


# LLM bridge (optional)
try:
    from agents.llm_bridge import assistant_factory, get_fallback_suggestion
except Exception:
    try:
        from llm_bridge import assistant_factory, get_fallback_suggestion
    except Exception:
        assistant_factory = None
        get_fallback_suggestion = None


def _safe_name(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", path)


def _norm(p: str) -> str:
    if not p:
        return ""
    s = p.replace("\\", "/").strip()
    while s.startswith("./"):
        s = s[2:]
    return s


def _extract_first_unified_diff(text: str) -> str:
    """
    Extract a valid unified diff from arbitrary model output.
    Supports:
      - prose before diff
      - ```diff code fences
      - diff --git blocks
    Returns empty string if no diff found.
    """
    if not text:
        return ""

    t = text.replace("\r\n", "\n")

    # Remove common fences but keep content
    t = re.sub(r"```diff\s*\n", "", t, flags=re.I)
    t = re.sub(r"```patch\s*\n", "", t, flags=re.I)
    t = re.sub(r"```\s*\n", "", t)

    # Prefer start at first '--- ' header
    m = re.search(r"(?m)^---\s+", t)
    if not m:
        return ""

    diff = t[m.start():]

    # If there's trailing fence markers, drop them
    diff = re.split(r"(?m)^```$", diff)[0].strip("\n") + "\n"

    # Must include both headers
    if not (diff.startswith("--- ") and "\n+++ " in diff):
        return ""
    return diff


def _make_unified_diff_git(old_text: str, new_text: str, repo_rel_path: str, context: int = 2) -> str:
    """
    Use git diff --no-index to produce robust unified diffs.
    """
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        a = td_path / "a.txt"
        b = td_path / "b.txt"
        a.write_text(old_text or "", encoding="utf-8", newline="\n")
        b.write_text(new_text or "", encoding="utf-8", newline="\n")

        cmd = [
            "git", "diff", "--no-index", f"--unified={context}", "--no-color",
            f"--label=a/{repo_rel_path}", f"--label=b/{repo_rel_path}",
            str(a), str(b)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        out = res.stdout or ""
        diff = _extract_first_unified_diff(out)
        return diff


class Fixer:
    def __init__(
        self,
        config: Dict[str, Any],
        output_dir: Path,
        repo_root: Optional[Path] = None,
        targets: Optional[List[str]] = None,
    ):
        self.cfg = config or {}
        self.out = Path(output_dir)
        self.repo = Path(repo_root) if repo_root else Path(".")

        self.defaults = (self.cfg.get("remediation") or {}).get("defaults", {})
        self.docker_nonroot_user = self.defaults.get("docker_nonroot_user", "appuser")
        self.k8s_default_cpu_limit = self.defaults.get("k8s_default_cpu_limit", "250m")
        self.k8s_default_mem_limit = self.defaults.get("k8s_default_mem_limit", "256Mi")
        self.terraform_allowed_cidr = self.defaults.get("terraform_allowed_cidr", "10.0.0.0/24")

        self.patch_dir = self.out / "patches"
        self.patch_dir.mkdir(parents=True, exist_ok=True)

        self.targeted_only = bool((self.cfg.get("remediation") or {}).get("targeted_only", True))

        # Normalize targets to repo-relative
        self.targets: Set[str] = set(_norm(t) for t in (targets or []) if t)
        if self.targets:
            print(f"[fixer] Targeting: restricted to {len(self.targets)} recorded file(s)")
        else:
            print("[fixer] Targeting: no targets provided; will patch based on findings (broader)")

    def _is_target(self, repo_rel: str) -> bool:
        if not self.targeted_only:
            return True
        if not self.targets:
            return True
        rr = _norm(repo_rel)
        return rr in self.targets

    def _write_patch(self, repo_rel_path: str, patch_text: str, prefix: str = "patch_") -> str:
        diff = _extract_first_unified_diff(patch_text)
        if not diff:
            print(f"[fixer] WARNING: missing unified headers in patch for {repo_rel_path}; skipping write")
            return ""
        safe = _safe_name(repo_rel_path or "unnamed")
        out_path = self.patch_dir / f"{prefix}{safe}.patch"
        out_path.write_text(diff, encoding="utf-8", newline="\n")
        print(f"[fixer] patch written: {out_path}")
        return str(out_path)

    def apply(self, findings: Any) -> Dict[str, Any]:
        emitted: List[str] = []
        notes: List[str] = []

        print("[fixer] Starting remediation (patch-first).")

        # 1) Semgrep quick patches for targeted files
        qp_notes, qp_patches = self._apply_semgrep_quick_patches(findings)
        notes.extend(qp_notes)
        emitted.extend([p for p in qp_patches if p])

        # 2) Deterministic infra patches, but only if target matches
        det_notes, det_patches = self._apply_deterministic_patches()
        notes.extend(det_notes)
        emitted.extend([p for p in det_patches if p])

        # 3) Optional LLM-based diffs (enabled via env)
        if os.getenv("LLM_AUTOFIX", "").strip() == "1":
            llm_notes, llm_patches = self._save_llm_autofix_patches(findings)
            notes.extend(llm_notes)
            emitted.extend([p for p in llm_patches if p])

        # write summary
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "remediation_changes.txt").write_text(
            "PATCHES EMITTED:\n" +
            "\n".join(emitted if emitted else ["(none)"]) +
            "\n\nNOTES:\n" + "\n".join(notes if notes else ["(none)"]),
            encoding="utf-8"
        )

        print(f"[fixer] Completed. Patches generated: {len(emitted)}")
        return {"changed": bool(emitted), "files": emitted, "notes": notes}

    # -------------------------
    # Findings normalization
    # -------------------------

    def _normalize_findings_grouped(self, findings: Any) -> Dict[str, List[Dict[str, Any]]]:
        if isinstance(findings, dict):
            grouped = {}
            for k, v in findings.items():
                if isinstance(v, list):
                    grouped[k] = v
            for k in ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap"):
                grouped.setdefault(k, [])
            return grouped

        grouped = {k: [] for k in ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap")}
        if isinstance(findings, list):
            for f in findings:
                if not isinstance(f, dict):
                    continue
                tool = (f.get("tool") or f.get("source") or "").lower()
                if tool == "semgrep" or ("rule_id" in f and "file" in f):
                    grouped["semgrep"].append({
                        "file": f.get("file") or f.get("path") or "(unknown)",
                        "line": f.get("line") or (f.get("location") or {}).get("line"),
                        "severity": f.get("severity") or "low",
                        "rule_id": f.get("rule_id") or f.get("id") or "",
                        "message": f.get("message") or f.get("title") or "",
                        "snippet": f.get("snippet") or f.get("code") or "",
                    })
        return grouped

    # -------------------------
    # Semgrep quick patches (deterministic)
    # -------------------------

    def _resolve_repo_path(self, reported_path: str) -> Optional[Path]:
        """
        Resolve reported file path:
          - as-is (repo root)
          - under APP_DIR
        """
        reported = _norm(reported_path)
        if not reported or reported.startswith("("):
            return None

        p1 = self.repo / reported
        if p1.exists() and p1.is_file():
            return p1

        app_dir = os.getenv("APP_DIR", "").strip()
        if app_dir:
            p2 = self.repo / app_dir / reported
            if p2.exists() and p2.is_file():
                return p2

        return None

    def _apply_semgrep_quick_patches(self, findings: Any) -> Tuple[List[str], List[str]]:
        notes: List[str] = []
        emitted: List[str] = []
        grouped = self._normalize_findings_grouped(findings)
        items = grouped.get("semgrep", []) or []

        for it in items:
            reported_path = it.get("file") or ""
            target = self._resolve_repo_path(reported_path)
            if not target:
                notes.append(f"Semgrep quick: file not found: {reported_path}")
                continue

            repo_rel = _norm(str(target.relative_to(self.repo)))
            if not self._is_target(repo_rel):
                continue

            try:
                original = target.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                notes.append(f"Semgrep quick: cannot read {repo_rel}: {e}")
                continue

            rule = (it.get("rule_id") or "").lower()
            msg = (it.get("message") or "").lower()

            # HTML SRI
            if repo_rel.lower().endswith((".html", ".htm")) and ("integrity" in msg or "integrity" in rule):
                new_text, changed = self._patch_html_add_sri(original)
                if changed:
                    diff = _make_unified_diff_git(original, new_text, repo_rel, context=2)
                    if diff:
                        p = self._write_patch(repo_rel, diff, prefix="semgrep_html_")
                        if p:
                            emitted.append(p)
                            notes.append(f"Semgrep quick: added integrity placeholder to <script> in {repo_rel}")
                continue

            # Python eval
            if repo_rel.lower().endswith(".py") and ("eval" in msg or "eval" in rule):
                new_text, changed = self._patch_python_eval(original)
                if changed:
                    diff = _make_unified_diff_git(original, new_text, repo_rel, context=2)
                    if diff:
                        p = self._write_patch(repo_rel, diff, prefix="semgrep_eval_")
                        if p:
                            emitted.append(p)
                            notes.append(f"Semgrep quick: replaced eval(...) with ast.literal_eval(...) in {repo_rel}")
                continue

            # subprocess shell=True
            if repo_rel.lower().endswith(".py") and ("subprocess" in msg or "shell" in msg or "subprocess" in rule or "shell" in rule):
                new_text, changed = self._patch_python_subprocess_shell(original)
                if changed:
                    diff = _make_unified_diff_git(original, new_text, repo_rel, context=2)
                    if diff:
                        p = self._write_patch(repo_rel, diff, prefix="semgrep_subproc_")
                        if p:
                            emitted.append(p)
                            notes.append(f"Semgrep quick: hardened subprocess(shell) usage in {repo_rel}")
                continue

        return notes, emitted

    def _patch_html_add_sri(self, text: str) -> Tuple[str, bool]:
        changed = False

        def repl(m):
            nonlocal changed
            tag = m.group(0)
            if re.search(r'\bintegrity\s*=\s*["\']', tag, flags=re.I):
                return tag
            changed = True
            return re.sub(r'>\s*$', ' integrity="sha384-TODO-SRI-HASH" crossorigin="anonymous">', tag)

        new_text = re.sub(r'<script\b[^>]*>', repl, text, flags=re.I)
        return new_text, changed

    def _patch_python_eval(self, text: str) -> Tuple[str, bool]:
        new_text = re.sub(r'\beval\s*\(', 'ast.literal_eval(', text)
        if new_text != text:
            if not re.search(r'^\s*import\s+ast\b', new_text, flags=re.M):
                new_text = "import ast\n" + new_text
            return new_text, True
        return text, False

    def _patch_python_subprocess_shell(self, text: str) -> Tuple[str, bool]:
        new_text = re.sub(r'shell\s*=\s*True', 'shell=False', text)
        if new_text != text:
            if not re.search(r'^\s*import\s+shlex\b', new_text, flags=re.M):
                new_text = "import shlex\n" + new_text
            return new_text, True
        return text, False

    # -------------------------
    # Deterministic infra patches (targeted)
    # -------------------------

    def _apply_deterministic_patches(self) -> Tuple[List[str], List[str]]:
        notes: List[str] = []
        emitted: List[str] = []

        # Dockerfile candidates: app/Dockerfile and APP_DIR/Dockerfile
        docker_candidates: List[Tuple[str, Path]] = []
        docker_candidates.append(("app/Dockerfile", self.repo / "app" / "Dockerfile"))

        app_dir = os.getenv("APP_DIR", "").strip()
        if app_dir:
            docker_candidates.append((f"{app_dir}/Dockerfile", self.repo / app_dir / "Dockerfile"))

        for rel, p in docker_candidates:
            if not p.exists():
                continue
            reln = _norm(rel)
            if not self._is_target(reln):
                continue
            try:
                txt = p.read_text(encoding="utf-8", errors="ignore")
                new_txt = self._fix_dockerfile_text(txt, notes)
                if new_txt != txt:
                    diff = _make_unified_diff_git(txt, new_txt, reln, context=2)
                    if diff:
                        outp = self._write_patch(reln, diff, prefix="det_docker_")
                        if outp:
                            emitted.append(outp)
                            notes.append(f"Dockerfile: patch emitted for {reln}")
            except Exception as e:
                notes.append(f"Error building Dockerfile patch for {reln}: {e}")

        # K8s
        kdir = self.repo / "k8s"
        if kdir.exists():
            for yf in sorted(list(kdir.glob("*.yaml")) + list(kdir.glob("*.yml"))):
                rel = _norm(f"k8s/{yf.name}")
                if not self._is_target(rel):
                    continue
                try:
                    original = yf.read_text(encoding="utf-8", errors="ignore").replace("\r\n", "\n")
                    original_clean = "\n".join([ln.rstrip() for ln in original.splitlines()]) + "\n"

                    docs = list(yaml.safe_load_all(original_clean))
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
                        new_clean = "\n".join([ln.rstrip() for ln in new_text.replace("\r\n", "\n").splitlines()]) + "\n"
                        diff = _make_unified_diff_git(original_clean, new_clean, rel, context=2)
                        if diff:
                            outp = self._write_patch(rel, diff, prefix="det_k8s_")
                            if outp:
                                emitted.append(outp)
                                notes.append(f"K8s: patch emitted for {rel}")
                except Exception as e:
                    notes.append(f"Error building K8s patch for {rel}: {e}")

        # Terraform
        tdir = self.repo / "terraform"
        if tdir.exists():
            for tf in sorted(tdir.rglob("*.tf")):
                rel = _norm(str(tf.relative_to(self.repo)))
                if not self._is_target(rel):
                    continue
                try:
                    orig = tf.read_text(encoding="utf-8", errors="ignore")
                    new_tf = self._fix_tf_text(orig, notes)
                    if new_tf != orig:
                        diff = _make_unified_diff_git(orig, new_tf, rel, context=2)
                        if diff:
                            outp = self._write_patch(rel, diff, prefix="det_tf_")
                            if outp:
                                emitted.append(outp)
                                notes.append(f"Terraform: patch emitted for {rel}")
                except Exception as e:
                    notes.append(f"Error building Terraform patch for {rel}: {e}")

        return notes, emitted

    def _fix_dockerfile_text(self, txt: str, notes: List[str]) -> str:
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
                    if sc2.get("allowPrivilegeEscalation") is not False:
                        sc2["allowPrivilegeEscalation"] = False
                        changed = True
                    res = c.setdefault("resources", {})
                    lim = res.setdefault("limits", {})
                    if not lim:
                        lim["cpu"] = self.k8s_default_cpu_limit
                        lim["memory"] = self.k8s_default_mem_limit
                        changed = True

            elif kind == "Pod":
                spec = d.setdefault("spec", {})
                sc = spec.setdefault("securityContext", {})
                if sc.get("runAsNonRoot") is not True:
                    sc["runAsNonRoot"] = True
                    changed = True

                containers = spec.get("containers") or []
                for c in containers:
                    if not isinstance(c, dict):
                        continue
                    sc2 = c.setdefault("securityContext", {})
                    if sc2.get("privileged") is True:
                        sc2["privileged"] = False
                        changed = True
                    if sc2.get("allowPrivilegeEscalation") is not False:
                        sc2["allowPrivilegeEscalation"] = False
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

    def _fix_tf_text(self, text: str, notes: List[str]) -> str:
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
    # Optional LLM patching (targeted)
    # -------------------------

    def _llm_fallback(self, item: Dict[str, Any], tool_group: str) -> str:
        if get_fallback_suggestion is None:
            return "[No fallback available - llm_bridge not loaded]"
        if tool_group == "semgrep":
            return get_fallback_suggestion(
                tool="semgrep",
                rule_id=item.get("rule_id", ""),
                severity=item.get("severity", ""),
                message=item.get("message", ""),
            )
        return get_fallback_suggestion(tool=tool_group, severity=item.get("severity", ""), message=str(item)[:200])

    def _save_llm_autofix_patches(self, findings: Any) -> Tuple[List[str], List[str]]:
        notes: List[str] = []
        emitted: List[str] = []

        grouped = self._normalize_findings_grouped(findings)
        items = grouped.get("semgrep", []) or []

        if assistant_factory is None:
            notes.append("LLM_AUTOFIX enabled but assistant_factory unavailable; skipping.")
            return notes, emitted

        temperature = float(os.getenv("OLLAMA_TEMP", os.getenv("OLLAMA_TEMPERATURE", "0.2")))

        for idx, it in enumerate(items, 1):
            reported_path = it.get("file") or ""
            target = self._resolve_repo_path(reported_path)
            if not target:
                continue
            repo_rel = _norm(str(target.relative_to(self.repo)))
            if not self._is_target(repo_rel):
                continue

            sys_msg = "You are a senior AppSec engineer. Return ONLY a unified diff (---/+++). No prose."
            user = (
                f"Fix the vulnerability with minimal safe changes.\n"
                f"File: {repo_rel}\n"
                f"Rule: {it.get('rule_id','')}\n"
                f"Message: {it.get('message','')}\n"
                f"Line: {it.get('line','')}\n\n"
                f"Snippet:\n{it.get('snippet','')}\n"
            )

            try:
                agent = assistant_factory(name="semgrep_fixer", system_message=sys_msg, temperature=temperature)
                resp = agent.chat_completion_fn([
                    {"role": "system", "content": agent.system_message},
                    {"role": "user", "content": user},
                ])
            except Exception as e:
                notes.append(f"LLM: error for {repo_rel}: {e}")
                resp = self._llm_fallback(it, "semgrep")

            diff = _extract_first_unified_diff(resp or "")
            if diff:
                p = self._write_patch(repo_rel, diff, prefix="llm_")
                if p:
                    emitted.append(p)
                    notes.append(f"LLM: diff saved for {repo_rel}")
            else:
                notes.append(f"LLM: no diff returned for {repo_rel} (fallback or invalid format)")

        return notes, emitted