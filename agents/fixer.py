# agents/fixer.py
"""
Enhanced Fixer (Patch-first, Targeted Remediation)

What’s new:
- Strict allow-list targeting: touches only files recorded during analysis (agent_output/targets.json)
- Robust finding field extraction (semgrep variations)
- Canonical path normalization (./, absolute paths, windows slashes)
- Deterministic infra patches still patch-first but only if file is allowed
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Set
import re
import yaml
import os
import subprocess
import tempfile
import json

# Robust imports
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


def _llm_banner() -> str:
    model = os.getenv("LLM_MODEL") or os.getenv("OLLAMA_MODEL") or "(unset)"
    url = os.getenv("OLLAMA_URL") or (("http://" + os.getenv("OLLAMA_HOST")) if os.getenv("OLLAMA_HOST") else "(unset)")
    mode = os.getenv("LLM_MODE", "ollama")
    return f"> LLM mode: {mode} | Model: {model} | URL: {url}\n\n"


def _truncate_any(val: Any, limit: int = 1200) -> str:
    if isinstance(val, str):
        s = val
    else:
        try:
            s = json.dumps(val, ensure_ascii=False)
        except Exception:
            s = str(val)
    return s if len(s) <= limit else (s[:limit] + "\n... [truncated] ...")


def _safe_name(path: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", path)


def _make_unified_diff_git(old_text: str, new_text: str, repo_rel_path: str, context: int = 2) -> str:
    """
    Produce a robust unified diff using git diff --no-index.
    Keep diff headers (diff --git / index) to help git apply --3way.
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
        diff = res.stdout or ""
        if not diff.strip():
            return ""
        if not diff.endswith("\n"):
            diff += "\n"
        return diff


class Fixer:
    """
    Patch-first auto-remediation with strict targeting.

    If targets are provided (or targets.json exists), only those files are modified.
    """

    def __init__(
        self,
        config: Dict[str, Any],
        output_dir: Path,
        repo_root: Optional[Path] = None,
        allowed_targets: Optional[Set[str]] = None,
        targets_file: Optional[Path] = None,
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

        # Load allow-list targets
        self.allowed_targets: Optional[Set[str]] = set(allowed_targets) if allowed_targets else None
        if self.allowed_targets is None:
            tf = targets_file or (self.out / "targets.json")
            self.allowed_targets = self._load_targets(tf)

        # If file missing, treat as no restrictions (fallback)
        if self.allowed_targets is not None and len(self.allowed_targets) == 0:
            self.allowed_targets = None  # “flexible” fallback

    # -------------------------
    # Targeting / path helpers
    # -------------------------

    def _load_targets(self, path: Path) -> Optional[Set[str]]:
        try:
            if not path.exists():
                return set()  # signal "no targets file"
            data = json.loads(path.read_text(encoding="utf-8"))
            files = data.get("files") or []
            out: Set[str] = set()
            for f in files:
                norm = self._normalize_repo_path(str(f))
                if norm:
                    out.add(norm)
            return out
        except Exception:
            return set()

    def _normalize_repo_path(self, p: str) -> str:
        p = (p or "").strip().replace("\\", "/")
        p = re.sub(r"^\./", "", p)
        if not p:
            return ""

        # If absolute, try to make it relative to repo root
        try:
            pp = Path(p)
            if pp.is_absolute():
                rp = str(pp.resolve()).replace("\\", "/")
                rr = str(self.repo.resolve()).replace("\\", "/")
                if rp.startswith(rr + "/"):
                    p = rp[len(rr) + 1 :]
                else:
                    # last resort: keep basename only
                    p = pp.name
        except Exception:
            pass

        return p

    def _is_allowed(self, repo_rel_path: str) -> bool:
        if self.allowed_targets is None:
            return True
        repo_rel_path = self._normalize_repo_path(repo_rel_path)
        return repo_rel_path in self.allowed_targets

    def _resolve_target_file(self, reported_path: str) -> Optional[Path]:
        rp = self._normalize_repo_path(reported_path)
        if not rp:
            return None

        # 1) direct repo-relative
        t = self.repo / rp
        if t.exists() and t.is_file():
            return t

        # 2) app_dir prefix fallback
        app_dir = os.getenv("APP_DIR", "").strip()
        if app_dir:
            alt = self.repo / app_dir / rp
            if alt.exists() and alt.is_file():
                return alt

            alt2 = self.repo / app_dir / Path(rp).name
            if alt2.exists() and alt2.is_file():
                return alt2

        # 3) basename search in repo (avoid huge scan: shallow)
        # Only if allow-list exists: safe and deterministic
        if self.allowed_targets is not None:
            base = Path(rp).name
            for allowed in self.allowed_targets:
                if Path(allowed).name == base:
                    cand = self.repo / allowed
                    if cand.exists() and cand.is_file():
                        return cand
        return None

    # -------------------------
    # Findings normalization
    # -------------------------

    def _normalize_findings_grouped(self, findings: Any) -> Dict[str, List[Dict[str, Any]]]:
        if isinstance(findings, dict):
            grouped = {k: list(v) for k, v in findings.items() if isinstance(v, list)}
            for k in ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap"):
                grouped.setdefault(k, [])
            return grouped

        grouped: Dict[str, List[Dict[str, Any]]] = {k: [] for k in
            ("semgrep", "trivy_fs", "trivy_image", "tfsec", "gitleaks", "conftest", "zap")}

        if isinstance(findings, list):
            for f in findings:
                tool = (f.get("tool") or f.get("source") or "").lower()
                if tool == "semgrep" or ("check_id" in f or "rule_id" in f):
                    grouped["semgrep"].append(f)
                elif tool in ("trivy-fs", "trivy", "trivy_config", "trivy-config", "trivyfs"):
                    grouped["trivy_fs"].append(f)
                else:
                    grouped["conftest"].append(f)
        return grouped

    def _semgrep_get(self, it: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract semgrep fields robustly from a finding dict.
        Supports common shapes from semgrep JSON parsers.
        """
        def dig(d: Any, keys: List[str]) -> Any:
            cur = d
            for k in keys:
                if not isinstance(cur, dict) or k not in cur:
                    return None
                cur = cur[k]
            return cur

        path = (
            it.get("file") or it.get("path") or
            dig(it, ["location", "path"]) or
            dig(it, ["extra", "path"]) or
            dig(it, ["extra", "metadata", "path"]) or
            ""
        )

        line = (
            it.get("line") or
            dig(it, ["start", "line"]) or
            dig(it, ["location", "line"]) or
            dig(it, ["extra", "lines"]) or
            ""
        )

        rule_id = it.get("rule_id") or it.get("check_id") or it.get("id") or ""
        message = (
            it.get("message") or it.get("title") or
            dig(it, ["extra", "message"]) or
            dig(it, ["extra", "metadata", "message"]) or
            ""
        )
        severity = (it.get("severity") or dig(it, ["extra", "severity"]) or "low")
        snippet = it.get("snippet") or it.get("code") or dig(it, ["extra", "lines"]) or ""

        return {
            "file": str(path),
            "line": line,
            "rule_id": str(rule_id),
            "message": str(message),
            "severity": str(severity),
            "snippet": str(snippet),
        }

    # -------------------------
    # Main apply
    # -------------------------

    def apply(self, findings: Any) -> Dict[str, Any]:
        emitted_patches: List[str] = []
        notes: List[str] = []
        llm_report_path: Optional[str] = None

        print("[fixer] Starting remediation (patch-first)...")
        if self.allowed_targets is None:
            print("[fixer] Targeting: unrestricted (no targets.json or empty targets)")
        else:
            print(f"[fixer] Targeting: restricted to {len(self.allowed_targets)} recorded file(s)")

        qp_notes, qp_patches = self._apply_semgrep_quick_patches(findings)
        notes.extend(qp_notes)
        emitted_patches.extend([p for p in qp_patches if p])

        det_notes, det_patches = self._apply_deterministic_patches()
        notes.extend(det_notes)
        emitted_patches.extend([p for p in det_patches if p])

        # Optional LLM
        if (os.getenv("LLM_AUTOFIX", "").strip() == "1"):
            print("[fixer] LLM autofix enabled; gathering patches...")
            llm_notes, llm_patches = self._save_llm_autofix_patches(findings)
            notes.extend(llm_notes)
            emitted_patches.extend([p for p in llm_patches if p])

        if self.cfg.get("llm", {}).get("enabled", False) or os.getenv("LLM_EXPLAIN", "") == "1":
            llm_report_path = self._maybe_generate_llm_report(emitted_patches, notes, findings)

        # Write audit summary
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
            "files": emitted_patches,
            "notes": notes,
            "llm_report": llm_report_path,
            "llm_report_path": llm_report_path,
        }

    # ------------------------------------------------------------
    # Semgrep quick patches (strict targeting)
    # ------------------------------------------------------------

    def _apply_semgrep_quick_patches(self, findings: Any) -> Tuple[List[str], List[str]]:
        notes: List[str] = []
        emitted: List[str] = []
        grouped = self._normalize_findings_grouped(findings)
        items = grouped.get("semgrep", []) or []

        for raw in items:
            it = self._semgrep_get(raw)
            reported_path = it.get("file") or ""
            if not reported_path:
                notes.append("Semgrep quick: missing file path in finding")
                continue

            target = self._resolve_target_file(reported_path)
            if not target:
                notes.append(f"Semgrep quick: file not found for patch: {reported_path}")
                continue

            repo_rel_path = str(target.relative_to(self.repo)).replace("\\", "/")

            # Enforce allow-list
            if not self._is_allowed(repo_rel_path):
                notes.append(f"Semgrep quick: SKIP (not in targets) {repo_rel_path}")
                continue

            try:
                original = target.read_text(encoding="utf-8", errors="ignore")
            except Exception as e:
                notes.append(f"Semgrep quick: cannot read {repo_rel_path}: {e}")
                continue

            rule = (it.get("rule_id") or "").lower()
            msg  = (it.get("message") or "").lower()

            # HTML SRI
            if repo_rel_path.lower().endswith((".html", ".htm")) and ("integrity" in msg or "integrity" in rule):
                new_text, changed = self._patch_html_add_sri(original)
                if changed:
                    diff = _make_unified_diff_git(original, new_text, repo_rel_path, context=2)
                    p = self._write_patch(repo_rel_path, diff, prefix="semgrep_html_")
                    if p:
                        emitted.append(p)
                        notes.append(f"Semgrep quick: added integrity placeholder in {repo_rel_path}")
                continue

            # Python eval -> ast.literal_eval
            if repo_rel_path.lower().endswith(".py") and ("eval" in msg or "eval" in rule):
                new_text, changed = self._patch_python_eval(original)
                if changed:
                    diff = _make_unified_diff_git(original, new_text, repo_rel_path, context=2)
                    p = self._write_patch(repo_rel_path, diff, prefix="semgrep_eval_")
                    if p:
                        emitted.append(p)
                        notes.append(f"Semgrep quick: replaced eval(...) in {repo_rel_path}")
                continue

            # Python subprocess shell=True -> shell=False
            if repo_rel_path.lower().endswith(".py") and ("subprocess" in msg or "subprocess" in rule or "shell" in msg or "shell" in rule):
                new_text, changed = self._patch_python_subprocess_shell(original)
                if changed:
                    diff = _make_unified_diff_git(original, new_text, repo_rel_path, context=2)
                    p = self._write_patch(repo_rel_path, diff, prefix="semgrep_subproc_")
                    if p:
                        emitted.append(p)
                        notes.append(f"Semgrep quick: hardened subprocess usage in {repo_rel_path}")
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
        changed = False
        new_text = re.sub(r'\beval\s*\(', 'ast.literal_eval(', text)
        if new_text != text:
            changed = True
            if not re.search(r'^\s*import\s+ast\b', new_text, flags=re.M):
                new_text = "import ast\n" + new_text
        return new_text, changed

    def _patch_python_subprocess_shell(self, text: str) -> Tuple[str, bool]:
        changed = False
        new_text = re.sub(r'shell\s*=\s*True', 'shell=False', text)
        if new_text != text:
            changed = True
            if not re.search(r'^\s*import\s+shlex\b', new_text, flags=re.M):
                new_text = "import shlex\n" + new_text
        return new_text, changed

    # ------------------------------------------------------------
    # Deterministic infra patches (only if target is allowed)
    # ------------------------------------------------------------

    def _apply_deterministic_patches(self) -> Tuple[List[str], List[str]]:
        notes: List[str] = []
        emitted: List[str] = []

        # Dockerfile candidates
        candidates: List[Path] = [self.repo / "app" / "Dockerfile"]
        app_dir = os.getenv("APP_DIR", "").strip()
        if app_dir:
            candidates.append(self.repo / app_dir / "Dockerfile")

        for dockerfile in candidates:
            if not dockerfile.exists():
                continue
            rel_path = str(dockerfile.relative_to(self.repo)).replace("\\", "/")
            if not self._is_allowed(rel_path):
                notes.append(f"Dockerfile: SKIP (not in targets) {rel_path}")
                continue
            try:
                txt = dockerfile.read_text(encoding="utf-8")
                new_txt = self._fix_dockerfile_text(txt, notes)
                if new_txt != txt:
                    diff = _make_unified_diff_git(txt, new_txt, rel_path, context=2)
                    p = self._write_patch(rel_path, diff, prefix="det_docker_")
                    if p:
                        emitted.append(p)
                        notes.append(f"Dockerfile: patch emitted for {rel_path}")
            except Exception as e:
                notes.append(f"Error building Dockerfile patch for {rel_path}: {e}")

        # Kubernetes
        kdir = self.repo / "k8s"
        if kdir.exists():
            for p in sorted(list(kdir.glob("*.yaml")) + list(kdir.glob("*.yml"))):
                rel_path = f"k8s/{p.name}"
                if not self._is_allowed(rel_path):
                    notes.append(f"K8s: SKIP (not in targets) {rel_path}")
                    continue
                try:
                    original = p.read_text(encoding="utf-8")
                    original_clean = "\n".join([ln.rstrip() for ln in original.replace("\r\n", "\n").splitlines()]) + "\n"
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
                        diff = _make_unified_diff_git(original_clean, new_clean, rel_path, context=2)
                        pp = self._write_patch(rel_path, diff, prefix="det_k8s_")
                        if pp:
                            emitted.append(pp)
                            notes.append(f"K8s: patch emitted for {rel_path}")
                except Exception as e:
                    notes.append(f"Error building K8s patch for {rel_path}: {e}")

        # Terraform
        tdir = self.repo / "terraform"
        if tdir.exists():
            for p in sorted(tdir.rglob("*.tf")):
                rel = str(p.relative_to(self.repo)).replace("\\", "/")
                if not self._is_allowed(rel):
                    notes.append(f"Terraform: SKIP (not in targets) {rel}")
                    continue
                try:
                    orig = p.read_text(encoding="utf-8")
                    new_tf = self._fix_tf_text(orig, notes)
                    if new_tf != orig:
                        diff = _make_unified_diff_git(orig, new_tf, rel, context=2)
                        path = self._write_patch(rel, diff, prefix="det_tf_")
                        if path:
                            emitted.append(path)
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
                f"RUN (adduser --disabled-password --gecos '' {user}) || (adduser -D {user}) || (useradd -m {user} || true)\n"
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
                    sc["runAsNonRoot"] = True; changed = True
                containers = tpl.get("containers") or []
                for c in containers:
                    if not isinstance(c, dict):
                        continue
                    sc2 = c.setdefault("securityContext", {})
                    if sc2.get("privileged") is True:
                        sc2["privileged"] = False; changed = True
                    if sc2.get("allowPrivilegeEscalation") is not False:
                        sc2["allowPrivilegeEscalation"] = False; changed = True
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
                    sc["runAsNonRoot"] = True; changed = True
                containers = tpl.get("containers") or []
                for c in containers:
                    if not isinstance(c, dict):
                        continue
                    sc2 = c.setdefault("securityContext", {})
                    if sc2.get("privileged") is True:
                        sc2["privileged"] = False; changed = True
                    if sc2.get("allowPrivilegeEscalation") is not False:
                        sc2["allowPrivilegeEscalation"] = False; changed = True
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
    # Optional LLM explanation for audit (unchanged)
    # ------------------------------------------------------------

    def _maybe_generate_llm_report(self, emitted_patches: List[str], notes: List[str], findings: Any) -> Optional[str]:
        if assistant_factory is None:
            return None

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

        try:
            agent = assistant_factory(name="remediation_reporter", system_message=system_msg, temperature=0.2)
            messages = [{"role": "system", "content": agent.system_message}, {"role": "user", "content": context}]
            text = agent.chat_completion_fn(messages)
        except Exception:
            return None

        if text:
            md_path = self.out / "remediation_explained.md"
            try:
                md_path.write_text(_llm_banner() + text.strip(), encoding="utf-8")
                return str(md_path)
            except Exception:
                return None
        return None

    # ------------------------------------------------------------
    # Patch writing helper
    # ------------------------------------------------------------

    def _write_patch(self, repo_rel_path: str, patch_text: str, prefix: str = "patch_") -> str:
        text = (patch_text or "").lstrip("\ufeff\r\n")

        # Must contain unified headers somewhere
        if not (re.search(r"(?m)^---\s+", text) and re.search(r"(?m)^\+\+\+\s+", text)):
            print(f"[fixer] WARNING: missing unified headers in patch for {repo_rel_path}; skipping write")
            return ""

        safe = _safe_name(repo_rel_path or "unnamed")
        out_path = self.patch_dir / f"{prefix}{safe}.patch"
        out_path.write_text(text, encoding="utf-8", newline="\n")
        print(f"[fixer] patch written: {out_path}")
        return str(out_path)