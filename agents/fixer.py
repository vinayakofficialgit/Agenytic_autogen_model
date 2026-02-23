from __future__ import annotations

import os
import re
import json
import subprocess
import yaml
from pathlib import Path
from typing import Dict, List, Tuple, Any

from agents.ast_java_engine import ASTJavaEngine


# =============================
# Utilities
# =============================
def _is_autofix_severity(sev):
    return str(sev or "").lower() in ["high", "critical", "error"]


def _sanitize_diff(diff: str) -> str:
    if not diff:
        return diff
    diff = diff.replace("```diff", "").replace("```", "").strip()
    return diff


def _parse_diff_changed_files(diff: str) -> List[str]:
    files = []
    for line in diff.splitlines():
        if line.startswith("+++ b/"):
            files.append(line.replace("+++ b/", "").strip())
    return list(set(files))


def _patch_targets_repo(repo_root: Path, files: List[str]) -> bool:
    repo_root = repo_root.resolve()
    for f in files:
        p = (repo_root / f).resolve()
        if not str(p).startswith(str(repo_root)):
            return False
    return True


def _git_apply_patch(repo: Path, diff: str) -> bool:
    try:
        proc = subprocess.run(
            ["git", "apply", "--check", "-"],
            cwd=repo,
            input=diff.encode(),
        )
        if proc.returncode != 0:
            return False

        proc = subprocess.run(
            ["git", "apply", "-"],
            cwd=repo,
            input=diff.encode(),
        )
        return proc.returncode == 0

    except Exception as e:
        print("[fixer] patch error:", e)
        return False


# =========================================================
# Kubernetes hardener helpers (module-level)
# =========================================================
def _ensure_dict(d):
    return d if isinstance(d, dict) else {}


def _harden_container_sc(c: dict) -> bool:
    """
    Harden a single container (or initContainer) security context.
    Returns True if mutated.
    """
    changed = False
    sc = c.setdefault("securityContext", {})
    if sc.get("privileged", False) is True:
        sc["privileged"] = False
        changed = True
    if sc.get("allowPrivilegeEscalation") is not False:
        sc["allowPrivilegeEscalation"] = False
        changed = True
    if sc.get("readOnlyRootFilesystem") is not True:
        sc["readOnlyRootFilesystem"] = True
        changed = True

    # Capabilities: drop ALL (merge if user provided existing list)
    caps = sc.setdefault("capabilities", {})
    drops = set(caps.get("drop", []) or [])
    if "ALL" not in drops:
        drops.add("ALL")
        caps["drop"] = sorted(drops)
        changed = True

    # Sensible default if not present
    if not c.get("imagePullPolicy"):
        c["imagePullPolicy"] = "IfNotPresent"
        changed = True

    return changed


def _get_podspec_for(doc: dict) -> dict | None:
    """
    Return the pod 'spec' dict for a given K8s resource 'doc', or None if not applicable.
    Handles: Pod, Deployment, ReplicaSet, StatefulSet, DaemonSet, Job, CronJob
    """
    kind = (doc.get("kind") or "").lower()
    spec = _ensure_dict(doc.get("spec", {}))

    if kind == "pod":
        return spec

    # Workloads with template.spec
    if kind in ("deployment", "replicaset", "statefulset", "daemonset"):
        tmpl = _ensure_dict(spec.get("template", {}))
        return _ensure_dict(tmpl.get("spec", {}))

    if kind == "job":
        tmpl = _ensure_dict(spec.get("template", {}))
        return _ensure_dict(tmpl.get("spec", {}))

    if kind == "cronjob":
        jt = _ensure_dict(spec.get("jobTemplate", {}))
        jts = _ensure_dict(jt.get("spec", {}))
        tmpl = _ensure_dict(jts.get("template", {}))
        return _ensure_dict(tmpl.get("spec", {}))

    return None


def _harden_podspec(podspec: dict) -> bool:
    """
    Apply pod-level and container-level hardening to a Pod spec.
    Returns True if any mutation performed.
    """
    changed = False

    # Pod-level security context
    psc = podspec.setdefault("securityContext", {})
    if psc.get("runAsNonRoot") is not True:
        psc["runAsNonRoot"] = True
        changed = True
    # Only set user/group if not already present (do not override explicit config)
    if "runAsUser" not in psc:
        psc["runAsUser"] = 10001
        changed = True
    if "runAsGroup" not in psc:
        psc["runAsGroup"] = 10001
        changed = True

    # seccomp profile (Pod-level)
    sp = psc.setdefault("seccompProfile", {})
    if sp.get("type") != "RuntimeDefault":
        sp["type"] = "RuntimeDefault"
        changed = True

    # Harden containers and initContainers
    for key in ("containers", "initContainers"):
        for c in podspec.get(key, []) or []:
            if _harden_container_sc(c):
                changed = True

    return changed


def _harden_service(doc: dict) -> bool:
    """
    Enforce safe defaults for Service:
      - type: ClusterIP
      - remove ports[].nodePort
      - sessionAffinity: None (if missing)
    """
    changed = False
    spec = _ensure_dict(doc.get("spec", {}))

    svc_type = spec.get("type", "ClusterIP")
    if svc_type in ("NodePort", "LoadBalancer"):
        spec["type"] = "ClusterIP"
        changed = True
        # Remove nodePort fields that become invalid
        for p in spec.get("ports", []) or []:
            if "nodePort" in p:
                p.pop("nodePort", None)
                changed = True

    if "sessionAffinity" not in spec:
        spec["sessionAffinity"] = "None"
        changed = True

    # Write back if mutated
    if changed:
        doc["spec"] = spec
    return changed


# =========================================================
# FIXER CLASS
# =========================================================
class Fixer:
    def __init__(self, cfg, output_dir, repo_root=Path(".")):
        self.cfg = cfg or {}
        self.out = Path(output_dir)
        self.repo = Path(repo_root)

        # ✅ Toggle AST fallback via env; default True for local runs
        self.ast_enabled = str(os.getenv("AST_ENABLED", "true")).lower() in ("1", "true", "yes")

        self.ast_engine = ASTJavaEngine(repo_root=self.repo, debug=False)

    # -------------------------------------------------
    def _apply_deterministic_fixes(self) -> Tuple[List[str], List[str]]:
        notes, changed = [], []

        dockerfile = self.repo / "Dockerfile"
        if dockerfile.exists():
            text = dockerfile.read_text()
            if "USER root" in text:
                dockerfile.write_text(text.replace("USER root", "USER appuser"))
                notes.append("[deterministic] Dockerfile hardened")
                changed.append("Dockerfile")

        # Terraform S3 fixes (if present)
        tf_root = (self.repo / "hackathon-vuln-app" / "terraform")
        if tf_root.exists():
            n_iac, c_iac = self._apply_iac_s3_fixes(tf_root)  # previously added method
            notes += n_iac
            changed += c_iac

        return notes, changed

    # -------------------------------------------------
    # IaC: Terraform S3 hardener (deterministic)
    # -------------------------------------------------
    def _apply_iac_s3_fixes(self, tf_root: Path):
        """
        Deterministic Terraform fixes for S3 buckets flagged by tfsec:
          - AVD-AWS-0092: public ACL -> private
          - AVD-AWS-0088/0132: add SSE (uses KMS if S3_KMS_KEY_ARN env provided; else SSE-S3)
          - AVD-AWS-0086/87/91/93/0094: add aws_s3_bucket_public_access_block with all four booleans true
        """
        notes, changed = [], []
        if not tf_root.exists():
            return notes, changed

        kms_arn = os.getenv("S3_KMS_KEY_ARN", "").strip()

        # 1) In-place update for bucket resources across *.tf
        for tf in tf_root.rglob("*.tf"):
            text = tf.read_text(encoding="utf-8")
            original = text

            # (a) Prevent public ACLs
            text = re.sub(r'acl\s*=\s*"public-read(-write)?"', 'acl = "private"', text)

            # (b) Ensure SSE block (prefer KMS if provided; else SSE-S3)
            def add_sse_block(match):
                block = match.group(0)
                if "server_side_encryption_configuration" in block:
                    return block  # already present
                if kms_arn:
                    sse = f'''
  server_side_encryption_configuration {{
    rule {{
      apply_server_side_encryption_by_default {{
        sse_algorithm     = "aws:kms"
        kms_master_key_id = "{kms_arn}"
      }}
    }}
  }}'''
                else:
                    sse = '''
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }'''
                return re.sub(r'\}\s*$', f'{sse}\n}}', block, flags=re.S)

            # inject SSE into each aws_s3_bucket resource
            text = re.sub(
                r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s*\{[\s\S]*?\}',
                add_sse_block,
                text,
                flags=re.S
            )

            if text != original:
                tf.write_text(text, encoding="utf-8")
                notes.append(f"[iac] updated {tf}")
                changed.append(str(tf.relative_to(self.repo)))

        # 2) Ensure Public Access Block is present (one per bucket)
        pab_tf = tf_root / "s3_public_access_block.tf"
        required = []
        for tf in tf_root.rglob("*.tf"):
            if tf == pab_tf:
                continue
            src = tf.read_text(encoding="utf-8")
            required += re.findall(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', src)
        required = sorted(set(required))

        want_body = ""
        for name in required:
            want_body += f'''
resource "aws_s3_bucket_public_access_block" "{name}_pab" {{
  bucket = aws_s3_bucket.{name}.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}
'''.strip() + "\n\n"

        if required:
            current = pab_tf.read_text(encoding="utf-8") if pab_tf.exists() else ""
            if current.strip() != want_body.strip():
                pab_tf.write_text(want_body.strip() + "\n", encoding="utf-8")
                notes.append(f"[iac] wrote {pab_tf.relative_to(self.repo)} for: {', '.join(required)}")
                changed.append(str(pab_tf.relative_to(self.repo)))

        return notes, list(set(changed))

    # -------------------------------------------------
    def _llm_propose_patch_for_item(self, item: Dict[str, Any]) -> Tuple[str, bool]:
        prompt = f"You MUST output ONLY unified git diff patch.\nFix vulnerability:\n{item}"

        try:
            from agents.llm_bridge import assistant_factory
            diff = assistant_factory().generate_patch(prompt)
            diff = _sanitize_diff(diff)
            return diff, False

        except Exception as e:
            print("[fixer] LLM error:", e)
            return "", True

    # -------------------------------------------------
    def _apply_llm_autofixes(self, grouped: Dict[str, List[Dict]]) -> Tuple[List[str], List[str]]:
        notes, changed_files = [], []

        for tool, items in grouped.items():
            for item in items:

                if not _is_autofix_severity(item.get("severity")):
                    continue

                file_path = item.get("file") or item.get("path") or ""
                title = str(item.get("title", "")).lower()

                print(f"[fixer] vulnerability in: {file_path} -> {item.get('title')}")

                # Only Java handled by AST (optional); non-Java is handled elsewhere
                if not file_path.endswith(".java"):
                    notes.append(f"[fixer] AST skipped (non-java finding): {item.get('title')}")
                    continue

                diff, fallback = self._llm_propose_patch_for_item(item)

                # ======================================================
                # LLM invalid → AST structural fallback (optional)
                # ======================================================
                if fallback or not diff or "--- a/" not in diff:

                    if not self.ast_enabled:
                        notes.append(f"[fixer] AST disabled; skipping fallback for: {item.get('title')}")
                        continue

                    notes.append(f"[fixer] LLM patch invalid → AST fallback: {item.get('title')}")

                    # Normalize title for classifier
                    if "sql" in title:
                        item["title"] = "SQL injection"
                    elif "command" in title or "exec" in title:
                        item["title"] = "command injection"

                    ast_result = self.ast_engine.apply_for_finding(item)

                    notes.extend(ast_result.notes)
                    changed_files.extend(ast_result.changed_files)

                    # Compile validation after AST change
                    if ast_result.ok and ast_result.changed_files:
                        ok, msg = self.ast_engine.compile_validate()
                        notes.append(msg)
                        if not ok:
                            notes.append("[fixer] compile failed after AST fix")

                    continue

                # ======================================================
                # LLM patch apply path
                # ======================================================
                targets = _parse_diff_changed_files(diff)
                targets = [t.replace("a/", "").replace("b/", "") for t in targets]

                if not _patch_targets_repo(self.repo, targets):
                    notes.append("[fixer] patch rejected outside repo")
                    continue

                if _git_apply_patch(self.repo, diff):
                    notes.append("[fixer] LLM patch applied")
                    changed_files.extend(targets)
                else:
                    # If LLM patch can't be applied
                    if not self.ast_enabled:
                        notes.append("[fixer] LLM patch failed and AST disabled; skipping fallback")
                        continue

                    notes.append("[fixer] LLM patch failed → AST fallback")

                    ast_result = self.ast_engine.apply_for_finding(item)
                    notes.extend(ast_result.notes)
                    changed_files.extend(ast_result.changed_files)

                    if ast_result.ok and ast_result.changed_files:
                        ok, msg = self.ast_engine.compile_validate()
                        notes.append(msg)
                        if not ok:
                            notes.append("[fixer] compile failed after AST fix")

        return notes, list(set(changed_files))

    # -------------------------------------------------
    # Kubernetes hardener (deterministic IaC for K8s)
    # -------------------------------------------------
    def _apply_k8s_fixes(self, k8s_root: Path):
        """
        Deterministic Kubernetes hardening:
          - Finds YAML files
          - Hardens Pod specs across core workloads
          - Hardens Services to ClusterIP (removes nodePort), sessionAffinity: None
        """
        notes, changed_files = [], []
        if not k8s_root.exists():
            return notes, changed_files

        for yf in k8s_root.rglob("*.y*ml"):
            text = yf.read_text(encoding="utf-8")
            orig = text

            try:
                docs = list(yaml.safe_load_all(text)) or []
            except Exception:
                # Skip malformed YAML
                continue

            file_changed = False

            for i, doc in enumerate(docs):
                if not isinstance(doc, dict):
                    continue
                kind = (doc.get("kind") or "").lower()

                # Workloads with Pod specs
                podspec = _get_podspec_for(doc)
                if podspec is not None and isinstance(podspec, dict):
                    if _harden_podspec(podspec):
                        # write back podspec (re-nest where appropriate)
                        if kind == "pod":
                            doc["spec"] = podspec
                        elif kind in ("deployment", "replicaset", "statefulset", "daemonset", "job"):
                            spec = _ensure_dict(doc.get("spec", {}))
                            tmpl = _ensure_dict(spec.get("template", {}))
                            tmpl["spec"] = podspec
                            spec["template"] = tmpl
                            doc["spec"] = spec
                        elif kind == "cronjob":
                            spec = _ensure_dict(doc.get("spec", {}))
                            jt = _ensure_dict(spec.get("jobTemplate", {}))
                            jts = _ensure_dict(jt.get("spec", {}))
                            tmpl = _ensure_dict(jts.get("template", {}))
                            tmpl["spec"] = podspec
                            jts["template"] = tmpl
                            jt["spec"] = jts
                            spec["jobTemplate"] = jt
                            doc["spec"] = spec
                        docs[i] = doc
                        file_changed = True

                # Services
                if kind == "service":
                    if _harden_service(doc):
                        docs[i] = doc
                        file_changed = True

            if file_changed:
                # dump back (preserve doc separators; keep natural key order)
                new_text = yaml.safe_dump_all(docs, sort_keys=False)
                if new_text != orig:
                    yf.write_text(new_text, encoding="utf-8")
                    rel = str(yf.relative_to(self.repo))
                    notes.append(f"[k8s] hardened {rel}")
                    changed_files.append(rel)

        return notes, list(set(changed_files))

    # -------------------------------------------------
    def apply(self, grouped):
        notes, changed = [], []

        # Deterministic fixes (Dockerfile + Terraform S3)
        n1, c1 = self._apply_deterministic_fixes()
        notes += n1; changed += c1

        # ✅ Kubernetes hardening (Pods/Workloads/Services)
        k8s_root = (self.repo / "hackathon-vuln-app" / "kubernetes")
        n_k8s, c_k8s = self._apply_k8s_fixes(k8s_root)
        notes += n_k8s; changed += c_k8s

        # LLM fixes (Java etc., AST optional)
        n2, c2 = self._apply_llm_autofixes(grouped)
        notes += n2; changed += c2

        changed = list(set(changed))
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "patch_manifest.json").write_text(
            json.dumps({"files": changed, "notes": notes}, indent=2), encoding="utf-8"
        )

        print("[fixer] changed files:", changed)
        return notes, changed