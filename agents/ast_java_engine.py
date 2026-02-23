# agents/ast_java_engine.py
"""
AST Java Autofix Engine (Production-style)
-----------------------------------------
Orchestrates Java AST transformations using a dedicated JavaParser-based fixer
implemented as a small Maven tool under tools/java-ast-fixer/.
"""
from __future__ import annotations
import os
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

@dataclass
class AstFixResult:
    changed_files: List[str]
    notes: List[str]
    ok: bool
    raw: Dict[str, Any]

class ASTJavaEngine:
    """Runs JavaParser AST fixes via tools/java-ast-fixer Maven module."""
    def __init__(
        self,
        repo_root: Path,
        tool_dir: Optional[Path] = None,
        app_pom: Optional[Path] = None,
        debug: bool = False,
    ):
        self.repo_root = Path(repo_root).resolve()
        self.tool_dir = (tool_dir or (self.repo_root / "tools" / "java-ast-fixer")).resolve()
        # Allow override from env for CI flexibility
        env_tool_pom = os.getenv("AST_FIXER_POM")
        self.tool_pom = Path(env_tool_pom).resolve() if env_tool_pom else (self.tool_dir / "pom.xml")
        self.app_pom = (app_pom or self._auto_detect_app_pom()).resolve() if (app_pom or self._auto_detect_app_pom()) else None
        self.debug = debug

    # -------------------------
    def _auto_detect_app_pom(self) -> Optional[Path]:
        candidates = [
            # self.repo_root / "pom.xml",
            self.repo_root / "hackathon-vuln-app" / "pom.xml",
        ]
        for c in candidates:
            if c.exists():
                return c
        return None

    # -------------------------
    def apply_for_finding(self, finding: Dict[str, Any]) -> AstFixResult:
        file_path = (finding.get("file") or finding.get("path") or "").strip()
        title = str(finding.get("title", "")).strip()
        if not file_path:
            return AstFixResult([], ["[ast] missing file/path in finding; skipping"], True, {"skipped": True})

        target = (self.repo_root / file_path).resolve()
        if not str(target).startswith(str(self.repo_root)) or not target.exists():
            return AstFixResult([], [f"[ast] target not found or outside repo: {file_path}"], True, {"skipped": True})

        vuln_type = self._classify(title)
        if vuln_type is None:
            return AstFixResult([], [f"[ast] no AST recipe for: {title}"], True, {"skipped": True})

        payload = {
            "repo_root": str(self.repo_root),
            "file": file_path.replace("\\", "/"),
            "vuln_type": vuln_type,
            "title": title,
            "rule_id": finding.get("rule_id") or finding.get("check_id") or finding.get("cve") or "",
        }
        return self._run_java_tool(payload)

    # ⭐ EXTENDED CLASSIFIER
    def _classify(self, title: str) -> Optional[str]:
        t = title.lower()
        if "sql injection" in t or ("sql" in t and "inject" in t):
            return "SQL_INJECTION"
        if "command injection" in t or ("cmd" in t and "inject" in t):
            return "COMMAND_INJECTION"
        if "path traversal" in t or "directory traversal" in t:
            return "PATH_TRAVERSAL"
        if "ssrf" in t or "server-side request forgery" in t:
            return "SSRF"
        if "xss" in t or "cross-site scripting" in t:
            return "XSS"
        if "template injection" in t:
            return "TEMPLATE_INJECTION"
        return None

    # -------------------------
    def _run_java_tool(self, payload: Dict[str, Any]) -> AstFixResult:
        if not self.tool_pom.exists():
            return AstFixResult([], [f"[ast] tool missing ->skip AST"], True, {"skipped": True})

        tmp_dir = self.repo_root / "agent_output"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        in_file = tmp_dir / "ast_fix_request.json"
        out_file = tmp_dir / "ast_fix_result.json"
        in_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if out_file.exists():
            out_file.unlink()

        # IMPORTANT: no embedded quotes around args (we are not using a shell)
        cmd = [
            "mvn", "-q",
            "-f", str(self.tool_pom),
            "exec:java",
            f"-Dexec.args={in_file} {out_file}",
        ]
        if self.debug:
            print("[ast] running:", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                cwd=str(self.repo_root),
                capture_output=True,
                text=True,
            )
        except Exception as e:
            return AstFixResult([], [f"[ast] failed to invoke maven tool: {e}"], False, {"error": "invoke_failed"})

        # persist logs for diagnostics
        log_file = tmp_dir / "ast_fixer.log"
        log_file.write_text(
            f"$ {' '.join(cmd)}\n\n[STDOUT]\n{proc.stdout or ''}\n\n[STDERR]\n{proc.stderr or ''}\n",
            encoding="utf-8"
        )

        if proc.returncode != 0:
            err = (proc.stderr or "").strip()
            out = (proc.stdout or "").strip()
            notes = ["[ast] tool failed (non-zero exit)", err[:500], out[:500], f"[ast] see {log_file.name}"]
            return AstFixResult([], [n for n in notes if n], False, {"error": "tool_failed"})

        if not out_file.exists():
            return AstFixResult([], ["[ast] tool produced no output json"], False, {"error": "no_output"})

        raw = json.loads(out_file.read_text(encoding="utf-8"))
        changed = raw.get("changed_files", []) or []
        notes = raw.get("notes", []) or []
        ok = bool(raw.get("ok", True))
        return AstFixResult(changed_files=list(changed), notes=list(notes), ok=ok, raw=raw)

    # -------------------------
    def compile_validate(self) -> Tuple[bool, str]:
        if not self.app_pom or not self.app_pom.exists():
            return True, "[ast] compile validation skipped (no app pom detected)"
        cmd = ["mvn", "-q", "-f", str(self.app_pom), "clean", "test", "-DskipTests=true"]
        try:
            proc = subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True, text=True)
            if proc.returncode == 0:
                return True, "[ast] compile validation OK"
            return False, f"[ast] compile validation FAILED: {proc.stderr[-400:]}"
        except Exception as e:
            return False, f"[ast] compile validation error: {e}"



# # agents/ast_java_engine.py
# """
# AST Java Autofix Engine (Production-style)
# -----------------------------------------
# Orchestrates Java AST transformations using a dedicated JavaParser-based fixer
# implemented as a small Maven tool under tools/java-ast-fixer/.
# """

# from __future__ import annotations

# import json
# import subprocess
# from dataclasses import dataclass
# from pathlib import Path
# from typing import Any, Dict, List, Tuple, Optional


# @dataclass
# class AstFixResult:
#     changed_files: List[str]
#     notes: List[str]
#     ok: bool
#     raw: Dict[str, Any]


# class ASTJavaEngine:
#     """Runs JavaParser AST fixes via tools/java-ast-fixer Maven module."""

#     def __init__(
#         self,
#         repo_root: Path,
#         tool_dir: Optional[Path] = None,
#         app_pom: Optional[Path] = None,
#         debug: bool = False,
#     ):
#         self.repo_root = Path(repo_root).resolve()
#         self.tool_dir = (tool_dir or (self.repo_root / "tools" / "java-ast-fixer")).resolve()
#         self.tool_pom = self.tool_dir / "pom.xml"
#         self.app_pom = (app_pom or self._auto_detect_app_pom()).resolve() if (app_pom or self._auto_detect_app_pom()) else None
#         self.debug = debug

#     # -------------------------
#     def _auto_detect_app_pom(self) -> Optional[Path]:
#         candidates = [
#             # self.repo_root / "pom.xml",
#             self.repo_root / "hackathon-vuln-app" / "pom.xml",
#         ]
#         for c in candidates:
#             if c.exists():
#                 return c
#         return None

#     # -------------------------
#     def apply_for_finding(self, finding: Dict[str, Any]) -> AstFixResult:
#         file_path = (finding.get("file") or finding.get("path") or "").strip()
#         title = str(finding.get("title", "")).strip()

#         if not file_path:
#             return AstFixResult([], ["[ast] missing file/path in finding; skipping"], True, {"skipped": True})

#         target = (self.repo_root / file_path).resolve()
#         if not str(target).startswith(str(self.repo_root)) or not target.exists():
#             return AstFixResult([], [f"[ast] target not found or outside repo: {file_path}"], True, {"skipped": True})

#         vuln_type = self._classify(title)
#         if vuln_type is None:
#             return AstFixResult([], [f"[ast] no AST recipe for: {title}"], True, {"skipped": True})

#         payload = {
#             "repo_root": str(self.repo_root),
#             "file": file_path.replace("\\", "/"),
#             "vuln_type": vuln_type,
#             "title": title,
#             "rule_id": finding.get("rule_id") or finding.get("check_id") or finding.get("cve") or "",
#         }

#         return self._run_java_tool(payload)

#     # ⭐ EXTENDED CLASSIFIER
#     def _classify(self, title: str) -> Optional[str]:
#         t = title.lower()

#         if "sql injection" in t or ("sql" in t and "inject" in t):
#             return "SQL_INJECTION"

#         if "command injection" in t or ("cmd" in t and "inject" in t):
#             return "COMMAND_INJECTION"

#         if "path traversal" in t or "directory traversal" in t:
#             return "PATH_TRAVERSAL"

#         if "ssrf" in t or "server-side request forgery" in t:
#             return "SSRF"

#         if "xss" in t or "cross-site scripting" in t:
#             return "XSS"

#         if "template injection" in t:
#             return "TEMPLATE_INJECTION"

#         return None

#     # -------------------------
#     def _run_java_tool(self, payload: Dict[str, Any]) -> AstFixResult:
#         if not self.tool_pom.exists():
#             return AstFixResult([], [f"[ast] tool missing ->skip AST"],True,{"skipped":True})
#             # return AstFixResult([], [f"[ast] tool missing: {self.tool_pom}"], False, {"error": "tool_missing"})

#         tmp_dir = self.repo_root / "agent_output"
#         tmp_dir.mkdir(parents=True, exist_ok=True)
#         in_file = tmp_dir / "ast_fix_request.json"
#         out_file = tmp_dir / "ast_fix_result.json"

#         in_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
#         if out_file.exists():
#             out_file.unlink()

#         cmd = [
#             "mvn",
#             "-q",
#             "-f",
#             str(self.tool_pom),
#             "exec:java",
#             f'-Dexec.args="{in_file} {out_file}"',
#         ]       
        
#         # cmd = [
#         #     "mvn",
#         #     "-q",
#         #     "-f",
#         #     str(self.tool_pom),
#         #     "exec:java",
#         #     f"-Dexec.args={in_file} {out_file}",
#         # ]

#         if self.debug:
#             print("[ast] running:", " ".join(cmd))

#         try:
#             proc = subprocess.run(
#                 cmd,
#                 cwd=str(self.repo_root),
#                 capture_output=not self.debug,
#                 text=True,
#             )
#         except Exception as e:
#             return AstFixResult([], [f"[ast] failed to invoke maven tool: {e}"], False, {"error": "invoke_failed"})

#         if proc.returncode != 0:
#             err = proc.stderr.strip() if proc.stderr else ""
#             out = proc.stdout.strip() if proc.stdout else ""
#             notes = ["[ast] tool failed (non-zero exit)", err[:500], out[:500]]
#             return AstFixResult([], [n for n in notes if n], False, {"error": "tool_failed"})

#         if not out_file.exists():
#             return AstFixResult([], ["[ast] tool produced no output json"], False, {"error": "no_output"})

#         raw = json.loads(out_file.read_text(encoding="utf-8"))
#         changed = raw.get("changed_files", []) or []
#         notes = raw.get("notes", []) or []

#         ok = bool(raw.get("ok", True))
#         return AstFixResult(changed_files=list(changed), notes=list(notes), ok=ok, raw=raw)

#     # -------------------------
#     def compile_validate(self) -> Tuple[bool, str]:
#         if not self.app_pom or not self.app_pom.exists():
#             return True, "[ast] compile validation skipped (no app pom detected)"

#         cmd = ["mvn", "-q", "-f", str(self.app_pom), "clean", "test", "-DskipTests=true"]

#         try:
#             proc = subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True, text=True)
#             if proc.returncode == 0:
#                 return True, "[ast] compile validation OK"
#             return False, f"[ast] compile validation FAILED: {proc.stderr[-400:]}"
#         except Exception as e:
#             return False, f"[ast] compile validation error: {e}"


# # # agents/ast_java_engine.py
# # """
# # AST Java Autofix Engine (Production-style)
# # -----------------------------------------
# # Orchestrates Java AST transformations using a dedicated JavaParser-based fixer
# # implemented as a small Maven tool under tools/java-ast-fixer/.

# # Why this design?
# # - AST patching is done in Java (correct parser, correct syntax)
# # - Python only chooses strategy + runs the tool + collects results
# # - Safe-by-default: if pattern doesn't match confidently -> no-op + note

# # Inputs:
# # - finding dict (must include: title, file/path, severity)
# # Outputs:
# # - (notes, changed_files): notes explain what happened; changed_files contains paths modified
# # """

# # from __future__ import annotations

# # import json
# # import subprocess
# # from dataclasses import dataclass
# # from pathlib import Path
# # from typing import Any, Dict, List, Tuple, Optional


# # @dataclass
# # class AstFixResult:
# #     changed_files: List[str]
# #     notes: List[str]
# #     ok: bool
# #     raw: Dict[str, Any]


# # class ASTJavaEngine:
# #     """Runs JavaParser AST fixes via tools/java-ast-fixer Maven module."""

# #     def __init__(
# #         self,
# #         repo_root: Path,
# #         tool_dir: Optional[Path] = None,
# #         app_pom: Optional[Path] = None,
# #         debug: bool = False,
# #     ):
# #         self.repo_root = Path(repo_root).resolve()
# #         self.tool_dir = (tool_dir or (self.repo_root / "tools" / "java-ast-fixer")).resolve()
# #         self.tool_pom = self.tool_dir / "pom.xml"
# #         self.app_pom = (app_pom or self._auto_detect_app_pom()).resolve() if (app_pom or self._auto_detect_app_pom()) else None
# #         self.debug = debug

# #     # -------------------------
# #     # Detect app pom.xml (optional; used if you want compile validation later)
# #     # -------------------------
# #     def _auto_detect_app_pom(self) -> Optional[Path]:
# #         candidates = [
# #             self.repo_root / "pom.xml",
# #             self.repo_root / "enterprise-devsecops-hackathon" / "app" / "pom.xml",
# #         ]
# #         for c in candidates:
# #             if c.exists():
# #                 return c
# #         return None

# #     # -------------------------
# #     # Public: apply AST fix for a single finding
# #     # -------------------------
# #     def apply_for_finding(self, finding: Dict[str, Any]) -> AstFixResult:
# #         """Attempt an AST fix for a given finding; safe no-op if not applicable."""
# #         file_path = (finding.get("file") or finding.get("path") or "").strip()
# #         title = str(finding.get("title", "")).strip()

# #         if not file_path:
# #             return AstFixResult([], ["[ast] missing file/path in finding; skipping"], True, {"skipped": True})

# #         target = (self.repo_root / file_path).resolve()
# #         if not str(target).startswith(str(self.repo_root)) or not target.exists():
# #             return AstFixResult([], [f"[ast] target not found or outside repo: {file_path}"], True, {"skipped": True})

# #         vuln_type = self._classify(title)
# #         if vuln_type is None:
# #             return AstFixResult([], [f"[ast] no AST recipe for: {title}"], True, {"skipped": True})

# #         payload = {
# #             "repo_root": str(self.repo_root),
# #             "file": file_path.replace("\\", "/"),
# #             "vuln_type": vuln_type,
# #             # extra context (optional)
# #             "title": title,
# #             "rule_id": finding.get("rule_id") or finding.get("check_id") or finding.get("cve") or "",
# #         }

# #         return self._run_java_tool(payload)

# #     # -------------------------
# #     # Simple classifier (extend later)
# #     # -------------------------
# #     def _classify(self, title: str) -> Optional[str]:
# #         t = title.lower()
# #         if "sql injection" in t or ("sql" in t and "inject" in t):
# #             return "SQL_INJECTION"
# #         if "command injection" in t or ("cmd" in t and "inject" in t):
# #             return "COMMAND_INJECTION"
# #         return None

# #     # -------------------------
# #     # Run Maven tool: tools/java-ast-fixer
# #     # -------------------------
# #     def _run_java_tool(self, payload: Dict[str, Any]) -> AstFixResult:
# #         if not self.tool_pom.exists():
# #             return AstFixResult([], [f"[ast] tool missing: {self.tool_pom}"], False, {"error": "tool_missing"})

# #         # Write payload to a temp file inside repo (so paths are consistent)
# #         tmp_dir = self.repo_root / "agent_output"
# #         tmp_dir.mkdir(parents=True, exist_ok=True)
# #         in_file = tmp_dir / "ast_fix_request.json"
# #         out_file = tmp_dir / "ast_fix_result.json"

# #         in_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
# #         if out_file.exists():
# #             out_file.unlink()

# #         cmd = [
# #             "mvn",
# #             "-q",
# #             "-f",
# #             str(self.tool_pom),
# #             "exec:java",
# #             f"-Dexec.args={in_file} {out_file}",
# #         ]

# #         if self.debug:
# #             print("[ast] running:", " ".join(cmd))

# #         try:
# #             proc = subprocess.run(
# #                 cmd,
# #                 cwd=str(self.repo_root),
# #                 capture_output=not self.debug,
# #                 text=True,
# #             )
# #         except Exception as e:
# #             return AstFixResult([], [f"[ast] failed to invoke maven tool: {e}"], False, {"error": "invoke_failed"})

# #         if proc.returncode != 0:
# #             err = proc.stderr.strip() if proc.stderr else ""
# #             out = proc.stdout.strip() if proc.stdout else ""
# #             notes = ["[ast] tool failed (non-zero exit)", err[:500], out[:500]]
# #             return AstFixResult([], [n for n in notes if n], False, {"error": "tool_failed"})

# #         if not out_file.exists():
# #             return AstFixResult([], ["[ast] tool produced no output json"], False, {"error": "no_output"})

# #         raw = json.loads(out_file.read_text(encoding="utf-8"))
# #         changed = raw.get("changed_files", []) or []
# #         notes = raw.get("notes", []) or []

# #         ok = bool(raw.get("ok", True))
# #         return AstFixResult(changed_files=list(changed), notes=list(notes), ok=ok, raw=raw)

# #     # -------------------------
# #     # Optional: compile validation hook (call from Fixer if you want)
# #     # -------------------------
# #     def compile_validate(self) -> Tuple[bool, str]:
# #         """Run mvn -q -f <app_pom> test/compile if configured."""
# #         if not self.app_pom or not self.app_pom.exists():
# #             return True, "[ast] compile validation skipped (no app pom detected)"
# #         cmd = ["mvn", "-q", "-f", str(self.app_pom), "clean", "test", "-DskipTests=true"]
# #         try:
# #             proc = subprocess.run(cmd, cwd=str(self.repo_root), capture_output=True, text=True)
# #             if proc.returncode == 0:
# #                 return True, "[ast] compile validation OK"
# #             return False, f"[ast] compile validation FAILED: {proc.stderr[-400:]}"
# #         except Exception as e:
# #             return False, f"[ast] compile validation error: {e}"