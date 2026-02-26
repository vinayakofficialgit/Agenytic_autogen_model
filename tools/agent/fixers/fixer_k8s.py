#!/usr/bin/env python3
import pathlib
import re
from typing import List, Dict, Any


# ============================================================
# Query Builder
# ============================================================

def query_for(item: dict) -> str:
    return (
        "k8s securityContext runAsNonRoot allowPrivilegeEscalation false "
        "readOnlyRootFilesystem capabilities drop"
    )


# ============================================================
# Helpers
# ============================================================

def _resolve_full_path(path: str) -> str:
    p = pathlib.Path(path)

    if p.exists():
        return str(p)

    prefixed = pathlib.Path("java-pilot-app") / p
    if prefixed.exists():
        return str(prefixed)

    return ""


def _read(path: str) -> str:
    p = pathlib.Path(path)
    if not p.exists():
        return ""
    data = p.read_text(encoding="utf-8", errors="ignore")
    return data.replace("\r\n", "\n").replace("\r", "\n")


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _ensure_security_block(text: str) -> str:
    lines = text.splitlines()
    output = []
    i = 0

    while i < len(lines):
        output.append(lines[i])
        match = re.match(r"^(?P<indent>\s*)securityContext:\s*$", lines[i])

        if match:
            base_indent = match.group("indent")
            child_indent = base_indent + "  "

            j = i + 1
            present_keys = set()

            while j < len(lines):
                line = lines[j]
                if line.strip() == "":
                    j += 1
                    continue
                if _indent_width(line) <= len(base_indent):
                    break
                if _indent_width(line) == len(child_indent) and ":" in line:
                    present_keys.add(line.strip().split(":", 1)[0])
                j += 1

            additions = []

            if "privileged" not in present_keys:
                additions.append(f"{child_indent}privileged: false")
            if "allowPrivilegeEscalation" not in present_keys:
                additions.append(f"{child_indent}allowPrivilegeEscalation: false")
            if "readOnlyRootFilesystem" not in present_keys:
                additions.append(f"{child_indent}readOnlyRootFilesystem: true")
            if "capabilities" not in present_keys:
                additions += [
                    f"{child_indent}capabilities:",
                    f"{child_indent}  drop:",
                    f"{child_indent}    - ALL",
                ]

            output.extend(additions)

        i += 1

    return "\n".join(output) + ("\n" if text.endswith("\n") else "")


# ============================================================
# Deterministic Fix
# ============================================================

def try_deterministic(item: dict) -> Dict[str, str] | None:
    raw_path = item.get("file", "")
    if not raw_path.endswith((".yml", ".yaml")):
        return None

    path = _resolve_full_path(raw_path)
    if not path:
        print(f"⚠ K8s file not found: {raw_path}")
        return None

    original = _read(path)
    if not original:
        return None

    modified = original

    # Basic hardening (no hardcoded indentation anymore)
    modified = re.sub(
        r"(?mi)^(\s*)privileged:\s*true\s*$",
        r"\1privileged: false",
        modified,
    )

    modified = re.sub(
        r"(?mi)^(\s*)allowPrivilegeEscalation:\s*true\s*$",
        r"\1allowPrivilegeEscalation: false",
        modified,
    )

    modified = re.sub(
        r"(?mi)^(\s*)runAsUser:\s*0\s*$",
        r"\1runAsNonRoot: true",
        modified,
    )

    if re.search(r"(?mi)^\s*securityContext:\s*$", modified):
        modified = _ensure_security_block(modified)

    # Service hardening
    if "kind: Service" in modified:
        modified = re.sub(
            r"(?mi)^(\s*)type:\s*NodePort\s*$",
            r"\1type: ClusterIP",
            modified,
        )

    if modified == original:
        return None

    return {
        "file": path,
        "content": modified
    }


# ============================================================
# RAG fallback (optional)
# ============================================================

def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> Dict[str, str] | None:
    return None