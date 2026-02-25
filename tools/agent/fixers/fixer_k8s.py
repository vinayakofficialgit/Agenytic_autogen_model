#!/usr/bin/env python3
import pathlib
import difflib
import re
from typing import List, Dict, Any


def query_for(item: dict) -> str:
    return (
        "k8s securityContext runAsNonRoot allowPrivilegeEscalation false "
        "readOnlyRootFilesystem capabilities drop"
    )


def _read(p: str) -> str:
    data = pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")
    return data.replace("\r\n", "\n").replace("\r", "\n")  # normalize EOL


def _write_diff(old: str, new: str, path: str) -> str:
    """Return a plain unified diff (no diff --git, no a/b prefixes)."""
    a = old.splitlines(keepends=True)
    b = new.splitlines(keepends=True)
    body = difflib.unified_diff(a, b, fromfile=path, tofile=path)
    out = "".join(body)
    if not out.endswith("\n"):
        out += "\n"
    return out


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _ensure_block(text: str) -> str:
    """
    Conservatively add missing securityContext hardening keys:
      - privileged: false
      - allowPrivilegeEscalation: false
      - readOnlyRootFilesystem: true
      - capabilities:
          drop:
            - ALL
    """
    lines = text.splitlines()
    out: List[str] = []
    i = 0
    while i < len(lines):
        out.append(lines[i])
        sc_match = re.match(r"^(?P<indent>\s*)securityContext:\s*$", lines[i])
        if sc_match:
            base_indent = sc_match.group("indent")
            child_indent = base_indent + "  "  # two spaces

            j = i + 1
            present_top_keys = set()
            while j < len(lines):
                lj = lines[j]
                if lj.strip() == "":
                    j += 1
                    continue
                if _indent_width(lj) <= len(base_indent):
                    break
                if _indent_width(lj) == len(child_indent) and ":" in lj:
                    present_top_keys.add(lj.strip().split(":", 1)[0])
                j += 1

            insertions: List[str] = []
            if "privileged" not in present_top_keys:
                insertions.append(f"{child_indent}privileged: false")
            if "allowPrivilegeEscalation" not in present_top_keys:
                insertions.append(f"{child_indent}allowPrivilegeEscalation: false")
            if "readOnlyRootFilesystem" not in present_top_keys:
                insertions.append(f"{child_indent}readOnlyRootFilesystem: true")
            if "capabilities" not in present_top_keys:
                insertions += [
                    f"{child_indent}capabilities:",
                    f"{child_indent}  drop:",
                    f"{child_indent}    - ALL",
                ]

            if insertions:
                out.extend(insertions)
        i += 1

    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def try_deterministic(item: dict) -> str | None:
    path = item.get("file", "")
    if not path.endswith((".yml", ".yaml")):
        return None

    raw = _read(path)
    changed = raw

    # Basic hardening
    changed = re.sub(r"(?mi)^\s*privileged:\s*true\s*$", "          privileged: false", changed)
    changed = re.sub(
        r"(?mi)^\s*allowPrivilegeEscalation:\s*true\s*$",
        "          allowPrivilegeEscalation: false",
        changed,
    )
    changed = re.sub(r"(?mi)^\s*runAsUser:\s*0\s*$", "          runAsNonRoot: true", changed)

    if re.search(r"(?mi)^\s*securityContext:\s*$", changed):
        changed = _ensure_block(changed)

    # Services: NodePort → ClusterIP
    if "kind: Service" in changed:
        changed = re.sub(r"(?mi)^\s*type:\s*NodePort\s*$", "  type: ClusterIP", changed)

    if changed != raw:
        return _write_diff(raw, changed, path)
    return None


def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
    path = item.get("file", "")
    if not path.endswith((".yml", ".yaml")):
        return None

    raw = _read(path)
    target = raw

    rag_harden = False
    for c in (topk or []):
        snip = c.get("snippet", "") or ""
        if (
            "readOnlyRootFilesystem: true" in snip
            or re.search(r"\bcapabilities\b", snip)
            or "allowPrivilegeEscalation: false" in snip
        ):
            rag_harden = True
            break

    if rag_harden and re.search(r"(?mi)^\s*securityContext:\s*$", target):
        target = _ensure_block(target)

    if "kind: Service" in target:
        target = re.sub(r"(?mi)^\s*type:\s*NodePort\s*$", "  type: ClusterIP", target)

    if target != raw:
        return _write_diff(raw, target, path)
    return None
