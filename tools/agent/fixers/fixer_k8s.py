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
    return pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")


def _write_diff(old: str, new: str, path: str) -> str:
    """Return a git-apply friendly unified diff for a single file.

    We add a leading 'diff --git' header and prefix paths with a/ and b/ so that
    `git apply` can consume it reliably.
    """
    a = old.splitlines(keepends=True)
    b = new.splitlines(keepends=True)
    fromfile = f"a/{path}"
    tofile = f"b/{path}"
    body = difflib.unified_diff(a, b, fromfile=fromfile, tofile=tofile)
    patch = [f"diff --git {fromfile} {tofile}\n"]
    patch.extend(body)
    out = "".join(patch)
    if not out.endswith("\n"):
        out += "\n"
    return out


def _indent_width(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _ensure_block(text: str) -> str:
    """
    Add/ensure hardened fields near 'securityContext:'.
    This is a conservative textual insertion that avoids YAML parsing.
    It tries to add the following under a detected securityContext:
      - privileged: false
      - allowPrivilegeEscalation: false
      - readOnlyRootFilesystem: true
      - capabilities:
          drop:
            - ALL
    Indentation for inserted keys is derived from the securityContext line.
    """
    lines = text.splitlines()
    out: List[str] = []
    i = 0
    while i < len(lines):
        out.append(lines[i])
        sc_match = re.match(r"^(?P<indent>\s*)securityContext:\s*$", lines[i])
        if sc_match:
            base_indent = sc_match.group("indent")
            child_indent = base_indent + "  "  # +2 spaces under securityContext

            # Determine end of this block (next line with indent <= base and non-blank)
            j = i + 1
            present_top_keys = set()
            while j < len(lines):
                line_j = lines[j]
                if line_j.strip() == "":
                    j += 1
                    continue
                if _indent_width(line_j) <= len(base_indent):
                    break
                # Only capture keys exactly one indent level below securityContext
                if _indent_width(line_j) == len(child_indent) and ":" in line_j:
                    key = line_j.strip().split(":", 1)[0]
                    present_top_keys.add(key)
                j += 1

            # Prepare insertions for missing keys
            insertions: List[str] = []
            if "privileged" not in present_top_keys:
                insertions.append(f"{child_indent}privileged: false")
            if "allowPrivilegeEscalation" not in present_top_keys:
                insertions.append(f"{child_indent}allowPrivilegeEscalation: false")
            if "readOnlyRootFilesystem" not in present_top_keys:
                insertions.append(f"{child_indent}readOnlyRootFilesystem: true")
            if "capabilities" not in present_top_keys:
                insertions.extend(
                    [
                        f"{child_indent}capabilities:",
                        f"{child_indent}  drop:",
                        f"{child_indent}    - ALL",
                    ]
                )

            # Insert right after current line before the rest of the block
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

    # Privileged / APE / UID=0 → harden
    changed = re.sub(
        r"(?mi)^\s*privileged:\s*true\s*$",
        "          privileged: false",
        changed,
    )
    changed = re.sub(
        r"(?mi)^\s*allowPrivilegeEscalation:\s*true\s*$",
        "          allowPrivilegeEscalation: false",
        changed,
    )
    changed = re.sub(
        r"(?mi)^\s*runAsUser:\s*0\s*$",
        "          runAsNonRoot: true",
        changed,
    )

    # Ensure hardening block if securityContext exists
    if re.search(r"(?mi)^\s*securityContext:\s*$", changed):
        changed = _ensure_block(changed)

    # Services: NodePort → ClusterIP (minimal change)
    if "kind: Service" in changed:
        changed = re.sub(
            r"(?mi)^\s*type:\s*NodePort\s*$",
            "  type: ClusterIP",
            changed,
        )

    if changed != raw:
        return _write_diff(raw, changed, path)
    return None


def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
    """
    If Top‑K context shows readOnlyRootFilesystem or capabilities drop, ensure we add them.
    """
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
        target = re.sub(
            r"(?mi)^\s*type:\s*NodePort\s*$",
            "  type: ClusterIP",
            target,
        )

    if target != raw:
        return _write_diff(raw, target, path)
    return None


# #!/usr/bin/env python3
# import pathlib
# import difflib
# import re
# from typing import List, Dict, Any


# def query_for(item: dict) -> str:
#     return (
#         "k8s securityContext runAsNonRoot allowPrivilegeEscalation false "
#         "readOnlyRootFilesystem capabilities drop"
#     )


# def _read(p: str) -> str:
#     return pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")


# def _write_diff(old: str, new: str, path: str) -> str:
#     a = old.splitlines(keepends=True)
#     b = new.splitlines(keepends=True)
#     diff = difflib.unified_diff(a, b, fromfile=path, tofile=path)
#     return "".join(diff)


# def _indent_width(line: str) -> int:
#     return len(line) - len(line.lstrip(" "))


# def _ensure_block(text: str) -> str:
#     """
#     Add/ensure hardened fields near 'securityContext:'.
#     This is a conservative textual insertion that avoids YAML parsing.
#     It tries to add the following under a detected securityContext:
#       - privileged: false
#       - allowPrivilegeEscalation: false
#       - readOnlyRootFilesystem: true
#       - capabilities:
#           drop:
#             - ALL
#     Indentation for inserted keys is derived from the securityContext line.
#     """
#     lines = text.splitlines()
#     out: List[str] = []
#     i = 0
#     while i < len(lines):
#         out.append(lines[i])
#         sc_match = re.match(r"^(?P<indent>\s*)securityContext:\s*$", lines[i])
#         if sc_match:
#             base_indent = sc_match.group("indent")
#             child_indent = base_indent + "  "  # +2 spaces under securityContext

#             # Determine end of this block (next line with indent <= base and non-blank)
#             j = i + 1
#             present_top_keys = set()
#             while j < len(lines):
#                 line_j = lines[j]
#                 if line_j.strip() == "":
#                     j += 1
#                     continue
#                 if _indent_width(line_j) <= len(base_indent):
#                     break
#                 # Only capture keys exactly one indent level below securityContext
#                 if _indent_width(line_j) == len(child_indent) and ":" in line_j:
#                     key = line_j.strip().split(":", 1)[0]
#                     present_top_keys.add(key)
#                 j += 1

#             # Prepare insertions for missing keys
#             insertions: List[str] = []
#             if "privileged" not in present_top_keys:
#                 insertions.append(f"{child_indent}privileged: false")
#             if "allowPrivilegeEscalation" not in present_top_keys:
#                 insertions.append(f"{child_indent}allowPrivilegeEscalation: false")
#             if "readOnlyRootFilesystem" not in present_top_keys:
#                 insertions.append(f"{child_indent}readOnlyRootFilesystem: true")
#             if "capabilities" not in present_top_keys:
#                 insertions.extend(
#                     [
#                         f"{child_indent}capabilities:",
#                         f"{child_indent}  drop:",
#                         f"{child_indent}    - ALL",
#                     ]
#                 )

#             # Insert right after current line before the rest of the block
#             if insertions:
#                 out.extend(insertions)
#         i += 1

#     return "\n".join(out) + ("\n" if text.endswith("\n") else "")


# def try_deterministic(item: dict) -> str | None:
#     path = item.get("file", "")
#     if not path.endswith((".yml", ".yaml")):
#         return None

#     raw = _read(path)
#     changed = raw

#     # Privileged / APE / UID=0 → harden
#     changed = re.sub(
#         r"(?mi)^\s*privileged:\s*true\s*$",
#         "          privileged: false",
#         changed,
#     )
#     changed = re.sub(
#         r"(?mi)^\s*allowPrivilegeEscalation:\s*true\s*$",
#         "          allowPrivilegeEscalation: false",
#         changed,
#     )
#     changed = re.sub(
#         r"(?mi)^\s*runAsUser:\s*0\s*$",
#         "          runAsNonRoot: true",
#         changed,
#     )

#     # Ensure hardening block if securityContext exists
#     if re.search(r"(?mi)^\s*securityContext:\s*$", changed):
#         changed = _ensure_block(changed)

#     # Services: NodePort → ClusterIP (minimal change)
#     if "kind: Service" in changed:
#         changed = re.sub(
#             r"(?mi)^\s*type:\s*NodePort\s*$",
#             "  type: ClusterIP",
#             changed,
#         )

#     if changed != raw:
#         return _write_diff(raw, changed, path)
#     return None


# def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
#     """
#     If Top‑K context shows readOnlyRootFilesystem or capabilities drop, ensure we add them.
#     """
#     path = item.get("file", "")
#     if not path.endswith((".yml", ".yaml")):
#         return None

#     raw = _read(path)
#     target = raw

#     rag_harden = False
#     for c in (topk or []):
#         snip = c.get("snippet", "") or ""
#         if (
#             "readOnlyRootFilesystem: true" in snip
#             or re.search(r"\bcapabilities\b", snip)
#             or "allowPrivilegeEscalation: false" in snip
#         ):
#             rag_harden = True
#             break

#     if rag_harden and re.search(r"(?mi)^\s*securityContext:\s*$", target):
#         target = _ensure_block(target)

#     if "kind: Service" in target:
#         target = re.sub(
#             r"(?mi)^\s*type:\s*NodePort\s*$",
#             "  type: ClusterIP",
#             target,
#         )

#     if target != raw:
#         return _write_diff(raw, target, path)
#     return None


# #!/usr/bin/env python3
# import pathlib
# import difflib
# import re
# from typing import List, Dict, Any

# def query_for(item: dict) -> str:
#     return "k8s securityContext runAsNonRoot allowPrivilegeEscalation false readOnlyRootFilesystem capabilities drop"

# def _read(p: str) -> str:
#     return pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")

# def _write_diff(old: str, new: str, path: str) -> str:
#     a = old.splitlines(keepends=True)
#     b = new.splitlines(keepends=True)
#     diff = difflib.unified_diff(a, b, fromfile=path, tofile=path)
#     return "".join(diff)

# def _ensure_block(text: str) -> str:
#     """
#     Add/ensure hardened fields near 'securityContext:'.
#     """
#     lines = text.splitlines()
#     hardened = [
#         "          privileged: false",
#         "          allowPrivilegeEscalation: false",
#         "          readOnlyRootFilesystem: true",
#         "          capabilities:",
#         "            drop:",
#         "              - ALL",
#     ]
#     out = []
#     i = 0
#     while i < len(lines):
#         out.append(lines[i])
#         if re.search(r"^\s*securityContext:\s*$", lines[i]):
#             # scan following indented block to see present keys
#             j = i + 1
#             present = set()
#             while j < len(lines) and (lines[j].startswith(" ") or lines[j].strip() == ""):
#                 fragment = lines[j].strip()
#                 if ":" in fragment:
#                     present.add(fragment.split(":")[0])
#                 j += 1
#             for h in hardened:
#                 key = h.strip().split(":")[0]
#                 if key not in present:
#                     out.append(h)
#                changed = re.sub(r"(?mi)^\s*type:\s*NodePort\s*$", "  type: ClusterIP", changed)        i += 1

#     if changed != raw:
#         return _write_diff(raw, changed, path)
#     return None

# def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
#     """
#     If Top‑K context shows readOnlyRootFilesystem or capabilities drop, ensure we add them.
#     """
#     path = item.get("file", "")
#     if not path.endswith((".yml", ".yaml")):
#         return None

#     raw = _read(path)
#     target = raw

#     rag_harden = False
#     for c in topk or []:
#         snip = c.get("snippet", "") or ""
#         if "readOnlyRootFilesystem: true" in snip or "capabilities:" in snip:
#             rag_harden = True
#             break

#     if rag_harden:
#         if re.search(r"(?mi)^\s*securityContext:\s*$", target):
#             target = _ensure_block(target)

#     if target != raw:
#         return _write_diff(raw, target, path)
#     return None
#     return "\n".join(out) + ("\n" if text.endswith("\n") else "")

# def try_deterministic(item: dict) -> str | None:
#     path = item.get("file", "")
#     if not path.endswith((".yml", ".yaml")):
#         return None

#     raw = _read(path)
#     changed = raw

#     # Privileged / APE / UID=0 → harden
#     changed = re.sub(r"(?mi)^\s*privileged:\s*true\s*$", "          privileged: false", changed)
#     changed = re.sub(r"(?mi)^\s*allowPrivilegeEscalation:\s*true\s*$", "          allowPrivilegeEscalation: false", changed)
#     changed = re.sub(r"(?mi)^\s*runAsUser:\s*0\s*$", "          runAsNonRoot: true", changed)

#     # Ensure hardening block if securityContext exists
#     if re.search(r"(?mi)^\s*securityContext:\s*$", changed):
#         changed = _ensure_block(changed)

#     # Services: NodePort → ClusterIP (minimal change)
#     if "kind: Service" in changed and re.search(r"(?mi)^\s*type:\s*NodePort\s*$", changed):




# # import pathlib, difflib, re
# # from typing import List, Dict, Any, Optional


# # def query_for(item: dict) -> str:
# #     return "k8s securityContext runAsNonRoot allowPrivilegeEscalation false readOnlyRootFilesystem capabilities drop"


# # def _read(p: str) -> str:
# #     return pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")


# # def _write_diff(old: str, new: str, path: str) -> str:
# #     a = old.splitlines(keepends=True)
# #     b = new.splitlines(keepends=True)
# #     diff = difflib.unified_diff(a, b, fromfile=path, tofile=path)
# #     return "".join(diff)


# # def _ensure_block(text: str) -> str:
# #     lines = text.splitlines()
# #     hardened = [
# #         "          privileged: false",
# #         "          allowPrivilegeEscalation: false",
# #         "          readOnlyRootFilesystem: true",
# #         "          capabilities:",
# #         "            drop:",
# #         "              - ALL",
# #     ]

# #     out = []
# #     i = 0
# #     while i < len(lines):
# #         out.append(lines[i])

# #         if re.search(r"^\s*securityContext:\s*$", lines[i]):
# #             j = i + 1
# #             present = set()

# #             while j < len(lines) and (lines[j].startswith(" ") or lines[j].strip() == ""):
# #                 if ":" in lines[j]:
# #                     present.add(lines[j].strip().split(":")[0])
# #                 j += 1

# #             for h in hardened:
# #                 k = h.strip().split(":")[0]
# #                 if k not in present:
# #                     out.append(h)

# #         i += 1

# #     return "\n".join(out) + ("\n" if text.endswith("\n") else "")


# # def try_deterministic(item: dict, topk: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
# #     path = item.get("file", "")
# #     if not path.endswith((".yml", ".yaml")):
# #         return None

# #     raw = _read(path)
# #     changed = raw

# #     # Fix privileged / escalation / root user
# #     changed = re.sub(r"(?mi)^\s*privileged:\s*true\s*$", "          privileged: false", changed)
# #     changed = re.sub(r"(?mi)^\s*allowPrivilegeEscalation:\s*true\s*$", "          allowPrivilegeEscalation: false", changed)
# #     changed = re.sub(r"(?mi)^\s*runAsUser:\s*0\s*$", "          runAsNonRoot: true", changed)

# #     # Ensure hardened block
# #     if re.search(r"(?mi)^\s*securityContext:\s*$", changed):
# #         changed = _ensure_block(changed)

# #     # NodePort → ClusterIP
# #     if "kind: Service" in changed:
# #         changed = re.sub(r"(?mi)^\s*type:\s*NodePort\s*$", "  type: ClusterIP", changed)

# #     # RAG style hints
# #     rag_harden = False
# #     if topk:
# #         for c in topk:
# #             snip = c.get("snippet", "")
# #             if "readOnlyRootFilesystem: true" in snip or "capabilities:" in snip:
# #                 rag_harden = True
# #                 break

# #     if rag_harden:
# #         changed = _ensure_block(changed)

# #     if changed != raw:
# #         return _write_diff(raw, changed, path)

# #     return None


# # def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> Optional[str]:
# #     path = item.get("file", "")
# #     if not path:
# #         return None

# #     raw = _read(path)
# #     changed = raw

# #     for c in topk:
# #         snip = c.get("snippet", "")

# #         if "allowPrivilegeEscalation: false" in snip:
# #             changed = re.sub(
# #                 r"(?mi)^\s*allowPrivilegeEscalation:\s*true\s*$",
# #                 "          allowPrivilegeEscalation: false",
# #                 changed,
# #             )

# #         if "readOnlyRootFilesystem: true" in snip or "capabilities:" in snip:
# #             changed = _ensure_block(changed)

# #     if changed != raw:
# #         return _write_diff(raw, changed, path)

# #     return None