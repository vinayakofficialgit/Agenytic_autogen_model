import pathlib, difflib, re
from typing import List, Dict, Any

def query_for(item: dict) -> str:
    return "k8s securityContext runAsNonRoot allowPrivilegeEscalation false readOnlyRootFilesystem capabilities drop"

def _read(p: str) -> str:
    return pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")

def _write_diff(old: str, new: str, path: str) -> str:
    a = old.splitlines(keepends=True)
    b = new.splitlines(keepends=True)
    diff = difflib.unified_diff(a, b, fromfile=path, tofile=path)
    return "".join(diff)

def _ensure_block(text: str) -> str:
    # Add hardened fields near 'securityContext:' if found; otherwise append a hardened block to the container spec
    lines = text.splitlines()
    hardened = [
        "          privileged: false",
        "          allowPrivilegeEscalation: false",
        "          readOnlyRootFilesystem: true",
        "          capabilities:",
        "            drop:",
        "              - ALL",
    ]
    out = []
    i=0
    while i < len(lines):
        out.append(lines[i])
        if re.search(r"^\s*securityContext:\s*$", lines[i]):
            # inject if missing
            j = i+1
            present = set()
            while j < len(lines) and (lines[j].startswith(" ") or lines[j].strip()==""):
                present.add(lines[j].strip().split(":")[0] if ":" in lines[j] else "")
                j+=1
            # add missing hardened keys
            for h in hardened:
                k = h.strip().split(":")[0]
                if k not in present:
                    out.append(h)
        i+=1
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")

def try_deterministic(item: dict) -> str|None:
    path = item.get("file","")
    if not path.endswith((".yml",".yaml")): return None
    raw = _read(path)
    changed = raw

    # Privileged, runAsUser: 0, allowPrivilegeEscalation
    changed = re.sub(r"(?mi)^\s*privileged:\s*true\s*$", "          privileged: false", changed)
    changed = re.sub(r"(?mi)^\s*allowPrivilegeEscalation:\s*true\s*$", "          allowPrivilegeEscalation: false", changed)
    changed = re.sub(r"(?mi)^\s*runAsUser:\s*0\s*$", "          runAsNonRoot: true", changed)

    # If securityContext present, ensure hardened block
    if re.search(r"(?mi)^\s*securityContext:\s*$", changed):
        changed = _ensure_block(changed)

    # Services: NodePort -> ClusterIP (minimal)
    if "kind: Service" in changed and re.search(r"(?mi)^\s*type:\s*NodePort\s*$", changed):
        changed    target = raw        changed = re.sub(r"(?mi)^\s*type:\s*NodePort\s*$", "  type: ClusterIP", changed)

    # Heuristic: if any context shows readOnlyRootFilesystem or capabilities drop, ensure we add them
    rag_harden = False
    for c in topk or []:
        snip = c.get("snippet","")
        if "readOnlyRootFilesystem: true" in snip or "capabilities:" in snip:
            rag_harden = True
            break
    if rag_harden:
        target = _ensure_block(target)

    if target != raw:
        return _write_diff(raw, target, path)
    return None

    if changed != raw:
        return _write_diff(raw, changed, path)
    return None

def try_rag_style(item: dict, topk: List[Dict[str,Any]]) -> str|None:
    """Copy style hints from Top‑K (e.g., presence of allowPrivilegeEscalation: false, caps drop, probes)."""
    path = item.get("file","")
    if not path: return None
    raw = _read(path)
