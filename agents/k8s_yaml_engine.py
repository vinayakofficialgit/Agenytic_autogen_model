from pathlib import Path
from typing import Dict, Any, List, Tuple
import yaml


class K8sYamlEngine:

    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root)

    def apply_for_finding(self, item: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        notes = []
        changed = []

        file_path = item.get("file") or item.get("path")
        if not file_path:
            return notes, changed

        target = self.repo_root / file_path
        if not target.exists():
            return notes, changed

        with open(target) as f:
            docs = list(yaml.safe_load_all(f))

        modified = False

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            spec = (
                doc.get("spec", {})
                .get("template", {})
                .get("spec", {})
            )

            containers = spec.get("containers", [])
            for c in containers:
                sc = c.get("securityContext", {})
                updated = False

                if not sc.get("runAsNonRoot"):
                    sc["runAsNonRoot"] = True
                    updated = True

                if "runAsUser" not in sc:
                    sc["runAsUser"] = 1000
                    updated = True

                if sc.get("allowPrivilegeEscalation") != False:
                    sc["allowPrivilegeEscalation"] = False
                    updated = True

                if sc.get("privileged") != False:
                    sc["privileged"] = False
                    updated = True

                if updated:
                    c["securityContext"] = sc
                    modified = True

        if modified:
            with open(target, "w") as f:
                yaml.safe_dump_all(docs, f, sort_keys=False)

            notes.append("[k8s] securityContext enforced")
            changed.append(file_path)

        return notes, changed