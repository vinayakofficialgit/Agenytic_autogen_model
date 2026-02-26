#!/usr/bin/env python3
import pathlib
from typing import List, Dict, Any


# ============================================================
# Query Builder
# ============================================================

def query_for(item: dict) -> str:
    return "Dockerfile best practices multi-stage eclipse-temurin 17 jre non-root user 1000"


# ============================================================
# Helpers
# ============================================================

def _resolve_full_path(path: str) -> str:
    """
    Resolve Dockerfile path safely.
    """
    if not path:
        path = "java-pilot-app/Dockerfile"

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


# ============================================================
# Deterministic Docker Hardening
# ============================================================

def try_deterministic(item: dict) -> Dict[str, str] | None:
    raw_path = item.get("file", "") or "java-pilot-app/Dockerfile"
    path = _resolve_full_path(raw_path)

    if not path:
        print(f"⚠ Dockerfile not found: {raw_path}")
        return None

    original = _read(path)
    if not original:
        return None

    modified = original

    # Skip if already hardened
    if "FROM eclipse-temurin:17-jre" in modified and "USER 1000" in modified:
        return None

    # Replace entire Dockerfile with hardened multi-stage version
    hardened = """# ---- Builder stage ----
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B -DskipTests dependency:go-offline
COPY . .
RUN mvn -q -B -DskipTests package

# ---- Runtime stage ----
FROM eclipse-temurin:17-jre
WORKDIR /app
COPY --from=build /src/target/java-pilot-app-1.0.0.jar /app/app.jar
RUN adduser --system --uid 1000 appuser
USER 1000
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
"""

    if hardened.strip() == modified.strip():
        return None

    return {
        "file": path,
        "content": hardened
    }


# ============================================================
# RAG fallback (disabled for now)
# ============================================================

def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> Dict[str, str] | None:
    return None