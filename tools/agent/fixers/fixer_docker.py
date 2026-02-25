import pathlib
import difflib
from typing import List, Dict, Any

def query_for(item: dict) -> str:
    return "Dockerfile best practices multi-stage eclipse-temurin 17 jre non-root user 1000"

def _read(p: str) -> str:
    return pathlib.Path(p).read_text(encoding="utf-8", errors="ignore")

def _write_diff(old: str, new: str, path: str) -> str:
    a = old.splitlines(keepends=True)
    b = new.splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=path, tofile=path))

def try_deterministic(item: dict) -> str | None:
    # We’ll harden java-pilot-app/Dockerfile if present
    path = "java-pilot-app/Dockerfile"
    p = pathlib.Path(path)
    if not p.exists():
        return None

    raw = _read(path)

    # If already using eclipse-temurin:17-jre and has USER, consider it somewhat hardened
    if "FROM eclipse-temurin:17-jre" in raw and "USER" in raw:
        return None  # already somewhat hardened

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
    return _write_diff(raw, hardened, path)

def try_rag_style(item: dict, topk: List[Dict[str, Any]]) -> str | None:
    return None