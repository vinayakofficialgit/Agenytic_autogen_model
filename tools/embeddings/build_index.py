#!/usr/bin/env python3
import os
import sys
import json
import faiss
import time
import hashlib
import pathlib
import numpy as np
from typing import List, Dict, Any
from openai import OpenAI
from openai import APIError, RateLimitError, APIConnectionError

# ==========================================================
# CONFIG
# ==========================================================

ROOT = pathlib.Path(".").resolve()
OUT = pathlib.Path("agent_output/index")
OUT.mkdir(parents=True, exist_ok=True)

EMBED_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
CHUNK_SIZE = int(os.getenv("RAG_CHUNK_SIZE", "1500"))
BATCH_SIZE = int(os.getenv("RAG_EMBED_BATCH", "128"))
MAX_FILES = int(os.getenv("RAG_MAX_FILES", "5000"))

INCLUDE_EXT = {".yaml", ".yml", ".tf", ".java", ".xml", ".properties", ".md"}
EXCLUDE_DIRS = {".git", ".github", "target", "node_modules", ".venv", "__pycache__"}

# ==========================================================
# UTILITIES
# ==========================================================

def require_api_key() -> str:
    key = os.getenv("OPENAI_API_KEY", "")
    if not key:
        print("ERROR: OPENAI_API_KEY is not set.", file=sys.stderr)
        sys.exit(2)
    return key


def iter_files():
    count = 0
    for p in ROOT.rglob("*"):
        if count >= MAX_FILES:
            break
        if p.is_file():
            if any(ex in p.parts for ex in EXCLUDE_DIRS):
                continue
            if p.name == "Dockerfile" or p.suffix in INCLUDE_EXT:
                count += 1
                yield p


def chunk_text(txt: str, size: int) -> List[Dict[str, Any]]:
    chunks = []
    start = 0
    L = len(txt)
    while start < L:
        end = min(start + size, L)
        if end < L:
            nl = txt.rfind("\n", start, end)
            if nl > start + int(size * 0.5):
                end = nl
        chunks.append({"start": start, "end": end, "text": txt[start:end]})
        start = end
    return chunks


def file_sha256(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda: f.read(16384), b""):
            h.update(b)
    return h.hexdigest()


def embed_with_retry(client, texts: List[str], max_retries: int = 5):
    for attempt in range(max_retries):
        try:
            resp = client.embeddings.create(model=EMBED_MODEL, input=texts)
            return resp
        except (RateLimitError, APIError, APIConnectionError) as e:
            wait = 2 ** attempt
            print(f"Embedding error: {e}. Retrying in {wait}s...")
            time.sleep(wait)
    raise RuntimeError("Failed embedding after retries.")


# ==========================================================
# MAIN
# ==========================================================

def main():
    start_time = time.time()

    api_key = require_api_key()
    client = OpenAI(api_key=api_key)

    metas: List[Dict[str, Any]] = []
    chunks_text: List[str] = []

    print("🔍 Scanning repository for indexable files...")

    for f in iter_files():
        try:
            raw = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        pieces = chunk_text(raw, CHUNK_SIZE)
        sha = file_sha256(f)

        for idx, ch in enumerate(pieces):
            metas.append({
                "path": str(f),
                "chunk": idx,
                "start": ch["start"],
                "end": ch["end"],
                "hash": sha
            })
            chunks_text.append(ch["text"])

    if not chunks_text:
        print("⚠ No files discovered. Writing empty manifest.")
        (OUT / "manifest.json").write_text(json.dumps({"docs": 0}), encoding="utf-8")
        sys.exit(0)

    print(f"📦 Total chunks collected: {len(chunks_text)}")

    embeddings: List[List[float]] = []

    for i in range(0, len(chunks_text), BATCH_SIZE):
        batch = chunks_text[i:i + BATCH_SIZE]
        print(f"Embedding batch {i//BATCH_SIZE + 1}...")
        resp = embed_with_retry(client, batch)

        if not resp.data:
            raise RuntimeError("Empty embedding response received.")

        embeddings.extend([e.embedding for e in resp.data])

    if not embeddings:
        raise RuntimeError("No embeddings generated.")

    mat = np.asarray(embeddings, dtype="float32")

    if len(mat.shape) != 2:
        raise RuntimeError("Embedding matrix shape invalid.")

    print(f"Vector dimension: {mat.shape[1]}")

    faiss.normalize_L2(mat)
    dim = mat.shape[1]

    index = faiss.IndexFlatIP(dim)
    index.add(mat)

    print("💾 Writing FAISS index...")
    faiss.write_index(index, str(OUT / "faiss.index"))

    with (OUT / "meta.jsonl").open("w", encoding="utf-8") as w:
        for m in metas:
            w.write(json.dumps(m) + "\n")

    manifest = {
        "docs": len(metas),
        "model": EMBED_MODEL,
        "dimension": dim,
        "timestamp": int(time.time())
    }

    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    duration = round(time.time() - start_time, 2)
    print(f"✅ Indexed {len(metas)} chunks in {duration}s")


if __name__ == "__main__":
    main()