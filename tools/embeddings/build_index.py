#!/usr/bin/env python3
import os, pathlib, json, hashlib, sys
from typing import List, Dict, Any

# pip install openai faiss-cpu
import faiss
from openai import OpenAI

ROOT = pathlib.Path(".").resolve()
OUT  = pathlib.Path("agent_output/index")
OUT.mkdir(parents=True, exist_ok=True)

EMBED_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
CHUNK_SIZE  = int(os.getenv("RAG_CHUNK_SIZE", "1500"))
INCLUDE_EXT = {".yaml", ".yml", ".tf", ".java", ".xml", ".properties", ".md"}
EXCLUDE_DIRS = {".git", ".github", "target", "node_modules", ".venv", "__pycache__"}

def iter_files():
    for p in ROOT.rglob("*"):
        if p.is_file():
            if any(ex in p.parts for ex in EXCLUDE_DIRS): 
                continue
            if p.name == "Dockerfile" or p.suffix in INCLUDE_EXT:
                yield p

def chunk_text(txt: str, size: int) -> List[Dict[str, Any]]:
    chunks = []
    start = 0
    while start < len(txt):
        end = min(start + size, len(txt))
        # try to break on newline
        if end < len(txt):
            nl = txt.rfind("\n", start, end)
            if nl > start + int(size*0.5):
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

def main():
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY",""))
    metas = []
    vectors = []

    # Collect docs
    for f in iter_files():
        try:
            raw = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        chunks = chunk_text(raw, CHUNK_SIZE)
        sha = file_sha256(f)
        for idx, ch in enumerate(chunks):
            metas.append({
                "path": str(f),
                "chunk": idx,
                "start": ch["start"],
                "end": ch["end"],
                "hash": sha,
            })
            vectors.append(ch["text"])

    if not vectors:
        print("No files to index; exiting.")
        (OUT/"manifest.json").write_text(json.dumps({"docs":0}), encoding="utf-8")
        sys.exit(0)

    # Embed in batches
    embs = []
    B = 256
    for i in range(0, len(vectors), B):
        batch = vectors[i:i+B]
        resp = client.embeddings.create(model=EMBED_MODEL, input=batch)
        embs.extend([e.embedding for e in resp.data])

    import numpy as np
    mat = np.array(embs, dtype="float32")
    dim = mat.shape[1]
    index = faiss.IndexFlatIP(dim)
    # Normalize for cosine similarity via dot product
    faiss.normalize_L2(mat)
    index.add(mat)

    faiss.write_index(index, str(OUT/"faiss.index"))
    with (OUT/"meta.jsonl").open("w", encoding="utf-8") as w:
        for m in metas:
            w.write(json.dumps(m) + "\n")

    (OUT/"manifest.json").write_text(json.dumps({"docs":len(metas), "model":EMBED_MODEL}), encoding="utf-8")
    print(f"Indexed {len(metas)} chunks into {OUT}")

if __name__ == "__main__":
    main()