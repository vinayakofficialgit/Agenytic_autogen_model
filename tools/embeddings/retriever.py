import os
import json
import faiss
import pathlib
import numpy as np
from typing import List, Dict, Any
from openai import OpenAI

INDEX_DIR = pathlib.Path("agent_output/index")
EMBED_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")

def _require_api_key() -> str:
    key = os.getenv("OPENAI_API_KEY", "")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not set in environment.")
    return key

class RepoRetriever:
    def __init__(self, top_k: int = 6):
        self.top_k = top_k
        self.index = faiss.read_index(str(INDEX_DIR / "faiss.index"))
        self.metas: List[Dict[str, Any]] = []
        with (INDEX_DIR / "meta.jsonl").open("r", encoding="utf-8") as f:
            for line in f:
                self.metas.append(json.loads(line))
        self.client = OpenAI(api_key=_require_api_key())

    def _embed(self, text: str) -> np.ndarray:
        resp = self.client.embeddings.create(model=EMBED_MODEL, input=[text])
        v = np.array(resp.data[0].embedding, dtype="float32")
        v = v.reshape(1, -1)
        faiss.normalize_L2(v)
        return v

    def search(self, query: str) -> List[Dict[str, Any]]:
        if not self.metas:
            return []
        qv = self._embed(query)
        scores, ids = self.index.search(qv, self.top_k)
        results = []
        for score, idx in zip(scores[0], ids[0]):
            if idx < 0:
                continue
            meta = self.metas[idx]
            snippet = self._load_snippet(meta)
            results.append({"score": float(score), "meta": meta, "snippet": snippet})
        return results

    def _load_snippet(self, meta: Dict[str, Any]) -> str:
        p = pathlib.Path(meta["path"])
        try:
            raw = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""
        return raw[meta["start"] : meta["end"]]



# import os, json, pathlib
# from typing import List, Dict, Any

# import faiss
# import numpy as np
# from openai import OpenAI

# INDEX_DIR = pathlib.Path("agent_output/index")
# EMBED_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")

# class RepoRetriever:
#     def __init__(self, top_k: int = 6):
#         self.top_k        faiss.normalize_L2(v.reshape(1, -1))        self.top_k = top_k
#         return v

#     def search(self, query: str) -> List[Dict[str, Any]]:
#         if not self.metas:
#             return []
#         qv = self.embed(query)
#         scores, ids = self.index.search(qv.reshape(1,-1), self.top_k)
#         res = []
#         for score, idx in zip(scores[0], ids[0]):
#             if idx < 0:
#                 continue
#             meta = self.metas[idx]
#             snippet = self._load_snippet(meta)
#             res.append({
#                 "score": float(score),
#                 "meta": meta,
#                 "snippet": snippet
#             })
#         return res

#     def _load_snippet(self, meta: Dict[str,Any]) -> str:
#         p = pathlib.Path(meta["path"])
#         try:
#             raw = p.read_text(encoding="utf-8", errors="ignore")
#             return raw[meta["start"]:meta["end"]]
#         except Exception:
#             return ""
#         self.index = faiss.read_index(str(INDEX_DIR/"faiss.index"))
#         self.metas = []
#         with (INDEX_DIR/"meta.jsonl").open("r", encoding="utf-8") as f:
#             for line in f:
#                 self.metas.append(json.loads(line))
#         self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY",""))

#     def embed(self, text: str) -> np.ndarray:
#         resp = self.client.embeddings.create(model=EMBED_MODEL, input=[text])
#         v = np.array(resp.data[0].embedding, dtype="float32")
