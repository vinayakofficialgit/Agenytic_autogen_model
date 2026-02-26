#!/usr/bin/env python3
import os
import json
import faiss
import pathlib
import numpy as np
import time
from typing import List, Dict, Any
from openai import OpenAI
from openai import APIError, RateLimitError, APIConnectionError

INDEX_DIR = pathlib.Path("agent_output/index")
EMBED_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")


def _require_api_key() -> str:
    key = os.getenv("OPENAI_API_KEY", "")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not set.")
    return key


class RepoRetriever:
    def __init__(self, top_k: int = 6):
        self.top_k = top_k
        self.disabled = False

        index_path = INDEX_DIR / "faiss.index"
        meta_path = INDEX_DIR / "meta.jsonl"

        if not index_path.exists() or not meta_path.exists():
            print("⚠ RAG disabled — index files missing.")
            self.disabled = True
            return

        try:
            self.index = faiss.read_index(str(index_path))
            self.metas: List[Dict[str, Any]] = []
            with meta_path.open("r", encoding="utf-8") as f:
                for line in f:
                    self.metas.append(json.loads(line))

            if self.index.ntotal != len(self.metas):
                raise RuntimeError("Index/meta size mismatch.")

            self.client = OpenAI(api_key=_require_api_key())
            print(f"RAG ready. Index dim={self.index.d}, vectors={self.index.ntotal}")

        except Exception as e:
            print(f"⚠ RAG initialization failed: {e}")
            self.disabled = True

    def _embed(self, text: str) -> np.ndarray:
        for attempt in range(5):
            try:
                resp = self.client.embeddings.create(
                    model=EMBED_MODEL,
                    input=[text]
                )
                v = np.array(resp.data[0].embedding, dtype="float32").reshape(1, -1)
                faiss.normalize_L2(v)
                if v.shape[1] != self.index.d:
                    raise RuntimeError(
                        f"Embedding dimension mismatch: "
                        f"query={v.shape[1]}, index={self.index.d}"
                    )
                return v
            except (RateLimitError, APIError, APIConnectionError) as e:
                wait = 2 ** attempt
                print(f"Embedding retry {attempt+1}: {e}")
                time.sleep(wait)
        raise RuntimeError("Embedding failed after retries.")

    def search(self, query: str) -> List[Dict[str, Any]]:
        if self.disabled:
            return []
        if not self.metas:
            return []

        try:
            qv = self._embed(query)
            scores, ids = self.index.search(qv, self.top_k)

            results = []
            for score, idx in zip(scores[0], ids[0]):
                if idx < 0:
                    continue
                meta = self.metas[idx]
                snippet = self._load_snippet(meta)
                results.append({
                    "score": float(score),
                    "meta": meta,
                    "snippet": snippet
                })
            return results

        except Exception as e:
            print(f"⚠ RAG search failed: {e}")
            return []

    def _load_snippet(self, meta: Dict[str, Any]) -> str:
        try:
            p = pathlib.Path(meta["path"]).resolve()
            repo_root = pathlib.Path(".").resolve()
            if not str(p).startswith(str(repo_root)):
                return ""
            raw = p.read_text(encoding="utf-8", errors="ignore")
            return raw[meta["start"]:meta["end"]]
        except Exception:
            return ""




# import os
# import json
# import faiss
# import pathlib
# import numpy as np
# from typing import List, Dict, Any
# from openai import OpenAI

# INDEX_DIR = pathlib.Path("agent_output/index")
# EMBED_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")

# def _require_api_key() -> str:
#     key = os.getenv("OPENAI_API_KEY", "")
#     if not key:
#         raise RuntimeError("OPENAI_API_KEY is not set in environment.")
#     return key

# class RepoRetriever:
#     def __init__(self, top_k: int = 6):
#         self.top_k = top_k
#         self.index = faiss.read_index(str(INDEX_DIR / "faiss.index"))
#         self.metas: List[Dict[str, Any]] = []
#         with (INDEX_DIR / "meta.jsonl").open("r", encoding="utf-8") as f:
#             for line in f:
#                 self.metas.append(json.loads(line))
#         self.client = OpenAI(api_key=_require_api_key())

#     def _embed(self, text: str) -> np.ndarray:
#         resp = self.client.embeddings.create(model=EMBED_MODEL, input=[text])
#         v = np.array(resp.data[0].embedding, dtype="float32")
#         v = v.reshape(1, -1)
#         faiss.normalize_L2(v)
#         return v

#     def search(self, query: str) -> List[Dict[str, Any]]:
#         if not self.metas:
#             return []
#         qv = self._embed(query)
#         scores, ids = self.index.search(qv, self.top_k)
#         results = []
#         for score, idx in zip(scores[0], ids[0]):
#             if idx < 0:
#                 continue
#             meta = self.metas[idx]
#             snippet = self._load_snippet(meta)
#             results.append({"score": float(score), "meta": meta, "snippet": snippet})
#         return results

#     def _load_snippet(self, meta: Dict[str, Any]) -> str:
#         p = pathlib.Path(meta["path"])
#         try:
#             raw = p.read_text(encoding="utf-8", errors="ignore")
#         except Exception:
#             return ""
#         return raw[meta["start"] : meta["end"]]



# # import os, json, pathlib
# # from typing import List, Dict, Any

# # import faiss
# # import numpy as np
# # from openai import OpenAI

# # INDEX_DIR = pathlib.Path("agent_output/index")
# # EMBED_MODEL = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")

# # class RepoRetriever:
# #     def __init__(self, top_k: int = 6):
# #         self.top_k        faiss.normalize_L2(v.reshape(1, -1))        self.top_k = top_k
# #         return v

# #     def search(self, query: str) -> List[Dict[str, Any]]:
# #         if not self.metas:
# #             return []
# #         qv = self.embed(query)
# #         scores, ids = self.index.search(qv.reshape(1,-1), self.top_k)
# #         res = []
# #         for score, idx in zip(scores[0], ids[0]):
# #             if idx < 0:
# #                 continue
# #             meta = self.metas[idx]
# #             snippet = self._load_snippet(meta)
# #             res.append({
# #                 "score": float(score),
# #                 "meta": meta,
# #                 "snippet": snippet
# #             })
# #         return res

# #     def _load_snippet(self, meta: Dict[str,Any]) -> str:
# #         p = pathlib.Path(meta["path"])
# #         try:
# #             raw = p.read_text(encoding="utf-8", errors="ignore")
# #             return raw[meta["start"]:meta["end"]]
# #         except Exception:
# #             return ""
# #         self.index = faiss.read_index(str(INDEX_DIR/"faiss.index"))
# #         self.metas = []
# #         with (INDEX_DIR/"meta.jsonl").open("r", encoding="utf-8") as f:
# #             for line in f:
# #                 self.metas.append(json.loads(line))
# #         self.client = OpenAI(api_key=os.getenv("OPENAI_API_KEY",""))

# #     def embed(self, text: str) -> np.ndarray:
# #         resp = self.client.embeddings.create(model=EMBED_MODEL, input=[text])
# #         v = np.array(resp.data[0].embedding, dtype="float32")
