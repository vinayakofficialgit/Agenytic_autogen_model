"""
Patch Ranker
Selects best patch from candidates.
"""

def rank_patches(patches):
    return sorted(patches, key=lambda x: x["confidence"], reverse=True)