import hashlib

def bad_hash(s):
    return hashlib.md5(s.encode()).hexdigest()
