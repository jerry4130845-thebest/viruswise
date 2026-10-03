import hashlib, mmap
def get_file_hash(path):
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            sha256.update(mm)
            mm.close()
        return sha256.hexdigest()
    except: return None