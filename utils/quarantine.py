import os, zipfile
from utils.paths import QUARANTINE_DIR
def quarantine(path):
    try:
        name = os.path.basename(path)
        zip_path = os.path.join(QUARANTINE_DIR, name + ".zip")
        with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(path, arcname=name)
        os.remove(path)
        return True
    except: return False