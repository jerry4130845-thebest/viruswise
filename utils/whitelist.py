import os, json
from utils.paths import WHITELIST_FILE
def load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE, 'r') as f: return json.load(f)
        except: return []
    return []

def save_whitelist(whitelist):
    try:
        with open(WHITELIST_FILE, 'w') as f: json.dump(whitelist, f, indent=2)
    except: pass