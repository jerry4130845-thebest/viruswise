import os, sys
from datetime import datetime

CRASH_LOG = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "crash.log")

def safe_get_base_dir():
    return os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__))

BASE_DIR = safe_get_base_dir()
DATA_DIR = os.path.join(BASE_DIR, "data")
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
WHITELIST_FILE = os.path.join(DATA_DIR, "whitelist.json")
PROFILES_DIR = os.path.join(DATA_DIR, "profiles")
CONFIG_FILE = os.path.join(DATA_DIR, "config.txt")
THEME_WARM_YELLOW = os.path.join(DATA_DIR, "warm_yellow.json")

for dir_path in [DATA_DIR, QUARANTINE_DIR, PROFILES_DIR]:
    os.makedirs(dir_path, exist_ok=True)