import requests

def is_offline():
    try:
        requests.get("https://www.virustotal.com", timeout=2)
        return False
    except: return True
