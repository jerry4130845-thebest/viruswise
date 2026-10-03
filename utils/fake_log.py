import os

def is_fake_log(filepath):
    try:
        if not os.path.exists(filepath) or os.path.getsize(filepath) == 0: return True
        with open(filepath, 'rb') as f: header = f.read(1024)
        if not header: return True
        if header.startswith(b'MZ') or header.startswith(b'PK') or header.startswith(b'\x7fELF') or header.startswith(b'%PDF') or header.startswith(b'\xff\xd8\xff') or header.startswith(b'\x89PNG'): return True
        try:
            text_content = header.decode('utf-8', errors='ignore')
            if text_content.strip():
                log_indicators = ['[', ']', ':', 'error', 'warn', 'info', 'debug', 'log', '|', '-', '2024', '2025', '2026']
                if any(indicator.lower() in text_content.lower() for indicator in log_indicators): return False
            return True
        except: return True
    except: return False
