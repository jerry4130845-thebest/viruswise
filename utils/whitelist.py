"""Lazy whitelist storage; strict callers never confuse unreadable with empty."""
import hashlib
import json
import os
import sys
import tempfile


def whitelist_path():
    override = globals().get('WHITELIST_FILE')
    if override is not None:
        return os.fspath(override)
    base = os.path.dirname(sys.executable if getattr(sys, 'frozen', False)
                           else os.path.abspath(__file__))
    return os.path.join(base, 'data', 'whitelist.json')


def validate_whitelist(entries, *, require_hashes=False):
    if not isinstance(entries, list):
        raise ValueError('Whitelist must be a list')
    hashes = 0
    for index, item in enumerate(entries):
        if not isinstance(item, dict) or not isinstance(item.get('name'), str) or not item['name']:
            raise ValueError(f'Invalid whitelist entry {index}: missing name')
        if item.get('path') is not None and not isinstance(item['path'], str):
            raise ValueError(f'Invalid whitelist entry {index}: path')
        digest = item.get('hash')
        if digest is not None:
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdefABCDEF' for c in digest):
                raise ValueError(f'Invalid whitelist entry {index}: SHA256')
            hashes += 1
    if require_hashes and not hashes:
        raise ValueError('Whitelist contains no hashed executable baseline')
    return entries


def snapshot_identity(entries):
    validate_whitelist(entries, require_hashes=True)
    return hashlib.sha256(json.dumps(entries, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode('utf-8')).hexdigest()


def load_whitelist(*, path=None, strict=False, require_hashes=False):
    try:
        with open(path or whitelist_path(), 'r', encoding='utf-8') as stream:
            return validate_whitelist(json.load(stream), require_hashes=require_hashes)
    except (OSError, UnicodeError, ValueError, TypeError):
        if strict:
            raise
        return []


def save_whitelist(whitelist, *, path=None, strict=False):
    """Atomic durable save. Returns bool; strict=True propagates all failures."""
    temporary = None
    try:
        validate_whitelist(whitelist)
        payload = json.dumps(whitelist, indent=2, ensure_ascii=True, allow_nan=False)
        path = path or whitelist_path()
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.whitelist-', dir=directory)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        return True
    except (OSError, UnicodeError, ValueError, TypeError):
        if strict:
            raise
        return False
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)
