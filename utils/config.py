import math
import os
import sys
import tempfile
import threading
import time
from contextlib import contextmanager

_config_lock = threading.RLock()
_RECORDING_KEYS = ('last_whitelist_recorded_at', 'last_whitelist_snapshot_id')
UPDATE_CHECK_INTERVAL = 24 * 60 * 60
_PROTECTED_METADATA_KEYS = _RECORDING_KEYS + ('last_update_check_at',)
_DEFAULTS = {
    'apikey': '', 'sensitive': False, 'auto_process': False, 'virustotal': True,
    'windows_defender': False, 'windows_defender_offline_only': True,
    'windows_defender_force': False, 'ad_enabled': False,
    'delete_protection': True, 'batch_delete_threshold': 5,
    'modify_protection': True, 'monitor_dirs': [], 'wl_by_name': False,
    'wl_by_hash': True, 'ad_warned_on_enable': False,
    'autoruns_prompted': False, 'theme': 'default',
    'last_whitelist_recorded_at': None, 'last_whitelist_snapshot_id': '',
    'last_update_check_at': None,
}


def config_path():
    # Match utils.paths exactly, without its import-time mkdir side effects.
    override = globals().get('CONFIG_FILE')
    if override is not None:
        return os.fspath(override)
    base = os.path.dirname(sys.executable if getattr(sys, 'frozen', False)
                           else os.path.abspath(__file__))
    return os.path.join(base, 'data', 'config.txt')


def _config_lines(path):
    try:
        with open(path, 'r', encoding='utf-8-sig') as stream:
            return stream.readlines()
    except UnicodeDecodeError:
        # Older GUI versions wrote with the Windows locale encoding. New saves
        # use UTF-8, but reading an existing local-codepage config must still work.
        with open(path, 'r') as stream:
            return stream.readlines()


def _read_config(path, strict):
    config = dict(_DEFAULTS, monitor_dirs=[])
    try:
        for line in _config_lines(path):
            line = line.strip()
            if not line or '=' not in line:
                continue
            key, value = line.split('=', 1)
            if key in ('last_whitelist_recorded_at', 'last_update_check_at'):
                try:
                    stamp = float(value)
                    config[key] = stamp if math.isfinite(stamp) else None
                except ValueError:
                    config[key] = None
            elif key == 'monitor_dirs':
                config[key] = [d for d in value.split('|') if d]
            elif isinstance(_DEFAULTS.get(key), bool):
                config[key] = value == '1'
            elif key == 'batch_delete_threshold':
                try:
                    config[key] = int(value)
                except ValueError:
                    if strict:
                        raise
            else:
                config[key] = value
    except FileNotFoundError:
        pass
    except (OSError, UnicodeError, ValueError):
        if strict:
            raise
    return config


def load_config(*, path=None, strict=False):
    with _config_lock:
        return _read_config(path or config_path(), strict)


@contextmanager
def _write_lock(path):
    """Lock a stable sidecar, not the atomically replaced configuration inode."""
    with _config_lock:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(os.fspath(path) + '.lock', 'a+b') as lock:
            if os.name == 'nt':
                import msvcrt
                lock.seek(0, os.SEEK_END)
                if lock.tell() == 0:
                    lock.write(b'0')
                    lock.flush()
                deadline = time.monotonic() + 5
                while True:
                    lock.seek(0)
                    try:
                        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise TimeoutError('Configuration writer lock timed out')
                        time.sleep(0.05)
                try:
                    yield
                finally:
                    try:
                        lock.seek(0)
                        msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        # Closing the handle also releases the lock. A cleanup
                        # error must not turn an already committed save into failure.
                        pass
            else:
                import fcntl
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    try:
                        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass


def _atomic_save(config, path, before_replace=None):
    lines = []
    for key, value in config.items():
        if key == 'monitor_dirs':
            value = '|'.join(value)
        elif isinstance(value, bool):
            value = '1' if value else '0'
        elif value is None:
            value = ''
        text = str(value)
        if '\n' in key or '\r' in key or '=' in key or '\n' in text or '\r' in text:
            raise ValueError('Configuration keys and values must be single-line')
        lines.append(f'{key}={text}\n')
    fd, temporary = tempfile.mkstemp(prefix='.config-', dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='') as stream:
            stream.writelines(lines)
            stream.flush()
            os.fsync(stream.fileno())
        if before_replace is not None:
            before_replace()
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_config(config, *, path=None, strict=False):
    """Save preferences, retaining disk-owned metadata; return success.

    strict=True propagates errors. Recording and update-check timestamps are
    changed only by their dedicated commits, never by a cached GUI dictionary.
    """
    path = path or config_path()
    try:
        with _write_lock(path):
            current = _read_config(path, True)
            merged = dict(current, **config)
            for key in _PROTECTED_METADATA_KEYS:
                merged[key] = current[key]
            _atomic_save(merged, path)
        return True
    except (OSError, UnicodeError, ValueError) as exc:
        if strict:
            raise
        print(f'Configuration save failed: {exc}')
        return False


def commit_whitelist_recording(recorded_at, snapshot_id, *, path=None, before_commit=None):
    """Recorder-only commit, called AFTER durable whitelist save and >=30s.

    No cached preference dict is written back. Failures propagate to callers.
    """
    if isinstance(recorded_at, bool) or not isinstance(recorded_at, (int, float)) or not math.isfinite(recorded_at) or recorded_at <= 0:
        raise ValueError('Invalid recording success timestamp')
    if not isinstance(snapshot_id, str) or len(snapshot_id) != 64 or any(c not in '0123456789abcdef' for c in snapshot_id):
        raise ValueError('Invalid whitelist snapshot identity')
    path = path or config_path()
    with _write_lock(path):
        config = _read_config(path, True)
        config['last_whitelist_recorded_at'] = recorded_at
        config['last_whitelist_snapshot_id'] = snapshot_id
        _atomic_save(config, path, before_replace=before_commit)
    return True


def claim_update_check(checked_at=None, *, force=False, path=None):
    """Atomically reserve an attempt; return (claimed, last_attempt_timestamp).

    Failed HTTP attempts also count. Call this before networking, off the GUI
    thread. A future timestamp (clock rollback) is repaired by a new attempt.
    No stale preferences or whitelist metadata are written back.
    """
    path = path or config_path()
    with _write_lock(path):
        # Take the clock inside the lock: queued workers must not mistake a
        # slightly newer writer's timestamp for a system clock rollback.
        checked_at = time.time() if checked_at is None else checked_at
        if (isinstance(checked_at, bool) or not isinstance(checked_at, (int, float))
                or not math.isfinite(checked_at) or checked_at <= 0):
            raise ValueError('Invalid update-check timestamp')
        config = _read_config(path, True)
        previous = config['last_update_check_at']
        if (not force and previous is not None and 0 < previous <= checked_at
                and checked_at - previous < UPDATE_CHECK_INTERVAL):
            return False, previous
        config['last_update_check_at'] = checked_at
        _atomic_save(config, path)
    return True, checked_at
