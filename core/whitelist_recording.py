"""Shared explicit recorder for GUI and non-GUI callers (no hourly policy here).

Importing this module performs no filesystem/process/service operations and uses
only stdlib. Recording trusts observed executable hashes, NOT a malware scan.
Call only on a user-approved, known-clean baseline with enforcement paused.
Results are dictionaries; errors never imply a completed recording or readiness.
"""
import hashlib
import math
import os
import threading
import time

MIN_RECORDING_SECONDS = 30.0
_record_lock = threading.Lock()


class RecordingError(RuntimeError):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.exit_code = {'cancelled': 130, 'timeout': 124, 'invalid_duration': 2,
                          'invalid_timeout': 2, 'dependency_missing': 3}.get(code, 5)


def _emit(callback, event, **fields):
    if callback is not None:
        try:
            callback(dict(event=event, **fields))
        except Exception:
            # A display callback must not alter persistence semantics.
            pass


def _check(cancel_event, deadline):
    if cancel_event is not None and cancel_event.is_set():
        raise RecordingError('cancelled', 'Whitelist recording cancelled')
    if time.monotonic() >= deadline:
        raise RecordingError('timeout', 'Whitelist recording timed out')


def _enumerate_processes():
    try:
        import psutil
    except ImportError as exc:
        raise RecordingError("dependency_missing", "psutil is required for recording") from exc
    return psutil.process_iter(['pid', 'name', 'exe'])


def _hash_executable(path, check):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        before = os.fstat(stream.fileno())
        while True:
            check()
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise OSError('Executable changed while hashing')
    return digest.hexdigest()


def record_whitelist(duration=30, timeout=120, cancel_event=None, on_event=None,
                     *, config_path=None, whitelist_path=None, guard=None):
    """Observe processes for >=30 monotonic seconds, save, then commit timestamp.

    guard (optional) must raise if it becomes unsafe to learn, e.g. service starts
    concurrently. It is checked before every enumeration and before committing.
    Cancellation/deadline checks occur during hashing and before persistence.
    The final atomic timestamp replacement is the success commit point; after it
    the result is success, not a retroactive cancellation. Partial item failures
    are returned and emitted; no successfully hashed observations is total failure.
    """
    errors = []
    seen_errors = set()
    error_count = 0
    observed = {}
    added = 0
    started = time.monotonic()
    locked = False

    def report(code, message, pid=None, path=None):
        nonlocal error_count
        key = (code, pid, path, message)
        if key in seen_errors:
            return
        seen_errors.add(key)
        error_count += 1
        item = dict(code=code, error=message, pid=pid, path=path)
        if len(errors) < 256:
            errors.append(item)
        _emit(on_event, 'item_error', **item)

    try:
        try:
            duration = float(duration)
        except (TypeError, ValueError, OverflowError) as exc:
            raise RecordingError('invalid_duration', 'Duration must be numeric') from exc
        try:
            timeout = float(timeout)
        except (TypeError, ValueError, OverflowError) as exc:
            raise RecordingError('invalid_timeout', 'Timeout must be numeric') from exc
        if not math.isfinite(duration):
            raise RecordingError('invalid_duration', 'Recording duration must be finite')
        duration = max(MIN_RECORDING_SECONDS, duration)
        if not math.isfinite(timeout) or timeout <= duration:
            raise RecordingError('invalid_timeout', 'Timeout must exceed the >=30 second recording duration')
        deadline = started + timeout
        _check(cancel_event, deadline)
        locked = _record_lock.acquire(blocking=False)
        if not locked:
            raise RecordingError('recording_busy', 'Another recording is already in progress')
        if guard is not None:
            guard()
        from utils.config import commit_whitelist_recording
        from utils.whitelist import load_whitelist, save_whitelist, snapshot_identity
        try:
            entries = load_whitelist(path=whitelist_path, strict=True)
        except (OSError, ValueError, TypeError) as exc:
            entries = []
            report('previous_baseline_unreadable', str(exc))
        existing = {item['hash'].lower() for item in entries if item.get('hash')}
        _emit(on_event, 'recording_started', duration=duration)
        # Measure the actual observation interval, excluding setup/loading time.
        observation_started = time.monotonic()
        while time.monotonic() - observation_started < duration:
            _check(cancel_event, deadline)
            if guard is not None:
                guard()
            try:
                processes = _enumerate_processes()
                for proc in processes:
                    _check(cancel_event, deadline)
                    pid = getattr(proc, 'pid', None)
                    path = None
                    try:
                        info = proc.info
                        path = info.get('exe')
                        name = info.get('name')
                        if not path or not name:
                            raise ValueError('Process executable/name is unavailable')
                        # Re-hash new paths once per recording, not merely each PID.
                        if path in observed:
                            continue
                        digest = _hash_executable(path, lambda: _check(cancel_event, deadline))
                        observed[path] = digest
                        if digest not in existing:
                            entries.append(dict(name=name, pid=pid, path=path,
                                                hash=digest, time=time.time()))
                            existing.add(digest)
                            added += 1
                        _emit(on_event, 'process_recorded', pid=pid, path=path, name=name)
                    except RecordingError:
                        raise
                    except Exception as exc:
                        report('process_unreadable', str(exc), pid, path)
            except RecordingError:
                raise
            except Exception as exc:
                # Enumeration failure is not hidden by previously loaded entries.
                report('enumeration_failed', str(exc))
                raise RecordingError('enumeration_failed', str(exc)) from exc
            elapsed = time.monotonic() - observation_started
            _emit(on_event, 'recording_progress', elapsed=elapsed, duration=duration,
                  observed=len(observed), added=added)
            wait = min(1.0, max(0.0, duration - elapsed), max(0.0, deadline - time.monotonic()))
            if cancel_event is not None:
                cancel_event.wait(wait)
            else:
                time.sleep(wait)
        _check(cancel_event, deadline)
        if not observed:
            raise RecordingError('empty_recording', 'No executable could be hashed; baseline was not saved')
        if guard is not None:
            guard()
        identity = snapshot_identity(entries)
        if save_whitelist(entries, path=whitelist_path, strict=True) is not True:
            raise RecordingError('save_failed', 'Whitelist save did not report success')
        _check(cancel_event, deadline)
        if snapshot_identity(load_whitelist(path=whitelist_path, strict=True, require_hashes=True)) != identity:
            raise RecordingError('baseline_changed', 'Whitelist changed during recording commit')
        if guard is not None:
            guard()
        _check(cancel_event, deadline)
        recorded_at = time.time()

        def before_commit():
            # Recheck after waiting for the cross-process config lock and after
            # temporary-file flush, immediately before the success replacement.
            _check(cancel_event, deadline)
            if snapshot_identity(load_whitelist(path=whitelist_path, strict=True, require_hashes=True)) != identity:
                raise RecordingError('baseline_changed', 'Whitelist changed before timestamp commit')
            if guard is not None:
                guard()
            _check(cancel_event, deadline)

        if commit_whitelist_recording(recorded_at, identity, path=config_path,
                                      before_commit=before_commit) is not True:
            raise RecordingError('timestamp_save_failed', 'Recording timestamp was not committed')
        result = dict(ok=True, ready=False, code='recorded', exit_code=0, entries=entries,
                      recorded_at=recorded_at, snapshot_id=identity, added=added,
                      observed=len(observed), elapsed=time.monotonic() - observation_started,
                      errors=errors, error_count=error_count)
        _emit(on_event, 'recording_complete', recorded_at=recorded_at,
              snapshot_id=identity, observed=len(observed), added=added)
        return result
    except Exception as exc:
        code = getattr(exc, 'code', 'recording_failed')
        result = dict(ok=False, ready=False, code=code, exit_code=getattr(exc, 'exit_code', 5),
                      error=str(exc), entries=[], recorded_at=None, errors=errors,
                      error_count=error_count, elapsed=time.monotonic() - started)
        _emit(on_event, 'recording_failed', code=code, error=str(exc))
        return result
    finally:
        if locked:
            _record_lock.release()
