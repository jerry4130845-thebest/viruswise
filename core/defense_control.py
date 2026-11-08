"""Explicit control of the installed VirusWiseActiveDefense service only.

No installation, elevation, ACL changes, or import-time platform dependencies.
All public results are JSON-compatible dicts with ok/ready/code/exit_code.
RUNNING is never a readiness acknowledgement. Until an authenticated service
snapshot acknowledgement protocol exists, ready is always False (exit 6 for
start). This is intentionally unsuitable as permission to run destructive tests.

A baseline is handed directly to SCM StartService as an immutable JSON argument,
not via a GUI/SYSTEM profile or a user-writable service file. SCM SERVICE_START
access is the authority boundary. An old installed service may ignore arguments;
that is another reason SCM RUNNING alone cannot prove protection.
"""
import json
import math
import os
import time

SERVICE_NAME = 'VirusWiseActiveDefense'
BASELINE_ARGUMENT = '--viruswise-baseline-v1'
MAX_HANDOFF_BYTES = 65536
_STATE_NAMES = {1: 'stopped', 2: 'start_pending', 3: 'stop_pending',
                4: 'running', 5: 'continue_pending', 6: 'pause_pending', 7: 'paused'}


class DefenseControlError(RuntimeError):
    def __init__(self, code, message, exit_code=5, next_action=None):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code
        self.next_action = next_action


def _result(ok, code, **fields):
    exit_code = fields.pop("exit_code", 0 if ok else 5)
    return dict(ok=ok, ready=False, code=code, exit_code=exit_code, **fields)


def _failure(exc):
    if isinstance(exc, KeyboardInterrupt):
        return _result(False, 'cancelled', exit_code=130, error='Operation interrupted')
    if isinstance(exc, DefenseControlError):
        return _result(False, exc.code, exit_code=exc.exit_code, error=str(exc),
                       next_action=exc.next_action)
    code = getattr(exc, 'winerror', None)
    if code is None and exc.args:
        code = exc.args[0]
    name, exit_code = {5: ('access_denied', 4), 1060: ('not_installed', 3)}.get(
        code if isinstance(code, int) else None, ('service_error', 5))
    return _result(False, name, exit_code=exit_code, error='Service operation failed',
                   next_action='Check service availability and permissions; no elevation was attempted')


def _emit(callback, event, **fields):
    if callback is not None:
        try:
            callback(dict(event=event, **fields))
        except Exception:
            pass


def _check(cancel_event, deadline):
    if cancel_event is not None and cancel_event.is_set():
        raise DefenseControlError('cancelled', 'Operation cancelled', 130)
    if time.monotonic() >= deadline:
        raise DefenseControlError('timeout', 'Service operation timed out', 124)


def _deadline(timeout):
    try:
        timeout = float(timeout)
    except (TypeError, ValueError, OverflowError) as exc:
        raise DefenseControlError('invalid_timeout', 'Timeout must be numeric', 2) from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise DefenseControlError('invalid_timeout', 'Timeout must be positive and finite', 2)
    return time.monotonic() + timeout


class _Service:
    def __init__(self, action='query'):
        self.action = action
        self.manager = None
        self.handle = None

    def __enter__(self):
        if os.name != 'nt':
            raise DefenseControlError('unsupported_platform', 'Service control requires Windows', 3)
        try:
            import win32service
        except ImportError as exc:
            raise DefenseControlError('dependency_missing', 'pywin32 is required for service control', 3) from exc
        self.api = win32service
        access = win32service.SERVICE_QUERY_STATUS
        if self.action == 'start':
            access |= win32service.SERVICE_START
        elif self.action == 'stop':
            access |= win32service.SERVICE_STOP
        try:
            self.manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
            self.handle = win32service.OpenService(self.manager, SERVICE_NAME, access)
            return self
        except Exception as exc:
            self.__exit__(None, None, None)
            code = getattr(exc, 'winerror', None)
            if code is None and exc.args:
                code = exc.args[0]
            if code == 1060:
                raise DefenseControlError('not_installed', 'VirusWiseActiveDefense is not installed', 3,
                                          'Ask an administrator to provision the service separately; this command never installs it') from exc
            if code == 5:
                raise DefenseControlError('access_denied', 'Service access denied; no elevation was attempted', 4) from exc
            raise

    def __exit__(self, *_):
        for handle in (self.handle, self.manager):
            if handle is not None:
                self.api.CloseServiceHandle(handle)
        self.handle = self.manager = None

    def query(self):
        info = self.api.QueryServiceStatusEx(self.handle)
        return dict(service_state=_STATE_NAMES.get(info['CurrentState'], 'unknown'),
                    process_id=info.get('ProcessId'),
                    service_exit_code=info.get('Win32ExitCode', 0))

    def start(self, payload):
        self.api.StartService(self.handle, [BASELINE_ARGUMENT, payload])

    def stop(self):
        self.api.ControlService(self.handle, self.api.SERVICE_CONTROL_STOP)


def _baseline():
    from utils.config import load_config
    from utils.whitelist import load_whitelist, snapshot_identity
    try:
        config = load_config(strict=True)
        stamp = config.get('last_whitelist_recorded_at')
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)) or not math.isfinite(stamp):
            return dict(valid=False, reason='missing_or_malformed_timestamp')
        age = time.time() - stamp
        if not 0 <= age <= 3600:
            return dict(valid=False, reason='future_timestamp' if age < 0 else 'expired', age=age)
        entries = load_whitelist(strict=True, require_hashes=True)
        identity = snapshot_identity(entries)
        recorded_identity = config.get('last_whitelist_snapshot_id')
        if recorded_identity != identity:
            return dict(valid=False, reason='snapshot_changed')
        return dict(valid=True, reason='fresh', entries=entries, snapshot_id=identity,
                    recorded_at=stamp, age=age)
    except (OSError, ValueError, TypeError) as exc:
        return dict(valid=False, reason='baseline_unreadable', error='Baseline/configuration could not be validated')


def _baseline_summary(baseline):
    return {key: value for key, value in baseline.items() if key != 'entries'}


def _require_stopped():
    with _Service() as service:
        info = service.query()
    if info['service_state'] != 'stopped':
        raise DefenseControlError('baseline_refresh_requires_stop',
                                  'Cannot learn a baseline while the service is active',
                                  next_action='Explicitly stop defense, then retry start on a known-clean baseline')


def _unconfirmed(info, baseline, *, start_requested=False):
    return _result(False, 'readiness_unconfirmed', exit_code=6, **info,
                   baseline=_baseline_summary(baseline), start_requested=start_requested,
                   error='SCM state does not acknowledge the loaded whitelist snapshot',
                   next_action='Do not run tests requiring protection; verify an authenticated service snapshot acknowledgement')


def status():
    """Read-only query; ready=False even when SCM reports RUNNING."""
    try:
        with _Service() as service:
            info = service.query()
        baseline = _baseline_summary(_baseline())
        return _result(True, 'readiness_unconfirmed' if info['service_state'] == 'running' else 'status',
                       **info, baseline=baseline, readiness='unconfirmed')
    except Exception as exc:
        return _failure(exc)


def start(timeout=120, cancel_event=None, on_event=None, allow_system_effects=False):
    """Record/reuse baseline, request start; never claim acknowledged readiness.

    No implicit stop/restart, install, elevation or learning under enforcement.
    After StartService has been sent, cancellation/timeout never silently stops
    the service: start_requested=True tells the caller it may still be running.
    """
    requested = False
    recording = None
    try:
        if allow_system_effects is not True:
            raise DefenseControlError('authorization_required', 'Start requires allow_system_effects=True', 4)
        deadline = _deadline(timeout)
        _check(cancel_event, deadline)
        with _Service('start') as service:
            info = service.query()
            baseline = _baseline()
            state = info['service_state']
            if state == 'running':
                if not baseline['valid']:
                    return _result(False, 'baseline_refresh_requires_stop', **info,
                                   baseline=_baseline_summary(baseline),
                                   error='Baseline is stale/unreadable; refusing to learn under active enforcement',
                                   next_action='Explicitly stop defense, then retry start on a known-clean baseline')
                return _unconfirmed(info, baseline)
            if state != 'stopped':
                raise DefenseControlError('service_busy', f'Service is {state}; no implicit stop/restart',
                                          next_action='Wait for a stable stopped state or explicitly stop defense')
            if not baseline['valid']:
                _emit(on_event, 'baseline_required', **_baseline_summary(baseline))
                from core.whitelist_recording import record_whitelist
                recording = record_whitelist(timeout=deadline - time.monotonic(),
                                             cancel_event=cancel_event, on_event=on_event,
                                             guard=_require_stopped)
                if not recording['ok']:
                    return dict(recording, ready=False, start_requested=False,
                                next_action='Resolve recording failure before starting defense')
                baseline = _baseline()
                if not baseline['valid'] or baseline.get('snapshot_id') != recording.get('snapshot_id'):
                    raise DefenseControlError('baseline_changed', 'Saved baseline changed before service start')
            else:
                _emit(on_event, 'baseline_reused', **_baseline_summary(baseline))
            _check(cancel_event, deadline)
            # Recheck the same service handle immediately before the start call.
            if service.query()['service_state'] != 'stopped':
                raise DefenseControlError('service_state_changed', 'Service became active; refusing concurrent start')
            payload = json.dumps(dict(version=1, entries=baseline['entries'],
                                      snapshot_id=baseline['snapshot_id'],
                                      recorded_at=baseline['recorded_at']),
                                 sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)
            if len(payload.encode('utf-8')) > MAX_HANDOFF_BYTES:
                raise DefenseControlError('baseline_too_large', 'Baseline exceeds bounded SCM handoff size',
                                          next_action='Provision a protected, acknowledged snapshot transport; no profile fallback is allowed')
            _check(cancel_event, deadline)
            requested = True  # Submission may succeed even if the call is interrupted.
            service.start(payload)
            _emit(on_event, 'service_start_requested', snapshot_id=baseline['snapshot_id'])
            while True:
                _check(cancel_event, deadline)
                info = service.query()
                if info['service_state'] == 'running':
                    result = _unconfirmed(info, baseline, start_requested=True)
                    if recording is not None:
                        result['recording'] = {key: value for key, value in recording.items() if key != 'entries'}
                    return result
                if info['service_state'] == 'stopped':
                    raise DefenseControlError('service_start_failed',
                                              f"Service stopped during startup (exit {info['service_exit_code']})")
                if cancel_event is not None:
                    cancel_event.wait(min(0.25, max(0.0, deadline - time.monotonic())))
                else:
                    time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
    except (Exception, KeyboardInterrupt) as exc:
        result = _failure(exc)
        result['start_requested'] = requested
        if requested:
            result['next_action'] = 'Query status; service may still start. Stop only through an explicit stop request'
        return result


def stop(timeout=120, cancel_event=None, on_event=None, allow_system_effects=False):
    """Explicitly request stop of the installed service; never install/elevate."""
    requested = False
    try:
        if allow_system_effects is not True:
            raise DefenseControlError('authorization_required', 'Stop requires allow_system_effects=True', 4)
        deadline = _deadline(timeout)
        _check(cancel_event, deadline)
        with _Service('stop') as service:
            info = service.query()
            if info['service_state'] == 'stopped':
                return _result(True, 'already_stopped', **info, stop_requested=False)
            if info['service_state'] != 'stop_pending':
                _check(cancel_event, deadline)
                requested = True  # Preserve possible effects if SCM call is interrupted.
                service.stop()
                _emit(on_event, 'service_stop_requested')
            while True:
                _check(cancel_event, deadline)
                info = service.query()
                if info['service_state'] == 'stopped':
                    return _result(True, 'stopped', **info, stop_requested=requested)
                wait = min(0.25, max(0.0, deadline - time.monotonic()))
                if cancel_event is not None:
                    cancel_event.wait(wait)
                else:
                    time.sleep(wait)
    except (Exception, KeyboardInterrupt) as exc:
        result = _failure(exc)
        result['stop_requested'] = requested
        return result
