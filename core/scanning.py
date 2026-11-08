"""Shared, explicitly authorized scanners (stdlib-only at import time).

No configuration or environment API key is read here. Authorization precedes
path access, hashing, config inspection and optional dependency imports.
Timeouts are cooperative: file/directory I/O, DNS and requests cannot be forcibly
interrupted. Requests have bounded connect/read inactivity timeouts, not a hard
wall-clock limit. Cancelling a client does not cancel remote VT analysis or the
Defender service. No quarantine/remediation is performed by this module; however
Defender itself may remediate and therefore requires system-effects consent.
"""

import hashlib
import math
import os
import threading
import time
from uuid import uuid4

BASE_URL = "https://www.virustotal.com/api/v3"
MAX_UPLOAD_SIZE = 30 * 1024 * 1024


class ScanError(ValueError):
    """Preflight error: code plus CLI exit_code (2 args, 4 auth, 3 capability)."""

    def __init__(self, message, code="invalid_argument", exit_code=2):
        super().__init__(message)
        self.code = code
        self.exit_code = exit_code


class _Stopped(Exception):
    def __init__(self, status):
        self.status = status


def _authorize(engine, allow_network, allow_upload, allow_system_effects):
    if engine == 'vt' and allow_network is not True:
        raise ScanError("VirusTotal requires explicit network authorization",
                        'authorization_required', 4)
    if engine == 'defender' and allow_system_effects is not True:
        raise ScanError("Defender may remediate files; explicit system-effects authorization is required",
                        'authorization_required', 4)
    if any(type(value) is not bool for value in
           (allow_network, allow_upload, allow_system_effects)):
        raise ScanError("Authorization flags must be booleans")
    if engine == 'defender' and allow_upload:
        raise ScanError("Upload authorization is only applicable to VirusTotal")


def _duration(value):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value <= 0):
        raise ScanError("timeout must be a positive finite number")
    return float(value)


def _checkpoint(cancel, deadline):
    if cancel is not None and cancel.is_set():
        raise _Stopped('cancelled')
    if deadline is not None and time.monotonic() >= deadline:
        raise _Stopped('timeout')


def _remaining(deadline, maximum):
    if deadline is None:
        return maximum
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _Stopped('timeout')
    return min(maximum, remaining)


def _result(task, path, status='unknown', verdict='unknown', engine='VirusTotal'):
    return dict(scan_id=task['scan_id'], item_id=uuid4().hex, path=path,
                status=status, verdict=verdict, engine=engine, error='',
                remediation_state='not_attempted', can_quarantine=False)


def _hash_file(path, cancel, deadline):
    # Same SHA256 lookup as the GUI, streamed so cancellation can be observed.
    digest = hashlib.sha256()
    with open(path, 'rb') as file:
        while True:
            _checkpoint(cancel, deadline)
            chunk = file.read(1024 * 1024)
            _checkpoint(cancel, deadline)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _load_requests():
    try:
        import requests
    except ImportError as exc:
        raise ScanError("VirusTotal requires the optional requests dependency",
                        'capability_unavailable', 3) from exc
    return requests


def _request(requests, method, url, cancel, deadline, maximum=30, **kwargs):
    _checkpoint(cancel, deadline)
    response = None
    try:
        response = getattr(requests, method)(
            url, timeout=_remaining(deadline, maximum), allow_redirects=False, **kwargs)
        _checkpoint(cancel, deadline)
        status = response.status_code
        payload = response.json() if status == 200 else {}
        _checkpoint(cancel, deadline)
        return status, payload
    except requests.exceptions.Timeout as exc:
        _checkpoint(cancel, deadline)
        raise _Stopped('timeout') from exc
    finally:
        if response is not None:
            response.close()


def scan_vt_file(path, task, whitelist_hashes, poll_attempts, logger=None):
    """Use the existing GUI VT result/threshold/upload contract.

    task: scan_id, cancel (Event), config (already loaded mapping with apikey and
    sensitive), allow_network=True, allow_upload (bool). Optional timeout seconds
    and/or absolute monotonic deadline constrain this call. No task/config reads
    beyond consent occur before authorization. GUI retains its own whitelist and
    calls with 20 polls for one file or 6 for each directory file.

    Raises ScanError for authorization/arguments/missing optional dependencies.
    Operational errors are returned as status failed/timeout/cancelled; absent VT
    data stays unknown and exhausted analysis polls stay pending, never clean.
    """
    _authorize('vt', task.get('allow_network', False),
               task.get('allow_upload', False), False)
    if type(poll_attempts) is not int or poll_attempts < 0:
        raise ScanError("poll_attempts must be a nonnegative integer")
    cancel = task.get('cancel')
    deadline = task.get('deadline')
    if deadline is not None and (isinstance(deadline, bool)
                                or not isinstance(deadline, (int, float))
                                or not math.isfinite(deadline)):
        raise ScanError("deadline must be a finite monotonic timestamp")
    if task.get('timeout') is not None:
        local_deadline = time.monotonic() + _duration(task['timeout'])
        deadline = local_deadline if deadline is None else min(deadline, local_deadline)
    result = _result(task, path)
    try:
        _checkpoint(cancel, deadline)
        api_key = task['config'].get('apikey', '').strip()
        if not api_key:
            raise ValueError("API Key为空")
        if not os.path.isfile(path):
            raise ValueError("文件不存在或不是普通文件")
        _checkpoint(cancel, deadline)
        h = _hash_file(path, cancel, deadline)
        result['sha256'] = h
        _checkpoint(cancel, deadline)
        if h in whitelist_hashes:
            result.update(status='completed', verdict='whitelisted', type='白名单跳过（未经扫描）')
            return result
        _checkpoint(cancel, deadline)
        requests = _load_requests()
        headers = {'x-apikey': api_key}
        status, payload = _request(requests, 'get', f"{BASE_URL}/files/{h}",
                                   cancel, deadline, headers=headers)
        uploaded = False
        if status == 404:
            if not task.get('allow_upload', False):
                result['error'] = "VT未收录；未授权上传，仅查询哈希，未判定"
                return result
            if os.path.getsize(path) > MAX_UPLOAD_SIZE:
                result['error'] = "VT未收录且文件超过30MB；不上传，未判定"
                return result
            with open(path, 'rb') as file:
                if os.fstat(file.fileno()).st_size > MAX_UPLOAD_SIZE:
                    result['error'] = "文件已增大至超过30MB；不上传，未判定"
                    return result
                _checkpoint(cancel, deadline)
                status, payload = _request(
                    requests, 'post', f"{BASE_URL}/files", cancel, deadline,
                    maximum=60, headers=headers,
                    files={'file': (os.path.basename(path), file)})
            if status != 200:
                raise ValueError(f"VT上传失败 HTTP {status}")
            analysis_id = payload.get('data', {}).get('id')
            if not isinstance(analysis_id, str) or not analysis_id:
                raise ValueError("VT未返回有效分析ID")
            uploaded = True
            for _ in range(poll_attempts):
                _checkpoint(cancel, deadline)
                wait = _remaining(deadline, 5)
                if cancel is None:
                    time.sleep(wait)
                else:
                    cancel.wait(wait)
                _checkpoint(cancel, deadline)
                status, payload = _request(
                    requests, 'get', f"{BASE_URL}/analyses/{analysis_id}",
                    cancel, deadline, headers=headers)
                if status != 200:
                    raise ValueError(f"VT分析查询失败 HTTP {status}")
                attributes = payload.get('data', {}).get('attributes', {})
                if attributes.get('status') == 'completed':
                    stats = attributes.get('stats')
                    break
            else:
                result.update(status='pending', error='VT分析尚未完成，等待超时；未判定')
                return result
        elif status == 200:
            stats = payload.get('data', {}).get('attributes', {}).get('last_analysis_stats')
        else:
            raise ValueError(f"VT查询失败 HTTP {status}")
        _checkpoint(cancel, deadline)
        if (not isinstance(stats, dict) or 'malicious' not in stats or 'suspicious' not in stats
                or any(type(v) is not int or v < 0 for v in stats.values())):
            raise ValueError("VT统计数据缺失或格式无效，未判定")
        if sum(stats.get(k, 0) for k in ('malicious', 'suspicious', 'harmless', 'undetected')) == 0:
            result['error'] = "VT未提供有效引擎判定，不能视为安全"
            return result
        malicious, suspicious = stats['malicious'], stats['suspicious']
        threshold = 1 if task['config'].get('sensitive') else 6
        flagged = malicious >= threshold
        result.update(status='completed', verdict='malicious' if flagged else 'not_flagged',
                      malicious=malicious, suspicious=suspicious, can_quarantine=flagged,
                      type=('恶意' if flagged else '未达到报警阈值') + ('(上传分析)' if uploaded else ''))
    except _Stopped as exc:
        result.update(status=exc.status, error=(
            '已停止客户端等待；不代表远端分析已停止' if exc.status == 'cancelled'
            else '协作式等待超时；未判定，不代表远端分析已停止'))
    except ScanError:
        raise
    except Exception:
        # Request/header exceptions can embed the API key; never serialize them.
        result.update(status='failed', error='VT操作失败：文件、请求或响应异常；未判定',
                      error_code='vt_operation_failed')
    if logger is not None:
        logger(f"VT: {path}: {result['status']} / {result['verdict']}")
    return result


def _files(path, cancel, deadline, errors):
    def onerror(exc):
        errors.append(str(exc))
    # os.walk does not follow directory symlinks. Check between directories AND
    # entries, without first accumulating the entire tree in memory.
    for root, dirs, names in os.walk(path, onerror=onerror, followlinks=False):
        _checkpoint(cancel, deadline)
        for name in names:
            _checkpoint(cancel, deadline)
            yield os.path.join(root, name)
        _checkpoint(cancel, deadline)


def scan_path(path, engine, allow_network=False, allow_upload=False,
              allow_system_effects=False, api_key='', timeout=120,
              cancel_event=None, on_event=None, *, whitelist_hashes=(),
              sensitive=False, poll_attempts=None, logger=None):
    """Scan a file/directory with explicit vt or defender, never auto-detection.

    Returns {scan_id, engine, path, status, verdict, results, counts, message}.
    status describes execution, NOT cleanliness; verdict is malicious, not_flagged
    or unknown. Whitelisted/unscanned/empty/Defender-only results remain unknown.
    Per-item dictionaries preserve the GUI schema. ScanError is preflight only;
    other operational outcomes use completed/partial/failed/unknown/pending/
    timeout/cancelled/unavailable. No exit-code equivalence to clean is implied.

    on_event receives dictionaries with type=start/result/complete and scan_id;
    result events include result, complete events include status. Callbacks run
    synchronously and should not block or raise. Deadline is shared by traversal,
    hashing, lookup, upload and polls; in-flight blocking I/O is cooperative only.
    """
    if not isinstance(engine, str) or engine.lower() not in ('vt', 'virustotal', 'defender'):
        raise ScanError("engine must be vt (virustotal) or defender")
    engine = 'vt' if engine.lower() in ('vt', 'virustotal') else 'defender'
    _authorize(engine, allow_network, allow_upload, allow_system_effects)
    timeout = _duration(timeout)
    if engine == 'vt' and (not isinstance(api_key, str) or not api_key.strip()):
        raise ScanError("VirusTotal requires an explicitly supplied API key")
    if poll_attempts is not None and (type(poll_attempts) is not int or poll_attempts < 0):
        raise ScanError("poll_attempts must be a nonnegative integer")
    try:
        path = os.fspath(path)
    except TypeError as exc:
        raise ScanError("path must be a file or directory path") from exc
    if not isinstance(path, str) or not path.strip() or '\x00' in path:
        raise ScanError("path must be a nonempty text path")
    cancel = cancel_event if cancel_event is not None else threading.Event()
    deadline = time.monotonic() + timeout
    task = dict(scan_id=uuid4().hex, cancel=cancel, deadline=deadline,
                allow_network=allow_network, allow_upload=allow_upload,
                config={'apikey': api_key, 'sensitive': sensitive})
    results, errors = [], []
    status, message = 'completed', ''

    def emit(kind, **data):
        if on_event is not None:
            on_event(dict(type=kind, scan_id=task['scan_id'], **data))

    try:
        _checkpoint(cancel, deadline)
        is_file = os.path.isfile(path)
        is_directory = False if is_file else os.path.isdir(path)
        _checkpoint(cancel, deadline)
        if not is_file and not is_directory:
            raise ScanError("path does not exist or is not a regular file/directory")
        emit('start', path=path, engine=engine)
        _checkpoint(cancel, deadline)
        if engine == 'defender':
            from core.defender import DefenderScanner
            scanner = DefenderScanner(offline_only=False, force_use=True,
                                      logger=logger, timeout=_remaining(deadline, timeout),
                                      deadline=deadline)
            if not scanner.available:
                raise ScanError("Windows Defender MpCmdRun.exe is unavailable",
                                'capability_unavailable', 3)
            _checkpoint(cancel, deadline)
            scanner.timeout = _remaining(deadline, timeout)
            report = scanner.scan_drive(path, cancel_event=cancel)
            status = report['status']
            message = report.get('message') or report.get('error') or ''
            item = _result(task, path, status=status, engine='Defender')
            item.update(returncode=report.get('returncode'), error=report.get('error') or '',
                        remediation_state=report['remediation_state'], type=message)
            results.append(item)
            emit('result', result=item)
        else:
            attempts = poll_attempts if poll_attempts is not None else (20 if is_file else 6)
            paths = (path,) if is_file else _files(path, cancel, deadline, errors)
            for file_path in paths:
                _checkpoint(cancel, deadline)
                item = scan_vt_file(file_path, task, whitelist_hashes, attempts, logger)
                results.append(item)
                emit('result', result=item)
                if item['status'] in ('cancelled', 'timeout'):
                    status = item['status']
                    break
            else:
                _checkpoint(cancel, deadline)
                if is_file:
                    status = results[0]['status']
                elif errors or any(item['status'] != 'completed' for item in results):
                    status = 'partial'
            if errors:
                message = '扫描不完整，部分目录无法读取：' + '; '.join(errors)
    except _Stopped as exc:
        status = exc.status
        message = '客户端协作式等待已停止；不能据此认定远端或系统服务已停止扫描'
    except OSError as exc:
        status, message = 'failed', str(exc)
    counts = {key: sum(item['verdict'] == key for item in results)
              for key in ('malicious', 'not_flagged', 'whitelisted', 'unknown')}
    verdict = ('malicious' if counts['malicious'] else
               'not_flagged' if results and status == 'completed'
               and counts['not_flagged'] == len(results) else 'unknown')
    outcome = dict(scan_id=task['scan_id'], engine=engine, path=path, status=status,
                   verdict=verdict, results=results, counts=counts, message=message)
    emit('complete', status=status)
    return outcome
