"""Read-only phase-one diagnostics; never import application initialization."""

import importlib.machinery
import os
import stat
import sys


# Top-level module names only; never execute dependency code or path hooks.
DEPENDENCIES = {
    "gui": ("tkinter", "customtkinter"),
    "cloud_scan": ("requests",),
    "active_defense": (
        "psutil", "win32serviceutil", "win32service", "win32event",
        "servicemanager", "win32security", "ntsecuritycon", "win32con",
        "win32api", "win32process", "pythoncom", "win32com",
    ),
}


def capabilities():
    """Describe implemented interfaces, not health or protection effectiveness."""
    return {
        "implementation_phase": 2,
        "commands": ["capabilities", "doctor", "scan", "defense"],
        "output_formats": ["json", "jsonl"], "jsonl_events": ["result"],
        "scan_engines": ["defender", "virustotal"], "test_modes": [],
        "defense_actions": ["status", "start", "stop"],
        "defense_readiness_acknowledgement": False,
        "service_start_requires_snapshot": True, "directory_monitoring_supported": False,
        "unimplemented_commands": ["test"],
        "side_effects": {
            "capabilities": "none", "doctor": "none", "defense status": "read-only local service query",
            "scan virustotal": "explicit --allow-network; full-file upload separately requires --allow-upload",
            "scan defender": "explicit --allow-system-effects; Defender may remediate and use its own network policy",
            "defense start/stop": "explicit --allow-system-effects; start may record/save whitelist and timestamp",
        },
        "invocation": "python cli.py (independent process)",
        "timeout_supported": True, "hard_timeout_supported": False,
        "timeout_commands": ["scan", "defense start", "defense stop"],
        "timeout_default_seconds": 120,
        "cancellation": "cooperative cancellation and bounded client waits; completed external effects are not rolled back",
        "whitelist_policy": {
            "record_seconds": 30, "max_age_seconds": 3600,
            "timestamp_key": "last_whitelist_recorded_at",
            "snapshot_key": "last_whitelist_snapshot_id",
            "applies_to": "non-GUI defense start", "gui_age_gate": False,
            "invalid_or_missing_baseline": "record before startup; failure blocks readiness",
        },
        "limitations": [
            "No test execution, cleanup, service installation, elevation, or running-GUI communication.",
            "Operation budgets are not hard deadlines for blocked filesystem, hashing, SCM, or HTTP I/O.",
            "Stopping a Defender client does not prove the system service stopped scanning or remediation.",
            "SCM RUNNING alone does not confirm the whitelist loaded or protection effectiveness.",
            "Dependency discovery does not prove importability or runtime health.",
            "Doctor inspects verified-local Windows search directories only; archives and custom loaders are skipped.",
            "Doctor does not read configuration/credentials, access network, or verify protection state.",
            "Defender executable presence does not prove service readiness.",
        ],
        "exit_codes": {
            "0": "command completed; inspect evidence, not a safety or protection certificate",
            "2": "invalid arguments", "3": "capability or dependency unavailable",
            "4": "permission or authorization required", "5": "execution error",
            "6": "partial or unconfirmed result", "124": "operation budget expired (not a hard I/O deadline)",
            "130": "cancelled",
        },
    }


def _local_kind(path):
    """Conservatively inspect Windows local paths, without following reparse points."""
    if os.name != "nt":
        return "unchecked"
    try:
        import ctypes
        path = os.path.abspath(path)
        drive, tail = os.path.splitdrive(path)
        if len(drive) != 2 or drive[1] != ":":
            return "unchecked"
        root = drive + os.sep
        # Removable, fixed, and RAM disks only; never probe mapped network drives.
        if ctypes.windll.kernel32.GetDriveTypeW(root) not in (2, 3, 6):
            return "unchecked"
        current = root
        info = os.lstat(current)
        for part in [p for p in tail.split(os.sep) if p]:
            if getattr(info, "st_file_attributes", 0) & 0x400:
                return "unchecked"
            current = os.path.join(current, part)
            info = os.lstat(current)
        if getattr(info, "st_file_attributes", 0) & 0x400:
            return "unchecked"
        if stat.S_ISREG(info.st_mode):
            return "file"
        if stat.S_ISDIR(info.st_mode):
            return "directory"
        return "unchecked"
    except (FileNotFoundError, NotADirectoryError):
        return "missing"
    except Exception:
        return "unchecked"


def _dependency_paths():
    directories = []
    skipped = False
    for entry in sys.path:
        if not isinstance(entry, str):
            skipped = True
            continue
        path = os.path.abspath(entry)
        kind = _local_kind(path)
        if kind == "directory":
            directories.append(path)
        elif kind != "missing":
            # Archives, remote paths, and custom loaders are not inspected.
            skipped = True
    return directories, skipped


def _dependency(name, search=None):
    directories, skipped = _dependency_paths() if search is None else search
    suffixes = (".py", ".pyc") + tuple(importlib.machinery.EXTENSION_SUFFIXES)
    for directory in directories:
        for suffix in suffixes:
            kind = _local_kind(os.path.join(directory, name + suffix))
            if kind == "file":
                return {"status": "discoverable", "runtime_status": "unchecked"}
            skipped = skipped or kind == "unchecked"
        # A directory can also be a namespace package; this is discovery only.
        kind = _local_kind(os.path.join(directory, name))
        if kind == "directory":
            return {"status": "discoverable", "runtime_status": "unchecked"}
        skipped = skipped or kind == "unchecked"
    return {
        "status": "unchecked" if skipped else "unavailable",
        "reason_code": "SEARCH_PATHS_NOT_FULLY_CHECKED" if skipped else "MODULE_NOT_FOUND",
        "runtime_status": "unchecked",
    }


def _permissions():
    if os.name != "nt":
        return {"status": "unsupported", "reason_code": "WINDOWS_ONLY"}
    try:
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return {"status": "unchecked", "reason_code": "TOKEN_CHECK_FAILED"}
    return {
        "status": "checked", "is_admin": is_admin,
        "elevation_requested": False, "admin_required_for_diagnostics": False,
    }


def _defender():
    if os.name != "nt":
        return {"status": "unsupported", "reason_code": "WINDOWS_ONLY"}
    # Match the existing scanner's location without importing or constructing it.
    program_files = os.environ.get("ProgramFiles", "C:/Program Files")
    if not os.path.isabs(program_files):
        return {"status": "unchecked", "reason_code": "INVALID_PROGRAM_FILES"}
    path = os.path.join(program_files, "Windows Defender", "MpCmdRun.exe")
    kind = _local_kind(path)
    if kind == "unchecked":
        return {"status": "unchecked", "reason_code": "LOCAL_PATH_NOT_VERIFIED"}
    present = kind == "file"
    return {
        "status": "present" if present else "unavailable",
        "location_scope": "existing_scanner_path_only",
        "runtime_status": "unchecked",
        "service_status": "unchecked",
        "scan_started": False,
    }


def doctor():
    """Perform local observations only; missing optional modules are findings."""
    search = _dependency_paths()
    dependencies = {
        group: {name: _dependency(name, search) for name in names}
        for group, names in DEPENDENCIES.items()
    }
    return {
        "python": {
            "version": ".".join(str(part) for part in sys.version_info[:3]),
            "minimum": "3.8", "supported": sys.version_info >= (3, 8),
        },
        "platform": {
            "name": sys.platform,
            "windows_features": "supported" if os.name == "nt" else "unsupported",
        },
        "permissions": _permissions(),
        "dependencies": dependencies,
        "engines": {
            "defender": _defender(),
            "virustotal": {
                "status": "unchecked", "reason_code": "NETWORK_AND_CONFIG_NOT_READ",
            },
            "active_defense": {
                "status": "unchecked", "reason_code": "NO_INSTANCE_COMMUNICATION",
            },
        },
        "configuration": "not_read",
        "application_version": "unchecked",
        "limitations": capabilities()["limitations"],
    }
