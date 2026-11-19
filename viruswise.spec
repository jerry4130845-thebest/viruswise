# -*- mode: python ; coding: utf-8 -*-
"""Windows onedir build; never collect the user's runtime data directories."""
import ast
import json
import re
from pathlib import Path

from PyInstaller.config import CONF
from PyInstaller.utils.hooks import collect_data_files, copy_metadata

ROOT = Path(SPECPATH).resolve()
ENTRYPOINT = ROOT / "main.py"
helper_bundle = Path(CONF["distpath"]) / "VirusWiseUpdater"
helper = helper_bundle / "VirusWiseUpdater.exe"
helper_runtime = helper_bundle / "_internal"
if not helper.is_file() or not (helper_runtime / "base_library.zip").is_file():
    raise SystemExit("Build updater.spec first, using the same --distpath.")

# Extract a checked-in literal without importing GUI code or reading user data.
tree = ast.parse((ROOT / "ui" / "theme.py").read_text(encoding="utf-8"))
theme = next(
    ast.literal_eval(node.value)
    for node in tree.body
    if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "WARM_YELLOW_THEME_JSON"
            for target in node.targets)
)
json.loads(theme)
static_dir = Path(CONF["workpath"]) / "viruswise-static"
static_dir.mkdir(parents=True, exist_ok=True)
theme_file = static_dir / "warm_yellow.json"
theme_file.write_text(theme, encoding="utf-8")

# Read the same release version as the GUI without importing configuration.
version_tree = ast.parse((ROOT / "versions.py").read_text(encoding="utf-8"))
version = next(
    ast.literal_eval(node.value)
    for node in version_tree.body
    if isinstance(node, ast.Assign)
    and any(isinstance(target, ast.Name) and target.id == "CURRENT_VERSION"
            for target in node.targets)
)
if not re.fullmatch(r"[0-9]{1,12}(?:\.[0-9]{1,12}){2}", version):
    raise SystemExit("CURRENT_VERSION must be a three-component version.")
manifest = static_dir / "viruswise-release.json"
manifest.write_text(json.dumps({"version": version, "protocol": 1}), encoding="utf-8")

# Standard hooks handle customtkinter/Tcl, pythoncom/pywintypes DLLs and psutil.
# win10toast needs its default icon and distribution metadata for pkg_resources.
datas = [(str(theme_file), "resources"), (str(manifest), ".")]
datas += collect_data_files("win10toast", includes=["data/python.ico"])
datas += copy_metadata("win10toast")
hiddenimports = [
    "cli", "core.active_defense", "core.defense_control", "core.diagnostics",
    "core.scanning", "core.whitelist_recording", "core.defender", "core.notifier",
    "ui.app", "ui.theme", "servicemanager", "win32serviceutil", "win32service",
    "win32event", "win32api", "win32security", "win32process", "win32gui",
    "win32evtlog", "win32evtlogutil", "win32timezone", "ntsecuritycon",
    "pythoncom", "pywintypes", "win32com.client", "psutil", "psutil._psutil_windows",
    "tkinter", "customtkinter", "PIL.Image", "PIL.ImageTk", "requests",
    "win10toast", "pkg_resources",
]

a = Analysis(
    [str(ENTRYPOINT)],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="VirusWise",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    uac_admin=False,
    # Only this runtime subtree is managed by the updater; data remains at the root.
    contents_directory="_internal",
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    [(helper.name, str(helper), "EXECUTABLE")],
    [(str(Path("updater-runtime") / path.relative_to(helper_runtime)), str(path), "DATA")
     for path in sorted(helper_runtime.rglob("*")) if path.is_file()],
    strip=False,
    upx=False,
    name="VirusWise",
)
