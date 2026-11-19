# -*- mode: python ; coding: utf-8 -*-
"""Standalone Windows update helper; build before viruswise.spec."""
from pathlib import Path

ROOT = Path(SPECPATH).resolve()
a = Analysis(
    [str(ROOT / "updater.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[],
    hiddenimports=["win32timezone"],
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
    name="VirusWiseUpdater",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    uac_admin=False,
    contents_directory="_internal",
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="VirusWiseUpdater")
