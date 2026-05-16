# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for mxrestore-gui.

Build on macOS:
    pip install -r requirements.txt
    pyinstaller mxrestore-gui.spec

Output: dist/mxrestore-gui.app   (open this in Finder)

We bundle:
  - sparserestore/   from ../mxrestore/sparserestore (single source of truth)
  - payload/PersistenceHelper_Embedded   from ../mxrestore/payload/  (CI artifact)
  - mxconfig.plist   from ../mxhelper/mxconfig.plist
so this .app stays in sync with the CLI without copying files at git level.
"""
from pathlib import Path
import gzip
import platform
import tempfile

HERE = Path(SPECPATH).resolve()
ROOT = HERE.parent
MXRESTORE = ROOT / "mxrestore"
MXHELPER = ROOT / "mxhelper"

# Gzip the helper at build time. Otherwise PyInstaller's auto-classifier sees
# the Mach-O magic bytes, treats it as a "binary" rather than data, and tries
# to ad-hoc codesign it (`codesign -s -`). That fails with
#   "internal error in Code Signing subsystem"
# because the file already carries TrollStore's CoreTrust-bypass fakesign,
# which macOS codesign does not understand. The .gz extension hides it.
HELPER_SRC = MXRESTORE / "payload" / "PersistenceHelper_Embedded"
HELPER_GZ_DIR = Path(tempfile.gettempdir()) / "mxrestore-gui-build"
HELPER_GZ_DIR.mkdir(parents=True, exist_ok=True)
HELPER_GZ = HELPER_GZ_DIR / "PersistenceHelper_Embedded.gz"
with open(HELPER_SRC, "rb") as _fi, gzip.open(HELPER_GZ, "wb") as _fo:
    _fo.write(_fi.read())

datas = [
    (str(HELPER_GZ), "payload"),
    (str(MXHELPER / "mxconfig.plist"), "."),
]
# Bundle sparserestore as a real package next to the entry script so the
# `from sparserestore import ...` works inside the frozen app.
datas += [(str(MXRESTORE / "sparserestore"), "sparserestore")]

# Bundle the configs/ directory if it exists so the GUI can offer user
# alternative plist files from a dropdown.
_configs_dir = MXHELPER / "configs"
if _configs_dir.exists():
    datas += [(str(_configs_dir), "configs")]

a = Analysis(
    ["mxrestore_gui.py"],
    pathex=[str(MXRESTORE)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "_payload",
        "sparserestore",
        "sparserestore.backup",
        "sparserestore.mbdb",
        "pymobiledevice3",
        "pymobiledevice3.lockdown",
        "pymobiledevice3.services.diagnostics",
        "pymobiledevice3.services.installation_proxy",
        "pymobiledevice3.services.mobilebackup2",
        "pymobiledevice3.exceptions",
        "ttkbootstrap",
        "bpylist2",
    ],
    hookspath=[],
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
    name="mxrestore-gui",
    debug=False,
    strip=False,
    upx=False,
    console=False,        # windowed app, no terminal
    target_arch=None,
)

coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False, upx=False,
    name="mxrestore-gui",
)

# Wrap into a real .app bundle on macOS.
if platform.system() == "Darwin":
    app = BUNDLE(
        coll,
        name="mxrestore-gui.app",
        icon=None,
        bundle_identifier="com.vavacci.mxrestore-gui",
        info_plist={
            "CFBundleName": "mxrestore-gui",
            "CFBundleDisplayName": "TrollRestoreX",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "1",
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
            # We don't need network/camera/etc.; pymobiledevice3 talks over USB.
        },
    )
