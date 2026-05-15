# mxrestore-gui

Tk-based GUI wrapper around the same MobileBackup CVE-2024-44252 flow that
[`../mxrestore/mxrestore.py`](../mxrestore/mxrestore.py) runs from the CLI.

**Architectural rule**: this directory does **not** duplicate any logic from the CLI.
At runtime (and at PyInstaller-bundle time) it pulls:

| What | From |
|---|---|
| `sparserestore/` (CVE payload crafting) | `../mxrestore/sparserestore/` |
| `PersistenceHelper_Embedded` (custom helper) | `../mxrestore/payload/` |
| `mxconfig.plist` (Apps array) | `../mxhelper/mxconfig.plist` |

One helper rebuild → both CLI and GUI updated. Nothing in `mxrestore/`,
`mxhelper/`, or `.github/workflows/build.yml` was touched by this addition.

## Run from source

```sh
cd mxrestore-gui
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 mxrestore_gui.py
```

Tested on macOS 14 with Python 3.11.

## Build .app for distribution

```sh
cd mxrestore-gui
source .venv/bin/activate
pyinstaller mxrestore-gui.spec
open dist/mxrestore-gui.app
```

The .app contains a frozen Python runtime + all deps + the helper payload +
`mxconfig.plist`. ~30-50 MB total.

### Code signing & notarization (for distribution outside your own Mac)

PyInstaller bundles ship unsigned by default; Gatekeeper will block them on
other Macs. To distribute:

```sh
# 1. Sign every .dylib + Mach-O inside the bundle (PyInstaller drops many)
codesign --deep --force --options runtime \
  --sign "Developer ID Application: YOUR NAME (TEAMID)" \
  --entitlements entitlements.plist \
  dist/mxrestore-gui.app

# 2. Submit for notarization
xcrun notarytool submit dist/mxrestore-gui.app \
  --keychain-profile "AC_PASSWORD" --wait

# 3. Staple the ticket
xcrun stapler staple dist/mxrestore-gui.app
```

If you don't need to share the .app off your own machine, skip this — just
right-click → Open the first time.

## What the GUI lets you do

1. Pick a removable system app to overwrite (default: Tips)
2. "从设备读取" — refresh the list from the connected device
3. "开始安装" — push the backup + reboot
4. After reboot, tap the swapped icon → device-side `MXAutoFlow` auto-installs
   TrollStore + every IPA in `mxconfig.plist`

If your helper binary is opa334's vanilla `PersistenceHelper_Embedded`
(no `MXAutoFlow`), the GUI prints fallback `apple-magnifier://install?url=…`
links you can open manually in Safari on the iPhone.

## Differences from the CLI (`../mxrestore/mxrestore.py`)

Nothing functional — same CVE payload, same version gate (iOS 15.0–16.7 RC,
17.0), same helper binary. Just:
- Tk window instead of `click` prompts
- Background thread so the UI stays responsive
- System app list pulled from `InstallationProxyService` and shown as a
  Combobox

## Credits

Forked from [seregonwar/TrollRestore-GuiVersion](https://github.com/seregonwar/TrollRestore-GuiVersion),
which is itself a fork of [JJTech0130/TrollRestore](https://github.com/JJTech0130/TrollRestore).
Heavy modifications to align with this repo's mxhelper flow (multi-IPA,
custom helper, system-app target).
