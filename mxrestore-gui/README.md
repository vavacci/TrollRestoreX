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

PyInstaller automatically ad-hoc signs every Mach-O inside the bundle
(`codesign -s -`), which is **all Apple Silicon needs to launch the binary**.
No Developer ID required.

#### Why `PersistenceHelper_Embedded` is shipped as `.gz`

The .spec gzips the helper payload at build time. Without that, PyInstaller's
Mach-O auto-classifier treats the file as a "binary" and tries to ad-hoc
codesign it. macOS `codesign` then errors out with
`internal error in Code Signing subsystem` because the file already carries
TrollStore's CoreTrust-bypass fakesign — a layout `codesign` doesn't
understand. Renaming to `.gz` skips the classifier, and `mxrestore_gui.py`
decompresses in memory at use-site.

### Distributing it (the easy way — what everyone in the community does)

Just send `dist/mxrestore-gui.app` to whoever needs it (zip it first, AirDrop
loses the bundle structure otherwise):

```sh
cd dist && zip -r mxrestore-gui.zip mxrestore-gui.app
```

**On the recipient's Mac**, depending on how they got the .app:

| How they got it | First-open ritual |
|---|---|
| AirDrop / U盘 / scp | Double-click. Done. |
| Downloaded from a browser, email, Slack, etc. | Right-click the .app → **Open** → confirm "Open" in the dialog. **Once.** Then double-click normally. |
| Already tried double-click and got blocked | `xattr -dr com.apple.quarantine /path/to/mxrestore-gui.app`  then double-click. |

The "developer cannot be verified" warning is just the quarantine flag macOS
attaches to anything downloaded from the internet. It's a **one-tap bypass**,
not a wall. Every TrollStore/jailbreak tool out there ships exactly this way.

### Optional: Developer ID + notarization

You only need this if you want recipients to be able to **double-click on
first launch with no right-click and no warning**. For this audience (people
already using TrollStore) it's typically not worth the $99/yr Apple Developer
account + the notarization roundtrip.

If you do want it later:

```sh
codesign --deep --force --options runtime \
  --sign "Developer ID Application: YOUR NAME (TEAMID)" \
  dist/mxrestore-gui.app
xcrun notarytool submit dist/mxrestore-gui.app --keychain-profile "AC_PASSWORD" --wait
xcrun stapler staple dist/mxrestore-gui.app
```

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
