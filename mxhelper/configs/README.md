# mxhelper/configs/

Drop additional `*.plist` files in here to make them selectable at install time
from both the CLI and the GUI **without rebuilding the helper binary**.

## How the selection takes effect

| Selected | What happens at install time | What MXAutoFlow on device reads |
|---|---|---|
| `Default` (the file at `mxhelper/mxconfig.plist`, embedded into the helper at CI build time) | Nothing extra pushed. | `__DATA,__mxconfig` section in the binary. |
| One of `configs/*.plist` | Host pushes it into `Tips.app/mxconfig.plist` via the same MobileBackup CVE that drops the helper binary. | The bundle file (disk override wins over embedded section). |

The override mechanism lives in:
- Host: [`../../mxrestore/_payload.py`](../../mxrestore/_payload.py) — `build_backup_files`'s `extra_bundle_files`
- Device: [`../MXAutoFlow.m`](../MXAutoFlow.m) — `loadConfig` tries bundle first, falls back to embedded section

## Usage

CLI:
```sh
python3 mxrestore/mxrestore.py --system-app Tips --config mxhelper/configs/livestream-only.plist
```

GUI: pick from the "使用哪个 config" dropdown, or click `…` for an arbitrary file.

## Plist format

Same as the default `mxhelper/mxconfig.plist`. Required key is `Apps`, an array
of dicts with `URL` (required), `Name` (optional), `SHA256` (optional).

```xml
<dict>
    <key>Apps</key>
    <array>
        <dict>
            <key>URL</key>      <string>https://your-cdn/app.ipa</string>
            <key>Name</key>     <string>YourApp</string>
            <key>SHA256</key>   <string>0123...64 hex chars or empty</string>
        </dict>
    </array>
</dict>
```

## Adding your own

Just drop `your-config.plist` here. No rebuild needed for either CLI or GUI —
the GUI rescans this directory at startup, the CLI takes any path via `--config`.

> Note: if you ship the GUI as a frozen `.app` (PyInstaller), the contents of
> this directory at build time are bundled into the `.app` and the runtime
> dropdown is fixed to that snapshot. To add configs to a built .app you must
> rebuild it.
