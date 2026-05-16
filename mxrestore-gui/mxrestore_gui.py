#!/usr/bin/env python3
"""
mxrestore-gui — Tk wrapper around the same MobileBackup CVE-2024-44252 flow
that mxrestore/mxrestore.py runs from the CLI.

Design rule: this file MUST NOT duplicate logic from mxrestore.py. It imports
sparserestore from ../mxrestore and reuses the same PersistenceHelper_Embedded
payload + the same mxconfig.plist Apps array, so a single helper rebuild
propagates to both CLI and GUI.

Stripped from seregonwar's upstream GUI:
  - Backup/Restore/Remove buttons (they called sparserestore.delete_app /
    perform_backup / fetch_logs which don't exist in our vendored sparserestore)
  - Network fetch of PersistenceHelper_Embedded (we ship our own)
  - User-app list (we overwrite SYSTEM apps like Tips)
"""
import gzip
import os
import platform
import plistlib
import sys
import threading
import traceback
import urllib.parse
import webbrowser
from pathlib import Path
from tkinter import StringVar, SUNKEN, filedialog, messagebox

# Resolve paths whether running in source tree or frozen by PyInstaller.
# In dev: read raw helper from ../mxrestore/payload/.
# Frozen: read PersistenceHelper_Embedded.gz (the .spec gzips it at build
# time so PyInstaller's auto-classifier doesn't try to ad-hoc codesign the
# iOS CoreTrust-bypass binary, which macOS codesign refuses).
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys._MEIPASS)
    PAYLOAD_PATH = BASE_DIR / "payload" / "PersistenceHelper_Embedded.gz"
    DEFAULT_CONFIG_PATH = BASE_DIR / "mxconfig.plist"
    CONFIGS_DIR = BASE_DIR / "configs"
else:
    HERE = Path(__file__).resolve().parent
    sys.path.insert(0, str(HERE.parent / "mxrestore"))
    PAYLOAD_PATH = HERE.parent / "mxrestore" / "payload" / "PersistenceHelper_Embedded"
    DEFAULT_CONFIG_PATH = HERE.parent / "mxhelper" / "mxconfig.plist"
    CONFIGS_DIR = HERE.parent / "mxhelper" / "configs"


def load_helper_payload() -> bytes:
    if not PAYLOAD_PATH.exists():
        raise RuntimeError(f"Payload missing: {PAYLOAD_PATH}\nBuild mxhelper first.")
    data = PAYLOAD_PATH.read_bytes()
    if PAYLOAD_PATH.suffix == ".gz":
        data = gzip.decompress(data)
    return data


def list_available_configs() -> list[tuple[str, Path | None]]:
    """Return [(label, path_or_None), ...]. The first entry is always the
    "Default (embedded)" option which sends no override and lets the helper
    use its compile-time __DATA,__mxconfig section."""
    out: list[tuple[str, Path | None]] = [
        ("Default (helper 内嵌的 mxconfig.plist)", None),
    ]
    if CONFIGS_DIR.exists() and CONFIGS_DIR.is_dir():
        for p in sorted(CONFIGS_DIR.glob("*.plist")):
            out.append((p.name, p))
    return out

from packaging.version import parse as parse_version
from pymobiledevice3.exceptions import NoDeviceConnectedError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from sparserestore import backup, perform_restore
from _payload import build_backup_files

import ttkbootstrap as ttk
from ttkbootstrap.constants import PRIMARY, SUCCESS, DANGER, INFO, SECONDARY


OS_NAMES = {
    "iPhone": "iOS", "iPad": "iPadOS", "iPod": "iOS",
    "AppleTV": "tvOS", "Watch": "watchOS",
    "AudioAccessory": "HomePod Software Version", "RealityDevice": "visionOS",
}


def read_app_urls(config_path: Path | None = None) -> list[tuple[str, str]]:
    """Parse an mxconfig.plist (default-or-override) and return (name, url)
    pairs. Returns [] when no plist found — handled gracefully by the UI."""
    path = config_path or DEFAULT_CONFIG_PATH
    if not path.exists():
        return []
    try:
        with open(path, "rb") as f:
            cfg = plistlib.load(f)
    except Exception:
        return []
    out = []
    for app in cfg.get("Apps") or []:
        if not isinstance(app, dict):
            continue
        url = (app.get("URL") or "").strip()
        if not url or url.startswith(("https://example.com", "http://example.com")):
            continue
        name = (app.get("Name") or "").strip() or url.rsplit("/", 1)[-1]
        out.append((name, url))
    return out


def list_system_apps(service_provider) -> list[str]:
    apps_json = InstallationProxyService(service_provider).get_apps(
        application_type="System", calculate_sizes=False)
    names = []
    for value in apps_json.values():
        if not isinstance(value, dict) or "Path" not in value:
            continue
        path = Path(value["Path"])
        if Path("/private/var/containers/Bundle/Application") in path.parents:
            names.append(path.name.replace(".app", ""))
    return sorted(names)


def install_flow(system_app: str, do_reboot: bool, log, config_override: Path | None = None):
    """Runs in a worker thread. `log(msg, color)` posts to the UI.

    config_override: if not None, push this plist into Tips.app/mxconfig.plist
    so MXAutoFlow on device uses it instead of the helper's compile-time
    embedded section."""
    log("Connecting to device …", INFO)
    service_provider = create_using_usbmux()

    device_class = service_provider.get_value(key="DeviceClass")
    device_build = service_provider.get_value(key="BuildVersion")
    device_version = parse_version(service_provider.product_version)
    if not all([device_class, device_build, device_version]):
        raise RuntimeError("Failed to get device info; reconnect and retry.")

    os_name = (OS_NAMES.get(device_class, "") + " ").strip()
    log(f"Device: {os_name} {device_version} ({device_build})", INFO)

    if (
        device_version < parse_version("15.0")
        or device_version > parse_version("17.0")
        or parse_version("16.7") < device_version < parse_version("17.0")
        or device_version == parse_version("16.7") and device_build != "20H18"
    ):
        raise RuntimeError(
            f"{os_name} {device_version} ({device_build}) is not supported. "
            "Window is iOS 15.0–16.7 RC (20H18) and 17.0 only."
        )

    helper_contents = load_helper_payload()

    if not system_app.endswith(".app"):
        system_app = system_app + ".app"
    apps_json = InstallationProxyService(service_provider).get_apps(
        application_type="System", calculate_sizes=False)
    app_path = None
    for value in apps_json.values():
        if isinstance(value, dict) and "Path" in value:
            cand = Path(value["Path"])
            if cand.name.lower() == system_app.lower():
                app_path = cand
                system_app = cand.name
                break
    if not app_path:
        raise RuntimeError(f"System app '{system_app}' not found on device.")
    if Path("/private/var/containers/Bundle/Application") not in app_path.parents:
        raise RuntimeError(f"'{system_app}' is not a removable system app. Pick Tips, GarageBand, etc.")

    app_uuid = app_path.parent.name

    extra_files: list[tuple[str, bytes]] = []
    if config_override:
        plist_bytes = config_override.read_bytes()
        extra_files.append(("mxconfig.plist", plist_bytes))
        log(f"Pushing config override: {config_override.name} ({len(plist_bytes)} bytes)", PRIMARY)

    log(f"Overwriting {system_app} (UUID: {app_uuid}) …", PRIMARY)

    back = backup.Backup(files=build_backup_files(
        helper_contents=helper_contents,
        app_uuid=app_uuid,
        system_app=system_app,
        extra_bundle_files=extra_files,
    ))

    log("Pushing backup (CVE-2024-44252) …", PRIMARY)
    try:
        perform_restore(back, reboot=False)
    except PyMobileDevice3Exception as e:
        if "Find My" in str(e):
            raise RuntimeError("Find My must be disabled. Settings → [Your Name] → Find My → off.")
        if "crash_on_purpose" not in str(e):
            raise
    log("Backup pushed successfully.", SUCCESS)

    if do_reboot:
        log("Rebooting device …", PRIMARY)
        with DiagnosticsService(service_provider) as ds:
            ds.restart()
        log("Reboot triggered. Tap the swapped icon after boot to auto-install.", SUCCESS)
    else:
        log("Skipping reboot. Manually reboot then tap the swapped icon.", SUCCESS)


class App:
    def __init__(self):
        self.root = ttk.Window(themename="darkly")
        self.root.title("mxrestore — TrollRestoreX")
        self.root.geometry("620x640")
        self.root.resizable(False, False)

        ttk.Label(self.root, text="TrollRestoreX", font=("Helvetica", 18, "bold")).pack(pady=(14, 4))
        ttk.Label(self.root,
                  text="一键装 TrollStore + 自定义 IPA  (iOS 15.0–17.0)",
                  font=("Helvetica", 11)).pack(pady=(0, 12))

        row = ttk.Frame(self.root); row.pack(fill="x", padx=18, pady=4)
        ttk.Label(row, text="覆盖哪个系统 App:", width=18).pack(side="left")
        self.app_var = StringVar(value="Tips")
        self.app_combo = ttk.Combobox(row, textvariable=self.app_var, bootstyle=PRIMARY, width=20)
        self.app_combo["values"] = ["Tips", "GarageBand", "iMovie", "Keynote", "Numbers", "Pages"]
        self.app_combo.pack(side="left", padx=8)
        ttk.Button(row, text="从设备读取", command=self.refresh_apps, bootstyle=SECONDARY).pack(side="left", padx=4)

        # Config dropdown — picks which mxconfig.plist drives the install.
        # "Default" leaves the helper to use its compile-time embedded section;
        # other entries are pushed as a runtime override.
        crow = ttk.Frame(self.root); crow.pack(fill="x", padx=18, pady=4)
        ttk.Label(crow, text="使用哪个 config:", width=18).pack(side="left")
        self._configs = list_available_configs()  # [(label, path|None), ...]
        self.config_var = StringVar(value=self._configs[0][0])
        self.config_combo = ttk.Combobox(crow, textvariable=self.config_var,
                                         bootstyle=PRIMARY, width=32, state="readonly")
        self.config_combo["values"] = [label for label, _ in self._configs]
        self.config_combo.pack(side="left", padx=8)
        self.config_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_apps_preview())
        ttk.Button(crow, text="…", width=3, command=self._browse_config,
                   bootstyle=SECONDARY).pack(side="left", padx=2)

        ttk.Separator(self.root).pack(fill="x", padx=18, pady=10)

        self._apps_preview_frame = ttk.Frame(self.root)
        self._apps_preview_frame.pack(fill="x", padx=18)
        self._refresh_apps_preview()

        ttk.Separator(self.root).pack(fill="x", padx=18, pady=10)

        btnrow = ttk.Frame(self.root); btnrow.pack(pady=4)
        self.install_btn = ttk.Button(btnrow, text="开始安装  (会自动重启)",
                                      command=self.on_install, bootstyle=SUCCESS, width=22)
        self.install_btn.pack(side="left", padx=4)
        self.noreboot_btn = ttk.Button(btnrow, text="安装但不重启",
                                       command=lambda: self.on_install(reboot=False),
                                       bootstyle=SECONDARY, width=16)
        self.noreboot_btn.pack(side="left", padx=4)

        self.status_var = StringVar(value="未连接。请插上 iPhone 并禁用 Find My。")
        ttk.Label(self.root, textvariable=self.status_var, relief=SUNKEN,
                  anchor="w", wraplength=520, padding=8).pack(fill="x", padx=18, pady=(14, 4))

        self.log_box = ttk.Text(self.root, height=8, font=("Menlo", 10))
        self.log_box.pack(fill="both", expand=True, padx=18, pady=(0, 14))
        self.log_box.configure(state="disabled")

    def _selected_config_path(self) -> Path | None:
        """Returns the Path of the selected config override, or None for
        the 'Default (embedded)' option."""
        label = self.config_var.get()
        for lbl, path in self._configs:
            if lbl == label:
                return path
        return None

    def _refresh_apps_preview(self):
        for w in self._apps_preview_frame.winfo_children():
            w.destroy()
        cfg_path = self._selected_config_path()
        # For "Default (embedded)" we have no on-disk copy to read on the host,
        # so we tell the user the helper will use its baked-in list.
        if cfg_path is None:
            ttk.Label(self._apps_preview_frame,
                      text="使用 helper 二进制内嵌的 Apps 列表（host 看不到具体内容）",
                      font=("Helvetica", 10), bootstyle="secondary").pack(anchor="w")
            return
        apps = read_app_urls(cfg_path)
        if not apps:
            ttk.Label(self._apps_preview_frame,
                      text=f"⚠ {cfg_path.name} 里没有有效的 Apps 条目",
                      bootstyle="warning").pack(anchor="w")
            return
        ttk.Label(self._apps_preview_frame,
                  text=f"将自动安装 ({cfg_path.name}):",
                  font=("Helvetica", 11, "bold")).pack(anchor="w")
        for name, url in apps:
            short = url if len(url) <= 60 else url[:57] + "..."
            ttk.Label(self._apps_preview_frame, text=f"  • {name}  —  {short}",
                      font=("Helvetica", 9)).pack(anchor="w", padx=8)

    def _browse_config(self):
        """File picker — adds the chosen plist to the dropdown list and
        selects it. Useful when the plist lives outside mxhelper/configs/."""
        path_str = filedialog.askopenfilename(
            title="选择 mxconfig plist",
            filetypes=[("plist", "*.plist"), ("all", "*.*")])
        if not path_str:
            return
        p = Path(path_str)
        label = f"{p.name}  ({p.parent})"
        if not any(lbl == label for lbl, _ in self._configs):
            self._configs.append((label, p))
            self.config_combo["values"] = [lbl for lbl, _ in self._configs]
        self.config_var.set(label)
        self._refresh_apps_preview()

    def log(self, msg, color=INFO):
        def _do():
            self.status_var.set(msg)
            self.log_box.configure(state="normal")
            self.log_box.insert("end", msg + "\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
        self.root.after(0, _do)

    def refresh_apps(self):
        def _w():
            try:
                sp = create_using_usbmux()
                names = list_system_apps(sp)
                self.root.after(0, lambda: self.app_combo.configure(values=names or ["Tips"]))
                self.log(f"读到 {len(names)} 个可覆盖的系统 App", INFO)
            except NoDeviceConnectedError:
                self.log("没连接到设备", DANGER)
            except Exception as e:
                self.log(f"读取失败: {e}", DANGER)
        threading.Thread(target=_w, daemon=True).start()

    def on_install(self, reboot=True):
        app_name = self.app_var.get().strip() or "Tips"
        cfg_path = self._selected_config_path()
        self.install_btn.configure(state="disabled")
        self.noreboot_btn.configure(state="disabled")
        def _w():
            try:
                install_flow(app_name, do_reboot=reboot, log=self.log,
                             config_override=cfg_path)
                self._render_done(reboot, cfg_path)
            except NoDeviceConnectedError:
                self.log("没连接到设备", DANGER)
            except Exception as e:
                self.log(f"失败: {e}", DANGER)
                traceback.print_exc()
            finally:
                self.root.after(0, lambda: (
                    self.install_btn.configure(state="normal"),
                    self.noreboot_btn.configure(state="normal"),
                ))
        threading.Thread(target=_w, daemon=True).start()

    def _render_done(self, rebooted, cfg_path: Path | None):
        apps = read_app_urls(cfg_path) if cfg_path else []
        if not apps:
            self.log("完成。设备重启后点桌面图标。", SUCCESS)
            return
        msg = "完成。" + ("设备会自动重启。" if rebooted else "请手动重启。") + \
              " 重启后桌面点一下被覆盖的图标即可触发自动安装。"
        self.log(msg, SUCCESS)

        # If the helper on device is opa334's vanilla version (no MXAutoFlow),
        # the IPA won't auto-install — print fallback apple-magnifier links the
        # user can open in Safari on the iPhone instead.
        self.log("──── 兜底 apple-magnifier:// 链接 (helper 是 opa334 原版时用) ────", INFO)
        for name, url in apps:
            link = f"apple-magnifier://install?url={urllib.parse.quote(url, safe=':/?&=')}"
            self.log(f"  {name}:  {link}", INFO)

    def run(self):
        self.root.mainloop()


def main():
    try:
        App().run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
