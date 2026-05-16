#!/usr/bin/env python3
"""
mxrestore — fork of JJTech0130/TrollRestore that drops our own
PersistenceHelper_Embedded (built by mxhelper/) instead of downloading
opa334's release asset.

Two differences vs upstream trollstore.py:
  1. No network fetch of PersistenceHelper_Embedded; reads
     ./payload/PersistenceHelper_Embedded (relative to this file).
  2. CLI takes --system-app / --no-reboot to make non-interactive use easy
     (so a SwiftUI shell can drive it via subprocess.run).
"""
import json
import platform
import plistlib
import sys
import traceback
import urllib.parse
from pathlib import Path

import click
from packaging.version import parse as parse_version
from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.exceptions import NoDeviceConnectedError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.installation_proxy import InstallationProxyService

from sparserestore import backup, perform_restore
from _payload import build_backup_files

PAYLOAD_PATH = Path(__file__).resolve().parent / "payload" / "PersistenceHelper_Embedded"
DEFAULT_MXCONFIG_PATH = Path(__file__).resolve().parent.parent / "mxhelper" / "mxconfig.plist"


def _read_app_urls(config_path: Path = DEFAULT_MXCONFIG_PATH) -> list[tuple[str, str]]:
    """Return [(name, url), ...] from a plist file. Supports both the new
    `Apps` array format and the legacy single `IPAURL` field."""
    if not config_path.exists():
        return []
    try:
        with open(config_path, "rb") as f:
            cfg = plistlib.load(f)
    except Exception:
        return []
    out: list[tuple[str, str]] = []
    for app in cfg.get("Apps") or []:
        if not isinstance(app, dict):
            continue
        url = (app.get("URL") or "").strip()
        if not url or url.startswith(("https://example.com", "http://example.com")):
            continue
        name = (app.get("Name") or "").strip() or url.rsplit("/", 1)[-1]
        out.append((name, url))
    if not out:
        legacy = (cfg.get("IPAURL") or "").strip()
        if legacy and not legacy.startswith(("https://example.com", "http://example.com")):
            out.append((legacy.rsplit("/", 1)[-1], legacy))
    return out


# build_backup_files lives in _payload.py so mxrestore-gui can import the same
# function without dragging in click / pymobiledevice3 CLI dependencies.


def _print_post_install_url(progress: bool, config_path: Path = DEFAULT_MXCONFIG_PATH) -> None:
    """After TrollRestore succeeds, surface the apple-magnifier:// URLs that
    will install each configured IPA. Useful as a fallback when the helper
    binary is opa334's vanilla version (no MXAutoFlow); the CI-built version
    auto-installs and these URLs are redundant."""
    apps = _read_app_urls(config_path)
    if not apps:
        return
    if progress:
        for name, url in apps:
            install_url = f"apple-magnifier://install?url={urllib.parse.quote(url, safe=':/?&=')}"
            _emit(True, stage="post_install_url", name=name, url=install_url, ipa_url=url)
        return
    click.secho("\n── 装完 TrollStore 后，下面是 IPA 的 apple-magnifier 安装链接 ──", fg="cyan", bold=True)
    click.secho("  CI 编译版 helper 会自动装这些；如果是 opa334 兜底版本，需要在 iPhone Safari 里逐个打开:\n", fg="cyan")
    for name, url in apps:
        install_url = f"apple-magnifier://install?url={urllib.parse.quote(url, safe=':/?&=')}"
        click.secho(f"  {name}:", fg="yellow")
        click.secho(f"    {install_url}", fg="white")
    click.echo("")


def _emit(progress, **kw):
    """If --json-progress is on, dump an NDJSON line; else write a colored
    human message. Lets a GUI shell consume structured progress."""
    if progress:
        sys.stdout.write(json.dumps(kw, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    else:
        fg = kw.pop("_color", "white")
        msg = kw.get("msg") or kw.get("error") or json.dumps(kw, ensure_ascii=False)
        click.secho(msg, fg=fg)


def _exit(code=0):
    if platform.system() == "Windows" and getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        input("Press Enter to exit...")
    sys.exit(code)


@click.command(cls=Command)
@click.option("--system-app", "system_app",
              help="Removable system app to overwrite (e.g. Tips). If omitted, prompts interactively.")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False),
              default=None,
              help="Path to an mxconfig.plist override. If set, the file is pushed into the bundle "
                   "(Tips.app/mxconfig.plist) and MXAutoFlow on device uses it instead of the "
                   "compile-time embedded list. Omit to keep the embedded Apps list.")
@click.option("--no-reboot", is_flag=True, default=False,
              help="Skip the post-restore reboot. The device will need a manual reboot to land the swapped binary.")
@click.option("--json-progress", "json_progress", is_flag=True, default=False,
              help="Emit NDJSON progress on stdout (for GUI shells).")
@click.pass_context
def cli(ctx, service_provider: LockdownClient, system_app, config_path, no_reboot, json_progress) -> None:
    os_names = {
        "iPhone": "iOS", "iPad": "iPadOS", "iPod": "iOS",
        "AppleTV": "tvOS", "Watch": "watchOS",
        "AudioAccessory": "HomePod Software Version", "RealityDevice": "visionOS",
    }

    if not PAYLOAD_PATH.exists():
        _emit(json_progress, _color="red",
              msg=f"payload missing: {PAYLOAD_PATH}",
              error="PAYLOAD_MISSING",
              hint="Build mxhelper first: cd mxhelper && make")
        _exit(1)
    helper_contents = PAYLOAD_PATH.read_bytes()

    device_class = service_provider.get_value(key="DeviceClass")
    device_build = service_provider.get_value(key="BuildVersion")
    device_version = parse_version(service_provider.product_version)

    if not all([device_class, device_build, device_version]):
        _emit(json_progress, _color="red", msg="Failed to get device information; reconnect and retry",
              error="DEVICE_INFO")
        return

    os_name = (os_names[device_class] + " ") if device_class in os_names else ""

    # Upstream's exact compatibility check: iOS/iPadOS 15.0 - 16.7 RC (20H18) and 17.0.
    # We DON'T relax this: outside the window MobileBackup CVE-2024-44252 is patched.
    if (
        device_version < parse_version("15.0")
        or device_version > parse_version("17.0")
        or parse_version("16.7") < device_version < parse_version("17.0")
        or device_version == parse_version("16.7") and device_build != "20H18"
    ):
        _emit(json_progress, _color="red",
              msg=f"{os_name}{device_version} ({device_build}) is not supported. Tool only covers iOS 15.0–16.7 RC and 17.0.",
              error="UNSUPPORTED_OS",
              os_name=os_name, version=str(device_version), build=device_build)
        return

    # Pick the system app to overwrite.
    if not system_app:
        system_app = click.prompt(
            "\nRemovable system app to replace (e.g. Tips, GarageBand). "
            "Pick something you can reinstall from App Store later.\nApp name",
            default="Tips")
    if not system_app.endswith(".app"):
        system_app += ".app"

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
        _emit(json_progress, _color="red",
              msg=f"System app '{system_app}' not found. Make sure it is installed and try again.",
              error="APP_NOT_FOUND", app=system_app)
        return
    if Path("/private/var/containers/Bundle/Application") not in app_path.parents:
        _emit(json_progress, _color="red",
              msg=f"'{system_app}' is not a removable system app. Pick a deletable Apple app (Tips, GarageBand, …).",
              error="APP_NOT_REMOVABLE", app=system_app)
        return

    app_uuid = app_path.parent.name

    # Optional plist override: push it into the bundle so MXAutoFlow on device
    # reads it via NSBundle and ignores the compile-time embedded section.
    extra_files: list[tuple[str, bytes]] = []
    effective_config = DEFAULT_MXCONFIG_PATH
    if config_path:
        effective_config = Path(config_path)
        plist_bytes = effective_config.read_bytes()
        extra_files.append(("mxconfig.plist", plist_bytes))
        _emit(json_progress, _color="yellow",
              msg=f"Will push mxconfig override: {effective_config} ({len(plist_bytes)} bytes)",
              stage="config_override", path=str(effective_config), size=len(plist_bytes))

    _emit(json_progress, _color="yellow",
          msg=f"Replacing {system_app} with mxhelper. (UUID: {app_uuid})",
          stage="replacing", app=system_app, uuid=app_uuid)

    back = backup.Backup(files=build_backup_files(
        helper_contents=helper_contents,
        app_uuid=app_uuid,
        system_app=system_app,
        extra_bundle_files=extra_files,
    ))

    try:
        perform_restore(back, reboot=False)
    except PyMobileDevice3Exception as e:
        if "Find My" in str(e):
            _emit(json_progress, _color="red",
                  msg="Find My must be disabled (Settings → [Your Name] → Find My).",
                  error="FIND_MY_ENABLED")
            _exit(1)
        elif "crash_on_purpose" not in str(e):
            raise

    if no_reboot:
        _emit(json_progress, _color="green",
              msg="Restore done. Reboot the device manually to activate.",
              stage="restore_done", reboot_required=True)
        _print_post_install_url(json_progress, effective_config)
        return

    _emit(json_progress, _color="green",
          msg="Restore done, rebooting device …",
          stage="rebooting")
    with DiagnosticsService(service_provider) as diagnostics_service:
        diagnostics_service.restart()

    _emit(json_progress, _color="green",
          msg="Reboot triggered. After the device comes back up, tap the swapped system app "
              "icon to start auto-install. Re-enable Find My if you use it.",
          stage="done")
    _print_post_install_url(json_progress)


def main():
    try:
        cli(standalone_mode=False)
    except NoDeviceConnectedError:
        click.secho("No device connected!", fg="red")
        _exit(1)
    except click.UsageError as e:
        click.secho(e.format_message(), fg="red")
        click.echo(cli.get_help(click.Context(cli)))
        _exit(2)
    except Exception:
        click.secho("An error occurred!", fg="red")
        click.secho(traceback.format_exc(), fg="red")
        _exit(1)
    _exit(0)


if __name__ == "__main__":
    main()
