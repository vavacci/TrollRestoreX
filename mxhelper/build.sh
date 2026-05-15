#!/usr/bin/env bash
# Build mxhelper by splicing our deltas into the pinned upstream TrollHelper
# tree, invoking Theos with EMBEDDED_ROOT_HELPER=1, then exporting the embedded
# persistence helper binary to mxrestore/payload/PersistenceHelper_Embedded.
#
# Must run on macOS with Theos + Xcode CLT installed and $THEOS exported.
# Won't work on Linux: TrollStore's Makefile calls iphoneos-clang, fastPathSign,
# brew --prefix libarchive headers, etc.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
UPSTREAM="$ROOT/third_party/TrollStore"
PAYLOAD_OUT="$ROOT/mxrestore/payload/PersistenceHelper_Embedded"

if [ -z "${THEOS:-}" ]; then
    echo "[!] \$THEOS not set. Install Theos: https://theos.dev/docs/installation" >&2
    exit 1
fi

# 1. Stage our deltas into the upstream tree. Save originals to a sentinel so
#    we can `git checkout` them back at the end even if we crash midway.
echo "[*] Staging mxhelper deltas into $UPSTREAM/TrollHelper/"
cp "$HERE/MXAutoFlow.h"        "$UPSTREAM/TrollHelper/MXAutoFlow.h"
cp "$HERE/MXAutoFlow.m"        "$UPSTREAM/TrollHelper/MXAutoFlow.m"
cp "$HERE/mxconfig.plist"      "$UPSTREAM/TrollHelper/Resources/mxconfig.plist"
cp "$HERE/Resources/TrollStore.tar" "$UPSTREAM/TrollHelper/Resources/TrollStore.tar"

# 2. Run the existing TrollHelper Theos build with EMBEDDED_ROOT_HELPER=1.
#    The Makefile already globs *.m so MXAutoFlow.m gets picked up automatically.
echo "[*] Building TrollHelper (EMBEDDED_ROOT_HELPER=1, FINALPACKAGE=1)"
(
    cd "$UPSTREAM/TrollHelper"
    make clean >/dev/null
    make FINALPACKAGE=1 EMBEDDED_ROOT_HELPER=1
)

# 3. Export the binary to mxrestore/payload/.
SRC_BIN="$UPSTREAM/TrollHelper/.theos/obj/TrollStorePersistenceHelper.app/TrollStorePersistenceHelper"
if [ ! -f "$SRC_BIN" ]; then
    echo "[!] Build did not produce $SRC_BIN" >&2
    exit 1
fi
mkdir -p "$(dirname "$PAYLOAD_OUT")"
cp "$SRC_BIN" "$PAYLOAD_OUT"
echo "[+] Wrote $PAYLOAD_OUT ($(stat -f%z "$PAYLOAD_OUT" 2>/dev/null || stat -c%s "$PAYLOAD_OUT") bytes)"

# 4. Restore upstream tree to pristine state so re-runs and `git diff` are clean.
echo "[*] Cleaning up staged deltas"
rm -f "$UPSTREAM/TrollHelper/MXAutoFlow.h" \
      "$UPSTREAM/TrollHelper/MXAutoFlow.m" \
      "$UPSTREAM/TrollHelper/Resources/mxconfig.plist" \
      "$UPSTREAM/TrollHelper/Resources/TrollStore.tar"
(cd "$UPSTREAM/TrollHelper" && make clean >/dev/null || true)
