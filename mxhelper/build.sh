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

# 0. Build fastPathSign first — TrollHelper's Makefile uses it as the
#    codesign tool (TARGET_CODESIGN=../Exploits/fastPathSign/fastPathSign).
#    Needs pkg-config + openssl (brew install pkg-config openssl).
FPS_BIN="$UPSTREAM/Exploits/fastPathSign/fastPathSign"
if [ ! -x "$FPS_BIN" ]; then
    echo "[*] Building fastPathSign (host CoreTrust signer)"
    if ! pkg-config --exists libcrypto; then
        # macOS Homebrew ships openssl with its own pkgconfig dir not on PATH.
        for p in "$(brew --prefix openssl@3 2>/dev/null)/lib/pkgconfig" \
                 "$(brew --prefix openssl 2>/dev/null)/lib/pkgconfig"; do
            if [ -d "$p" ]; then
                export PKG_CONFIG_PATH="$p:${PKG_CONFIG_PATH:-}"
                break
            fi
        done
    fi
    if ! pkg-config --exists libcrypto; then
        echo "[!] libcrypto pkg-config not found. Run: brew install pkg-config openssl" >&2
        exit 1
    fi
    (cd "$UPSTREAM/Exploits/fastPathSign" && make)
fi

# 1. Stage our deltas into the upstream tree.
#    MX_VANILLA=1 skips all of our injections and builds an upstream-equivalent
#    binary — useful as an A/B test when debugging launch issues.
# Snapshot upstream files we're about to overwrite (third_party is flat-vendored,
# no `git checkout` recovery is possible).
ORIG_TSHRVC="$UPSTREAM/TrollHelper/TSHRootViewController.m.mxorig"
ORIG_MK="$UPSTREAM/TrollHelper/Makefile.mxorig"
[ -f "$ORIG_TSHRVC" ] || cp "$UPSTREAM/TrollHelper/TSHRootViewController.m" "$ORIG_TSHRVC"
[ -f "$ORIG_MK" ]     || cp "$UPSTREAM/TrollHelper/Makefile"                "$ORIG_MK"

if [ "${MX_VANILLA:-0}" = "1" ]; then
    echo "[*] MX_VANILLA=1 → skipping mxhelper deltas (building upstream-equivalent)"
    cp "$ORIG_TSHRVC" "$UPSTREAM/TrollHelper/TSHRootViewController.m"
    cp "$ORIG_MK"     "$UPSTREAM/TrollHelper/Makefile"
else
    echo "[*] Staging mxhelper deltas into $UPSTREAM/TrollHelper/"
    cp "$HERE/MXAutoFlow.h"             "$UPSTREAM/TrollHelper/MXAutoFlow.h"
    cp "$HERE/MXAutoFlow.m"             "$UPSTREAM/TrollHelper/MXAutoFlow.m"
    cp "$HERE/TSHRootViewController.m"  "$UPSTREAM/TrollHelper/TSHRootViewController.m"
    cp "$HERE/mxconfig.plist"           "$UPSTREAM/TrollHelper/Resources/mxconfig.plist"
    cp "$HERE/Resources/TrollStore.tar" "$UPSTREAM/TrollHelper/Resources/TrollStore.tar"

    # Patch Makefile: insert -Wl,-sectcreate LDFLAGS before the application.mk
    # include, so mxconfig.plist + TrollStore.tar get baked into the binary as
    # __DATA,__mxconfig / __DATA,__tstar sections. Runtime reads them via
    # getsectiondata() in MXAutoFlow.m — no separate file injection needed.
    cp "$ORIG_MK" "$UPSTREAM/TrollHelper/Makefile"
    python3 - <<PYEOF
import pathlib
p = pathlib.Path("$UPSTREAM/TrollHelper/Makefile")
content = p.read_text()
marker = "include \$(THEOS_MAKE_PATH)/application.mk"
inject = ("# mxhelper: embed mxconfig.plist + TrollStore.tar as __DATA sections\n"
          "TrollStorePersistenceHelper_LDFLAGS += -Wl,-sectcreate,__DATA,__mxconfig,Resources/mxconfig.plist\n"
          "TrollStorePersistenceHelper_LDFLAGS += -Wl,-sectcreate,__DATA,__tstar,Resources/TrollStore.tar\n\n")
assert marker in content, "Makefile layout changed upstream; rework insertion marker"
p.write_text(content.replace(marker, inject + marker, 1))
PYEOF
fi

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
# Restore upstream files from our snapshots.
[ -f "$ORIG_TSHRVC" ] && cp "$ORIG_TSHRVC" "$UPSTREAM/TrollHelper/TSHRootViewController.m"
[ -f "$ORIG_MK" ]     && cp "$ORIG_MK"     "$UPSTREAM/TrollHelper/Makefile"
(cd "$UPSTREAM/TrollHelper" && make clean >/dev/null || true)
