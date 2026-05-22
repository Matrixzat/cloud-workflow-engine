#!/bin/bash
set -x
ADB=/usr/local/lib/android/sdk/platform-tools/adb
TARGET=com.mm.droid.livetv.mobile31027704
ACTIVITY=com.mm.mobile.m.home.ui.HomeActivity
WDIR=$(pwd)
mkdir -p "$WDIR/dumped_dex"

echo "=== Install SapaTV ==="
$ADB install -r "$WDIR/SapaTV.apk"
sleep 3

echo "=== Push + start frida-server ==="
$ADB push "$WDIR/frida-server" /data/local/tmp/frida-server
$ADB shell "chmod +x /data/local/tmp/frida-server"
$ADB shell "/data/local/tmp/frida-server &"
sleep 5

echo "=== frida-dexdump: spawn mode — Jiagu decrypts during startup ==="
# -f = spawn (frida starts the app itself, hooks from the very first instruction)
# --sleep 20 = wait 20s inside the app before dumping (gives Jiagu time to decrypt)
frida-dexdump -U -f "$TARGET" --sleep 20 -o "$WDIR/dumped_dex/" 2>&1 || true

echo "=== Result ==="
find "$WDIR/dumped_dex" -name "*.dex" -exec ls -lh {} \; 2>/dev/null || echo "Nothing dumped"
