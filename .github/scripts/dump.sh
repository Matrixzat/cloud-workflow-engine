#!/bin/bash
set -x
ADB=/usr/local/lib/android/sdk/platform-tools/adb
TARGET=com.mm.droid.livetv.mobile31027704
ACTIVITY=com.mm.mobile.m.home.ui.HomeActivity
WDIR=$(pwd)
mkdir -p "$WDIR/dumped_dex"

echo "=== adb root ==="
$ADB root && sleep 3
$ADB shell "setenforce 0" 2>/dev/null || true

echo "=== Install SapaTV ==="
$ADB install -r "$WDIR/SapaTV.apk"
sleep 2

echo "=== Push frida-server ==="
$ADB push "$WDIR/frida-server" /data/local/tmp/frida-server
$ADB shell "chmod +x /data/local/tmp/frida-server"
$ADB shell "nohup /data/local/tmp/frida-server >/data/local/tmp/fs.log 2>&1 &"
sleep 5

# Verify frida-server running
$ADB shell "ps -A | grep frida" || true
$ADB shell "cat /data/local/tmp/fs.log" || true

echo "=== Run frida hook (75s max) ==="
# NOTE: frida -l reads script from HOST filesystem, not device
# Use local path to the checked-out script
timeout 75 frida -U -f "$TARGET" -l "$WDIR/.github/scripts/fast_dump.js" 2>&1 || true

echo "=== Pull dumped DEX files ==="
$ADB pull /sdcard/ "$WDIR/dumped_dex/" 2>/dev/null || true
# Keep only .dex files
find "$WDIR/dumped_dex" ! -name "*.dex" -delete 2>/dev/null || true
find "$WDIR/dumped_dex" -name "*.dex" -exec ls -lh {} \; 2>/dev/null || echo "Nothing"
