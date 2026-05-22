#!/bin/bash
set -x
ADB=/usr/local/lib/android/sdk/platform-tools/adb
TARGET=com.mm.droid.livetv.mobile31027704
WDIR=$(pwd)
mkdir -p "$WDIR/dumped_dex"

echo "=== adb root (needed for frida-server SELinux) ==="
$ADB root
sleep 3

echo "=== Disable SELinux enforcing ==="
$ADB shell "setenforce 0" 2>/dev/null || true

echo "=== Install SapaTV ==="
$ADB install -r "$WDIR/SapaTV.apk"
sleep 2

echo "=== Push + start frida-server ==="
$ADB push "$WDIR/frida-server" /data/local/tmp/frida-server
$ADB shell "chmod +x /data/local/tmp/frida-server"
$ADB shell "nohup /data/local/tmp/frida-server > /data/local/tmp/frida.log 2>&1 &"
sleep 5
$ADB shell "cat /data/local/tmp/frida.log" || true
$ADB shell "ps | grep frida" || true

echo "=== frida-dexdump spawn mode (Jiagu decrypts during startup) ==="
frida-dexdump -U -f "$TARGET" --sleep 20 -o "$WDIR/dumped_dex/" 2>&1 || true

echo "=== Result ==="
find "$WDIR/dumped_dex" -name "*.dex" -exec ls -lh {} \; 2>/dev/null || echo "Nothing dumped"
