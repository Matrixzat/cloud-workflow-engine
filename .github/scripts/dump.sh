#!/usr/bin/env bash
set -x
ADB=/usr/local/lib/android/sdk/platform-tools/adb
TARGET=com.mm.droid.livetv.mobile31027704
ACTIVITY=com.mm.mobile.m.home.ui.HomeActivity
WDIR=$(pwd)
mkdir -p "$WDIR/dumped_dex"

echo "=== Install Sapa TV ==="
$ADB install -r "$WDIR/SapaTV.apk" || true
INST=$($ADB shell pm list packages 2>/dev/null | grep -c "$TARGET" || echo 0)
echo "Sapa TV installed: $INST"

echo "=== Install BlackDex64 ==="
$ADB install -r "$WDIR/BlackDex.apk" && echo "BlackDex installed"
BPKG=$($ADB shell pm list packages 2>/dev/null | grep niunaijun | tr -d '\r' | cut -d: -f2 | head -1)
echo "BlackDex pkg: $BPKG"
$ADB shell pm grant "$BPKG" android.permission.READ_EXTERNAL_STORAGE  2>/dev/null || true
$ADB shell pm grant "$BPKG" android.permission.WRITE_EXTERNAL_STORAGE 2>/dev/null || true
$ADB shell appops set  "$BPKG" MANAGE_EXTERNAL_STORAGE allow           2>/dev/null || true

echo "=== Launch Sapa TV (correct activity) ==="
$ADB shell am start -n "$TARGET/$ACTIVITY" 2>&1 || \
$ADB shell monkey -p "$TARGET" -c android.intent.category.LAUNCHER 1 || true
sleep 20

echo "=== Open BlackDex ==="
$ADB shell am start -n "$BPKG/.MainActivity" 2>&1 || true
sleep 8

echo "=== uiautomator: click Sapa TV in BlackDex list ==="
$ADB shell uiautomator dump /sdcard/uidump.xml 2>&1 || true
$ADB pull /sdcard/uidump.xml /tmp/uidump.xml 2>/dev/null || true
python3 "$WDIR/.github/scripts/click_app.py" "$ADB" /tmp/uidump.xml || true
sleep 4
$ADB shell input swipe 540 900 540 300 500 || true
sleep 3
$ADB shell uiautomator dump /sdcard/uidump2.xml 2>&1 || true
$ADB pull /sdcard/uidump2.xml /tmp/uidump2.xml 2>/dev/null || true
python3 "$WDIR/.github/scripts/click_app.py" "$ADB" /tmp/uidump2.xml || true

echo "=== Wait 90s for BlackDex dump ==="
sleep 90
$ADB pull "/sdcard/BlackDex/$TARGET/" "$WDIR/dumped_dex/" 2>/dev/null || \
$ADB pull "/sdcard/BlackDex/"          "$WDIR/dumped_dex/" 2>/dev/null || true
COUNT=$(find "$WDIR/dumped_dex" -name "*.dex" | wc -l)
echo "BlackDex: $COUNT dex files"

if [ "$COUNT" -lt 1 ]; then
  echo "=== frida-dexdump (attach mode — standard for packed apps) ==="
  pip3 install -q frida-tools frida-dexdump
  FV=$(python3 -c "import frida; print(frida.__version__)")
  echo "Frida: $FV"

  wget -q "https://github.com/frida/frida/releases/download/${FV}/frida-server-${FV}-android-x86_64.xz" \
       -O "$WDIR/frida-server.xz"
  xz -d "$WDIR/frida-server.xz"
  # xz strips .xz → file is now named frida-server
  ls -lh "$WDIR/frida-server"
  $ADB push "$WDIR/frida-server" /data/local/tmp/frida-server
  $ADB shell "chmod +x /data/local/tmp/frida-server && nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"
  sleep 6

  echo "=== Launch app + wait 30s for Jiagu to decrypt DEX ==="
  $ADB shell am start -n "$TARGET/$ACTIVITY" 2>&1 || \
  $ADB shell monkey -p "$TARGET" -c android.intent.category.LAUNCHER 1 || true
  sleep 30

  echo "=== Attach frida-dexdump to running process ==="
  frida-dexdump -U "$TARGET" -o "$WDIR/dumped_dex/" 2>&1 || true
fi

echo "=== Final result ==="
find "$WDIR/dumped_dex" -type f | xargs ls -lh 2>/dev/null || echo "Nothing dumped"
