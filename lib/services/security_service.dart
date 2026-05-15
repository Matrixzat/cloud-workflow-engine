import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'dex_integrity_service.dart';

// ── Manifest-integrity channel ────────────────────────────────────────────────
const _kSystemChannel = MethodChannel('com.adiza.moviezbox/system');

class SecurityService {
  SecurityService._();

  // ── XOR-encoded HMAC secrets ─────────────────────────────────────────────
  // These are integer arrays — not string literals — so `strings` analysis
  // on the compiled binary cannot find them.

  // Request signing key  (server env: APP_HMAC_SECRET)
  static const _kEncReq  = [0x41,0x1f,0x66,0x3f,0x0d,0x4f,0x43,0x26,
                             0x58,0x3d,0x1c,0x29,0x39,0x4d,0x36,0x78,
                             0x45,0x25,0x19,0x3b,0x27,0x09,0x1c,0x4c,
                             0x70,0x06,0x1a,0x34,0x3d,0x49,0x42,0x7d];
  static const _kKeyReq  = [0x13,0x47,0x2b,0x5e,0x69,0x3c,0x7a,0x15];

  // Response verification key  (server env: RESP_SIGN_SECRET)
  static const _kEncResp = [0x57,0x1c,0x08,0x07,0x04,0x6b,0x26,0x1e,
                             0x49,0x0c,0x46,0x3a,0x75,0x75,0x21,0x4e,
                             0x6d,0x68,0x4c,0x20,0x35,0x4d,0x0c,0x70,
                             0x15,0x38,0x77,0x1d,0x0a,0x79,0x37,0x1d];
  static const _kKeyResp = [0x27,0x5b,0x3e,0x71,0x4c,0x18,0x63,0x2a];

  // Cache signing key  (client-only — never transmitted)
  static const _kEncCach = [0x49,0x29,0x23,0x31,0x31,0x55,0x1b,0x04,
                             0x4c,0x2c,0x67,0x0a,0x4a,0x54,0x0b,0x57,
                             0x04,0x04,0x5e,0x39,0x26,0x4d,0x13,0x02,
                             0x5a,0x34,0x72,0x02,0x16,0x66,0x25,0x00];
  static const _kKeyCach = [0x3d,0x61,0x14,0x5a,0x7f,0x22,0x49,0x36];

  // ── XOR decoder ──────────────────────────────────────────────────────────
  static List<int> _xorDec(List<int> enc, List<int> key) =>
      List.generate(enc.length, (i) => enc[i] ^ key[i % key.length]);

  static List<int> get _reqKey  => _xorDec(_kEncReq,  _kKeyReq);
  static List<int> get _respKey => _xorDec(_kEncResp, _kKeyResp);
  static List<int> get _cachKey => _xorDec(_kEncCach, _kKeyCach);

  // ── HMAC-SHA256 ──────────────────────────────────────────────────────────
  static String _hmac(String message, List<int> keyBytes) =>
      Hmac(sha256, keyBytes).convert(utf8.encode(message)).toString();

  // ── Nonce ────────────────────────────────────────────────────────────────
  static String generateNonce() {
    final bytes = List<int>.generate(16, (_) => Random.secure().nextInt(256));
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }

  // ── Request signing ──────────────────────────────────────────────────────
  /// Server uses APP_HMAC_SECRET to verify this before trusting any request.
  static String signRequest({
    required String deviceId,
    required String nonce,
    required int ts,
    String pkg = 'com.adiza.moviezbox',
  }) =>
      _hmac('$nonce|$ts|$deviceId|$pkg', _reqKey);

  // ── Response verification ─────────────────────────────────────────────────
  /// If server-signed HMAC doesn't match, the response was injected by a hook.
  static bool verifyResponse({
    required bool active,
    required int ts,
    required String nonce,
    required String sig,
  }) {
    if (sig.isEmpty) return true; // server not yet upgraded — allow gracefully
    final expected = _hmac('${active ? 1 : 0}|$ts|$nonce', _respKey);
    return _ctEqual(expected, sig);
  }

  // ── Signed cache ─────────────────────────────────────────────────────────
  /// Stores a daily-expiring signature alongside the cached activation state.
  /// Simply writing `_amb_active = true` in SharedPreferences no longer works
  /// because the sig won't match.
  // Cache period: 7 days (background check refreshes it on every open, so
  // revoked users are still caught promptly via the silent background verify).
  static const _kCachePeriodMs = 604800000; // 7 × 86 400 000

  static String signCache({required bool active, required String deviceId}) {
    final period = DateTime.now().toUtc().millisecondsSinceEpoch ~/ _kCachePeriodMs;
    return _hmac('${active ? 1 : 0}|$deviceId|$period', _cachKey);
  }

  static bool verifyCacheSignature({
    required bool active,
    required String deviceId,
    required String sig,
  }) {
    if (sig.isEmpty) return false;
    final nowMs  = DateTime.now().toUtc().millisecondsSinceEpoch;
    final period = nowMs ~/ _kCachePeriodMs;
    // Accept current period OR the previous one (handles the rollover window).
    for (final p in [period, period - 1]) {
      final expected = _hmac('${active ? 1 : 0}|$deviceId|$p', _cachKey);
      if (_ctEqual(expected, sig)) return true;
    }
    return false;
  }

  // ── Constant-time compare (prevents timing-oracle attacks) ───────────────
  static bool _ctEqual(String a, String b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return diff == 0;
  }

  // ── Frida detection ───────────────────────────────────────────────────────
  static Future<bool> isFridaDetected() async {
    if (!Platform.isAndroid) return false;

    // 1. Scan /proc/self/maps for Frida memory regions
    try {
      final maps = await File('/proc/self/maps').readAsString();
      const markers = ['frida', 'gum-js-loop', 'gmain', 'frida-agent',
                       'linjector', 'frida-gadget'];
      for (final m in markers) {
        if (maps.contains(m)) return true;
      }
    } catch (_) {}

    // 2. Check for frida-server binary on disk
    const fsPaths = [
      '/data/local/tmp/frida-server',
      '/data/local/tmp/re.frida.server',
      '/data/local/frida-server',
      '/system/bin/frida-server',
    ];
    for (final p in fsPaths) {
      try {
        if (await File(p).exists()) return true;
      } catch (_) {}
    }

    // 3. Probe Frida's default server port (27042)
    try {
      final sock = await Socket.connect(
          '127.0.0.1', 27042, timeout: const Duration(milliseconds: 300));
      await sock.close();
      return true; // port open → frida-server is running
    } on SocketException {
      // Expected on clean devices
    } catch (_) {}

    return false;
  }

  // ── Xposed / LSPosed detection ────────────────────────────────────────────
  static Future<bool> isXposedDetected() async {
    if (!Platform.isAndroid) return false;
    try {
      final maps = await File('/proc/self/maps').readAsString();
      // Use precise markers that cannot false-positive on normal library paths.
      // 'xposed' is NOT checked standalone because it is a substring of
      // the common word 'exposed' which can appear in legitimate library names.
      const markers = [
        'XposedBridge',     // classic Xposed
        'lsposed',          // LSPosed
        'edxposed',         // EdXposed
        '/xposed/',         // path-based — requires surrounding slashes
        'de.robv.android.xposed', // Xposed package name
      ];
      for (final m in markers) {
        if (maps.contains(m)) return true;
      }
    } catch (_) {}
    return false;
  }

  // ── Root detection (informational — rooted ≠ hooked) ─────────────────────
  static Future<bool> isRooted() async {
    if (!Platform.isAndroid) return false;
    const suPaths = [
      '/system/bin/su', '/system/xbin/su', '/sbin/su',
      '/su/bin/su', '/data/local/su', '/data/local/bin/su',
      '/data/local/xbin/su', '/system/sd/xbin/su',
    ];
    for (final p in suPaths) {
      try {
        if (await File(p).exists()) return true;
      } catch (_) {}
    }
    try {
      final r = await Process.run('getprop', ['ro.build.tags']);
      if (r.stdout.toString().contains('test-keys')) return true;
    } catch (_) {}
    return false;
  }

  // ── Manifest integrity (via Kotlin PackageManager) ───────────────────────
  /// Asks the native side to verify:
  ///   1. FLAG_DEBUGGABLE is NOT set on our ApplicationInfo.
  ///   2. Every registered provider authority matches our whitelist.
  ///   3. Every registered service is in our whitelist.
  ///   4. Every registered receiver is in our whitelist.
  /// Returns true if the manifest has been tampered with.
  static Future<bool> isManifestTampered() async {
    if (!Platform.isAndroid) return false;
    try {
      final ok = await _kSystemChannel.invokeMethod<bool>('checkManifest');
      // ok == true  → manifest is clean
      // ok == false → tampered detected
      // null        → channel error (fail open)
      return ok == false;
    } catch (_) {
      return false; // fail open — don't false-positive on engine startup edge cases
    }
  }

  // ── Quick (pure-Dart) gate ────────────────────────────────────────────────
  /// Runs only the checks that need NO platform channel.
  /// Safe to call from main() before runApp() because it never touches
  /// MethodChannel — only reads files and opens sockets.
  static Future<SecurityThreat> runQuickChecks() async {
    if (!Platform.isAndroid) return SecurityThreat.clean;
    final results = await Future.wait([
      isFridaDetected(),
      isXposedDetected(),
      isRooted(),
      DexIntegrityService.isTampered(),
    ]);
    return SecurityThreat(
      fridaDetected:    results[0],
      xposedDetected:   results[1],
      rooted:           results[2],
      dexTampered:      results[3],
      manifestTampered: false, // not checked yet — needs platform channel
    );
  }

  // ── Full gate (all checks) ────────────────────────────────────────────────
  /// Runs every check including the Kotlin manifest check.
  /// Call this after the Flutter engine is running (e.g. in initState).
  static Future<SecurityThreat> runChecks() async {
    if (!Platform.isAndroid) return SecurityThreat.clean;
    final results = await Future.wait([
      isFridaDetected(),
      isXposedDetected(),
      isRooted(),
      DexIntegrityService.isTampered(),
      isManifestTampered(),
    ]);
    return SecurityThreat(
      fridaDetected:    results[0],
      xposedDetected:   results[1],
      rooted:           results[2],
      dexTampered:      results[3],
      manifestTampered: results[4],
    );
  }
}

class SecurityThreat {
  final bool fridaDetected;
  final bool xposedDetected;
  final bool rooted;
  final bool dexTampered;
  final bool manifestTampered;

  const SecurityThreat({
    required this.fridaDetected,
    required this.xposedDetected,
    required this.rooted,
    this.dexTampered      = false,
    this.manifestTampered = false,
  });

  /// True if any active hooking framework or APK/manifest tampering is present.
  /// Root alone is NOT blocked — many legit users are rooted without Frida.
  bool get isHooked =>
      fridaDetected || xposedDetected || dexTampered || manifestTampered;

  static const clean = SecurityThreat(
    fridaDetected:    false,
    xposedDetected:   false,
    rooted:           false,
    dexTampered:      false,
    manifestTampered: false,
  );
}
