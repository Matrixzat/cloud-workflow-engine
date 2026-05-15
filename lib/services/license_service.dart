import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:dio/dio.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'security_service.dart';

String _u(List<int> c) => String.fromCharCodes(c);

enum LicenseStatus { active, inactive, expired, leftGroup }

class LicenseResult {
  final LicenseStatus status;
  final String? expiry;

  const LicenseResult(this.status, {this.expiry});

  bool get isActive  => status == LicenseStatus.active;
  bool get isExpired => status == LicenseStatus.expired;
}

class LicenseService {
  LicenseService._();

  static final _workerBase = _u([104,116,116,112,115,58,47,47,97,100,105,122,97,45,109,111,118,105,101,122,45,98,111,120,46,109,97,116,114,105,120,122,97,116,57,57,46,119,111,114,107,101,114,115,46,100,101,118]);
  static const _pkg        = 'com.adiza.moviezbox';
  static const groupLink   = 'https://t.me/reversemoda';
  static const tgCommand   = 'reversalx';

  // Signed cache keys (v2 — old unsigned v1 key intentionally different)
  static const _cKeyActive = '_amb_cv2_active';
  static const _cKeySig    = '_amb_cv2_sig';

  static final _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 5),
    receiveTimeout: const Duration(seconds: 5),
  ));

  // ── Device ID ─────────────────────────────────────────────────────────────
  // Key for the ANDROID_ID-derived stable ID (hardware-bound; survives
  // "Clear Data" / "Clear Storage" because the hardware value is always
  // the same for this device+app+signing-cert combination).
  static const _cKeyStableId = '_amb_stable_id';
  // Legacy random-UUID key (kept as fallback for non-Android / emulators).
  static const _cKeyLegacyId = '_amb_device_id';

  // System channel — same channel registered in MainActivity.
  static const _kSysChannel = MethodChannel('com.adiza.moviezbox/system');

  /// Returns a stable device identifier that:
  ///   • Survives clear cache      ✅
  ///   • Survives clear data       ✅  (ANDROID_ID is re-derived from hardware)
  ///   • Survives app update       ✅
  ///   • Changes on factory reset  (acceptable — same as uninstall)
  ///
  /// Resolution order:
  ///   1. Cached stable ID in SharedPreferences  (fastest path, offline safe)
  ///   2. Kotlin → SHA-256(ANDROID_ID + pkg)[:32]  (hardware-bound)
  ///   3. Legacy UUID from SharedPreferences  (emulator / fallback)
  ///   4. Generate fresh UUID and persist it   (last resort)
  static Future<String> getDeviceId() async {
    final prefs = await SharedPreferences.getInstance();

    // ── 1. Cached stable ID ───────────────────────────────────────────────
    final cached = prefs.getString(_cKeyStableId) ?? '';
    if (cached.isNotEmpty) return cached;

    // ── 2. Derive from hardware (Android only) ────────────────────────────
    if (Platform.isAndroid) {
      try {
        final native =
            await _kSysChannel.invokeMethod<String>('getStableDeviceId');
        if (native != null && native.isNotEmpty) {
          await prefs.setString(_cKeyStableId, native);
          return native;
        }
      } catch (_) {
        // Engine not yet initialised (e.g. called from main() too early) —
        // fall through to UUID fallback.
      }
    }

    // ── 3 & 4. UUID fallback (emulator / non-Android) ────────────────────
    var id = prefs.getString(_cKeyLegacyId) ?? '';
    if (id.isEmpty) {
      final bytes =
          List<int>.generate(16, (_) => Random.secure().nextInt(256));
      id = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
      await prefs.setString(_cKeyLegacyId, id);
    }
    return id;
  }

  // ── Signed cache read/write ───────────────────────────────────────────────
  /// Public — used by the splash fast-path to avoid reading the old unsigned key.
  static Future<bool> hasCachedActive(String deviceId) async =>
      (await _readCache(deviceId))?.isActive == true;

  static Future<LicenseResult?> _readCache(String deviceId) async {
    try {
      final prefs   = await SharedPreferences.getInstance();
      final actVal  = prefs.getString(_cKeyActive);
      final sig     = prefs.getString(_cKeySig) ?? '';
      if (actVal == null || sig.isEmpty) return null;
      final active  = actVal == '1';
      if (!SecurityService.verifyCacheSignature(
              active: active, deviceId: deviceId, sig: sig)) {
        // Signature mismatch → cache was tampered; wipe it
        await _clearCache(prefs);
        return null;
      }
      return active
          ? const LicenseResult(LicenseStatus.active)
          : null;
    } catch (_) {
      return null;
    }
  }

  static Future<void> _writeCache(
      {required bool active, required String deviceId}) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final sig   = SecurityService.signCache(active: active, deviceId: deviceId);
      await prefs.setString(_cKeyActive, active ? '1' : '0');
      await prefs.setString(_cKeySig,    sig);
      // Clear old unsigned cache key so it cannot be used as a fallback
      await prefs.remove('_amb_active');
    } catch (_) {}
  }

  static Future<void> _clearCache(SharedPreferences prefs) async {
    await prefs.remove(_cKeyActive);
    await prefs.remove(_cKeySig);
    await prefs.remove('_amb_active'); // legacy unsigned key
  }

  static Future<void> invalidateCache() async {
    final prefs = await SharedPreferences.getInstance();
    await _clearCache(prefs);
  }

  // ── Token fetch (for activation code display) ─────────────────────────────
  static Future<String> fetchActivationCode(String deviceId) async {
    try {
      final nonce = SecurityService.generateNonce();
      final ts    = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final sig   = SecurityService.signRequest(
          deviceId: deviceId, nonce: nonce, ts: ts);

      final res = await _dio.get(
        '$_workerBase/api/vip/token',
        queryParameters: {
          'device_id': deviceId,
          'nonce':     nonce,
          'ts':        ts,
          'sig':       sig,
          'pkg':       _pkg,
        },
      );
      final token = res.data['token'];
      if (token != null && token.toString().isNotEmpty) {
        return '$deviceId.$token';
      }
    } catch (_) {}
    return deviceId;
  }

  // ── Main license check ────────────────────────────────────────────────────
  static Future<LicenseResult> checkActive(String deviceId) async {
    try {
      final nonce = SecurityService.generateNonce();
      final ts    = DateTime.now().millisecondsSinceEpoch ~/ 1000;
      final reqSig = SecurityService.signRequest(
          deviceId: deviceId, nonce: nonce, ts: ts);

      final res = await _dio.post(
        '$_workerBase/api/vip/check-direct',
        data: jsonEncode({
          'device_id': deviceId,
          'pkg':       _pkg,
          'nonce':     nonce,
          'ts':        ts,
          'sig':       reqSig,
        }),
        options: Options(headers: {'Content-Type': 'application/json'}),
      );

      final data = res.data as Map<String, dynamic>;

      if (data['active'] == true) {
        await _writeCache(active: true, deviceId: deviceId);
        return const LicenseResult(LicenseStatus.active);
      }
      if (data['reason'] == 'left_group') {
        await _writeCache(active: false, deviceId: deviceId);
        return const LicenseResult(LicenseStatus.leftGroup);
      }
      if (data['expired'] == true) {
        await _writeCache(active: false, deviceId: deviceId);
        return LicenseResult(LicenseStatus.expired,
            expiry: data['expiry'] as String?);
      }

      await _writeCache(active: false, deviceId: deviceId);
    } catch (_) {
      // Network error — fall back to HMAC-verified cache
      return await _readCache(deviceId) ??
          const LicenseResult(LicenseStatus.inactive);
    }
    return const LicenseResult(LicenseStatus.inactive);
  }
}
