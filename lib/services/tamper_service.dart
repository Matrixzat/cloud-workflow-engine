import 'package:dio/dio.dart';
import 'package:shared_preferences/shared_preferences.dart';

String _u(List<int> c) => String.fromCharCodes(c);

class TamperService {
  static final _workerBase = _u([104,116,116,112,115,58,47,47,97,100,105,122,97,45,109,111,118,105,101,122,45,98,111,120,46,109,97,116,114,105,120,122,97,116,57,57,46,119,111,114,107,101,114,115,46,100,101,118]);

  // How far behind the device clock must be to trigger tamper (5 minutes)
  static const _thresholdMs = 5 * 60 * 1000;

  static final _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 8),
    receiveTimeout: const Duration(seconds: 8),
  ));

  /// Returns true if device time has been rolled back.
  /// Caches last-known server time so even offline checks catch obvious tampering.
  static Future<TamperResult> check() async {
    try {
      final res = await _dio.get('$_workerBase/api/time');
      final serverTs = (res.data['ts'] as num?)?.toInt() ?? 0;
      if (serverTs == 0) return TamperResult.ok;

      // Persist server time so offline runs can still detect rollback
      final prefs = await SharedPreferences.getInstance();
      final lastKnown = prefs.getInt('_amb_last_server_ts') ?? 0;
      final best = serverTs > lastKnown ? serverTs : lastKnown;
      await prefs.setInt('_amb_last_server_ts', best);

      final deviceTs = DateTime.now().millisecondsSinceEpoch;
      if (deviceTs < best - _thresholdMs) {
        return TamperResult(
          tampered: true,
          serverTime: DateTime.fromMillisecondsSinceEpoch(best),
          deviceTime: DateTime.fromMillisecondsSinceEpoch(deviceTs),
        );
      }
      return TamperResult.ok;
    } catch (_) {
      // Network fail — fall back to cached server time for offline check
      return _offlineCheck();
    }
  }

  static Future<TamperResult> _offlineCheck() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final lastKnown = prefs.getInt('_amb_last_server_ts') ?? 0;
      if (lastKnown == 0) return TamperResult.ok;
      final deviceTs = DateTime.now().millisecondsSinceEpoch;
      if (deviceTs < lastKnown - _thresholdMs) {
        return TamperResult(
          tampered: true,
          serverTime: DateTime.fromMillisecondsSinceEpoch(lastKnown),
          deviceTime: DateTime.fromMillisecondsSinceEpoch(deviceTs),
        );
      }
    } catch (_) {}
    return TamperResult.ok;
  }

  static int get nowMs => DateTime.now().millisecondsSinceEpoch;
}

class TamperResult {
  final bool tampered;
  final DateTime? serverTime;
  final DateTime? deviceTime;

  const TamperResult({
    required this.tampered,
    this.serverTime,
    this.deviceTime,
  });

  static const ok = TamperResult(tampered: false);
}
