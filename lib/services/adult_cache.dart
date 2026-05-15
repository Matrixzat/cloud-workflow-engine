import 'package:flutter_cache_manager/flutter_cache_manager.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// Custom cache manager for adult content media (thumbnails + preview GIFs).
/// Limits: 120 objects max, 14-day stale period — keeps storage sensible.
class AdultCacheManager extends CacheManager {
  static const _key = 'adultMediaCache';

  static final AdultCacheManager _instance = AdultCacheManager._();
  factory AdultCacheManager() => _instance;

  AdultCacheManager._()
      : super(Config(
          _key,
          stalePeriod: const Duration(days: 14),
          maxNrOfCacheObjects: 120,
          repo: JsonCacheInfoRepository(databaseName: _key),
          fileService: HttpFileService(),
        ));
}

/// Runs once when the adult section opens.
/// If more than 7 days have passed since the last clear, empties the cache.
Future<void> maybeAutoCleanAdultCache() async {
  try {
    final prefs = await SharedPreferences.getInstance();
    const key = 'adult_cache_last_cleared';
    final last = prefs.getInt(key) ?? 0;
    final now = DateTime.now().millisecondsSinceEpoch;
    const sevenDaysMs = 7 * 24 * 60 * 60 * 1000;

    if (now - last > sevenDaysMs) {
      await AdultCacheManager().emptyCache();
      await prefs.setInt(key, now);
    }
  } catch (_) {
    // Non-fatal — ignore any cache-clear errors
  }
}
