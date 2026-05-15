import 'package:flutter_cache_manager/flutter_cache_manager.dart';

/// Shared cache manager used by all CachedNetworkImage widgets.
///
/// • 500 objects (default is 200 — fills up in one browsing session)
/// • 30-day stale period — posters rarely change, so keep them long
/// • Single instance so the disk cache is shared across every screen
class AdizaCacheManager extends CacheManager with ImageCacheManager {
  static const key = 'adizaMovieCache';

  static final AdizaCacheManager _instance = AdizaCacheManager._();
  factory AdizaCacheManager() => _instance;

  AdizaCacheManager._()
      : super(Config(
          key,
          maxNrOfCacheObjects: 500,
          stalePeriod: const Duration(days: 30),
        ));
}
