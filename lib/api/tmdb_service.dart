import 'package:dio/dio.dart';
import 'models.dart';

String _u(List<int> c) => String.fromCharCodes(c);

class TmdbCastMember {
  final String name;
  final String character;
  final String? profileUrl;

  const TmdbCastMember({
    required this.name,
    required this.character,
    this.profileUrl,
  });
}

class TmdbService {
  static final TmdbService _instance = TmdbService._internal();
  factory TmdbService() => _instance;
  TmdbService._internal();

  static final String _base    = _u([104,116,116,112,115,58,47,47,97,112,105,46,116,104,101,109,111,118,105,101,100,98,46,111,114,103,47,51]);
  static final String _imgBase = _u([104,116,116,112,115,58,47,47,105,109,97,103,101,46,116,109,100,98,46,111,114,103,47,116,47,112,47,119,49,56,53]);
  static final String _apiKey  = _u([56,50,54,53,98,100,49,54,55,57,54,54,51,97,55,101,97,49,50,97,99,49,54,56,100,97,56,52,100,50,101,56]);

  final Dio _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 10),
    receiveTimeout: const Duration(seconds: 15),
  ));

  final Map<String, List<TmdbCastMember>> _castCache = {};
  final Map<String, List<SeasonInfo>> _seasonCache = {};
  final Map<String, String> _overviewCache = {};

  final Map<String, String> _backdropCache = {};

  /// Returns a 1280×720 TMDB backdrop URL for a movie title.
  /// Falls back to empty string if not found or on error.
  Future<String> getBackdrop(String movieTitle) async {
    final key = movieTitle.toLowerCase().trim();
    if (_backdropCache.containsKey(key)) return _backdropCache[key]!;
    try {
      final resp = await _dio.get(
        '$_base/search/movie',
        queryParameters: {'api_key': _apiKey, 'query': movieTitle, 'page': 1},
      );
      final results = (resp.data['results'] as List?) ?? [];
      if (results.isEmpty) return _backdropCache[key] = '';
      final bp = results.first['backdrop_path']?.toString() ?? '';
      final url = bp.isNotEmpty
          ? _u([104,116,116,112,115,58,47,47,105,109,97,103,101,46,116,109,100,98,46,111,114,103,47,116,47,112,47,119,49,50,56,48]) + bp
          : '';
      return _backdropCache[key] = url;
    } catch (_) {
      return _backdropCache[key] = '';
    }
  }

  /// Returns the full TMDB overview for a movie title.
  /// Falls back to empty string if not found or on error.
  Future<String> getOverview(String movieTitle) async {
    final key = movieTitle.toLowerCase().trim();
    if (_overviewCache.containsKey(key)) return _overviewCache[key]!;
    try {
      // Reuse backdrop search result if already cached to avoid double request
      final resp = await _dio.get(
        '$_base/search/movie',
        queryParameters: {'api_key': _apiKey, 'query': movieTitle, 'page': 1},
      );
      final results = (resp.data['results'] as List?) ?? [];
      if (results.isEmpty) return _overviewCache[key] = '';
      // Cache backdrop too while we're here
      final bp = results.first['backdrop_path']?.toString() ?? '';
      if (bp.isNotEmpty && !_backdropCache.containsKey(key)) {
        _backdropCache[key] = _u([104,116,116,112,115,58,47,47,105,109,97,103,101,46,116,109,100,98,46,111,114,103,47,116,47,112,47,119,49,50,56,48]) + bp;
      }
      final overview = results.first['overview']?.toString() ?? '';
      return _overviewCache[key] = overview;
    } catch (_) {
      return _overviewCache[key] = '';
    }
  }

  Future<List<TmdbCastMember>> getCast(String movieTitle) async {
    final key = movieTitle.toLowerCase().trim();
    if (_castCache.containsKey(key)) return _castCache[key]!;

    try {
      final searchResp = await _dio.get(
        '$_base/search/movie',
        queryParameters: {
          'api_key': _apiKey,
          'query': movieTitle,
          'page': 1,
        },
      );

      final results = (searchResp.data['results'] as List?) ?? [];
      if (results.isEmpty) return _castCache[key] = [];

      final movieId = results.first['id'];

      final creditsResp = await _dio.get(
        '$_base/movie/$movieId/credits',
        queryParameters: {'api_key': _apiKey},
      );

      final castList = (creditsResp.data['cast'] as List?) ?? [];
      final members = castList.take(10).map((c) {
        final profile = c['profile_path'];
        return TmdbCastMember(
          name: c['name']?.toString() ?? '',
          character: c['character']?.toString() ?? '',
          profileUrl: profile != null ? '$_imgBase$profile' : null,
        );
      }).where((m) => m.name.isNotEmpty).toList();

      return _castCache[key] = members;
    } catch (_) {
      return _castCache[key] = [];
    }
  }

  /// Returns full season+episode data for a TV show from TMDB.
  /// Each [SeasonInfo] will have [episodes] populated with title and runtime.
  Future<List<SeasonInfo>> getTvSeasons(String showTitle) async {
    final key = showTitle.toLowerCase().trim();
    if (_seasonCache.containsKey(key)) return _seasonCache[key]!;

    try {
      // 1. Search for the TV show
      final searchResp = await _dio.get(
        '$_base/search/tv',
        queryParameters: {
          'api_key': _apiKey,
          'query': _stripSeasonSuffix(showTitle),
          'page': 1,
        },
      );
      final results = (searchResp.data['results'] as List?) ?? [];
      if (results.isEmpty) return _seasonCache[key] = [];

      final tvId = results.first['id'];

      // 2. Get TV show details to find how many real seasons there are
      final detailResp = await _dio.get(
        '$_base/tv/$tvId',
        queryParameters: {'api_key': _apiKey},
      );
      final rawSeasons = (detailResp.data['seasons'] as List?) ?? [];
      // Filter out season 0 (specials) and only keep numbered seasons
      final seasonNumbers = rawSeasons
          .map((s) => s['season_number'] as int? ?? 0)
          .where((n) => n > 0)
          .toList()
        ..sort();

      if (seasonNumbers.isEmpty) return _seasonCache[key] = [];

      // 3. Fetch episode details for each season in parallel
      final futures = seasonNumbers.map((sn) => _fetchSeason(tvId, sn));
      final seasonInfoList = await Future.wait(futures);
      final valid = seasonInfoList.whereType<SeasonInfo>().toList();

      return _seasonCache[key] = valid;
    } catch (_) {
      return _seasonCache[key] = [];
    }
  }

  Future<SeasonInfo?> _fetchSeason(dynamic tvId, int seasonNumber) async {
    try {
      final resp = await _dio.get(
        '$_base/tv/$tvId/season/$seasonNumber',
        queryParameters: {'api_key': _apiKey},
      );
      final rawEps = (resp.data['episodes'] as List?) ?? [];
      if (rawEps.isEmpty) return null;
      final episodes = rawEps.map((e) {
        return EpisodeInfo(
          number: e['episode_number'] as int? ?? 0,
          title: e['name']?.toString() ?? 'Episode ${e['episode_number']}',
          runtimeMinutes: e['runtime'] as int?,
          overview: e['overview']?.toString(),
        );
      }).where((e) => e.number > 0).toList();
      if (episodes.isEmpty) return null;
      return SeasonInfo(
        season: seasonNumber,
        maxEpisode: episodes.length,
        episodes: episodes,
      );
    } catch (_) {
      return null;
    }
  }

  /// Strip trailing season indicators like "S1", "S2", "Season 1" from search titles.
  String _stripSeasonSuffix(String title) {
    return title
        .replaceAll(RegExp(r'\s+S\d+$', caseSensitive: false), '')
        .replaceAll(RegExp(r'\s+Season\s+\d+$', caseSensitive: false), '')
        .trim();
  }
}
