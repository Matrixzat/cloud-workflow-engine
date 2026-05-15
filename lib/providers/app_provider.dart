import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../api/moviebox_client.dart';
import '../api/models.dart';

class AppProvider extends ChangeNotifier {
  final MovieBoxClient _client = MovieBoxClient();

  List<HomeSection> _homeSections = [];
  List<Movie> _trending = [];
  List<Movie> _newReleases = [];
  List<Movie> _nollywood = [];
  List<Movie> _kDrama = [];
  List<Movie> _saDrama = [];
  List<Movie> _horror = [];
  List<Movie> _adventure = [];
  List<Movie> _anime = [];
  List<Movie> _romance = [];
  List<Movie> _action = [];
  List<Movie> _shortTV = [];

  // ── Search ──────────────────────────────────────────────────────────────────
  List<Movie> _searchResults = [];
  bool _loadingSearch = false;
  bool _loadingMoreSearch = false;
  bool _searchHasMore = false;
  int _searchPage = 1;
  String _lastQuery = '';
  int _lastType = 0;

  // ── Search history ──────────────────────────────────────────────────────────
  List<String> _searchHistory = [];

  // ── Watchlist / History ─────────────────────────────────────────────────────
  List<Movie> _watchlist = [];
  List<Movie> _history = [];

  bool _loadingHome = false;
  bool _refreshingHome = false;
  String _error = '';
  int _currentIndex = 0;

  static const _homeCacheKey    = 'app_home_cache_v1';
  static const _homeCacheAgeKey = 'app_home_cache_v1_ts';
  static const _homeCacheTtlMs  = 4 * 60 * 60 * 1000; // 4 hours

  // ── Getters ─────────────────────────────────────────────────────────────────
  List<HomeSection> get homeSections => _homeSections;
  List<Movie> get trending => _trending;
  List<Movie> get newReleases => _newReleases;
  List<Movie> get nollywood => _nollywood;
  List<Movie> get kDrama => _kDrama;
  List<Movie> get saDrama => _saDrama;
  List<Movie> get horror => _horror;
  List<Movie> get adventure => _adventure;
  List<Movie> get anime => _anime;
  List<Movie> get romance => _romance;
  List<Movie> get action => _action;
  List<Movie> get shortTV => _shortTV;
  List<Movie> get searchResults => _searchResults;
  List<Movie> get watchlist => _watchlist;
  List<Movie> get history => _history;
  List<String> get searchHistory => List.unmodifiable(_searchHistory);
  bool get loadingHome => _loadingHome;
  bool get refreshingHome => _refreshingHome;
  bool get loadingSearch => _loadingSearch;
  bool get loadingMoreSearch => _loadingMoreSearch;
  bool get searchHasMore => _searchHasMore;
  String get error => _error;
  int get currentIndex => _currentIndex;

  AppProvider() {
    _loadLocalData();
  }

  void setIndex(int index) {
    _currentIndex = index;
    notifyListeners();
  }

  // ── Home ───────────────────────────────────────────────────────────────────
  Future<void> loadHome() async {
    if (_loadingHome) return;

    // 1. Restore from cache immediately (no spinner)
    final hadCache = await _restoreHomeCache();
    if (hadCache) {
      _refreshHomeSilently();
      return;
    }

    // 2. No cache — show spinner and fetch fresh
    _loadingHome = true;
    _error = '';
    notifyListeners();
    await _fetchAndCacheHome();
    _loadingHome = false;
    notifyListeners();
  }

  Future<bool> _restoreHomeCache() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_homeCacheKey);
      if (raw == null || raw.isEmpty) return false;
      final data = jsonDecode(raw) as Map<String, dynamic>;
      _applyCachedHome(data);
      notifyListeners();
      return true;
    } catch (_) {
      return false;
    }
  }

  Future<void> _refreshHomeSilently() async {
    if (_refreshingHome) return;
    try {
      final prefs = await SharedPreferences.getInstance();
      final ts  = prefs.getInt(_homeCacheAgeKey) ?? 0;
      final age = DateTime.now().millisecondsSinceEpoch - ts;
      if (age < _homeCacheTtlMs) return; // still fresh
    } catch (_) {}
    _refreshingHome = true;
    notifyListeners();
    await _fetchAndCacheHome();
    _refreshingHome = false;
    notifyListeners();
  }

  Future<void> _fetchAndCacheHome() async {
    // Start both requests simultaneously but keep error handling independent.
    // Using Future.wait on different-typed futures would fail atomically —
    // if trending throws, homepage would be lost too.
    final homeFuture   = _client.getHomepage();
    final trendFuture  = _client.getTrending(perPage: 12);

    try {
      _homeSections = await homeFuture;
      notifyListeners();
    } catch (_) {
      if (_homeSections.isEmpty) {
        _error = 'Failed to load content. Check your connection.';
      }
    }

    try {
      _trending = await trendFuture;
      notifyListeners();
    } catch (_) {}

    // Load all extra sections in parallel — no sequential delays
    await _loadExtraSections();
    await _saveHomeCache();
  }

  Map<String, dynamic> _homeToJson() => {
    'homeSections': _homeSections.map((s) => {
      'title': s.title,
      'items': s.items.map(_movieToJson).toList(),
    }).toList(),
    'trending':    _trending.map(_movieToJson).toList(),
    'newReleases': _newReleases.map(_movieToJson).toList(),
    'nollywood':   _nollywood.map(_movieToJson).toList(),
    'action':      _action.map(_movieToJson).toList(),
    'romance':     _romance.map(_movieToJson).toList(),
    'kDrama':      _kDrama.map(_movieToJson).toList(),
    'saDrama':     _saDrama.map(_movieToJson).toList(),
    'horror':      _horror.map(_movieToJson).toList(),
    'adventure':   _adventure.map(_movieToJson).toList(),
    'anime':       _anime.map(_movieToJson).toList(),
    'shortTV':     _shortTV.map(_movieToJson).toList(),
  };

  void _applyCachedHome(Map<String, dynamic> data) {
    List<Movie> _parseList(String key) =>
        ((data[key] as List?) ?? [])
            .map((e) => Movie.fromJson(Map<String, dynamic>.from(e)))
            .toList();

    final rawSections = (data['homeSections'] as List?) ?? [];
    _homeSections = rawSections.map((s) {
      final map = s as Map<String, dynamic>;
      return HomeSection(
        title: map['title'] as String? ?? '',
        items: ((map['items'] as List?) ?? [])
            .map((e) => Movie.fromJson(Map<String, dynamic>.from(e)))
            .toList(),
      );
    }).toList();

    _trending    = _parseList('trending');
    _newReleases = _parseList('newReleases');
    _nollywood   = _parseList('nollywood');
    _action      = _parseList('action');
    _romance     = _parseList('romance');
    _kDrama      = _parseList('kDrama');
    _saDrama     = _parseList('saDrama');
    _horror      = _parseList('horror');
    _adventure   = _parseList('adventure');
    _anime       = _parseList('anime');
    _shortTV     = _parseList('shortTV');
  }

  Future<void> _saveHomeCache() async {
    // Fire-and-forget — never await this while the user is scrolling.
    // jsonEncode of 300+ movies on the main thread freezes the UI.
    Future.microtask(() async {
      try {
        final data    = _homeToJson();
        final encoded = jsonEncode(data);
        final prefs   = await SharedPreferences.getInstance();
        await prefs.setString(_homeCacheKey, encoded);
        await prefs.setInt(_homeCacheAgeKey, DateTime.now().millisecondsSinceEpoch);
      } catch (_) {}
    });
  }

  Future<void> _loadExtraSections() async {
    // Load in batches of 3 — firing all 10 at once creates a memory spike
    // (10 concurrent HTTP responses in RAM) that crashes the app on device.
    // Uganda avoids this entirely with a single batch-grid call.
    final sections = [
      ('new',       (List<Movie> m) { _newReleases = m; }),
      ('nollywood', (List<Movie> m) { _nollywood   = m; }),
      ('action',    (List<Movie> m) { _action      = m; }),
      ('romance',   (List<Movie> m) { _romance     = m; }),
      ('k-drama',   (List<Movie> m) { _kDrama      = m; }),
      ('sa drama',  (List<Movie> m) { _saDrama     = m; }),
      ('horror',    (List<Movie> m) { _horror      = m; }),
      ('adventure', (List<Movie> m) { _adventure   = m; }),
      ('anime',     (List<Movie> m) { _anime       = m; }),
      ('short tv',  (List<Movie> m) { _shortTV     = m; }),
    ];
    for (int i = 0; i < sections.length; i += 3) {
      final batch = sections.sublist(i, (i + 3).clamp(0, sections.length));
      await Future.wait(batch.map((s) => _loadSection(s.$1, s.$2)));
      notifyListeners(); // paint each batch of 3 as they arrive
    }
  }

  Future<void> _loadSection(String keyword, void Function(List<Movie>) setter) async {
    try {
      List<Movie> results;
      if (keyword == 'new') {
        results = await _client.getNewReleases(perPage: 12);
      } else {
        results = await _client.getGenre(keyword, perPage: 12);
      }
      final withPosters = results
          .where((m) => m.thumbnail != null && m.thumbnail!.isNotEmpty)
          .toList();
      setter(withPosters.isNotEmpty ? withPosters : results);
    } catch (_) {}
  }

  // ── Search ─────────────────────────────────────────────────────────────────
  Future<void> searchContent(String query, {int type = 0}) async {
    if (query.trim().isEmpty) {
      _searchResults = [];
      _searchHasMore = false;
      _lastQuery = '';
      notifyListeners();
      return;
    }
    _lastQuery = query;
    _lastType = type;
    _searchPage = 1;
    _loadingSearch = true;
    _searchHasMore = false;
    notifyListeners();
    try {
      final results = await _client.search(query, subjectType: type, page: 1, perPage: 24);
      _searchResults = results;
      _searchHasMore = results.length >= 24;
      _searchPage = 2;
    } catch (e) {
      _searchResults = [];
      _searchHasMore = false;
    }
    _loadingSearch = false;
    notifyListeners();
  }

  Future<void> loadMoreSearch() async {
    if (_loadingMoreSearch || !_searchHasMore || _lastQuery.isEmpty) return;
    _loadingMoreSearch = true;
    notifyListeners();
    try {
      final results = await _client.search(
        _lastQuery,
        subjectType: _lastType,
        page: _searchPage,
        perPage: 24,
      );
      if (results.isEmpty) {
        _searchHasMore = false;
      } else {
        final existingIds = _searchResults.map((m) => m.id).toSet();
        _searchResults = [
          ..._searchResults,
          ...results.where((m) => !existingIds.contains(m.id)),
        ];
        _searchPage++;
        if (results.length < 24) _searchHasMore = false;
      }
    } catch (_) {
      _searchHasMore = false;
    }
    _loadingMoreSearch = false;
    notifyListeners();
  }

  // ── Search history ──────────────────────────────────────────────────────────
  void addSearchHistory(String query) {
    final q = query.trim();
    if (q.isEmpty) return;
    _searchHistory.removeWhere((h) => h.toLowerCase() == q.toLowerCase());
    _searchHistory.insert(0, q);
    if (_searchHistory.length > 15) _searchHistory = _searchHistory.take(15).toList();
    _saveSearchHistory();
  }

  void removeSearchHistory(String query) {
    _searchHistory.removeWhere((h) => h == query);
    _saveSearchHistory();
    notifyListeners();
  }

  void clearSearchHistory() {
    _searchHistory.clear();
    _saveSearchHistory();
    notifyListeners();
  }

  // ── Watchlist ──────────────────────────────────────────────────────────────
  bool isInWatchlist(String movieId) => _watchlist.any((m) => m.id == movieId);

  void toggleWatchlist(Movie movie) {
    if (isInWatchlist(movie.id)) {
      _watchlist.removeWhere((m) => m.id == movie.id);
    } else {
      _watchlist.insert(0, movie);
    }
    _saveWatchlist();
    notifyListeners();
  }

  // ── Watch history ──────────────────────────────────────────────────────────
  void addToHistory(Movie movie) {
    _history.removeWhere((m) => m.id == movie.id);
    _history.insert(0, movie);
    if (_history.length > 50) _history = _history.take(50).toList();
    _saveHistory();
    notifyListeners();
  }

  void removeFromHistory(String movieId) {
    _history.removeWhere((m) => m.id == movieId);
    _saveHistory();
    notifyListeners();
  }

  void clearHistory() {
    _history.clear();
    _saveHistory();
    notifyListeners();
  }

  // ── Persistence ────────────────────────────────────────────────────────────
  Future<void> _loadLocalData() async {
    final prefs = await SharedPreferences.getInstance();
    final wRaw = prefs.getString('watchlist');
    final hRaw = prefs.getString('history');
    final shRaw = prefs.getStringList('search_history');
    if (wRaw != null) {
      _watchlist = (jsonDecode(wRaw) as List)
          .map((e) => Movie.fromJson(Map<String, dynamic>.from(e)))
          .toList();
    }
    if (hRaw != null) {
      _history = (jsonDecode(hRaw) as List)
          .map((e) => Movie.fromJson(Map<String, dynamic>.from(e)))
          .toList();
    }
    if (shRaw != null) _searchHistory = shRaw;
    notifyListeners();
  }

  Future<void> _saveWatchlist() async {
    final prefs = await SharedPreferences.getInstance();
    prefs.setString('watchlist', jsonEncode(_watchlist.map(_movieToJson).toList()));
  }

  Future<void> _saveHistory() async {
    final prefs = await SharedPreferences.getInstance();
    prefs.setString('history', jsonEncode(_history.map(_movieToJson).toList()));
  }

  Future<void> _saveSearchHistory() async {
    final prefs = await SharedPreferences.getInstance();
    prefs.setStringList('search_history', _searchHistory);
  }

  Map<String, dynamic> _movieToJson(Movie m) => {
    'id': m.id, 'name': m.title, 'thumbnail': m.thumbnail,
    'rating': m.rating, 'year': m.year, 'subjectType': m.subjectType,
    'summary': m.summary, 'detailPath': m.detailPath,
    'subtitles': m.availableSubtitles.join(','),
  };

  MovieBoxClient get client => _client;
}
