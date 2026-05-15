import 'dart:convert';
import 'package:flutter/foundation.dart';
import 'package:dio/dio.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../api/vod_client.dart' show VodClient;
import '../api/models.dart';

String _u(List<int> c) => String.fromCharCodes(c);

class UgandaSection {
  final String title;
  final List<Movie> movies;
  final String badge;
  final String pipeType;
  final int pipeId;

  const UgandaSection({
    required this.title,
    required this.movies,
    this.badge = '',
    this.pipeType = 'g',
    this.pipeId = 0,
  });

  Map<String, dynamic> toJson() => {
        'title': title,
        'badge': badge,
        'pipeType': pipeType,
        'pipeId': pipeId,
        'movies': movies
            .map((m) => {
                  'id': m.id,
                  'title': m.title,
                  'thumbnail': m.thumbnail,
                  'summary': m.summary,
                })
            .toList(),
      };

  factory UgandaSection.fromJson(Map<String, dynamic> j) => UgandaSection(
        title: j['title'] as String? ?? '',
        badge: j['badge'] as String? ?? '',
        pipeType: j['pipeType'] as String? ?? 'g',
        pipeId: (j['pipeId'] as num?)?.toInt() ?? 0,
        movies: ((j['movies'] as List?) ?? [])
            .map((e) => _movieFromJson(e as Map<String, dynamic>))
            .toList(),
      );
}

Movie _movieFromJson(Map<String, dynamic> j) => Movie(
      id: j['id']?.toString() ?? '',
      title: j['title']?.toString() ?? 'Unknown',
      thumbnail: j['thumbnail']?.toString(),
      summary: j['summary']?.toString(),
      subjectType: 1,
    );

class UgandaProvider extends ChangeNotifier {
  final VodClient _client = VodClient();

  bool _loading = false;
  bool _loaded = false;
  bool _refreshing = false;
  String _error = '';

  List<UgandaSection> _sections = [];
  List<Movie> _featured = [];

  List<Movie> _searchResults = [];
  bool _loadingSearch = false;
  String _lastQuery = '';
  String _typedQuery = '';

  bool get loading => _loading;
  bool get loaded => _loaded;
  bool get refreshing => _refreshing;
  String get error => _error;
  List<UgandaSection> get sections => _sections;
  List<Movie> get featured => _featured;
  List<Movie> get searchResults => _searchResults;
  bool get loadingSearch => _loadingSearch;
  String get lastQuery => _lastQuery;
  String get typedQuery => _typedQuery;

  static const _cacheKey    = 'uganda_home_v3';  // bumped → clears old broken cache
  static const _cacheAgeKey = 'uganda_home_v3_ts';
  static const _cacheTtlMs  = 6 * 60 * 60 * 1000; // 6 hours

  static final _base = _u([104,116,116,112,115,58,47,47,97,100,105,122,97,45,109,111,118,105,101,122,45,98,111,120,46,109,97,116,114,105,120,122,97,116,57,57,46,119,111,114,107,101,114,115,46,100,101,118]);
  static final _dio  = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 10),
    receiveTimeout: const Duration(seconds: 30),
  ));

  List<Movie> getSuggestions(String query) {
    if (query.trim().length < 2) return [];
    final q = query.trim().toLowerCase();
    final seen = <String>{};
    final out = <Movie>[];
    for (final section in _sections) {
      for (final m in section.movies) {
        if (seen.contains(m.id)) continue;
        if (m.title.toLowerCase().contains(q)) {
          seen.add(m.id);
          out.add(m);
          if (out.length >= 6) return out;
        }
      }
    }
    return out;
  }

  // ── Load home sections ──────────────────────────────────────────────────────
  Future<void> loadHome() async {
    if (_loading) return;

    // 1. Try reading from cache first — show instantly with no spinner
    final hadCache = await _restoreFromCache();
    if (hadCache) {
      // Data is showing from cache. Prefetch streams + refresh silently.
      _prefetchTopStreams();
      _refreshSilently();
      return;
    }

    // 2. No cache — show spinner and fetch
    _loading = true;
    _error   = '';
    notifyListeners();

    await _fetchAndStore();

    _loading = false;
    notifyListeners();

    // Prefetch top stream URLs in background after fresh fetch
    _prefetchTopStreams();
  }

  // Silently warm the stream cache for the first 6 movies in each of the
  // first 2 sections — so tapping a card plays instantly.
  void _prefetchTopStreams() {
    final ids = <String>[];
    for (final section in _sections.take(2)) {
      for (final movie in section.movies.take(6)) {
        if (movie.id.isNotEmpty) ids.add(movie.id);
      }
    }
    if (ids.isEmpty) return;
    // Fire and forget — runs entirely in background
    _client.prefetchStreams(ids);
  }

  // Restore from SharedPreferences. Returns true if valid cache was found.
  Future<bool> _restoreFromCache() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw   = prefs.getString(_cacheKey);
      final ts    = prefs.getInt(_cacheAgeKey) ?? 0;
      if (raw == null || raw.isEmpty) return false;

      final decoded  = jsonDecode(raw) as Map<String, dynamic>;
      final sections = _parseSections(decoded);
      if (sections.isEmpty) return false;

      _sections = sections;
      _featured = sections.first.movies.take(10).toList();
      _loaded   = true;
      _error    = '';
      notifyListeners();

      return true; // always restore; _refreshSilently decides whether to re-fetch
    } catch (_) {
      return false;
    }
  }

  // Silent background refresh — doesn't show spinner, updates data when done
  Future<void> _refreshSilently() async {
    if (_refreshing) return;

    // Check if cache is fresh — skip network if < 6 hours old
    try {
      final prefs = await SharedPreferences.getInstance();
      final ts    = prefs.getInt(_cacheAgeKey) ?? 0;
      final age   = DateTime.now().millisecondsSinceEpoch - ts;
      if (age < _cacheTtlMs) return; // cache still fresh, no need to hit network
    } catch (_) {}

    _refreshing = true;
    notifyListeners();

    await _fetchAndStore();
    _prefetchTopStreams();

    _refreshing = false;
    notifyListeners();
  }

  // Fetch from network, update state, and write cache
  Future<void> _fetchAndStore() async {
    try {
      final res  = await _dio.get('$_base/batch-grid');
      final data = res.data as Map<String, dynamic>;

      final sections = _parseSections(data);
      if (sections.isEmpty) return;

      _sections = sections;
      _featured = sections.first.movies.take(10).toList();
      _loaded   = true;
      _error    = '';

      // Persist to cache
      try {
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString(_cacheKey, jsonEncode(data));
        await prefs.setInt(_cacheAgeKey, DateTime.now().millisecondsSinceEpoch);
      } catch (_) {}
    } catch (e) {
      if (!_loaded) {
        _error = 'Failed to load Uganda Cinema Plus. Check your connection.';
      }
      // If we already have cached data showing, silently swallow the error
    }
  }

  List<UgandaSection> _parseSections(Map<String, dynamic> data) {
    final rawSections = (data['sections'] as List? ?? []);
    final out = <UgandaSection>[];
    for (final s in rawSections) {
      final map    = s as Map<String, dynamic>;
      final title  = map['title']    as String? ?? '';
      final badge  = map['badge']    as String? ?? '';
      final pipe   = map['pipeType'] as String? ?? 'g';
      final pipeId = (map['pipeId']  as num?)?.toInt() ?? 0;
      final items  = (map['movies']  as List? ?? []);
      // Dedup only within this section (no cross-section dedup —
      // each genre/VJ section shows its own distinct movies)
      final seenInSection = <String>{};
      final movies = items
          .map((e) => _toMovie(e as Map<String, dynamic>))
          .where((m) => m.id.isNotEmpty && seenInSection.add(m.id))
          .take(24)
          .toList();
      if (movies.isNotEmpty) {
        out.add(UgandaSection(
          title:    title,
          movies:   movies,
          badge:    badge,
          pipeType: pipe,
          pipeId:   pipeId,
        ));
      }
    }
    return out;
  }

  Movie _toMovie(Map<String, dynamic> json) => Movie(
        id:          json['id']?.toString() ?? '',
        title:       json['title']?.toString() ?? 'Unknown',
        thumbnail:   json['thumbnail']?.toString(),
        summary:     json['vj'] != null ? 'By ${json['vj']}' : null,
        subjectType: 1,
      );

  Future<void> refresh() async {
    // Pull-to-refresh: force network even if cache is fresh
    _refreshing = false;
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setInt(_cacheAgeKey, 0); // invalidate TTL
    } catch (_) {}
    _refreshing = true;
    notifyListeners();
    await _fetchAndStore();
    _refreshing = false;
    notifyListeners();
  }

  // ── Search ──────────────────────────────────────────────────────────────────

  void beginSearch(String query) {
    _typedQuery = query;
    if (query.trim().isEmpty) {
      _searchResults = [];
      _lastQuery = '';
      _loadingSearch = false;
    } else {
      _searchResults = [];
      _lastQuery = query.trim();
      _loadingSearch = true;
    }
    notifyListeners();
  }

  Future<void> search(String query) async {
    if (query.trim().isEmpty) {
      _searchResults = [];
      _lastQuery = '';
      _loadingSearch = false;
      _typedQuery = '';
      notifyListeners();
      return;
    }
    if (query.trim() != _typedQuery.trim()) return;

    _lastQuery = query.trim();
    _loadingSearch = true;
    notifyListeners();

    try {
      _searchResults = await _client.search(query.trim());
    } catch (_) {
      _searchResults = [];
    }

    if (query.trim() == _typedQuery.trim()) {
      _loadingSearch = false;
      notifyListeners();
    }
  }

  void clearSearch() {
    _searchResults = [];
    _lastQuery = '';
    _typedQuery = '';
    _loadingSearch = false;
    notifyListeners();
  }
}
