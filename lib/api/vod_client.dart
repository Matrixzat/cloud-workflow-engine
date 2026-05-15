import 'dart:convert';
import 'package:dio/dio.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'models.dart';

String _u(List<int> c) => String.fromCharCodes(c);

class VodClient {
  static final VodClient _instance = VodClient._internal();
  factory VodClient() => _instance;
  VodClient._internal();

  static final String _base = _u([104,116,116,112,115,58,47,47,97,100,105,122,97,45,109,111,118,105,101,122,45,98,111,120,46,109,97,116,114,105,120,122,97,116,57,57,46,119,111,114,107,101,114,115,46,100,101,118]);

  late final Dio _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 12),
    receiveTimeout: const Duration(seconds: 20),
  ));

  // ── In-memory caches ───────────────────────────────────────────────────────
  static final Map<String, ({VodStream stream, int ts})> _streamMem  = {};
  static final Map<String, ({List<VodVersion> list, int ts})> _verMem = {};
  static final Map<String, ({List<VodEpisode> list, int ts})> _epMem  = {};

  static const _streamTtl = 8 * 60 * 60 * 1000;    // 8 hours
  static const _verTtl    = 30 * 60 * 1000;          // 30 minutes
  static const _epTtl     = 6 * 60 * 60 * 1000;     // 6 hours

  // ── /browse — VJs + genres ─────────────────────────────────────────────────
  Future<VodBrowse> getBrowse() async {
    final r = await _dio.get('$_base/browse');
    final data = r.data as Map<String, dynamic>;
    return VodBrowse.fromJson(data);
  }

  // ── /grid — movie listing by VJ or genre (cursor-based pagination) ──────────
  Future<MovieGridResult> getGrid({
    String pipeType = 'g',
    required int pipeId,
    String? lastFetchId,
    String? fallbackName,
  }) async {
    final params = <String, dynamic>{
      'pipe_type': pipeType,
      'pipe_id': pipeId,
    };
    if (lastFetchId != null && lastFetchId.isNotEmpty) {
      params['last_fetch_id'] = lastFetchId;
    }
    if (fallbackName != null && fallbackName.isNotEmpty) {
      params['name'] = fallbackName;
    }
    final r = await _dio.get('$_base/grid', queryParameters: params);
    final data = r.data as Map<String, dynamic>;
    final items = (data['movies'] as List? ?? []);
    return MovieGridResult(
      movies: items.map((e) => _toMovie(e as Map<String, dynamic>)).toList(),
      lastFetchId: data['last_fetch_id'] as String?,
      hasMore: (data['hasMore'] ?? data['has_more']) as bool? ?? false,
    );
  }

  // ── /search — search movies ─────────────────────────────────────────────────
  Future<List<Movie>> search(String query, {int page = 1}) async {
    final r = await _dio.get('$_base/search', queryParameters: {
      'q': query,
      'page': page,
    });
    final data = r.data as Map<String, dynamic>;
    final items = (data['movies'] as List? ?? []);
    return items.map((e) => _toMovie(e as Map<String, dynamic>)).toList();
  }

  // ── /stream — get direct CDN video URL (cached) ────────────────────────────
  Future<VodStream> getStream(String vid) async {
    final now = DateTime.now().millisecondsSinceEpoch;

    // 1. In-memory cache (instant)
    final mem = _streamMem[vid];
    if (mem != null && (now - mem.ts) < _streamTtl) return mem.stream;

    // 2. SharedPreferences disk cache (fast, survives restarts)
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw   = prefs.getString('vc_s_$vid');
      final ts    = prefs.getInt('vc_s_${vid}_t') ?? 0;
      if (raw != null && (now - ts) < _streamTtl) {
        final s = VodStream.fromJson(jsonDecode(raw) as Map<String, dynamic>);
        _streamMem[vid] = (stream: s, ts: ts);
        return s;
      }
    } catch (_) {}

    // 3. Network fetch
    final r    = await _dio.get('$_base/stream', queryParameters: {'vid': vid});
    final data = r.data as Map<String, dynamic>;
    if (data['error'] != null) throw Exception('Could not load video.');
    final s = VodStream.fromJson(data);

    // 4. Store in both caches
    _streamMem[vid] = (stream: s, ts: now);
    _saveStreamCache(vid, data, now);
    return s;
  }

  void _saveStreamCache(String vid, Map<String, dynamic> data, int ts) {
    SharedPreferences.getInstance().then((prefs) {
      prefs.setString('vc_s_$vid', jsonEncode(data));
      prefs.setInt('vc_s_${vid}_t', ts);
    }).catchError((_) {});
  }

  /// Returns stream from memory/disk cache only — no network call.
  /// Returns null if not cached at all. Ignores TTL (stale-ok) so the
  /// detail screen can show episodes immediately on re-open.
  Future<VodStream?> getCachedStream(String vid) async {
    if (vid.isEmpty) return null;
    final now = DateTime.now().millisecondsSinceEpoch;
    // 1. Memory (instant — stale ok)
    final mem = _streamMem[vid];
    if (mem != null) return mem.stream;
    // 2. Disk
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString('vc_s_$vid');
      if (raw != null) {
        final s = VodStream.fromJson(jsonDecode(raw) as Map<String, dynamic>);
        _streamMem[vid] = (stream: s, ts: now);
        return s;
      }
    } catch (_) {}
    return null;
  }

  // ── Prefetch stream URLs for a list of movie IDs silently ─────────────────
  Future<void> prefetchStreams(List<String> ids) async {
    for (final id in ids) {
      if (id.isEmpty) continue;
      final now = DateTime.now().millisecondsSinceEpoch;
      final mem = _streamMem[id];
      if (mem != null && (now - mem.ts) < _streamTtl) continue; // already cached
      try {
        await getStream(id);
        await Future.delayed(const Duration(milliseconds: 400));
      } catch (_) {}
    }
  }

  // ── /search — all VJ versions of the same movie title (cached) ─────────────
  Future<List<VodVersion>> getVersions(String title) async {
    if (title.isEmpty) return [];
    final now = DateTime.now().millisecondsSinceEpoch;

    // In-memory cache
    final mem = _verMem[title];
    if (mem != null && (now - mem.ts) < _verTtl) return mem.list;

    try {
      final r = await _dio.get('$_base/search', queryParameters: {'q': title, 'page': 1});
      final data = r.data as Map<String, dynamic>;
      final items = (data['movies'] as List? ?? []);
      final normalised = title.trim().toLowerCase();
      final versions = items
          .where((e) =>
              (e['title']?.toString() ?? '').trim().toLowerCase() == normalised &&
              (e['vj']?.toString() ?? '').isNotEmpty &&
              (e['id']?.toString() ?? '').isNotEmpty)
          .map((e) => VodVersion(
                id: e['id'].toString(),
                vjName: e['vj'].toString(),
                thumbnail: e['thumbnail']?.toString() ?? '',
              ))
          .toList();
      _verMem[title] = (list: versions, ts: now);
      return versions;
    } catch (_) {
      return [];
    }
  }

  // ── /episodes — fetch all episodes for a series (cached, stale-while-revalidate) ─
  // The API returns episode RANGES: [{"eps":"1-20","eps_range":"63605__63624"}, ...]
  // We expand each range into individual VodEpisode objects with sequential numbers.
  //
  // Strategy (fastest possible display):
  //   1. Memory hit → return instantly
  //   2. Disk hit (fresh) → return instantly, warm memory
  //   3. Disk hit (stale) → return stale immediately + refresh in background
  //   4. No cache → fetch from network synchronously
  Future<List<VodEpisode>> getEpisodes(String vid, String seriesCode) async {
    if (vid.isEmpty || seriesCode.isEmpty) return [];
    final cacheKey = '${seriesCode}_$vid';
    final now = DateTime.now().millisecondsSinceEpoch;

    // 1. In-memory cache (instant)
    final mem = _epMem[cacheKey];
    if (mem != null && (now - mem.ts) < _epTtl) return mem.list;

    // 2. Disk cache — return immediately whether fresh or stale
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString('vc_e_$cacheKey');
      final ts  = prefs.getInt('vc_e_${cacheKey}_t') ?? 0;
      if (raw != null) {
        final decoded  = jsonDecode(raw) as List<dynamic>;
        final episodes = _parseEpisodeList(decoded, seriesCode);
        _epMem[cacheKey] = (list: episodes, ts: ts);
        if ((now - ts) < _epTtl) {
          // Fresh — return immediately
          return episodes;
        }
        // Stale — return immediately and silently refresh in background
        _refreshEpisodesBackground(vid, seriesCode, cacheKey);
        return episodes;
      }
    } catch (_) {}

    // 3. No cache at all — must fetch from network synchronously
    return _fetchEpisodesNetwork(vid, seriesCode, cacheKey);
  }

  void _refreshEpisodesBackground(String vid, String seriesCode, String cacheKey) {
    _fetchEpisodesNetwork(vid, seriesCode, cacheKey).catchError((_) {});
  }

  Future<List<VodEpisode>> _fetchEpisodesNetwork(String vid, String seriesCode, String cacheKey) async {
    final now = DateTime.now().millisecondsSinceEpoch;
    try {
      final r = await _dio.get('$_base/episodes', queryParameters: {
        'vid': vid,
        'scode': seriesCode,
        'no': '1',
      });
      final data = r.data;
      final List<dynamic> rawList = data is List ? data : [];
      if (rawList.isEmpty) return _epMem[cacheKey]?.list ?? [];
      final episodes = _parseEpisodeList(rawList, seriesCode);
      _epMem[cacheKey] = (list: episodes, ts: now);
      _saveEpisodesCache(cacheKey, rawList, now);
      return episodes;
    } catch (_) {
      return _epMem[cacheKey]?.list ?? [];
    }
  }

  List<VodEpisode> _parseEpisodeList(List<dynamic> rawList, String seriesCode) {
    final episodes = <VodEpisode>[];
    int epNum = 1;
    for (final rangeObj in rawList) {
      final rangeStr = rangeObj['eps_range']?.toString() ?? '';
      final parts = rangeStr.split('__');
      if (parts.length != 2) continue;
      final start = int.tryParse(parts[0].trim()) ?? 0;
      final end   = int.tryParse(parts[1].trim()) ?? 0;
      if (start <= 0 || end <= 0 || end < start) continue;
      for (int vidNum = start; vidNum <= end; vidNum++) {
        episodes.add(VodEpisode(
          vid: vidNum.toString(),
          episodeNumber: epNum++,
          seriesCode: seriesCode,
        ));
      }
    }
    return episodes;
  }

  void _saveEpisodesCache(String cacheKey, List<dynamic> rawList, int ts) {
    SharedPreferences.getInstance().then((prefs) {
      prefs.setString('vc_e_$cacheKey', jsonEncode(rawList));
      prefs.setInt('vc_e_${cacheKey}_t', ts);
    }).catchError((_) {});
  }

  // ── Map worker movie JSON → app Movie model ────────────────────────────────
  Movie _toMovie(Map<String, dynamic> json) {
    return Movie(
      id: json['id']?.toString() ?? '',
      title: json['title']?.toString() ?? 'Unknown',
      thumbnail: json['thumbnail']?.toString(),
      summary: json['vj'] != null ? 'By ${json['vj']}' : null,
      subjectType: 1,
    );
  }
}

// ── Data models ───────────────────────────────────────────────────────────────

class MovieGridResult {
  final List<Movie> movies;
  final String? lastFetchId;
  final bool hasMore;
  const MovieGridResult({
    required this.movies,
    this.lastFetchId,
    required this.hasMore,
  });
}

class VodVersion {
  final String id;
  final String vjName;
  final String thumbnail;
  const VodVersion({required this.id, required this.vjName, required this.thumbnail});
}

class VodVj {
  final int id;
  final String name;
  final String icon;
  const VodVj({required this.id, required this.name, required this.icon});
  factory VodVj.fromJson(Map<String, dynamic> j) => VodVj(
        id: j['id'] as int,
        name: j['name'] as String,
        icon: j['icon'] as String,
      );
}

class VodGenre {
  final int id;
  final String name;
  const VodGenre({required this.id, required this.name});
  factory VodGenre.fromJson(Map<String, dynamic> j) => VodGenre(
        id: j['id'] as int,
        name: j['name'] as String,
      );
}

class VodBrowse {
  final List<VodVj> vjs;
  final List<VodGenre> genres;
  const VodBrowse({required this.vjs, required this.genres});
  factory VodBrowse.fromJson(Map<String, dynamic> j) => VodBrowse(
        vjs: (j['vj'] as List? ?? [])
            .map((e) => VodVj.fromJson(e as Map<String, dynamic>))
            .toList(),
        genres: (j['genre'] as List? ?? [])
            .map((e) => VodGenre.fromJson(e as Map<String, dynamic>))
            .toList(),
      );
}

class VodStream {
  final String url;
  final String title;
  final String vj;
  final String size;
  final String duration;
  final String image;
  final String description;
  final String seriesCode;
  final String categoryId;
  final String type;

  const VodStream({
    required this.url,
    required this.title,
    required this.vj,
    required this.size,
    required this.duration,
    required this.image,
    this.description = '',
    this.seriesCode = '',
    this.categoryId = '',
    this.type = '',
  });

  bool get isSeries => seriesCode.isNotEmpty;

  factory VodStream.fromJson(Map<String, dynamic> j) {
    String url = j['url']?.toString() ?? '';
    if (url.startsWith('//')) url = 'https:$url';
    url = url.replaceAll(' ', '%20');
    return VodStream(
      url: url,
      title: j['title']?.toString() ?? '',
      vj: j['vj']?.toString() ?? '',
      size: j['size']?.toString() ?? '',
      duration: j['duration']?.toString() ?? '',
      image: j['image']?.toString() ?? '',
      description: j['description']?.toString() ?? '',
      seriesCode: j['series_code']?.toString() ?? '',
      categoryId: j['category_id']?.toString() ?? '',
      type: j['type']?.toString() ?? '',
    );
  }

  Map<String, dynamic> toJson() => {
    'url': url,
    'title': title,
    'vj': vj,
    'size': size,
    'duration': duration,
    'image': image,
    'description': description,
    'series_code': seriesCode,
    'category_id': categoryId,
    'type': type,
  };
}

class VodEpisode {
  final String vid;
  final int episodeNumber;
  final String title;
  final String description;
  final String vj;
  final String image;
  final String duration;
  final String size;
  final String playingUrl;
  final String seriesCode;
  final String categoryId;
  final String type;

  const VodEpisode({
    required this.vid,
    this.episodeNumber = 0,
    this.title = '',
    this.description = '',
    this.vj = '',
    this.image = '',
    this.duration = '',
    this.size = '',
    this.playingUrl = '',
    this.seriesCode = '',
    this.categoryId = '',
    this.type = '',
  });
}
