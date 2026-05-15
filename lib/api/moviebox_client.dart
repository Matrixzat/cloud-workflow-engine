import 'dart:async';
import 'dart:io';
import 'dart:math';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:dio_cookie_manager/dio_cookie_manager.dart';
import 'package:cookie_jar/cookie_jar.dart';
import 'package:flutter/services.dart';
import 'models.dart';
import 'tmdb_service.dart';

class MovieBoxClient {
  static final MovieBoxClient _instance = MovieBoxClient._internal();
  factory MovieBoxClient() => _instance;
  MovieBoxClient._internal() { _init(); }

  // Runtime-reconstructed — not visible as a literal in the DEX
  static String _s(List<int> c) => String.fromCharCodes(c);
  String _primaryHost = _s([104,53,46,97,111,110,101,114,111,111,109,46,99,111,109]);
  String get _hostUrl => 'https://$_primaryHost';
  bool _hostsLoaded = false;

  static const MethodChannel _secCh = MethodChannel('com.adiza.moviezbox/media');

  late Dio _dio;
  final CookieJar _cookieJar = CookieJar();
  bool _initialized = false;
  DateTime? _initTime;
  Completer<void>? _initCompleter;
  final Random _random = Random();

  final Map<String, Map<String, dynamic>> _detailCache = {};

  static const List<String> _saIPs = [
    '41.0.0.1', '41.76.108.1', '102.65.0.1', '154.0.0.1',
    '196.21.0.1', '197.80.0.1', '41.0.0.2', '41.76.108.2',
  ];

  String _randomSAIP() => _saIPs[_random.nextInt(_saIPs.length)];

  Map<String, String> _headers({String? host, String? referer}) {
    final ip = _randomSAIP();
    return {
      'User-Agent': 'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
      'Accept': 'application/json',
      'Accept-Language': 'en-ZA,en;q=0.9,en-US;q=0.8',
      'X-Client-Info': '{"timezone":"Africa/Johannesburg"}',
      'Host': host ?? _primaryHost,
      'Referer': referer ?? _hostUrl,
      'Origin': _hostUrl,
      'Connection': 'keep-alive',
      'X-Forwarded-For': ip,
      'CF-Connecting-IP': ip,
      'X-Real-IP': ip,
      'True-Client-IP': ip,
    };
  }

  void _init() {
    _dio = Dio(BaseOptions(connectTimeout: const Duration(seconds: 30), receiveTimeout: const Duration(seconds: 60)));

    _dio.httpClientAdapter = IOHttpClientAdapter(
      createHttpClient: () {
        final client = HttpClient();
        client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
        return client;
      },
    );

    _dio.interceptors.add(CookieManager(_cookieJar));
  }

  static final String _relayBase = _s([104,116,116,112,115,58,47,47,97,100,105,122,97,45,109,111,118,105,101,122,45,98,111,120,46,109,97,116,114,105,120,122,97,116,57,57,46,119,111,114,107,101,114,115,46,100,101,118,47,114,101,108,97,121]);

  Future<void> _loadHosts() async {
    if (_hostsLoaded) return;
    try {
      final primary = await _secCh.invokeMethod<String>('getApiHost');
      if (primary != null && primary.isNotEmpty) _primaryHost = primary;
    } catch (_) {}
    _hostsLoaded = true;
  }

  Future<String> _getCookieString(String url) async {
    try {
      final cookies = await _cookieJar.loadForRequest(Uri.parse(url));
      return cookies.map((c) => '${c.name}=${c.value}').join('; ');
    } catch (_) { return ''; }
  }

  Future<Response?> _relayGet(String targetUrl, {Map<String, dynamic>? params, Map<String, String>? extra, String? referer}) async {
    try {
      String fullUrl = targetUrl;
      if (params != null && params.isNotEmpty) {
        final qs = params.entries.map((e) => '${Uri.encodeComponent(e.key)}=${Uri.encodeComponent(e.value.toString())}').join('&');
        fullUrl += '?$qs';
      }
      final relayUrl = '$_relayBase?url=${Uri.encodeComponent(fullUrl)}';
      final cookieStr = await _getCookieString(targetUrl);
      final headers = <String, dynamic>{
        'Accept': 'application/json',
      };
      if (cookieStr.isNotEmpty) headers['X-Forward-Cookie'] = cookieStr;
      // Forward a custom Referer so the Worker sends it to the upstream API.
      // The relay sets X-Forward-Referer → Referer on the upstream request.
      if (referer != null && referer.isNotEmpty) headers['X-Forward-Referer'] = referer;
      final res = await _dio.get(relayUrl, options: Options(headers: headers));
      final setCookie = res.headers.value('x-set-cookie');
      if (setCookie != null && setCookie.isNotEmpty) {
        try {
          final cookie = Cookie.fromSetCookieValue(setCookie);
          await _cookieJar.saveFromResponse(Uri.parse(targetUrl), [cookie]);
        } catch (_) {}
      }
      return res;
    } catch (_) { return null; }
  }

  Future<void> _ensureInit({bool forceRefresh = false}) async {
    // Session cookies expire — force refresh after 15 minutes so hasResource never stays stale.
    if (_initialized && !forceRefresh) {
      final age = _initTime == null ? 9999 : DateTime.now().difference(_initTime!).inMinutes;
      if (age < 15) return;
      // Session too old — drop it and re-init.
      _initialized = false;
      _initCompleter = null;
      _cookieJar.deleteAll();
    }
    if (_initialized && !forceRefresh) return;
    // Mutex: if another call is already initialising, wait for it instead of running again.
    if (_initCompleter != null && !forceRefresh) return _initCompleter!.future;
    _initCompleter = Completer<void>();
    try {
      await _loadHosts();
      // Establish session cookie — try relay first, then direct (both attempted so CookieManager captures Set-Cookie).
      // Without this cookie the download endpoint returns hasResource:false.
      final initUrl = '$_hostUrl/wefeed-h5-bff/app/get-latest-app-pkgs';
      try {
        await _relayGet(initUrl, params: {'app_name': 'moviebox'});
      } catch (_) {}
      // Always also do a direct call — CookieManager auto-saves Set-Cookie headers from direct responses.
      try {
        await _dio.get(initUrl, queryParameters: {'app_name': 'moviebox'}, options: Options(headers: _headers()));
      } catch (_) {}
      _initialized = true;
      _initTime = DateTime.now();
      _initCompleter!.complete();
      _initCompleter = null;
    } catch (e) {
      _initCompleter!.completeError(e);
      _initCompleter = null;
      rethrow;
    }
  }

  dynamic _data(Response res) {
    final d = res.data;
    if (d is Map) return d['data'] ?? d;
    return d;
  }

  Future<Response> _get(String path, {Map<String, dynamic>? params, Map<String, String>? extra, String? host, String? referer}) async {
    await _ensureInit();
    final h = {..._headers(host: host, referer: referer), ...?extra};
    return await _dio.get(path, queryParameters: params, options: Options(headers: h));
  }

  Future<Response> _post(String path, dynamic body, {Map<String, String>? extra}) async {
    await _ensureInit();
    final h = {..._headers(), ...?extra, 'Content-Type': 'application/json'};
    return await _dio.post(path, data: body, options: Options(headers: h));
  }

  List<Movie> _parseSubjects(dynamic raw) {
    if (raw == null) return [];
    if (raw is List) return raw.map((e) => Movie.fromJson(Map<String, dynamic>.from(e))).toList();
    return [];
  }

  Map<String, String> _parseCaptions(dynamic captions) {
    final map = <String, String>{};
    if (captions == null) return map;
    if (captions is List) {
      for (final c in captions) {
        if (c is Map) {
          // Try every known field name the API has ever used for language and URL
          final lang = (c['lanName'] ?? c['language'] ?? c['lang'] ?? c['lan'] ?? c['name'] ?? c['label'] ?? c['title'] ?? c['languageName'] ?? '').toString().trim();
          final url = (c['url'] ?? c['src'] ?? c['file'] ?? c['link'] ?? c['path'] ?? '').toString().trim();
          if (lang.isNotEmpty && url.isNotEmpty) map[lang] = url;
        }
      }
    } else if (captions is Map) {
      captions.forEach((k, v) {
        if (k != null && v != null) map[k.toString()] = v.toString();
      });
    }
    return map;
  }

  Future<String?> fetchSubtitleContent(String url) async {
    // Try 1: No special headers — many CDNs serve subtitles publicly
    try {
      final res = await _dio.get(url, options: Options(
        responseType: ResponseType.plain,
        headers: {'User-Agent': 'Mozilla/5.0', 'Accept': '*/*'},
        sendTimeout: const Duration(seconds: 15),
        receiveTimeout: const Duration(seconds: 20),
      ));
      final text = res.data?.toString();
      if (text != null && text.trim().isNotEmpty) return text;
    } catch (_) {}
    // Try 2: okhttp headers with aoneroom Referer
    try {
      final res = await _dio.get(url, options: Options(
        responseType: ResponseType.plain,
        headers: {
          'User-Agent': 'okhttp/4.12.0',
          'Referer': _hostUrl,
          'Origin': _hostUrl,
          'Accept': '*/*',
        },
        sendTimeout: const Duration(seconds: 15),
        receiveTimeout: const Duration(seconds: 20),
      ));
      final text = res.data?.toString();
      if (text != null && text.trim().isNotEmpty) return text;
    } catch (_) {}
    // Try 3: fmoviesunblocked Referer
    try {
      final res = await _dio.get(url, options: Options(
        responseType: ResponseType.plain,
        headers: {
          'User-Agent': 'okhttp/4.12.0',
          'Referer': 'https://fmoviesunblocked.net/',
          'Origin': 'https://fmoviesunblocked.net',
          'Accept': '*/*',
        },
        sendTimeout: const Duration(seconds: 15),
        receiveTimeout: const Duration(seconds: 20),
      ));
      final text = res.data?.toString();
      if (text != null && text.trim().isNotEmpty) return text;
    } catch (_) {}
    try {
      final relayUrl = '$_relayBase?url=${Uri.encodeComponent(url)}';
      final res = await _dio.get(relayUrl, options: Options(
        responseType: ResponseType.plain,
        sendTimeout: const Duration(seconds: 15),
        receiveTimeout: const Duration(seconds: 20),
      ));
      return res.data?.toString();
    } catch (_) {
      return null;
    }
  }

  Future<List<HomeSection>> getHomepage() async {
    final res = await _get('$_hostUrl/wefeed-h5-bff/web/home');
    final data = _data(res);
    if (data == null) return [];
    final List<HomeSection> sections = [];
    final operatingList = data['operatingList'] as List? ?? [];
    for (final section in operatingList) {
      final type = section['type'] as String? ?? '';
      if (!type.startsWith('SUBJECTS')) continue;
      final title = section['title'] as String? ?? '';
      if (title.isEmpty) continue;
      final subjects = section['subjects'] as List? ?? [];
      if (subjects.isEmpty) continue;
      final movies = _parseSubjects(subjects);
      if (movies.isNotEmpty) {
        sections.add(HomeSection(title: title, items: movies, opId: section['opId']?.toString()));
      }
    }
    return sections;
  }

  Future<List<Movie>> getTrending({int page = 0, int perPage = 20}) async {
    final res = await _get('$_hostUrl/wefeed-h5-bff/web/subject/trending', params: {'page': page, 'perPage': perPage, 'uid': '5591179548772780352'});
    final data = _data(res);
    return _parseSubjects(data['subjectList'] ?? data['items'] ?? data);
  }

  Future<List<Movie>> search(String query, {int page = 1, int perPage = 24, int subjectType = 0}) async {
    final res = await _post('$_hostUrl/wefeed-h5-bff/web/subject/search', {'keyword': query, 'page': page, 'perPage': perPage, 'subjectType': subjectType});
    final data = _data(res);
    List<Movie> results = _parseSubjects(data['items'] ?? data['subjects'] ?? data['subjectList']);
    if (subjectType != 0) results = results.where((m) => m.subjectType == subjectType).toList();
    return results;
  }

  Future<List<Movie>> getGenre(String keyword, {int page = 1, int perPage = 20, int subjectType = 0}) async {
    return search(keyword, page: page, perPage: perPage, subjectType: subjectType);
  }

  Future<List<Movie>> getNewReleases({int page = 1, int perPage = 20}) async {
    final raw = await search('2026', page: page, perPage: perPage);
    final seen = <String>{};
    final unique = raw.where((m) {
      if (seen.contains(m.id)) return false;
      seen.add(m.id);
      final y = int.tryParse(m.year ?? '');
      return y == 2026;
    }).toList();
    return unique.take(perPage).toList();
  }

  Future<Movie?> getInfo(String movieId) async {
    final res = await _get('$_hostUrl/wefeed-h5-bff/web/subject/detail', params: {'subjectId': movieId});
    final data = _data(res);
    final subject = data['subject'] ?? data;
    if (subject == null) return null;
    // Cache the raw detail response so getSources() can reuse it without a second network call
    _detailCache[movieId] = Map<String, dynamic>.from(data);
    // Merge top-level data fields into subject so cast (stars), resource, etc. are all accessible
    final merged = <String, dynamic>{...Map<String, dynamic>.from(data), ...Map<String, dynamic>.from(subject)};
    return Movie.fromJson(merged);
  }

  Future<List<SeasonInfo>> getEpisodes(String movieId) async {
    try {
      Map<String, dynamic> data;
      if (_detailCache.containsKey(movieId)) {
        data = _detailCache[movieId]!;
      } else {
        final res = await _get('$_hostUrl/wefeed-h5-bff/web/subject/detail', params: {'subjectId': movieId});
        data = _data(res);
        _detailCache[movieId] = Map<String, dynamic>.from(data);
      }

      // Try API seasons first
      final resource = data['resource'] as Map?;
      final seasons = resource?['seasons'] as List? ?? [];
      final result = seasons
          .where((s) => (s['se'] as int? ?? 0) > 0 && (s['maxEp'] as int? ?? 0) > 0)
          .map((s) => SeasonInfo.fromResource(Map<String, dynamic>.from(s)))
          .toList();
      result.sort((a, b) => a.season.compareTo(b.season));
      if (result.isNotEmpty) return result;

      // API seasons are always empty — fall back to TMDB for full episode/season data
      final subject = data['subject'] ?? data;
      final title = subject?['title']?.toString() ?? '';
      if (title.isEmpty) return [];
      final tmdbSeasons = await TmdbService().getTvSeasons(title);
      return tmdbSeasons;
    } catch (_) {
      return [];
    }
  }

  Future<List<MovieSource>> getSources(String movieId, {int season = 0, int episode = 0, bool retried = false}) async {
    String lastError = '';
    String lastResponse = '';

    // Step 1: Get detailPath for the correct Referer.
    // Use cached detail data from getInfo() if available — avoids a second network round-trip.
    String referer = _hostUrl;
    String detailPath = '';
    try {
      Map<String, dynamic> infoData;
      if (_detailCache.containsKey(movieId)) {
        infoData = _detailCache[movieId]!;
      } else {
        final infoRes = await _get('$_hostUrl/wefeed-h5-bff/web/subject/detail', params: {'subjectId': movieId});
        infoData = _data(infoRes);
        _detailCache[movieId] = Map<String, dynamic>.from(infoData);
      }
      final subject = infoData['subject'] ?? infoData;
      detailPath = subject?['detailPath']?.toString() ?? '';
      if (detailPath.isNotEmpty) referer = '$_hostUrl/movies/$detailPath';
    } catch (e) {
      lastError = 'Detail: $e';
    }

    // The download and play endpoints are geo-gated on the server side — the Cloudflare Worker relay
    // sits in a US/EU datacenter and the API returns 403 "invalid region" for it. But the Worker
    // then wraps that body in an HTTP 200, so _relayGet never throws and returns the 403-body
    // response, stopping the fallback to direct. Fix: always go direct for /download and /play.
    // African IPs (Nigeria, Ghana, SA, etc.) are whitelisted by the API — direct from the phone works.
    // The Referer header is MANDATORY — without it the API returns hasResource:false.

    final baseExtra = <String, String>{'Referer': referer, 'Origin': _hostUrl};

    // Helper: attempt one /download param combo via direct call; returns [] on failure/no results.
    Future<List<MovieSource>> tryDownload(Map<String, dynamic> params) async {
      try {
        final res = await _get('$_hostUrl/wefeed-h5-bff/web/subject/download',
            params: params, extra: baseExtra);
        final data = _data(res);
        lastResponse = 'dl:hasResource=${data['hasResource']}';
        final downloads = data['downloads'] as List?;
        final captions = _parseCaptions(data['captions'] ?? data['subtitles']);
        if (downloads != null && downloads.isNotEmpty) {
          final sources = downloads
              .map((d) => MovieSource.fromJson(Map<String, dynamic>.from(d), subtitleUrls: captions, referer: referer))
              .where((s) => s.directUrl.isNotEmpty)
              .toList();
          if (sources.isNotEmpty) return sources;
        }
      } catch (e) { lastError = 'Download: $e'; }
      return [];
    }

    // Helper: attempt /play endpoint via direct call; returns [] on failure/no results.
    Future<List<MovieSource>> tryPlay() async {
      try {
        final res = await _get('$_hostUrl/wefeed-h5-bff/web/subject/play',
            params: {'subjectId': movieId, 'se': season == 0 ? 1 : season, 'ep': episode == 0 ? 1 : episode},
            extra: baseExtra);
        final data = _data(res);
        lastResponse = 'play:hasResource=${data['hasResource']}';
        final captions = _parseCaptions(data['captions'] ?? data['subtitles']);
        final streams = data['streams'] as List?;
        if (streams != null && streams.isNotEmpty) {
          final sources = streams.map((s) {
            final m = Map<String, dynamic>.from(s);
            final quality = (m['resolutions'] ?? m['resolution'] ?? m['quality'] ?? 'Auto').toString();
            final url = (m['url'] ?? '').toString();
            return MovieSource(id: movieId, quality: quality, directUrl: url, subtitleUrls: captions, referer: referer);
          }).where((s) => s.directUrl.isNotEmpty).toList();
          if (sources.isNotEmpty) return sources;
        }
        final topUrl = data['url'] ?? data['playUrl'] ?? data['mediaUrl'];
        if (topUrl != null && topUrl.toString().isNotEmpty) {
          return [MovieSource(id: movieId, quality: data['quality']?.toString() ?? 'Auto', directUrl: topUrl.toString(), subtitleUrls: captions, referer: referer)];
        }
        final downloads = data['downloads'] as List?;
        if (downloads != null && downloads.isNotEmpty) {
          final sources = downloads
              .map((d) => MovieSource.fromJson(Map<String, dynamic>.from(d), subtitleUrls: captions, referer: referer))
              .where((s) => s.directUrl.isNotEmpty).toList();
          if (sources.isNotEmpty) return sources;
        }
        final rawJson = data.toString();
        final match = RegExp(r'https?://\S+\.(?:m3u8|mp4)\S*').firstMatch(rawJson);
        if (match != null) {
          return [MovieSource(id: movieId, quality: 'Auto', directUrl: match.group(0)!, subtitleUrls: captions, referer: referer)];
        }
      } catch (e) { lastError = 'Play: $e'; }
      return [];
    }

    // ── Fire primary /download combo AND /play simultaneously ──────────────────
    // Most movies resolve on the very first /download attempt. By racing it against
    // /play in parallel we cut the cold-path from two sequential round-trips to one.
    final primary = await Future.wait([
      tryDownload({'subjectId': movieId, 'se': season, 'ep': episode}),
      tryPlay(),
    ]);
    if (primary[0].isNotEmpty) return primary[0];
    if (primary[1].isNotEmpty) return primary[1];

    // ── Fallback: remaining /download param combos (sequential, rarely needed) ─
    final fallbackCombos = <Map<String, dynamic>>[
      if (season == 0 && episode == 0) ...[
        {'subjectId': movieId, 'se': 1, 'ep': 1},
        {'subjectId': movieId},
      ],
      if (season > 0 && episode == 0) {'subjectId': movieId, 'se': season, 'ep': 1},
      if (season > 0 && episode > 0) {'subjectId': movieId, 'se': season, 'ep': episode, 'uid': '5591179548772780352'},
    ];
    for (final combo in fallbackCombos) {
      final result = await tryDownload(combo);
      if (result.isNotEmpty) return result;
    }

    // If everything returned hasResource=false and we haven't retried yet, the session
    // cookie is likely stale. Force a fresh session and try once more.
    if (!retried && (lastResponse.contains('hasResource=false') || lastResponse.isEmpty)) {
      await _ensureInit(forceRefresh: true);
      return getSources(movieId, season: season, episode: episode, retried: true);
    }

    throw Exception('No streams. Last: $lastError | Resp: $lastResponse');
  }

  Future<List<Movie>> getPopularSearches() async {
    try {
      final res = await _get('$_hostUrl/wefeed-h5-bff/web/subject/everyone-search');
      final data = _data(res);
      final items = data['items'] ?? data['subjects'] ?? data['subjectList'] ?? data;
      return _parseSubjects(items is List ? items : null);
    } catch (_) {
      return [];
    }
  }
}
