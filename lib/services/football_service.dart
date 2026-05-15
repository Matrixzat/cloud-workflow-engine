import 'dart:convert';
import 'package:dio/dio.dart';

String _u(List<int> c) => String.fromCharCodes(c);

class FootballMatch {
  final String id;
  final String title;
  final String category;
  final DateTime date;
  final bool popular;
  final String homeTeam;
  final String awayTeam;
  final String? homeBadgeUrl;
  final String? awayBadgeUrl;
  final String? poster;
  final List<FootballSource> sources;

  FootballMatch({
    required this.id,
    required this.title,
    required this.category,
    required this.date,
    required this.popular,
    required this.homeTeam,
    required this.awayTeam,
    this.homeBadgeUrl,
    this.awayBadgeUrl,
    this.poster,
    required this.sources,
  });

  bool get isLive {
    final now = DateTime.now();
    final diff = now.difference(date);
    return diff.inMinutes >= -5 && diff.inMinutes <= 130;
  }

  bool get isUpcoming => date.isAfter(DateTime.now().add(const Duration(minutes: 5)));

  /// Build a badge URL through the worker so the real origin is never exposed.
  static String? _badgeUrl(String? raw, String workerBase) {
    if (raw == null || raw.isEmpty) return null;
    // raw is already a full worker URL if it came back rewritten from the worker;
    // otherwise it is the raw badge token — wrap it.
    if (raw.startsWith('http')) return raw;
    return '$workerBase/image/$raw.webp';
  }

  factory FootballMatch.fromJson(Map<String, dynamic> j, String workerBase) {
    final teams = j['teams'] as Map<String, dynamic>? ?? {};
    final home  = teams['home'] as Map<String, dynamic>? ?? {};
    final away  = teams['away'] as Map<String, dynamic>? ?? {};

    final rawSources = j['sources'] as List<dynamic>? ?? [];
    final sources = rawSources
        .map((s) => FootballSource.fromJson(s as Map<String, dynamic>))
        .toList();

    // poster may come back already rewritten by the worker, or as a relative path
    String? poster;
    final p = j['poster'] as String?;
    if (p != null && p.isNotEmpty) {
      if (p.startsWith('http')) {
        poster = p;
      } else if (p.startsWith('/api/images/proxy/')) {
        poster = '$workerBase/image/${p.substring('/api/images/proxy/'.length)}';
      } else {
        poster = p;
      }
    }

    return FootballMatch(
      id:           j['id']?.toString() ?? '',
      title:        j['title']?.toString() ?? '',
      category:     j['category']?.toString() ?? 'football',
      date:         DateTime.fromMillisecondsSinceEpoch(
                      (j['date'] as int? ?? 0), isUtc: true).toLocal(),
      popular:      j['popular'] as bool? ?? false,
      homeTeam:     home['name']?.toString() ?? '',
      awayTeam:     away['name']?.toString() ?? '',
      homeBadgeUrl: _badgeUrl(home['badge']?.toString(), workerBase),
      awayBadgeUrl: _badgeUrl(away['badge']?.toString(), workerBase),
      poster:       poster,
      sources:      sources,
    );
  }
}

class FootballSource {
  final String source;
  final String id;
  const FootballSource({required this.source, required this.id});

  factory FootballSource.fromJson(Map<String, dynamic> j) =>
      FootballSource(source: j['source']?.toString() ?? '', id: j['id']?.toString() ?? '');
}

class FootballStream {
  final String id;
  final int streamNo;
  final String language;
  final bool hd;
  final String embedUrl;
  final String source;
  final int viewers;

  const FootballStream({
    required this.id,
    required this.streamNo,
    required this.language,
    required this.hd,
    required this.embedUrl,
    required this.source,
    required this.viewers,
  });

  factory FootballStream.fromJson(Map<String, dynamic> j) => FootballStream(
        id:        j['id']?.toString() ?? '',
        streamNo:  j['streamNo'] as int? ?? 1,
        language:  j['language']?.toString() ?? '',
        hd:        j['hd'] as bool? ?? false,
        embedUrl:  j['embedUrl']?.toString() ?? '',
        source:    j['source']?.toString() ?? '',
        viewers:   j['viewers'] as int? ?? 0,
      );

  String get label {
    final parts = <String>[];
    if (language.isNotEmpty) parts.add(language);
    parts.add('Stream $streamNo');
    if (hd) parts.add('HD');
    return parts.join(' · ');
  }
}

class FootballService {
  // Football routes are now merged into the Uganda worker — single URL for everything
  static final _base = _u([104,116,116,112,115,58,47,47,97,100,105,122,97,45,109,111,118,105,101,122,45,98,111,120,46,109,97,116,114,105,120,122,97,116,57,57,46,119,111,114,107,101,114,115,46,100,101,118,47,102,111,111,116,98,97,108,108]);

  final _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 12),
    receiveTimeout: const Duration(seconds: 15),
    headers: const {
      'Accept': 'application/json, text/plain, */*',
    },
  ));

  Future<List<FootballMatch>> fetchMatches() async {
    final res  = await _dio.get('$_base/matches');
    final raw  = res.data;
    List<dynamic> list;
    if (raw is List) {
      list = raw;
    } else if (raw is String) {
      list = jsonDecode(raw) as List<dynamic>;
    } else {
      return [];
    }
    final matches = list
        .map((e) => FootballMatch.fromJson(e as Map<String, dynamic>, _base))
        .where((m) => m.sources.isNotEmpty)
        .toList();
    matches.sort((a, b) {
      final aScore = (a.popular ? 2 : 0) + (a.isLive ? 1 : 0);
      final bScore = (b.popular ? 2 : 0) + (b.isLive ? 1 : 0);
      if (bScore != aScore) return bScore.compareTo(aScore);
      return a.date.compareTo(b.date);
    });
    return matches;
  }

  Future<List<FootballStream>> fetchStreams(FootballSource src) async {
    final res  = await _dio.get('$_base/stream/${src.source}/${src.id}');
    final raw  = res.data;
    List<dynamic> list;
    if (raw is List) {
      list = raw;
    } else if (raw is String) {
      list = jsonDecode(raw) as List<dynamic>;
    } else {
      return [];
    }
    return list
        .map((e) => FootballStream.fromJson(e as Map<String, dynamic>))
        .where((s) => s.embedUrl.isNotEmpty)
        .toList();
  }
}
