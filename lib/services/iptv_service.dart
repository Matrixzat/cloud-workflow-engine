import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

class IptvChannel {
  final String id;
  final String name;
  final String logo;
  final String streamUrl;
  final String quality;
  final String category;

  const IptvChannel({
    required this.id,
    required this.name,
    required this.logo,
    required this.streamUrl,
    required this.quality,
    required this.category,
  });
}

class IptvCategory {
  final String id;
  final String label;
  final IconData icon;
  final int color;

  const IptvCategory({
    required this.id,
    required this.label,
    required this.icon,
    required this.color,
  });
}

const kIptvCategories = [
  IptvCategory(id: 'news',          label: 'News',          icon: Icons.newspaper_rounded,         color: 0xFF1565C0),
  IptvCategory(id: 'kids',          label: 'Kids',          icon: Icons.child_care_rounded,        color: 0xFFE91E63),
  IptvCategory(id: 'sports',        label: 'Sports',        icon: Icons.sports_soccer_rounded,     color: 0xFF2E7D32),
  IptvCategory(id: 'entertainment', label: 'Entertainment', icon: Icons.theater_comedy_rounded,    color: 0xFF6A1B9A),
  IptvCategory(id: 'music',         label: 'Music',         icon: Icons.music_note_rounded,        color: 0xFFAD1457),
  IptvCategory(id: 'movies',        label: 'Movies',        icon: Icons.movie_rounded,             color: 0xFFBF360C),
  IptvCategory(id: 'general',       label: 'General',       icon: Icons.tv_rounded,                color: 0xFF37474F),
  IptvCategory(id: 'documentary',   label: 'Documentary',   icon: Icons.public_rounded,            color: 0xFF00695C),
  IptvCategory(id: 'comedy',        label: 'Comedy',        icon: Icons.sentiment_very_satisfied_rounded, color: 0xFFF57F17),
  IptvCategory(id: 'animation',     label: 'Animation',     icon: Icons.animation_rounded,         color: 0xFF4527A0),
];

class IptvService {
  static const _base = 'https://iptv-org.github.io/iptv/categories';
  static final Map<String, List<IptvChannel>> _cache = {};

  static Future<List<IptvChannel>> fetchCategory(String categoryId) async {
    if (_cache.containsKey(categoryId)) return _cache[categoryId]!;

    final url = '$_base/$categoryId.m3u';
    final resp = await http.get(Uri.parse(url)).timeout(const Duration(seconds: 15));
    if (resp.statusCode != 200) return [];

    final channels = _parseM3u(resp.body, categoryId);
    _cache[categoryId] = channels;
    return channels;
  }

  static List<IptvChannel> _parseM3u(String raw, String category) {
    final lines = raw.split('\n');
    final channels = <IptvChannel>[];

    for (int i = 0; i < lines.length - 1; i++) {
      final line = lines[i].trim();
      if (!line.startsWith('#EXTINF')) continue;

      final streamLine = lines[i + 1].trim();
      if (streamLine.isEmpty || streamLine.startsWith('#')) continue;

      final id      = _attr(line, 'tvg-id') ?? '';
      final logo    = _attr(line, 'tvg-logo') ?? '';
      final quality = _extractQuality(line);
      final name    = _extractName(line);

      if (name.isEmpty || streamLine.isEmpty) continue;
      // Skip geo-blocked / not 24/7 for cleaner listing
      if (line.contains('[Geo-blocked]') || line.contains('[Not 24/7]')) continue;

      channels.add(IptvChannel(
        id:        id,
        name:      name,
        logo:      logo,
        streamUrl: streamLine,
        quality:   quality,
        category:  category,
      ));
    }
    return channels;
  }

  static String? _attr(String line, String key) {
    final rx = RegExp('$key="([^"]*)"');
    return rx.firstMatch(line)?.group(1);
  }

  static String _extractName(String line) {
    final comma = line.lastIndexOf(',');
    if (comma == -1) return '';
    var name = line.substring(comma + 1).trim();
    // Strip trailing quality tags like (1080p) (720p)
    name = name.replaceAll(RegExp(r'\s*\(\d+p\)\s*$'), '').trim();
    return name;
  }

  static String _extractQuality(String line) {
    final m = RegExp(r'\((\d+p)\)').firstMatch(line);
    return m?.group(1) ?? '';
  }

  static void clearCache() => _cache.clear();
}
