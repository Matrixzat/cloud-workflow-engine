import 'package:dio/dio.dart';

class AdultVideo {
  final String title;
  final String pageUrl;
  final String thumbnail;
  final String previewGif; // animated GIF preview (empty if unavailable)
  final String duration;
  final String views;

  const AdultVideo({
    required this.title,
    required this.pageUrl,
    required this.thumbnail,
    this.previewGif = '',
    required this.duration,
    required this.views,
  });
}

class AdultVideoDetails {
  final String title;
  final String? highUrl;
  final String? lowUrl;
  final String? hlsUrl;
  final String thumbnail;
  // Resolution-specific direct MP4 URLs, e.g. {'1080p': url, '720p': url, ...}
  final Map<String, String> directUrls;

  const AdultVideoDetails({
    required this.title,
    this.highUrl,
    this.lowUrl,
    this.hlsUrl,
    required this.thumbnail,
    this.directUrls = const {},
  });

  String? get bestUrl => directUrls.isNotEmpty
      ? directUrls.values.first
      : highUrl ?? lowUrl ?? hlsUrl;
  bool get hasVideo =>
      directUrls.isNotEmpty ||
      highUrl != null ||
      lowUrl != null ||
      hlsUrl != null;
}

class HlsQuality {
  final String label;
  final String url;
  const HlsQuality({required this.label, required this.url});
}

class AdultService {
  static final AdultService _i = AdultService._internal();
  factory AdultService() => _i;

  late final Dio _dio;

  static const _ua =
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

  static const _initialCookies =
      'cit=0596277437381d9crTTeVYF8Gpfk2dwz1zEmhA==; '
      'session_blih=34f692508d8192efAbWjk377u2V-3GqNEcPUCL0AJhiiLP7lY2So373HXXA=; '
      'session_token=82eb8858bc69ac80X9gZUHfkFISYRU4WGgm-Ys0dpdnGUwzupz-h_JYWxb2jjh8Ly1mAAAkt9NwpnrovWhOURSzjTZUcTh7ODryoZUZh__GbzYMI62eAO3dwPHjKXsVUOxd9Lh3HnVI6lorMOahr1UqUKI80hNx22QsgRFVb2KW6gcNaBOMSxsE2nsOmOxQYKWecAhp0GrSonfDbzmr6EYnF5UHA-JX-LHWAvonZbHiKKIpeCEne-KX7ZoJoCPugfrsee-eLrBEjcVw9eKdp1Jp3S6sw5FuOFVNoN621D-A8rdaDFTXUNybDWHrs4MraERLs7f-iKEWmS0N3KQTXX0eqHYTJTp_1vG27Ng==; '
      'session_token_auth=054a0c3dafc28bdc9-eIq3VoHtfFJBMN8ZJa9jQxwkMySH-lkAJ5ES-Kh1c6xJB_NDUizkDkGK6WtLoB0L1IPQ3jG4L2Y1PPLoNV-qbr6bdc6SipAve6spT2iBfOAswhKwv1g5DiVUhmrFcdsfPWrZTEw3yCaPdQH-okyfX6xqpK1XjGSAEb0m7HpEQaKyO-eTADOWjx_DxknWR-3qcD09wOnzAV_2Q4JqePUJfFH7CYwbS_QSObSOS_MdGO3zCd0hJFDFTBCDdkMVWo-Qas2_-vFkx1xmWOt5Ec_J7mPVCLBZtLnXNaZy8X3HwY3EPlnRd8yukQeRSUP_IP3dv99CpuGwUXgbjpwcaYjg==';

  AdultService._internal() {
    _dio = Dio(BaseOptions(
      connectTimeout: const Duration(seconds: 18),
      receiveTimeout: const Duration(seconds: 25),
      headers: {
        'User-Agent': _ua,
        'Cookie': _initialCookies,
        'Accept':
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Referer': 'https://www.xnxx.com/',
      },
    ));

    _dio.interceptors.add(InterceptorsWrapper(
      onResponse: (response, handler) {
        final setCookieList = response.headers['set-cookie'];
        if (setCookieList != null && setCookieList.isNotEmpty) {
          _mergeCookies(setCookieList);
        }
        handler.next(response);
      },
      onError: (err, handler) => handler.next(err),
    ));
  }

  void _mergeCookies(List<String> setCookieHeaders) {
    final existing = _parseCookieHeader(
        _dio.options.headers['Cookie'] as String? ?? '');
    for (final raw in setCookieHeaders) {
      final part = raw.split(';').first.trim();
      final eq = part.indexOf('=');
      if (eq > 0) {
        existing[part.substring(0, eq).trim()] =
            part.substring(eq + 1).trim();
      }
    }
    _dio.options.headers['Cookie'] =
        existing.entries.map((e) => '${e.key}=${e.value}').join('; ');
  }

  Map<String, String> _parseCookieHeader(String header) {
    final map = <String, String>{};
    for (final part in header.split(';')) {
      final eq = part.indexOf('=');
      if (eq > 0) {
        map[part.substring(0, eq).trim()] = part.substring(eq + 1).trim();
      }
    }
    return map;
  }

  Future<List<AdultVideo>> search(String query, {int page = 1}) async {
    final q = Uri.encodeComponent(query.trim().replaceAll(' ', '+'));
    final url = page > 1
        ? 'https://www.xnxx.com/search/$q/$page'
        : 'https://www.xnxx.com/search/$q';
    try {
      final resp = await _dio.get<String>(url,
          options: Options(responseType: ResponseType.plain));
      return _parseSearch(resp.data ?? '');
    } catch (_) {
      return [];
    }
  }

  List<AdultVideo> _parseSearch(String html) {
    final results = <AdultVideo>[];
    final seen = <String>{};

    final blocks = html.split('class="thumb-block');
    for (int i = 1; i < blocks.length; i++) {
      final block = blocks[i];

      final linkMatch = RegExp(
              r'href="(/video-[a-zA-Z0-9\-_/]+)"[^>]*title="([^"]+)"')
          .firstMatch(block);
      if (linkMatch == null) continue;

      final href = linkMatch.group(1) ?? '';
      final title = _decodeHtml(linkMatch.group(2) ?? '');

      final idMatch = RegExp(r'/video-([a-zA-Z0-9]+)/').firstMatch(href);
      if (idMatch == null) continue;
      final videoId = idMatch.group(1)!;
      if (seen.contains(videoId)) continue;
      seen.add(videoId);

      final pageUrl = 'https://www.xnxx.com$href';

      final thumbMatch =
          RegExp(r'data-src="(https://[^"]+)"').firstMatch(block);
      final thumbnail = thumbMatch?.group(1) ?? '';

      // Video preview — xnxx puts a short mp4 clip in data-pvv attribute
      final gifMatch =
          RegExp(r'data-pvv="(https://[^"]+)"').firstMatch(block);
      final previewGif = gifMatch?.group(1) ?? '';

      final durMatch =
          RegExp(r'class="[^"]*duration[^"]*"[^>]*>([^<]+)<').firstMatch(block);
      final duration = durMatch?.group(1)?.trim() ?? '';

      final metaMatch =
          RegExp(r'class="metadata"[^>]*>([^<]+)<').firstMatch(block);
      String views = '';
      if (metaMatch != null) {
        final meta = metaMatch.group(1) ?? '';
        views = meta.contains('-') ? meta.split('-')[0].trim() : meta.trim();
      }

      if (title.isNotEmpty && href.isNotEmpty) {
        results.add(AdultVideo(
          title: title,
          pageUrl: pageUrl,
          thumbnail: thumbnail,
          previewGif: previewGif,
          duration: duration,
          views: views,
        ));
      }
    }
    return results;
  }

  Future<AdultVideoDetails?> getVideoDetails(String pageUrl) async {
    try {
      final resp = await _dio.get<String>(pageUrl,
          options: Options(responseType: ResponseType.plain));
      return _parseVideoPage(resp.data ?? '');
    } catch (_) {
      return null;
    }
  }

  AdultVideoDetails? _parseVideoPage(String html) {
    final highMatch =
        RegExp(r"html5player\.setVideoUrlHigh\('([^']+)'\)").firstMatch(html);
    final lowMatch =
        RegExp(r"html5player\.setVideoUrlLow\('([^']+)'\)").firstMatch(html);
    final hlsMatch =
        RegExp(r"html5player\.setVideoHLS\('([^']+)'\)").firstMatch(html);

    final highUrl = highMatch?.group(1);
    final lowUrl  = lowMatch?.group(1);
    final hlsUrl  = hlsMatch?.group(1);

    // Extract resolution-specific direct MP4 URLs:
    // html5player.setVideoUrl1080p('...'), setVideoUrl720p('...'), etc.
    final directUrls = <String, String>{};
    final resMatches = RegExp(
      r"html5player\.setVideoUrl(\d+)p\('([^']+)'\)",
    ).allMatches(html);
    for (final m in resMatches) {
      final res = '${m.group(1)}p';   // e.g. "1080p"
      final url = m.group(2)!;
      directUrls[res] = url;
    }

    // Sort highest resolution first
    final sortedDirectUrls = Map.fromEntries(
      directUrls.entries.toList()
        ..sort((a, b) {
          final aRes = int.tryParse(a.key.replaceAll('p', '')) ?? 0;
          final bRes = int.tryParse(b.key.replaceAll('p', '')) ?? 0;
          return bRes.compareTo(aRes);
        }),
    );

    if (highUrl == null && lowUrl == null && hlsUrl == null &&
        sortedDirectUrls.isEmpty) return null;

    final titleMatch = RegExp(r'<title>([^<]+)</title>').firstMatch(html);
    final rawTitle = titleMatch?.group(1) ?? '';
    final title = rawTitle
        .replaceAll(' - XNXX.COM', '')
        .replaceAll(' - Free Porn Videos', '')
        .trim();

    final thumbMatch = RegExp(r'"image"\s*:\s*"([^"]+)"').firstMatch(html);
    final thumbnail = thumbMatch?.group(1) ?? '';

    return AdultVideoDetails(
      title: title,
      highUrl: highUrl,
      lowUrl: lowUrl,
      hlsUrl: hlsUrl,
      thumbnail: thumbnail,
      directUrls: sortedDirectUrls,
    );
  }

  Future<String> getFileSize(String url) async {
    try {
      // HEAD request first
      final head = await _dio.head<void>(
        url,
        options: Options(
          sendTimeout: const Duration(seconds: 12),
          receiveTimeout: const Duration(seconds: 12),
          headers: {'Referer': 'https://www.xnxx.com/'},
          validateStatus: (s) => s != null && s < 500,
        ),
      );
      final cl = head.headers.value('content-length');
      if (cl != null) {
        final b = int.tryParse(cl.trim());
        if (b != null && b > 0) return _fmtBytes(b);
      }
      // Fallback: byte-range request to read Content-Range total
      final range = await _dio.get<dynamic>(
        url,
        options: Options(
          sendTimeout: const Duration(seconds: 12),
          receiveTimeout: const Duration(seconds: 12),
          headers: {'Referer': 'https://www.xnxx.com/', 'Range': 'bytes=0-0'},
          responseType: ResponseType.bytes,
          validateStatus: (s) => s != null && s < 500,
        ),
      );
      final cr = range.headers.value('content-range');
      if (cr != null) {
        final slash = cr.lastIndexOf('/');
        if (slash != -1) {
          final b = int.tryParse(cr.substring(slash + 1).trim());
          if (b != null && b > 0) return _fmtBytes(b);
        }
      }
    } catch (_) {}
    return '—';
  }

  String _fmtBytes(int bytes) {
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(0)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  Future<List<HlsQuality>> getHlsQualities(String masterUrl) async {
    try {
      final resp = await _dio.get<String>(
        masterUrl,
        options: Options(
          responseType: ResponseType.plain,
          headers: {
            'Accept': '*/*',
            'Referer': 'https://www.xnxx.com/',
          },
        ),
      );
      return _parseM3u8(masterUrl, resp.data ?? '');
    } catch (_) {
      return [];
    }
  }

  List<HlsQuality> _parseM3u8(String baseUrl, String body) {
    final lines = body.split('\n');
    final qualities = <HlsQuality>[];
    String? pendingLabel;
    for (final raw in lines) {
      final line = raw.trim();
      if (line.startsWith('#EXT-X-STREAM-INF')) {
        final resMatch = RegExp(r'RESOLUTION=(\d+x\d+)').firstMatch(line);
        if (resMatch != null) {
          final parts = resMatch.group(1)!.split('x');
          pendingLabel = '${parts[1]}p';
        }
      } else if (!line.startsWith('#') && line.isNotEmpty && pendingLabel != null) {
        final url = line.startsWith('http')
            ? line
            : Uri.parse(baseUrl).resolve(line).toString();
        qualities.add(HlsQuality(label: pendingLabel, url: url));
        pendingLabel = null;
      }
    }
    qualities.sort((a, b) {
      final aRes = int.tryParse(a.label.replaceAll('p', '')) ?? 0;
      final bRes = int.tryParse(b.label.replaceAll('p', '')) ?? 0;
      return bRes.compareTo(aRes);
    });
    final seen = <String>{};
    return qualities.where((q) => seen.add(q.label)).toList();
  }

  String _decodeHtml(String text) => text
      .replaceAll('&amp;', '&')
      .replaceAll('&lt;', '<')
      .replaceAll('&gt;', '>')
      .replaceAll('&quot;', '"')
      .replaceAll('&#39;', "'")
      .replaceAll('&nbsp;', ' ');

  static const String userAgent = _ua;
}
