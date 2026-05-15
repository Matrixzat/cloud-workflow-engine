class CastMember {
  final String name;
  final String? character;
  final String? avatarUrl;

  CastMember({required this.name, this.character, this.avatarUrl});

  factory CastMember.fromJson(Map<String, dynamic> json) {
    return CastMember(
      name: json['name'] ?? json['starName'] ?? '',
      character: json['character'] ?? json['roleName'] ?? json['role'],
      avatarUrl: json['starAvatar'] ?? json['avatarUrl'] ?? json['headImg'] ?? json['avatar'] ?? json['photoUrl'] ?? json['pic'] ?? json['img'] ?? json['image'],
    );
  }
}

class Movie {
  final String id;
  final String title;
  final String? thumbnail;
  final String? bannerImage;
  final String? rating;
  final String? year;
  final int subjectType;
  final String? summary;
  final String? detailPath;
  final List<String> availableSubtitles;
  final String? defaultSubtitle;
  final List<String> genres;
  final List<CastMember> cast;
  final String? trailerUrl;

  Movie({
    required this.id,
    required this.title,
    this.thumbnail,
    this.bannerImage,
    this.rating,
    this.year,
    this.subjectType = 0,
    this.summary,
    this.detailPath,
    this.availableSubtitles = const [],
    this.defaultSubtitle,
    this.genres = const [],
    this.cast = const [],
    this.trailerUrl,
  });

  bool get isMovie => subjectType == 1;
  bool get isTvSeries => subjectType == 2;

  Map<String, dynamic> toJson() => {
    'id': id,
    'title': title,
    if (thumbnail != null)   'thumbnail': thumbnail,
    if (bannerImage != null) 'bannerImage': bannerImage,
    if (rating != null)      'rating': rating,
    if (year != null)        'year': year,
    'subjectType': subjectType,
    if (summary != null)     'description': summary,
    if (detailPath != null)  'detailPath': detailPath,
    if (trailerUrl != null)  'trailerUrl': trailerUrl,
    if (genres.isNotEmpty)   'genre': genres.join(','),
  };

  factory Movie.fromJson(Map<String, dynamic> json) {
    String? thumbnail;
    if (json['cover'] != null && json['cover']['url'] != null) {
      thumbnail = json['cover']['url'];
    } else if (json['thumbnail'] != null) {
      thumbnail = json['thumbnail'];
    } else if (json['stills'] != null && json['stills']['url'] != null) {
      thumbnail = json['stills']['url'];
    } else if (json['poster'] != null) {
      thumbnail = json['poster'];
    }

    // bannerImage: prefer wide landscape stills over portrait poster
    String? bannerImage;
    if (json['stills'] != null && json['stills']['url'] != null) {
      bannerImage = json['stills']['url'].toString();
    } else if (json['backdrop'] != null) {
      bannerImage = json['backdrop'].toString();
    } else if (json['horizontalCover'] != null) {
      bannerImage = json['horizontalCover'].toString();
    } else if (json['bannerImage'] != null) {
      bannerImage = json['bannerImage'].toString();
    }

    String? year;
    final rawYear = json['releaseDate'] ?? json['year'] ?? json['releaseYear'] ?? json['publishTime'];
    if (rawYear != null) {
      final s = rawYear.toString();
      final match = RegExp(r'\b(19|20)\d{2}\b').firstMatch(s);
      year = match?.group(0);
    }

    String? rating;
    final rawRating = json['rating'] ?? json['score'];
    if (rawRating != null) {
      final d = double.tryParse(rawRating.toString());
      rating = d != null ? d.toStringAsFixed(1) : rawRating.toString();
    }

    List<String> subtitles = [];
    if (json['subtitles'] != null) {
      subtitles = json['subtitles'].toString().split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
    }

    List<String> genres = [];
    if (json['genre'] != null) {
      genres = json['genre'].toString().split(',').map((s) => s.trim()).where((s) => s.isNotEmpty).toList();
    } else if (json['categoryList'] != null && json['categoryList'] is List) {
      genres = (json['categoryList'] as List).map((c) => (c['name'] ?? c.toString()).toString()).toList();
    } else if (json['tags'] != null && json['tags'] is List) {
      genres = (json['tags'] as List).map((t) => (t['name'] ?? t.toString()).toString()).toList();
    }

    List<CastMember> cast = [];
    if (json['stars'] != null && json['stars'] is List) {
      final seen = <String>{};
      cast = (json['stars'] as List)
          .map((s) => CastMember.fromJson(Map<String, dynamic>.from(s)))
          .where((c) => c.name.isNotEmpty && seen.add(c.name))
          .take(8)
          .toList();
    }

    String? trailerUrl;
    try {
      final trailer = json['trailer'];
      if (trailer != null && trailer is Map) {
        final videoAddress = trailer['videoAddress'];
        if (videoAddress != null && videoAddress is Map) {
          trailerUrl = videoAddress['url']?.toString();
        }
      }
    } catch (_) {}

    return Movie(
      id: (json['subjectId'] ?? json['id'] ?? '').toString(),
      title: json['title'] ?? json['name'] ?? 'Unknown',
      thumbnail: thumbnail,
      bannerImage: bannerImage,
      rating: rating,
      year: year,
      subjectType: json['subjectType'] ?? 0,
      summary: json['description'] ?? json['summary'],
      detailPath: json['detailPath'],
      availableSubtitles: subtitles,
      defaultSubtitle: subtitles.contains('English') ? 'English' : (subtitles.isNotEmpty ? subtitles.first : null),
      genres: genres,
      cast: cast,
      trailerUrl: trailerUrl,
    );
  }
}

class MovieSource {
  final String id;
  final String quality;
  final String directUrl;
  final int size;
  final Map<String, String> subtitleUrls;
  final String referer;

  MovieSource({
    required this.id,
    required this.quality,
    required this.directUrl,
    this.size = 0,
    this.subtitleUrls = const {},
    this.referer = '',
  });

  factory MovieSource.fromJson(Map<String, dynamic> json, {Map<String, String>? subtitleUrls, String referer = ''}) {
    // Per-item subtitles (e.g. download item has a 'subtitles' map {"English":"url"})
    final itemSubs = <String, String>{};
    final rawSubs = json['subtitles'] ?? json['captions'] ?? json['subs'];
    if (rawSubs is Map) {
      rawSubs.forEach((k, v) {
        if (k != null && v != null && v.toString().isNotEmpty) {
          itemSubs[k.toString()] = v.toString();
        }
      });
    } else if (rawSubs is List) {
      for (final s in rawSubs) {
        if (s is Map) {
          final lang = (s['lanName'] ?? s['language'] ?? s['lang'] ?? s['lan'] ?? s['name'] ?? s['label'] ?? '').toString().trim();
          final url = (s['url'] ?? s['src'] ?? s['file'] ?? '').toString().trim();
          if (lang.isNotEmpty && url.isNotEmpty) itemSubs[lang] = url;
        }
      }
    }
    final merged = {...?subtitleUrls, ...itemSubs};
    return MovieSource(
      id: (json['subjectId'] ?? json['id'] ?? '').toString(),
      quality: json['resolution']?.toString() ?? json['quality'] ?? 'Auto',
      directUrl: json['url'] ?? '',
      size: json['size'] is int ? json['size'] as int : int.tryParse(json['size']?.toString() ?? '') ?? 0,
      subtitleUrls: merged.isNotEmpty ? merged : (subtitleUrls ?? const {}),
      referer: referer,
    );
  }
}

class EpisodeInfo {
  final int number;
  final String title;
  final int? runtimeMinutes;
  final String? overview;

  const EpisodeInfo({
    required this.number,
    required this.title,
    this.runtimeMinutes,
    this.overview,
  });
}

class SeasonInfo {
  final int season;
  final int maxEpisode;
  final List<EpisodeInfo> episodes;

  SeasonInfo({required this.season, required this.maxEpisode, this.episodes = const []});

  factory SeasonInfo.fromResource(Map<String, dynamic> json) {
    return SeasonInfo(
      season: json['se'] ?? 1,
      maxEpisode: json['maxEp'] ?? 1,
    );
  }
}

class HomeSection {
  final String title;
  final List<Movie> items;
  final String? opId;

  HomeSection({required this.title, required this.items, this.opId});
}

class SubtitleEntry {
  final Duration start;
  final Duration end;
  final String text;
  SubtitleEntry({required this.start, required this.end, required this.text});
}
