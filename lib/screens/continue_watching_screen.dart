import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../api/models.dart';
import '../theme/app_theme.dart';
import 'detail_screen.dart';

class _CWEntry {
  final String prefKey;
  final String id;
  final String title;
  final String thumb;
  final int subjectType;
  final String year;
  final String rating;
  final String detailPath;
  final List<String> genres;
  final int? season;
  final int? episode;
  final int posSecs;
  final int durSecs;
  final int ts;

  _CWEntry({
    required this.prefKey,
    required this.id,
    required this.title,
    required this.thumb,
    required this.subjectType,
    required this.year,
    required this.rating,
    required this.detailPath,
    required this.genres,
    this.season,
    this.episode,
    required this.posSecs,
    required this.durSecs,
    required this.ts,
  });

  double get progress => (durSecs > 0) ? (posSecs / durSecs).clamp(0.0, 1.0) : 0.0;

  String get episodeLabel {
    if (season != null && episode != null) return 'S$season E$episode';
    return '';
  }

  String get timeLeft {
    final rem = durSecs - posSecs;
    if (rem <= 0) return '';
    final m = rem ~/ 60;
    final s = (rem % 60).toString().padLeft(2, '0');
    return m > 0 ? '${m}m ${s}s left' : '${s}s left';
  }

  Movie toMovie() => Movie(
        id: id,
        title: title,
        thumbnail: thumb.isNotEmpty ? thumb : null,
        subjectType: subjectType,
        year: year.isNotEmpty ? year : null,
        rating: rating.isNotEmpty ? rating : null,
        detailPath: detailPath.isNotEmpty ? detailPath : null,
        genres: genres,
      );

  factory _CWEntry.fromPrefs(String key, String raw) {
    final m = jsonDecode(raw) as Map<String, dynamic>;
    return _CWEntry(
      prefKey: key,
      id: m['id']?.toString() ?? '',
      title: m['title']?.toString() ?? 'Unknown',
      thumb: m['thumb']?.toString() ?? '',
      subjectType: (m['type'] as num?)?.toInt() ?? 1,
      year: m['year']?.toString() ?? '',
      rating: m['rating']?.toString() ?? '',
      detailPath: m['detailPath']?.toString() ?? '',
      genres: (m['genres'] as List?)?.map((e) => e.toString()).toList() ?? [],
      season: (m['season'] as num?)?.toInt(),
      episode: (m['episode'] as num?)?.toInt(),
      posSecs: (m['pos'] as num?)?.toInt() ?? 0,
      durSecs: (m['dur'] as num?)?.toInt() ?? 0,
      ts: (m['ts'] as num?)?.toInt() ?? 0,
    );
  }
}

class ContinueWatchingScreen extends StatefulWidget {
  const ContinueWatchingScreen({super.key});

  @override
  State<ContinueWatchingScreen> createState() => _ContinueWatchingScreenState();
}

class _ContinueWatchingScreenState extends State<ContinueWatchingScreen> {
  List<_CWEntry> _all = [];
  List<_CWEntry> _filtered = [];
  bool _loading = true;
  final TextEditingController _searchCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _load();
    _searchCtrl.addListener(_filter);
  }

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  Future<void> _load({bool showSpinner = true}) async {
    if (showSpinner && _all.isEmpty) setState(() => _loading = true);
    try {
      final prefs = await SharedPreferences.getInstance();
      final keys = prefs.getKeys().where((k) => k.startsWith('resume_') && !k.startsWith('resume_ug_')).toList();
      final entries = <_CWEntry>[];
      for (final key in keys) {
        final raw = prefs.getString(key);
        if (raw == null) continue;
        try {
          entries.add(_CWEntry.fromPrefs(key, raw));
        } catch (_) {}
      }
      entries.sort((a, b) => b.ts.compareTo(a.ts));
      if (!mounted) return;
      setState(() {
        _all = entries;
        _loading = false;
      });
      _filter();
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  void _filter() {
    final q = _searchCtrl.text.trim().toLowerCase();
    setState(() {
      _filtered = q.isEmpty
          ? List.of(_all)
          : _all.where((e) => e.title.toLowerCase().contains(q)).toList();
    });
  }

  Future<void> _remove(String prefKey) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove(prefKey);
    } catch (_) {}
    setState(() {
      _all.removeWhere((e) => e.prefKey == prefKey);
      _filter();
    });
  }

  Future<void> _clearAll() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppTheme.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text('Clear All?', style: TextStyle(color: AppTheme.textPrimary, fontWeight: FontWeight.w700)),
        content: const Text('This will remove all continue watching entries. Your watch positions will be lost.', style: TextStyle(color: AppTheme.textSecondary)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel', style: TextStyle(color: AppTheme.textMuted))),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Clear All', style: TextStyle(color: AppTheme.primary, fontWeight: FontWeight.w700)),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      final prefs = await SharedPreferences.getInstance();
      for (final e in _all) {
        await prefs.remove(e.prefKey);
      }
    } catch (_) {}
    setState(() {
      _all.clear();
      _filtered.clear();
    });
  }

  void _openDetail(_CWEntry entry) {
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => DetailScreen(movie: entry.toMovie())),
    ).then((_) => _load(showSpinner: false));
  }

  @override
  Widget build(BuildContext context) {
    final body = Column(
      children: [
        _buildSearchBar(),
        if (!_loading && _all.isNotEmpty)
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 0),
            child: Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(
                  '${_filtered.length} title${_filtered.length == 1 ? '' : 's'}',
                  style: const TextStyle(color: AppTheme.textMuted, fontSize: 12),
                ),
                TextButton.icon(
                  onPressed: _clearAll,
                  icon: const Icon(Icons.delete_sweep_rounded, size: 15, color: AppTheme.primary),
                  label: const Text('Clear All', style: TextStyle(color: AppTheme.primary, fontSize: 12)),
                  style: TextButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4)),
                ),
              ],
            ),
          ),
        Expanded(
          child: _loading
              ? const Center(child: CircularProgressIndicator(color: AppTheme.primary))
              : _filtered.isEmpty
                  ? _buildEmpty()
                  : RefreshIndicator(
                      color: AppTheme.primary,
                      backgroundColor: AppTheme.surface,
                      onRefresh: _load,
                      child: ListView.builder(
                        padding: const EdgeInsets.fromLTRB(16, 8, 16, 80),
                        physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
                        itemCount: _filtered.length,
                        itemBuilder: (_, i) => _buildCard(_filtered[i]),
                      ),
                    ),
        ),
      ],
    );

    // When pushed standalone (from drawer), wrap in a Scaffold so the AppBar
    // handles the status-bar safe area. When embedded as a HomeScreen tab the
    // parent Scaffold already covers it, so return the Column directly.
    if (Navigator.of(context).canPop()) {
      return Scaffold(
        backgroundColor: AppTheme.background,
        appBar: AppBar(
          backgroundColor: AppTheme.background,
          elevation: 0,
          leading: IconButton(
            icon: const Icon(Icons.arrow_back_rounded, color: AppTheme.textPrimary),
            onPressed: () => Navigator.pop(context),
          ),
          title: const Text(
            'Continue Watching',
            style: TextStyle(color: AppTheme.textPrimary, fontSize: 18, fontWeight: FontWeight.w700),
          ),
        ),
        body: body,
      );
    }
    return body;
  }

  Widget _buildSearchBar() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
      child: TextField(
        controller: _searchCtrl,
        style: const TextStyle(color: AppTheme.textPrimary, fontSize: 14),
        decoration: InputDecoration(
          hintText: 'Search continue watching…',
          prefixIcon: const Icon(Icons.search_rounded, color: AppTheme.textMuted, size: 20),
          suffixIcon: _searchCtrl.text.isNotEmpty
              ? IconButton(
                  icon: const Icon(Icons.close_rounded, color: AppTheme.textMuted, size: 18),
                  onPressed: () {
                    _searchCtrl.clear();
                    FocusScope.of(context).unfocus();
                  },
                )
              : null,
          filled: true,
          fillColor: AppTheme.surface,
          contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: AppTheme.border)),
          enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: AppTheme.border)),
          focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: AppTheme.primary, width: 1.5)),
        ),
      ),
    );
  }

  Widget _buildCard(_CWEntry entry) {
    return Dismissible(
      key: ValueKey(entry.prefKey),
      direction: DismissDirection.endToStart,
      background: Container(
        margin: const EdgeInsets.only(bottom: 10),
        decoration: BoxDecoration(
          color: AppTheme.primary.withOpacity(0.15),
          borderRadius: BorderRadius.circular(14),
        ),
        alignment: Alignment.centerRight,
        padding: const EdgeInsets.only(right: 20),
        child: const Icon(Icons.delete_outline_rounded, color: AppTheme.primary, size: 26),
      ),
      onDismissed: (_) => _remove(entry.prefKey),
      child: GestureDetector(
        onTap: () => _openDetail(entry),
        child: Container(
          margin: const EdgeInsets.only(bottom: 10),
          decoration: BoxDecoration(
            color: AppTheme.card,
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: AppTheme.border.withOpacity(0.5)),
          ),
          child: Row(
            children: [
              _buildThumbnail(entry),
              Expanded(child: _buildInfo(entry)),
              IconButton(
                icon: const Icon(Icons.close_rounded, size: 18, color: AppTheme.textMuted),
                onPressed: () => _remove(entry.prefKey),
                padding: const EdgeInsets.all(12),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildThumbnail(_CWEntry entry) {
    return ClipRRect(
      borderRadius: const BorderRadius.horizontal(left: Radius.circular(14)),
      child: Stack(
        children: [
          entry.thumb.isNotEmpty
              ? CachedNetworkImage(
                  imageUrl: entry.thumb,
                  width: 90,
                  height: 126,
                  fit: BoxFit.cover,
                  memCacheWidth: 360,
                  maxWidthDiskCache: 600,
                  filterQuality: FilterQuality.high,
                  errorWidget: (_, __, ___) => _thumbPlaceholder(),
                  placeholder: (_, __) => _thumbPlaceholder(),
                )
              : _thumbPlaceholder(),
          Positioned(
            bottom: 0, left: 0, right: 0,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                LinearProgressIndicator(
                  value: entry.progress,
                  backgroundColor: Colors.black45,
                  valueColor: const AlwaysStoppedAnimation<Color>(AppTheme.primary),
                  minHeight: 3,
                ),
              ],
            ),
          ),
          Positioned(
            top: 6, left: 6,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
              decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.7),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                '${(entry.progress * 100).round()}%',
                style: const TextStyle(color: AppTheme.textPrimary, fontSize: 9, fontWeight: FontWeight.w700),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _thumbPlaceholder() {
    return Container(
      width: 90,
      height: 126,
      color: AppTheme.surface,
      child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted, size: 30),
    );
  }

  Widget _buildInfo(_CWEntry entry) {
    final posStr = _fmtSecs(entry.posSecs);
    final durStr = entry.durSecs > 0 ? _fmtSecs(entry.durSecs) : '';
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 12, 4, 12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            entry.title,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(color: AppTheme.textPrimary, fontSize: 14, fontWeight: FontWeight.w600, height: 1.3),
          ),
          const SizedBox(height: 4),
          Row(
            children: [
              if (entry.episodeLabel.isNotEmpty) ...[
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(color: AppTheme.primary.withOpacity(0.15), borderRadius: BorderRadius.circular(4)),
                  child: Text(entry.episodeLabel, style: const TextStyle(color: AppTheme.primary, fontSize: 10, fontWeight: FontWeight.w700)),
                ),
                const SizedBox(width: 6),
              ],
              if (entry.year.isNotEmpty)
                Text(entry.year, style: const TextStyle(color: AppTheme.textMuted, fontSize: 11)),
              if (entry.year.isNotEmpty && entry.rating.isNotEmpty)
                const Text('  ·  ', style: TextStyle(color: AppTheme.textMuted, fontSize: 11)),
              if (entry.rating.isNotEmpty)
                Row(
                  children: [
                    const Icon(Icons.star_rounded, color: AppTheme.gold, size: 11),
                    const SizedBox(width: 2),
                    Text(entry.rating, style: const TextStyle(color: AppTheme.gold, fontSize: 11, fontWeight: FontWeight.w600)),
                  ],
                ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              const Icon(Icons.play_circle_outline_rounded, color: AppTheme.accent, size: 13),
              const SizedBox(width: 4),
              Text(
                durStr.isNotEmpty ? '$posStr / $durStr' : posStr,
                style: const TextStyle(color: AppTheme.textSecondary, fontSize: 11),
              ),
            ],
          ),
          if (entry.timeLeft.isNotEmpty) ...[
            const SizedBox(height: 2),
            Text(entry.timeLeft, style: const TextStyle(color: AppTheme.textMuted, fontSize: 10)),
          ],
        ],
      ),
    );
  }

  Widget _buildEmpty() {
    final hasQuery = _searchCtrl.text.isNotEmpty;
    return ListView(
      physics: const AlwaysScrollableScrollPhysics(),
      children: [
        SizedBox(
          height: MediaQuery.of(context).size.height * 0.6,
          child: Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  hasQuery ? Icons.search_off_rounded : Icons.play_circle_outline_rounded,
                  size: 72,
                  color: AppTheme.textMuted,
                ),
                const SizedBox(height: 16),
                Text(
                  hasQuery ? 'No results found' : 'Nothing in progress',
                  style: const TextStyle(color: AppTheme.textSecondary, fontSize: 16, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 8),
                Text(
                  hasQuery ? 'Try a different search term' : 'Movies you start watching will appear here',
                  style: const TextStyle(color: AppTheme.textMuted, fontSize: 13),
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  String _fmtSecs(int s) {
    final h = s ~/ 3600;
    final m = (s % 3600) ~/ 60;
    final sec = (s % 60).toString().padLeft(2, '0');
    if (h > 0) return '$h:${m.toString().padLeft(2, '0')}:$sec';
    return '${m.toString().padLeft(2, '0')}:$sec';
  }
}
