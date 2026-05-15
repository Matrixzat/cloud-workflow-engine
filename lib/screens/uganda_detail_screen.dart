import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:shimmer/shimmer.dart';
import 'package:url_launcher/url_launcher.dart';
import '../api/models.dart';
import '../api/vod_client.dart';

import '../api/tmdb_service.dart';
import '../providers/app_provider.dart';
import '../services/download_manager.dart';
import '../theme/app_theme.dart';
import '../widgets/cast_button.dart';
import 'player_screen.dart';

final _ugR = String.fromCharCodes([104,116,116,112,115,58,47,47,109,117,110,111,119,97,116,99,104,46,111,114,103,47]);

class UgandaDetailScreen extends StatefulWidget {
  final Movie movie;
  final List<Movie> related;
  final Future<VodStream>? streamFuture;
  final List<Movie>? ugandaPlaylist;
  final int? ugandaIndex;

  const UgandaDetailScreen({
    super.key,
    required this.movie,
    this.related = const [],
    this.streamFuture,
    this.ugandaPlaylist,
    this.ugandaIndex,
  });

  @override
  State<UgandaDetailScreen> createState() => _UgandaDetailScreenState();
}

class _UgandaDetailScreenState extends State<UgandaDetailScreen> {
  VodStream? _stream;
  bool _loadingStream = true;
  String? _streamError;
  bool _pendingPlay = false;

  List<TmdbCastMember> _cast = [];
  bool _loadingCast = true;

  // ── VJ version selector ───────────────────────────────────────────────────
  List<VodVersion> _versions = [];
  bool _loadingVersions = false;
  String? _selectedVid;

  String _tmdbOverview = '';
  String _tmdbBackdrop = '';

  // ── Episodes (series) ─────────────────────────────────────────────────────
  List<VodEpisode> _episodes = [];
  bool _loadingEpisodes = false;
  // Background-prefetched metadata keyed by episode vid
  final Map<String, VodStream> _episodeMeta = {};
  bool _prefetchCancelled = false;

  @override
  void initState() {
    super.initState();
    _selectedVid = widget.movie.id;
    _fetchStream(widget.streamFuture);
    _fetchCast();
    _fetchVersions(widget.movie.title);
    _fetchTmdbOverview();
    // Show episodes immediately from cache if this movie was opened before,
    // without waiting for the stream network call to complete.
    _eagerLoadEpisodesFromCache();
  }

  @override
  void dispose() {
    _prefetchCancelled = true;
    super.dispose();
  }

  /// Called at initState — immediately shows episodes from cache if this
  /// series was opened before, without waiting for the stream network call.
  Future<void> _eagerLoadEpisodesFromCache() async {
    try {
      final vid    = widget.movie.id;
      final cached = await VodClient().getCachedStream(vid);
      if (!mounted || cached == null || !cached.isSeries) return;
      if (_episodes.isNotEmpty) return; // already shown by _fetchStream (race won)
      final eps = await VodClient().getEpisodes(vid, cached.seriesCode);
      if (!mounted || _episodes.isNotEmpty || eps.isEmpty) return;
      setState(() {
        _episodes       = eps;
        _loadingEpisodes = false;
      });
      if (!_episodeMeta.containsKey(vid)) {
        setState(() => _episodeMeta[vid] = cached);
      }
      _prefetchCancelled = false;
      _prefetchEpisodeMeta(eps, skip: vid);
    } catch (_) {}
  }

  Future<void> _fetchTmdbOverview() async {
    final title = widget.movie.title;
    if (title.isEmpty) return;
    final tmdb = TmdbService();
    final results = await Future.wait([tmdb.getOverview(title), tmdb.getBackdrop(title)]);
    if (!mounted) return;
    setState(() {
      if (results[0].isNotEmpty) _tmdbOverview = results[0];
      if (results[1].isNotEmpty) _tmdbBackdrop = results[1];
    });
  }

  Future<void> _fetchCast() async {
    try {
      final cast = await TmdbService().getCast(widget.movie.title);
      if (!mounted) return;
      setState(() { _cast = cast; _loadingCast = false; });
    } catch (_) {
      if (!mounted) return;
      setState(() { _loadingCast = false; });
    }
  }

  Future<void> _fetchStream([Future<VodStream>? preloaded]) async {
    setState(() { _streamError = null; _loadingStream = true; });
    try {
      final s = await (preloaded ?? VodClient().getStream(_selectedVid ?? widget.movie.id));
      if (!mounted) return;
      setState(() { _stream = s; _loadingStream = false; });
      // Re-fetch versions using the confirmed title from the stream if it differs
      if (s.title.isNotEmpty &&
          s.title.trim().toLowerCase() != widget.movie.title.trim().toLowerCase() &&
          _versions.isEmpty) {
        _fetchVersions(s.title);
      }
      // Fetch episodes if this is a series
      if (s.isSeries) _fetchEpisodes(s);
      if (_pendingPlay) {
        _pendingPlay = false;
        _playNow();
      }
    } catch (_) {
      if (!mounted) return;
      setState(() { _streamError = 'Could not load video. Please try again.'; _loadingStream = false; _pendingPlay = false; });
    }
  }

  Future<void> _fetchEpisodes(VodStream s) async {
    if (!mounted) return;
    try {
      final eps = await VodClient().getEpisodes(
        _selectedVid ?? widget.movie.id,
        s.seriesCode,
      );
      if (!mounted) return;
      setState(() { _episodes = eps; _loadingEpisodes = false; });
      // Seed current vid metadata immediately (already loaded)
      final currentVid = _selectedVid ?? widget.movie.id;
      if (!_episodeMeta.containsKey(currentVid)) {
        setState(() => _episodeMeta[currentVid] = s);
      }
      // Prefetch the rest in background
      _prefetchCancelled = false;
      _prefetchEpisodeMeta(eps, skip: currentVid);
    } catch (_) {
      if (!mounted) return;
      setState(() => _loadingEpisodes = false);
    }
  }

  Future<void> _prefetchEpisodeMeta(List<VodEpisode> eps, {String skip = ''}) async {
    // Run 8 fetches in parallel; getStream() returns instantly from disk/memory cache
    const batchSize = 8;
    final toFetch = eps.where((e) => e.vid != skip && !_episodeMeta.containsKey(e.vid)).toList();
    for (int i = 0; i < toFetch.length; i += batchSize) {
      if (_prefetchCancelled || !mounted) return;
      final batch = toFetch.skip(i).take(batchSize).toList();
      await Future.wait(batch.map((ep) async {
        if (_prefetchCancelled || !mounted) return;
        try {
          final meta = await VodClient().getStream(ep.vid);
          if (!mounted || _prefetchCancelled) return;
          setState(() => _episodeMeta[ep.vid] = meta);
        } catch (_) {}
      }));
      // No inter-batch delay — disk cache hits are instant, network hits are
      // already throttled by the 4-at-a-time window
    }
  }

  Future<void> _fetchVersions(String title) async {
    if (title.isEmpty) return;
    setState(() => _loadingVersions = true);
    try {
      final versions = await VodClient().getVersions(title);
      if (!mounted) return;
      setState(() {
        _versions = versions;
        _loadingVersions = false;
        // Ensure the currently selected ID stays highlighted if it's in the list
        if (_selectedVid != null && !versions.any((v) => v.id == _selectedVid)) {
          if (versions.isNotEmpty) _selectedVid = versions.first.id;
        }
      });
    } catch (_) {
      if (!mounted) return;
      setState(() => _loadingVersions = false);
    }
  }

  Future<void> _switchVj(VodVersion v) async {
    if (_selectedVid == v.id || _loadingStream) return;
    _prefetchCancelled = true;
    setState(() {
      _selectedVid = v.id;
      _stream = null;
      _streamError = null;
      _loadingStream = true;
      _episodes = [];
      _episodeMeta.clear();
    });
    try {
      final s = await VodClient().getStream(v.id);
      if (!mounted) return;
      setState(() { _stream = s; _loadingStream = false; });
      if (s.isSeries) _fetchEpisodes(s);
    } catch (_) {
      if (!mounted) return;
      setState(() { _streamError = 'Could not load video. Please try again.'; _loadingStream = false; });
    }
  }

  void _playEpisode(VodEpisode ep) async {
    // If episode already has a direct URL, play it right away
    if (ep.playingUrl.isNotEmpty) {
      final movie = Movie(
        id: ep.vid,
        title: ep.title.isNotEmpty ? ep.title : widget.movie.title,
        thumbnail: ep.image.isNotEmpty ? ep.image : widget.movie.thumbnail,
        summary: ep.vj.isNotEmpty ? 'By ${ep.vj}' : widget.movie.summary,
        subjectType: 1,
      );
      final source = MovieSource(
        id: ep.vid,
        quality: ep.vj.isNotEmpty ? ep.vj : 'Uganda HD',
        directUrl: ep.playingUrl,
        referer: _ugR,
      );
      if (!mounted) return;
      Navigator.push(context, MaterialPageRoute(builder: (_) => PlayerScreen(movie: movie, source: source, noRelated: true)));
      return;
    }
    // Otherwise fetch the stream URL
    _toast('Loading episode…');
    try {
      final s = await VodClient().getStream(ep.vid);
      if (!mounted) return;
      if (s.url.isEmpty) { _toast('Could not load episode.'); return; }
      final movie = Movie(
        id: ep.vid,
        title: s.title.isNotEmpty ? s.title : ep.title.isNotEmpty ? ep.title : widget.movie.title,
        thumbnail: s.image.isNotEmpty ? s.image : ep.image.isNotEmpty ? ep.image : widget.movie.thumbnail,
        summary: s.vj.isNotEmpty ? 'By ${s.vj}' : widget.movie.summary,
        subjectType: 1,
      );
      final source = MovieSource(
        id: ep.vid,
        quality: s.vj.isNotEmpty ? s.vj : 'Uganda HD',
        directUrl: s.url,
        referer: _ugR,
      );
      Navigator.push(context, MaterialPageRoute(builder: (_) => PlayerScreen(movie: movie, source: source, noRelated: true)));
    } catch (_) {
      if (!mounted) return;
      _toast('Could not load episode. Please try again.');
    }
  }

  void _playNow() {
    final s = _stream;
    if (s == null || s.url.isEmpty) return;
    final activeId = _selectedVid ?? widget.movie.id;
    final movie = Movie(
      id: activeId,
      title: s.title.isNotEmpty ? s.title : widget.movie.title,
      thumbnail: s.image.isNotEmpty ? s.image : widget.movie.thumbnail,
      summary: s.vj.isNotEmpty ? 'By ${s.vj}' : widget.movie.summary,
      subjectType: 1,
    );
    final source = MovieSource(
      id: activeId,
      quality: s.vj.isNotEmpty ? s.vj : 'Uganda HD',
      directUrl: s.url,
      referer: _ugR,
    );
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => PlayerScreen(
          movie: movie,
          source: source,
          ugandaPlaylist: widget.ugandaPlaylist,
          ugandaIndex: widget.ugandaIndex,
          noRelated: true,
        ),
      ),
    );
  }

  void _download() {
    final s = _stream;
    if (s == null || s.url.isEmpty) return;
    final activeId = _selectedVid ?? widget.movie.id;
    final mgr = context.read<DownloadManager>();
    final alreadyActive = mgr.tasks.any((t) => t.movieId == activeId && t.isActive);
    if (alreadyActive) { _toast('Already downloading…'); return; }
    mgr.startDownload(
      movieId: activeId,
      title: s.title.isNotEmpty ? s.title : widget.movie.title,
      quality: s.vj.isNotEmpty ? s.vj : 'Uganda',
      url: s.url,
      thumbnail: s.image.isNotEmpty ? s.image : widget.movie.thumbnail,
      referer: _ugR,
    );
    _toast('Download started');
  }

  // Cast a specific episode to a nearby device
  Future<void> _castEpisode(VodEpisode ep) async {
    VodStream? s = _episodeMeta[ep.vid];
    if (s == null || s.url.isEmpty) {
      _toast('Fetching episode stream…');
      try {
        s = await VodClient().getStream(ep.vid);
        if (!mounted) return;
        setState(() => _episodeMeta[ep.vid] = s!);
      } catch (_) {
        if (mounted) _toast('Failed to get episode stream');
        return;
      }
    }
    if (s.url.isEmpty) { _toast('No stream URL for this episode'); return; }
    final title = s.title.isNotEmpty ? s.title : 'Episode ${ep.episodeNumber}';
    if (mounted) showCastSheet(context, s.url, title);
  }

  // Download a specific episode — uses prefetched meta if available, else fetches on demand
  void _downloadEpisode(VodEpisode ep) async {
    final mgr = context.read<DownloadManager>();
    final alreadyActive = mgr.tasks.any((t) => t.movieId == ep.vid && t.isActive);
    if (alreadyActive) { _toast('Already downloading…'); return; }

    VodStream? s = _episodeMeta[ep.vid];

    // If not yet prefetched, fetch it now
    if (s == null || s.url.isEmpty) {
      _toast('Fetching episode…');
      try {
        s = await VodClient().getStream(ep.vid);
        if (!mounted) return;
        setState(() => _episodeMeta[ep.vid] = s!);
      } catch (_) {
        if (mounted) _toast('Failed to get episode URL');
        return;
      }
    }

    if (s.url.isEmpty) { _toast('No download URL for this episode'); return; }

    mgr.startDownload(
      movieId: ep.vid,
      title: s.title.isNotEmpty ? s.title : 'Episode ${ep.episodeNumber}',
      quality: s.vj.isNotEmpty ? s.vj : 'Uganda',
      url: s.url,
      thumbnail: s.image.isNotEmpty ? s.image : widget.movie.thumbnail,
      referer: _ugR,
    );
    _toast('Downloading Episode ${ep.episodeNumber}…');
  }

  void _toast(String msg) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(msg),
        duration: const Duration(seconds: 2),
        backgroundColor: AppTheme.surface,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final movie = widget.movie;
    final s = _stream;
    final thumb = (s != null && s.image.isNotEmpty) ? s.image : movie.thumbnail;
    final vj = s?.vj ?? '';
    final size = s?.size ?? '';
    final duration = s?.duration ?? '';
    final description = s?.description ?? '';
    final title = (s != null && s.title.isNotEmpty) ? s.title : movie.title;

    return Scaffold(
      backgroundColor: AppTheme.background,
      body: SafeArea(
        top: true,
        bottom: false,
        child: CustomScrollView(
          physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
          slivers: [
            // ── Hero Image ──────────────────────────────────────────────────
            SliverAppBar(
              expandedHeight: 260,
              pinned: true,
              backgroundColor: AppTheme.background,
              elevation: 0,
              leading: IconButton(
                icon: const Icon(Icons.arrow_back_ios_rounded, color: Colors.white),
                onPressed: () => Navigator.pop(context),
              ),
              actions: [
                if (_stream != null && _stream!.url.isNotEmpty)
                  CastIconButton(
                    url: _stream!.url,
                    title: widget.movie.title,
                    size: 22,
                  ),
                Consumer<AppProvider>(
                  builder: (_, p, __) => IconButton(
                    icon: Icon(
                      p.isInWatchlist(movie.id) ? Icons.bookmark_rounded : Icons.bookmark_border_rounded,
                      color: p.isInWatchlist(movie.id) ? const Color(0xFFFCDC04) : Colors.white,
                    ),
                    onPressed: () => p.toggleWatchlist(movie),
                  ),
                ),
              ],
              flexibleSpace: FlexibleSpaceBar(
                background: Stack(
                  fit: StackFit.expand,
                  children: [
                    if (_tmdbBackdrop.isNotEmpty || thumb != null)
                      CachedNetworkImage(
                        imageUrl: _tmdbBackdrop.isNotEmpty ? _tmdbBackdrop : thumb!,
                        fit: BoxFit.cover,
                        alignment: Alignment.topCenter,
                        memCacheWidth: 1080,
                        maxWidthDiskCache: 1920,
                        filterQuality: FilterQuality.high,
                        placeholder: (_, __) => thumb != null
                            ? CachedNetworkImage(imageUrl: thumb, fit: BoxFit.cover, alignment: Alignment.topCenter, filterQuality: FilterQuality.medium)
                            : Container(color: AppTheme.shimmerBase),
                        errorWidget: (_, __, ___) => Container(color: AppTheme.shimmerBase),
                      )
                    else
                      Container(
                        color: AppTheme.card,
                        child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted, size: 64),
                      ),
                    Container(
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          begin: Alignment.topCenter,
                          end: Alignment.bottomCenter,
                          colors: [
                            Colors.black.withOpacity(0.1),
                            Colors.black.withOpacity(0.45),
                            AppTheme.background,
                          ],
                          stops: const [0.0, 0.6, 1.0],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),

            SliverToBoxAdapter(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 4, 16, 40),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    // ── VJ Badge ─────────────────────────────────────────────
                    if (vj.isNotEmpty) ...[
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: const Color(0xFFFCDC04).withOpacity(0.15),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(color: const Color(0xFFFCDC04).withOpacity(0.5)),
                        ),
                        child: Text(
                          'VJ $vj',
                          style: const TextStyle(
                            color: Color(0xFFFCDC04),
                            fontSize: 11,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ),
                      const SizedBox(height: 10),
                    ],

                    // ── Title ─────────────────────────────────────────────────
                    Text(
                      title,
                      style: const TextStyle(
                        color: AppTheme.textPrimary,
                        fontSize: 22,
                        fontWeight: FontWeight.w800,
                        height: 1.2,
                      ),
                    ),
                    const SizedBox(height: 10),

                    // ── Meta row: duration + size + type badge ────────────────
                    Wrap(
                      spacing: 12,
                      runSpacing: 6,
                      crossAxisAlignment: WrapCrossAlignment.center,
                      children: [
                        if (_loadingStream)
                          const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(color: Color(0xFFFCDC04), strokeWidth: 2),
                          ),
                        if (!_loadingStream && duration.isNotEmpty)
                          _MetaChip(icon: Icons.access_time_rounded, label: duration),
                        if (!_loadingStream && size.isNotEmpty)
                          _MetaChip(icon: Icons.storage_rounded, label: size),
                        _MetaChip(icon: Icons.flag_rounded, label: 'Uganda Cinema Plus'),
                      ],
                    ),
                    const SizedBox(height: 16),

                    // ── VJ selector (shown when multiple versions exist) ───────
                    if (_versions.length > 1) ...[
                      Row(children: [
                        const Text(
                          'Choose VJ',
                          style: TextStyle(
                            color: AppTheme.textMuted,
                            fontSize: 12,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 0.4,
                          ),
                        ),
                        if (_loadingVersions) ...[
                          const SizedBox(width: 8),
                          const SizedBox(
                            width: 10, height: 10,
                            child: CircularProgressIndicator(
                                color: Color(0xFFFCDC04), strokeWidth: 1.5),
                          ),
                        ],
                      ]),
                      const SizedBox(height: 8),
                      SingleChildScrollView(
                        scrollDirection: Axis.horizontal,
                        physics: const BouncingScrollPhysics(),
                        child: Row(
                          children: _versions.map((v) {
                            final selected = _selectedVid == v.id;
                            return GestureDetector(
                              onTap: selected ? null : () => _switchVj(v),
                              child: AnimatedContainer(
                                duration: const Duration(milliseconds: 200),
                                margin: const EdgeInsets.only(right: 8),
                                padding: const EdgeInsets.symmetric(
                                    horizontal: 16, vertical: 9),
                                decoration: BoxDecoration(
                                  color: selected
                                      ? const Color(0xFFFCDC04)
                                      : AppTheme.card,
                                  borderRadius: BorderRadius.circular(22),
                                  border: Border.all(
                                    color: selected
                                        ? const Color(0xFFFCDC04)
                                        : AppTheme.border,
                                    width: selected ? 1.5 : 1,
                                  ),
                                ),
                                child: Text(
                                  v.vjName,
                                  style: TextStyle(
                                    color: selected
                                        ? Colors.black
                                        : AppTheme.textPrimary,
                                    fontSize: 13,
                                    fontWeight: selected
                                        ? FontWeight.w800
                                        : FontWeight.w500,
                                  ),
                                ),
                              ),
                            );
                          }).toList(),
                        ),
                      ),
                      const SizedBox(height: 16),
                    ],

                    // ── Stream error ─────────────────────────────────────────
                    if (_streamError != null) ...[
                      _RetryCard(error: _streamError!, onRetry: _fetchStream),
                      const SizedBox(height: 16),
                    ],

                    // ── Watch Now (primary CTA) ───────────────────────────────
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: () {
                          if (_stream != null) {
                            _playNow();
                          } else {
                            setState(() => _pendingPlay = true);
                          }
                        },
                        icon: (_loadingStream && _pendingPlay)
                            ? const SizedBox(
                                width: 18, height: 18,
                                child: CircularProgressIndicator(
                                  color: Colors.black, strokeWidth: 2.5))
                            : const Icon(Icons.play_circle_filled_rounded, size: 22),
                        label: Text(
                          (_loadingStream && _pendingPlay) ? 'Starting…' : 'Watch Now',
                          style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w800),
                        ),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFFFCDC04),
                          foregroundColor: Colors.black,
                          padding: const EdgeInsets.symmetric(vertical: 15),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                        ),
                      ),
                    ),
                    const SizedBox(height: 10),

                    // ── Secondary actions ─────────────────────────────────────
                    Row(children: [
                      Expanded(
                        child: _ActionBtn(
                          icon: Icons.download_rounded,
                          label: 'Download',
                          color: const Color(0xFF1565C0),
                          onTap: (_stream != null && !_loadingStream) ? _download : null,
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: _ActionBtn(
                          icon: Icons.cast_rounded,
                          label: 'Cast',
                          color: const Color(0xFF1B5E20),
                          onTap: (_stream != null && _stream!.url.isNotEmpty)
                              ? () => showCastSheet(context, _stream!.url, widget.movie.title)
                              : null,
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Consumer<AppProvider>(
                          builder: (_, p, __) => _ActionBtn(
                            icon: p.isInWatchlist(movie.id)
                                ? Icons.bookmark_rounded
                                : Icons.bookmark_border_rounded,
                            label: p.isInWatchlist(movie.id) ? 'Saved' : 'Watchlist',
                            color: p.isInWatchlist(movie.id)
                                ? const Color(0xFF8B0000)
                                : AppTheme.card,
                            borderColor: AppTheme.border,
                            onTap: () => p.toggleWatchlist(movie),
                          ),
                        ),
                      ),
                    ]),
                    const SizedBox(height: 20),

                    // ── Download progress ─────────────────────────────────────
                    Consumer<DownloadManager>(
                      builder: (_, mgr, __) {
                        final tasks = mgr.tasks.where((t) => t.movieId == movie.id).toList();
                        if (tasks.isEmpty) return const SizedBox.shrink();
                        return Column(
                          children: [
                            for (final task in tasks)
                              _DownloadStatusCard(task: task),
                            const SizedBox(height: 8),
                          ],
                        );
                      },
                    ),

                    // ── Description ───────────────────────────────────────────
                    () {
                      final isTruncated = description.trim().endsWith('...');
                      final best = (isTruncated || description.isEmpty) && _tmdbOverview.isNotEmpty
                          ? _tmdbOverview
                          : description.isNotEmpty
                              ? description
                              : (movie.summary != null &&
                                      movie.summary!.isNotEmpty &&
                                      !movie.summary!.startsWith('By '))
                                  ? movie.summary!
                                  : '';
                      return best.isNotEmpty
                          ? Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                              _ExpandableSummary(summary: best),
                              const SizedBox(height: 16),
                            ])
                          : const SizedBox.shrink();
                    }(),

                    // ── Info rows ─────────────────────────────────────────────
                    if (!_loadingStream && vj.isNotEmpty)
                      _InfoRow(label: 'Narrator (VJ)', value: vj),
                    if (!_loadingStream && duration.isNotEmpty)
                      _InfoRow(label: 'Duration', value: duration),
                    if (!_loadingStream && size.isNotEmpty)
                      _InfoRow(label: 'File Size', value: size),
                    _InfoRow(label: 'Origin', value: 'Uganda'),
                    _InfoRow(label: 'Language', value: 'Luganda / English'),

                    // ── Episodes (series) ─────────────────────────────────────
                    if (_episodes.isNotEmpty) ...[
                      const SizedBox(height: 24),
                      Row(
                        children: [
                          const Text(
                            'Episodes',
                            style: TextStyle(
                              color: AppTheme.textPrimary,
                              fontSize: 17,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                          const SizedBox(width: 8),
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 8, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0xFFFCDC04).withOpacity(0.15),
                              borderRadius: BorderRadius.circular(10),
                            ),
                            child: Text(
                              '${_episodes.length}',
                              style: const TextStyle(
                                color: Color(0xFFFCDC04),
                                fontSize: 11,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Column(
                        children: _episodes.map((ep) {
                          final isCurrentVid = ep.vid == (_selectedVid ?? widget.movie.id);
                          return _EpisodeTile(
                            episode: ep,
                            meta: _episodeMeta[ep.vid],
                            isPlaying: isCurrentVid,
                            onTap: () => _playEpisode(ep),
                            onDownload: () => _downloadEpisode(ep),
                            onCast: () => _castEpisode(ep),
                          );
                        }).toList(),
                      ),
                    ],

                    // ── Cast ─────────────────────────────────────────────────
                    if (_loadingCast || _cast.isNotEmpty) ...[
                      const SizedBox(height: 24),
                      const Text(
                        'Cast',
                        style: TextStyle(
                          color: AppTheme.textPrimary,
                          fontSize: 17,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 14),
                      if (_loadingCast)
                        SizedBox(
                          height: 110,
                          child: ListView.builder(
                            scrollDirection: Axis.horizontal,
                            physics: const BouncingScrollPhysics(),
                            itemCount: 6,
                            itemBuilder: (_, __) => const _CastShimmer(),
                          ),
                        )
                      else
                        SizedBox(
                          height: 126,
                          child: ListView.builder(
                            scrollDirection: Axis.horizontal,
                            physics: const BouncingScrollPhysics(),
                            itemCount: _cast.length,
                            itemBuilder: (_, i) => _CastCard(member: _cast[i]),
                          ),
                        ),
                    ],

                    // ── You may also like ─────────────────────────────────────
                    if (widget.related.isNotEmpty) ...[
                      const SizedBox(height: 24),
                      const Text(
                        'You May Also Like',
                        style: TextStyle(
                          color: AppTheme.textPrimary,
                          fontSize: 17,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                      const SizedBox(height: 14),
                      SizedBox(
                        height: 205,
                        child: ListView.builder(
                          scrollDirection: Axis.horizontal,
                          physics: const BouncingScrollPhysics(),
                          itemCount: widget.related.length,
                          itemBuilder: (_, i) {
                            final m = widget.related[i];
                            return GestureDetector(
                              onTap: () => Navigator.pushReplacement(
                                context,
                                MaterialPageRoute(
                                  builder: (_) => UgandaDetailScreen(
                                    movie: m,
                                    related: widget.related
                                        .where((r) => r.id != m.id)
                                        .toList(),
                                  ),
                                ),
                              ),
                              child: _RelatedCard(movie: m),
                            );
                          },
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Supporting widgets ────────────────────────────────────────────────────────

class _MetaChip extends StatelessWidget {
  final IconData icon;
  final String label;
  const _MetaChip({required this.icon, required this.label});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(icon, color: AppTheme.textMuted, size: 13),
        const SizedBox(width: 4),
        Text(label, style: const TextStyle(color: AppTheme.textMuted, fontSize: 12)),
      ],
    );
  }
}

class _ActionBtn extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final Color? borderColor;
  final VoidCallback? onTap;

  const _ActionBtn({
    required this.icon,
    required this.label,
    required this.color,
    this.borderColor,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final enabled = onTap != null;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 14),
        decoration: BoxDecoration(
          color: enabled ? color : color.withOpacity(0.4),
          borderRadius: BorderRadius.circular(14),
          border: borderColor != null ? Border.all(color: borderColor!) : null,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: Colors.white, size: 20),
            const SizedBox(height: 4),
            Text(
              label,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 10.5,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _InfoRow extends StatelessWidget {
  final String label;
  final String value;
  const _InfoRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 140,
            child: Text(
              '$label:',
              style: const TextStyle(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.w600,
                fontSize: 13,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13),
            ),
          ),
        ],
      ),
    );
  }
}

class _ExpandableSummary extends StatefulWidget {
  final String summary;
  const _ExpandableSummary({required this.summary});

  @override
  State<_ExpandableSummary> createState() => _ExpandableSummaryState();
}

class _ExpandableSummaryState extends State<_ExpandableSummary> {
  bool _expanded = false;
  bool _overflows = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkOverflow());
  }

  void _checkOverflow() {
    if (!mounted) return;
    final tp = TextPainter(
      text: TextSpan(
        text: widget.summary,
        style: const TextStyle(fontSize: 13.5, height: 1.6),
      ),
      maxLines: 3,
      textDirection: TextDirection.ltr,
    )..layout(maxWidth: MediaQuery.of(context).size.width - 32);
    if (tp.didExceedMaxLines) setState(() => _overflows = true);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        AnimatedSize(
          duration: const Duration(milliseconds: 250),
          curve: Curves.easeInOut,
          alignment: Alignment.topLeft,
          child: Text(
            widget.summary,
            maxLines: _expanded ? null : 3,
            overflow: _expanded ? TextOverflow.visible : TextOverflow.ellipsis,
            style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13.5, height: 1.6),
          ),
        ),
        if (_overflows) ...[
          const SizedBox(height: 4),
          GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: () => setState(() => _expanded = !_expanded),
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 6),
              child: Text(
                _expanded ? 'Read less ▲' : 'Read more ▼',
                style: const TextStyle(
                  color: Color(0xFFFCDC04),
                  fontSize: 12.5,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
          ),
        ],
      ],
    );
  }
}

class _RetryCard extends StatelessWidget {
  final String error;
  final VoidCallback onRetry;
  const _RetryCard({required this.error, required this.onRetry});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.red.withOpacity(0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.red.withOpacity(0.3)),
      ),
      child: Column(
        children: [
          const Icon(Icons.error_outline_rounded, color: Colors.red, size: 32),
          const SizedBox(height: 8),
          const Text(
            'Could not load stream info',
            style: TextStyle(color: Colors.red, fontWeight: FontWeight.w700, fontSize: 14),
          ),
          const SizedBox(height: 4),
          Text(
            error,
            style: const TextStyle(color: AppTheme.textMuted, fontSize: 11),
            textAlign: TextAlign.center,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 12),
          ElevatedButton(
            onPressed: onRetry,
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red.shade800,
              foregroundColor: Colors.white,
            ),
            child: const Text('Retry'),
          ),
        ],
      ),
    );
  }
}

class _DownloadStatusCard extends StatelessWidget {
  final DownloadTask task;
  const _DownloadStatusCard({required this.task});

  @override
  Widget build(BuildContext context) {
    final mgr = context.read<DownloadManager>();
    final isDone = task.isDone;
    final isActive = task.isActive;
    final isPaused = task.status == DownloadStatus.paused;
    final isFailed = task.hasFailed;
    final color = isDone
        ? Colors.green
        : isActive
            ? const Color(0xFFFCDC04)
            : isPaused
                ? Colors.orange
                : isFailed
                    ? Colors.red
                    : AppTheme.textMuted;

    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: AppTheme.card,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                isDone
                    ? Icons.download_done_rounded
                    : isActive
                        ? Icons.downloading_rounded
                        : isPaused
                            ? Icons.pause_circle_rounded
                            : isFailed
                                ? Icons.error_rounded
                                : Icons.pause_circle_rounded,
                color: color,
                size: 18,
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  isDone
                      ? 'Downloaded — ${task.quality}'
                      : isPaused
                          ? 'Paused — ${task.progressText}'
                          : isFailed
                              ? 'Failed — ${task.quality}'
                              : task.progressText,
                  style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600),
                ),
              ),
              if (!isDone) ...[
                if (isActive)
                  _ctrl(Icons.pause_rounded, Colors.orange, () => mgr.pauseDownload(task.id)),
                if (isPaused || isFailed)
                  _ctrl(Icons.play_arrow_rounded, Colors.green, () => mgr.resumeDownload(task.id)),
                _ctrl(Icons.cancel_rounded, Colors.red, () => _confirmCancel(context, mgr)),
              ],
            ],
          ),
          if ((isActive || isPaused) && task.totalBytes > 0) ...[
            const SizedBox(height: 6),
            LinearProgressIndicator(
              value: task.progress,
              backgroundColor: AppTheme.border,
              color: isActive ? const Color(0xFFFCDC04) : Colors.orange,
              minHeight: 3,
            ),
            const SizedBox(height: 3),
            Text(
              '${(task.progress * 100).toStringAsFixed(0)}%',
              style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.w600),
            ),
          ],
        ],
      ),
    );
  }

  Widget _ctrl(IconData icon, Color color, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(5),
        margin: const EdgeInsets.only(left: 6),
        decoration: BoxDecoration(
          color: color.withOpacity(0.15),
          borderRadius: BorderRadius.circular(7),
        ),
        child: Icon(icon, color: color, size: 16),
      ),
    );
  }

  void _confirmCancel(BuildContext context, DownloadManager mgr) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppTheme.surface,
        title: const Text('Cancel Download?'),
        content: const Text('This will delete the partial download.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Keep')),
          TextButton(
            onPressed: () { Navigator.pop(context); mgr.cancelDownload(task.id); },
            child: const Text('Cancel Download', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
  }
}

class _CastCard extends StatelessWidget {
  final TmdbCastMember member;
  const _CastCard({required this.member});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 80,
      margin: const EdgeInsets.only(right: 12),
      child: Column(
        children: [
          ClipRRect(
            borderRadius: BorderRadius.circular(40),
            child: member.profileUrl != null
                ? CachedNetworkImage(
                    imageUrl: member.profileUrl!,
                    width: 72,
                    height: 72,
                    fit: BoxFit.cover,
                    placeholder: (_, __) => Container(
                      width: 72,
                      height: 72,
                      color: AppTheme.shimmerBase,
                    ),
                    errorWidget: (_, __, ___) => _CastAvatar(name: member.name),
                  )
                : _CastAvatar(name: member.name),
          ),
          const SizedBox(height: 6),
          Text(
            member.name,
            style: const TextStyle(
              color: AppTheme.textPrimary,
              fontSize: 10,
              fontWeight: FontWeight.w600,
            ),
            maxLines: 2,
            textAlign: TextAlign.center,
            overflow: TextOverflow.ellipsis,
          ),
          if (member.character.isNotEmpty) ...[
            const SizedBox(height: 2),
            Text(
              member.character,
              style: const TextStyle(
                color: AppTheme.textMuted,
                fontSize: 9,
              ),
              maxLines: 1,
              textAlign: TextAlign.center,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ],
      ),
    );
  }
}

class _CastAvatar extends StatelessWidget {
  final String name;
  const _CastAvatar({required this.name});

  @override
  Widget build(BuildContext context) {
    final initials = name.trim().split(' ').take(2).map((w) => w.isNotEmpty ? w[0] : '').join();
    return Container(
      width: 72,
      height: 72,
      decoration: const BoxDecoration(
        shape: BoxShape.circle,
        color: AppTheme.card,
      ),
      alignment: Alignment.center,
      child: Text(
        initials.toUpperCase(),
        style: const TextStyle(
          color: Color(0xFFFCDC04),
          fontSize: 22,
          fontWeight: FontWeight.w800,
        ),
      ),
    );
  }
}

class _CastShimmer extends StatelessWidget {
  const _CastShimmer();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 80,
      margin: const EdgeInsets.only(right: 12),
      child: Column(
        children: [
          Container(
            width: 72,
            height: 72,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: AppTheme.shimmerBase,
            ),
          ),
          const SizedBox(height: 6),
          Container(
            height: 9,
            width: 56,
            decoration: BoxDecoration(
              color: AppTheme.shimmerBase,
              borderRadius: BorderRadius.circular(4),
            ),
          ),
          const SizedBox(height: 4),
          Container(
            height: 8,
            width: 42,
            decoration: BoxDecoration(
              color: AppTheme.shimmerBase,
              borderRadius: BorderRadius.circular(4),
            ),
          ),
        ],
      ),
    );
  }
}

class _EpisodeTile extends StatelessWidget {
  final VodEpisode episode;
  final VodStream? meta;
  final bool isPlaying;
  final VoidCallback onTap;
  final VoidCallback? onDownload;
  final VoidCallback? onCast;

  const _EpisodeTile({
    required this.episode,
    this.meta,
    required this.isPlaying,
    required this.onTap,
    this.onDownload,
    this.onCast,
  });

  @override
  Widget build(BuildContext context) {
    final image       = meta?.image       ?? episode.image;
    final title       = meta?.title       ?? episode.title;
    final duration    = meta?.duration    ?? episode.duration;
    final description = meta?.description ?? episode.description;
    final hasImage    = image.isNotEmpty;
    final hasDesc     = description.isNotEmpty;
    final hasDuration = duration.isNotEmpty;
    // While metadata is still loading show a subtle shimmer on the number box
    final isLoading   = meta == null;

    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: isPlaying
              ? const Color(0xFFFCDC04).withOpacity(0.08)
              : AppTheme.card,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: isPlaying
                ? const Color(0xFFFCDC04).withOpacity(0.4)
                : AppTheme.border,
          ),
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Thumbnail or episode number box
            if (hasImage)
              ClipRRect(
                borderRadius: BorderRadius.circular(8),
                child: CachedNetworkImage(
                  imageUrl: image,
                  width: 80,
                  height: 56,
                  fit: BoxFit.cover,
                  placeholder: (_, __) => _EpNumBox(n: episode.episodeNumber),
                  errorWidget: (_, __, ___) => _EpNumBox(n: episode.episodeNumber),
                ),
              )
            else if (isLoading)
              // Pulsing shimmer box while meta loads
              Shimmer.fromColors(
                baseColor: AppTheme.card,
                highlightColor: AppTheme.border,
                child: Container(
                  width: 80,
                  height: 56,
                  decoration: BoxDecoration(
                    color: AppTheme.border,
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
              )
            else
              _EpNumBox(n: episode.episodeNumber),
            const SizedBox(width: 12),
            // Info
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Title
                  if (isLoading)
                    Shimmer.fromColors(
                      baseColor: AppTheme.card,
                      highlightColor: AppTheme.border,
                      child: Container(
                        height: 13,
                        width: 140,
                        decoration: BoxDecoration(
                          color: AppTheme.border,
                          borderRadius: BorderRadius.circular(4),
                        ),
                      ),
                    )
                  else
                    Text(
                      title.isNotEmpty ? title : 'Episode ${episode.episodeNumber}',
                      style: TextStyle(
                        color: isPlaying
                            ? const Color(0xFFFCDC04)
                            : AppTheme.textPrimary,
                        fontSize: 13.5,
                        fontWeight: FontWeight.w600,
                        height: 1.3,
                      ),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  if (hasDuration) ...[
                    const SizedBox(height: 4),
                    Row(
                      children: [
                        const Icon(Icons.access_time_rounded,
                            size: 11, color: AppTheme.textMuted),
                        const SizedBox(width: 3),
                        Text(
                          duration,
                          style: const TextStyle(
                              color: AppTheme.textMuted, fontSize: 11),
                        ),
                      ],
                    ),
                  ],
                  if (hasDesc) ...[
                    const SizedBox(height: 4),
                    Text(
                      description,
                      style: const TextStyle(
                          color: AppTheme.textSecondary,
                          fontSize: 11,
                          height: 1.4),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ] else if (isLoading) ...[
                    const SizedBox(height: 6),
                    Shimmer.fromColors(
                      baseColor: AppTheme.card,
                      highlightColor: AppTheme.border,
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Container(
                            height: 10,
                            width: double.infinity,
                            decoration: BoxDecoration(
                              color: AppTheme.border,
                              borderRadius: BorderRadius.circular(4),
                            ),
                          ),
                          const SizedBox(height: 4),
                          Container(
                            height: 10,
                            width: 100,
                            decoration: BoxDecoration(
                              color: AppTheme.border,
                              borderRadius: BorderRadius.circular(4),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(width: 6),
            // Actions column — play + cast + download
            Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  isPlaying
                      ? Icons.pause_circle_rounded
                      : Icons.play_circle_outline_rounded,
                  color: isPlaying
                      ? const Color(0xFFFCDC04)
                      : AppTheme.textMuted,
                  size: 26,
                ),
                const SizedBox(height: 6),
                GestureDetector(
                  onTap: onCast,
                  child: Icon(
                    Icons.cast_rounded,
                    color: onCast != null
                        ? Colors.white54
                        : AppTheme.textMuted.withOpacity(0.35),
                    size: 20,
                  ),
                ),
                const SizedBox(height: 6),
                GestureDetector(
                  onTap: onDownload,
                  child: Icon(
                    Icons.download_rounded,
                    color: onDownload != null
                        ? AppTheme.primary
                        : AppTheme.textMuted.withOpacity(0.35),
                    size: 22,
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}

class _EpNumBox extends StatelessWidget {
  final int n;
  const _EpNumBox({required this.n});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 72,
      height: 52,
      decoration: BoxDecoration(
        color: AppTheme.shimmerBase,
        borderRadius: BorderRadius.circular(8),
      ),
      alignment: Alignment.center,
      child: Text(
        'E$n',
        style: const TextStyle(
          color: AppTheme.textMuted,
          fontSize: 15,
          fontWeight: FontWeight.w700,
        ),
      ),
    );
  }
}

class _EpisodeShimmer extends StatelessWidget {
  const _EpisodeShimmer();

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTheme.card,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppTheme.border),
      ),
      child: Row(
        children: [
          Container(
            width: 72, height: 52,
            decoration: BoxDecoration(
              color: AppTheme.shimmerBase,
              borderRadius: BorderRadius.circular(8),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(height: 13, width: double.infinity,
                    decoration: BoxDecoration(color: AppTheme.shimmerBase, borderRadius: BorderRadius.circular(4))),
                const SizedBox(height: 6),
                Container(height: 11, width: 80,
                    decoration: BoxDecoration(color: AppTheme.shimmerBase, borderRadius: BorderRadius.circular(4))),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _RelatedCard extends StatelessWidget {
  final Movie movie;
  const _RelatedCard({required this.movie});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 120,
      margin: const EdgeInsets.only(right: 12),
      decoration: BoxDecoration(
        color: AppTheme.card,
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          ClipRRect(
            borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
            child: movie.thumbnail != null
                ? LayoutBuilder(builder: (ctx, c) {
                    final dpr = MediaQuery.of(ctx).devicePixelRatio;
                    return CachedNetworkImage(
                      imageUrl: movie.thumbnail!,
                      width: 120,
                      height: 155,
                      fit: BoxFit.cover,
                      alignment: Alignment.topCenter,
                      memCacheWidth: (120 * dpr).ceil(),
                      memCacheHeight: (155 * dpr).ceil(),
                      filterQuality: FilterQuality.high,
                      placeholder: (_, __) => Container(
                        width: 120, height: 155, color: AppTheme.shimmerBase),
                      errorWidget: (_, __, ___) => Container(
                        width: 120,
                        height: 155,
                        color: AppTheme.shimmerBase,
                        child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted),
                      ),
                    );
                  })
                : Container(
                    width: 120,
                    height: 155,
                    color: AppTheme.shimmerBase,
                    child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted),
                  ),
          ),
          Expanded(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(7, 6, 7, 4),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    movie.title,
                    style: const TextStyle(
                      color: AppTheme.textPrimary,
                      fontSize: 10.5,
                      fontWeight: FontWeight.w600,
                      height: 1.3,
                    ),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                  if (movie.summary != null) ...[
                    const SizedBox(height: 2),
                    Text(
                      movie.summary!,
                      style: const TextStyle(
                        color: Color(0xFFFCDC04),
                        fontSize: 9,
                        fontWeight: FontWeight.w600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }
}
