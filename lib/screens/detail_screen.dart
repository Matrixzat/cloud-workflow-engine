import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';
import '../api/models.dart';
import '../api/tmdb_service.dart';
import '../utils/app_cache_manager.dart';
import '../api/moviebox_client.dart';
import '../theme/app_theme.dart';
import '../providers/app_provider.dart';
import '../services/download_manager.dart';
import '../services/player_launcher.dart';
import '../utils/quality_utils.dart';
import '../widgets/cast_button.dart';

String _u(List<int> c) => String.fromCharCodes(c);

void _showTopToast(BuildContext context, String message) {
  final overlay = Overlay.of(context, rootOverlay: true);
  late OverlayEntry entry;
  entry = OverlayEntry(
    builder: (_) => _TopToast(message: message, onDone: () => entry.remove()),
  );
  overlay.insert(entry);
}

class _TopToast extends StatefulWidget {
  final String message;
  final VoidCallback onDone;
  const _TopToast({required this.message, required this.onDone});
  @override
  State<_TopToast> createState() => _TopToastState();
}

class _TopToastState extends State<_TopToast> with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;
  late final Animation<double> _opacity;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 300));
    _opacity = CurvedAnimation(parent: _ctrl, curve: Curves.easeOut);
    _ctrl.forward();
    Future.delayed(const Duration(milliseconds: 1800), () async {
      if (mounted) {
        await _ctrl.reverse();
        widget.onDone();
      }
    });
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    final top = MediaQuery.of(context).padding.top + 14;
    return Positioned(
      top: top, left: 16, right: 16,
      child: FadeTransition(
        opacity: _opacity,
        child: Material(
          color: Colors.transparent,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 13),
            decoration: BoxDecoration(
              color: Colors.black,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: AppTheme.primary.withOpacity(0.5)),
              boxShadow: const [BoxShadow(color: Colors.black54, blurRadius: 16, offset: Offset(0, 4))],
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                Container(
                  width: 34, height: 34,
                  decoration: BoxDecoration(color: AppTheme.primary, borderRadius: BorderRadius.circular(8)),
                  child: const Icon(Icons.arrow_circle_down_rounded, color: Colors.white, size: 20),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    widget.message,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(color: Colors.white, fontSize: 13.5, fontWeight: FontWeight.w600),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class DetailScreen extends StatefulWidget {
  final Movie movie;
  const DetailScreen({super.key, required this.movie});

  @override
  State<DetailScreen> createState() => _DetailScreenState();
}

class _DetailScreenState extends State<DetailScreen> {
  final MovieBoxClient _client = MovieBoxClient();
  Movie? _fullInfo;
  List<SeasonInfo> _seasons = [];
  List<Movie> _related = [];
  bool _loadingInfo = true;

  int _selectedSeason = 1;
  int _selectedEpisode = 1;

  String _tmdbOverview = '';
  String _tmdbBackdrop = '';

  // Pre-warmed source future: starts fetching in background as soon as movie
  // info loads so the quality sheet appears instantly when the user taps Watch Now.
  Future<List<MovieSource>>? _prewarmFuture;

  @override
  void initState() {
    super.initState();
    _load();
    _fetchTmdbOverview();
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

  Future<void> _load() async {
    setState(() => _loadingInfo = true);
    try {
      _fullInfo = await _client.getInfo(widget.movie.id);
      if (_fullInfo != null && _fullInfo!.isTvSeries) {
        final seasons = await _client.getEpisodes(widget.movie.id);
        setState(() => _seasons = seasons);
        // Pre-warm S1E1 sources for TV series
        _prewarmFuture = _client.getSources(widget.movie.id, season: 1, episode: 1);
      } else {
        // Pre-warm movie sources immediately after info is cached
        _prewarmFuture = _client.getSources(widget.movie.id);
      }
      _loadRelated();
    } catch (_) {
      _fullInfo = widget.movie;
    }
    setState(() => _loadingInfo = false);
  }

  Future<void> _loadRelated() async {
    try {
      final movie = _fullInfo ?? widget.movie;
      final keyword = movie.genres.isNotEmpty ? movie.genres.first : movie.title.split(' ').first;
      final results = await _client.search(keyword, perPage: 12);
      final filtered = results.where((m) => m.id != movie.id).take(10).toList();
      if (mounted) setState(() => _related = filtered);
    } catch (_) {}
  }

  void _showSourcesSheet({bool autoPlay = false}) {
    final movie = _fullInfo ?? widget.movie;
    final isTv = movie.isTvSeries;
    final season = isTv ? _selectedSeason : 0;
    final episode = isTv ? _selectedEpisode : 0;
    // Use the pre-warmed future only when it matches what the sheet needs (movies,
    // or TV S1E1 which is the most common first-watch). Any other episode tapped
    // starts fresh so we always fetch the correct episode's sources.
    final bool prewarmMatches = !isTv || (season == 1 && episode == 1);
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.black,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (_) => _SourcesSheet(
        movie: movie,
        season: isTv ? season : null,
        episode: isTv ? episode : null,
        seasons: isTv ? _seasons : null,
        prewarm: prewarmMatches ? _prewarmFuture : null,
        loader: () => _client.getSources(widget.movie.id, season: season, episode: episode),
        outerContext: context,
      ),
    );
  }

  void _openTrailer() {
    final movie = _fullInfo ?? widget.movie;
    final rawUrl = movie.trailerUrl;
    if (rawUrl == null || rawUrl.isEmpty) return;
    final relayBase = _u([104,116,116,112,115,58,47,47,97,100,105,122,97,45,109,111,118,105,101,122,45,98,111,120,46,109,97,116,114,105,120,122,97,116,57,57,46,119,111,114,107,101,114,115,46,100,101,118,47,114,101,108,97,121]);
    final proxied = '$relayBase?url=${Uri.encodeComponent(rawUrl)}';
    final source = MovieSource(
      id: movie.id,
      quality: 'Trailer',
      directUrl: proxied,
    );
    PlayerLauncher.launch(context, movie, source);
  }

  void _downloadTrailer(BuildContext context) {
    final movie = _fullInfo ?? widget.movie;
    final rawUrl = movie.trailerUrl;
    if (rawUrl == null || rawUrl.isEmpty) return;
    final manager = context.read<DownloadManager>();
    final alreadyActive = manager.tasks.any(
        (t) => t.movieId == movie.id && t.quality == 'Trailer' && t.isActive);
    if (alreadyActive) {
      _showTopToast(context, 'Trailer is already downloading…');
      return;
    }
    manager.startDownload(
      movieId: movie.id,
      title: '${movie.title} Trailer',
      quality: 'Trailer',
      url: rawUrl,
      thumbnail: movie.thumbnail,
    );
    _showTopToast(context, '${movie.title} trailer downloading…');
  }

  void _shareMovie() async {
    final movie = _fullInfo ?? widget.movie;
    final text = '🎬 Watch "${movie.title}" on Adiza Moviez Box!\n${movie.year ?? ''} • ${movie.rating != null ? '⭐ ${movie.rating}' : ''}';
    final uri = Uri.parse('https://wa.me/?text=${Uri.encodeComponent(text)}');
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  @override
  Widget build(BuildContext context) {
    final movie = _fullInfo ?? widget.movie;

    return Scaffold(
      backgroundColor: AppTheme.background,
      body: SafeArea(
        top: true,
        bottom: false,
        child: CustomScrollView(
        physics: const BouncingScrollPhysics(
            parent: AlwaysScrollableScrollPhysics()),
        cacheExtent: 500,
        slivers: [
          SliverAppBar(
            expandedHeight: 210,
            pinned: true,
            backgroundColor: AppTheme.background,
            leading: IconButton(icon: const Icon(Icons.arrow_back_ios_rounded), onPressed: () => Navigator.pop(context)),
            actions: [
              IconButton(
                icon: const Icon(Icons.cast_rounded, color: Colors.white),
                tooltip: 'Cast to device',
                onPressed: _showSourcesSheet,
              ),
              Consumer<AppProvider>(
                builder: (_, p, __) => IconButton(
                  icon: Icon(p.isInWatchlist(movie.id) ? Icons.bookmark_rounded : Icons.bookmark_border_rounded, color: p.isInWatchlist(movie.id) ? AppTheme.primary : Colors.white),
                  onPressed: () => p.toggleWatchlist(movie),
                ),
              ),
            ],
            flexibleSpace: FlexibleSpaceBar(
              background: Stack(
                fit: StackFit.expand,
                children: [
                  if (_tmdbBackdrop.isNotEmpty || movie.thumbnail != null)
                    CachedNetworkImage(
                      imageUrl: _tmdbBackdrop.isNotEmpty ? _tmdbBackdrop : movie.thumbnail!,
                      fit: BoxFit.cover,
                      alignment: Alignment.topCenter,
                      memCacheWidth: 1080,
                      maxWidthDiskCache: 1920,
                      filterQuality: FilterQuality.high,
                      cacheManager: AdizaCacheManager(),
                      placeholder: (_, __) => movie.thumbnail != null
                          ? CachedNetworkImage(imageUrl: movie.thumbnail!, fit: BoxFit.cover, alignment: Alignment.topCenter, filterQuality: FilterQuality.medium, cacheManager: AdizaCacheManager())
                          : Container(color: AppTheme.shimmerBase),
                      errorWidget: (_, __, ___) => Container(color: AppTheme.shimmerBase),
                    ),
                  Container(
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.topCenter,
                        end: Alignment.bottomCenter,
                        colors: [Colors.black.withOpacity(0.15), Colors.black.withOpacity(0.5), AppTheme.background],
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
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(movie.title,
                    style: const TextStyle(color: AppTheme.textPrimary, fontSize: 22, fontWeight: FontWeight.w800, height: 1.2)),
                  const SizedBox(height: 10),

                  _MetaRow(movie: movie),
                  const SizedBox(height: 14),

                  if (movie.genres.isNotEmpty) ...[
                    Wrap(
                      spacing: 8,
                      runSpacing: 4,
                      children: movie.genres.take(4).map((g) => Container(
                        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                        decoration: BoxDecoration(
                          color: AppTheme.card,
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(color: AppTheme.border),
                        ),
                        child: Text(g, style: const TextStyle(color: AppTheme.textSecondary, fontSize: 11, fontWeight: FontWeight.w600)),
                      )).toList(),
                    ),
                    const SizedBox(height: 14),
                  ],

                  () {
                    final raw = movie.summary ?? '';
                    final isTruncated = raw.trim().endsWith('...');
                    final best = (isTruncated || raw.isEmpty) && _tmdbOverview.isNotEmpty
                        ? _tmdbOverview
                        : raw;
                    return best.isNotEmpty
                        ? Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            _ExpandableSummary(summary: best),
                            const SizedBox(height: 16),
                          ])
                        : const SizedBox.shrink();
                  }(),

                  if (movie.trailerUrl != null && movie.trailerUrl!.isNotEmpty) ...[
                    Row(
                      children: [
                        Expanded(
                          child: ElevatedButton.icon(
                            onPressed: _openTrailer,
                            icon: const Icon(Icons.movie_filter_rounded, size: 20),
                            label: const Text('Watch Trailer', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w700)),
                            style: ElevatedButton.styleFrom(
                              backgroundColor: const Color(0xFFFF8C00),
                              foregroundColor: Colors.white,
                              padding: const EdgeInsets.symmetric(vertical: 15),
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                            ),
                          ),
                        ),
                        const SizedBox(width: 10),
                        Consumer<DownloadManager>(
                          builder: (ctx, manager, _) {
                            final trailerTask = manager.tasks.firstWhere(
                              (t) => t.movieId == movie.id && t.quality == 'Trailer',
                              orElse: () => DownloadTask(
                                id: '', movieId: '', title: '', quality: '', url: '',
                              ),
                            );
                            final isDownloading = trailerTask.id.isNotEmpty && trailerTask.isActive;
                            final isDone = trailerTask.id.isNotEmpty && trailerTask.isDone;
                            return Material(
                              color: const Color(0xFF1A1A2E),
                              borderRadius: BorderRadius.circular(14),
                              child: InkWell(
                                borderRadius: BorderRadius.circular(14),
                                onTap: isDone ? null : () => _downloadTrailer(ctx),
                                child: Container(
                                  width: 52,
                                  height: 52,
                                  decoration: BoxDecoration(
                                    borderRadius: BorderRadius.circular(14),
                                    border: Border.all(
                                      color: isDone
                                          ? Colors.green.withOpacity(0.5)
                                          : isDownloading
                                              ? const Color(0xFFFF8C00).withOpacity(0.5)
                                              : Colors.white.withOpacity(0.12),
                                    ),
                                  ),
                                  child: isDownloading
                                      ? Padding(
                                          padding: const EdgeInsets.all(14),
                                          child: CircularProgressIndicator(
                                            value: trailerTask.progress > 0 ? trailerTask.progress : null,
                                            strokeWidth: 2,
                                            color: const Color(0xFFFF8C00),
                                          ),
                                        )
                                      : Icon(
                                          isDone ? Icons.download_done_rounded : Icons.download_rounded,
                                          color: isDone ? Colors.green : Colors.white70,
                                          size: 22,
                                        ),
                                ),
                              ),
                            );
                          },
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                  ],

                  Row(
                    children: [
                      Expanded(
                        child: _ActionButton(
                          icon: Icons.play_circle_filled_rounded,
                          label: 'Watch',
                          color: AppTheme.primary,
                          onTap: _showSourcesSheet,
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Consumer<DownloadManager>(
                          builder: (_, mgr, __) => _ActionButton(
                            icon: Icons.download_rounded,
                            label: 'Download',
                            color: const Color(0xFF1565C0),
                            onTap: () {
                              final movie = _fullInfo ?? widget.movie;
                              _showDownloadSheet(movie);
                            },
                          ),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Consumer<AppProvider>(
                          builder: (_, p, __) => _ActionButton(
                            icon: p.isInWatchlist(movie.id) ? Icons.bookmark_rounded : Icons.bookmark_border_rounded,
                            label: p.isInWatchlist(movie.id) ? 'Saved' : 'Watchlist',
                            color: p.isInWatchlist(movie.id) ? const Color(0xFF8B0000) : AppTheme.card,
                            onTap: () => p.toggleWatchlist(movie),
                            borderColor: AppTheme.border,
                          ),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: _ActionButton(
                          icon: Icons.share_rounded,
                          label: 'Share',
                          color: AppTheme.card,
                          onTap: _shareMovie,
                          borderColor: AppTheme.border,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 20),

                  if (!_loadingInfo && movie.cast.isNotEmpty) _CastSection(cast: movie.cast),

                  if (!_loadingInfo && movie.isTvSeries && _seasons.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    _EpisodesSection(
                      seasons: _seasons,
                      selectedSeason: _selectedSeason,
                      selectedEpisode: _selectedEpisode,
                      onSeasonChanged: (s) => setState(() { _selectedSeason = s; _selectedEpisode = 1; }),
                      onEpisodeTap: (e) { setState(() => _selectedEpisode = e); _showSourcesSheet(); },
                    ),
                  ],

                  if (_loadingInfo)
                    const Center(child: Padding(padding: EdgeInsets.only(top: 24), child: CircularProgressIndicator(color: AppTheme.primary))),

                  if (!_loadingInfo) ...[
                    const SizedBox(height: 8),
                    _InfoRow(label: 'Release Date', value: movie.year ?? 'Unknown'),
                    if (movie.availableSubtitles.isNotEmpty)
                      _InfoRow(label: 'Subtitles', value: '${movie.availableSubtitles.length} language${movie.availableSubtitles.length > 1 ? 's' : ''}'),
                    const SizedBox(height: 24),
                  ],
                ],
              ),
            ),
          ),

          if (_related.isNotEmpty)
            SliverToBoxAdapter(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Padding(
                    padding: EdgeInsets.fromLTRB(16, 0, 16, 12),
                    child: Text('More Like This', style: TextStyle(color: AppTheme.textPrimary, fontSize: 18, fontWeight: FontWeight.w700)),
                  ),
                  SizedBox(
                    height: 220,
                    child: ListView.builder(
                      scrollDirection: Axis.horizontal,
                      physics: const BouncingScrollPhysics(),
                      padding: const EdgeInsets.symmetric(horizontal: 16),
                      itemCount: _related.length,
                      itemBuilder: (_, i) {
                        final m = _related[i];
                        return GestureDetector(
                          onTap: () => Navigator.pushReplacement(context, MaterialPageRoute(builder: (_) => DetailScreen(movie: m))),
                          child: Container(
                            width: 130,
                            margin: const EdgeInsets.only(right: 12),
                            decoration: BoxDecoration(color: AppTheme.card, borderRadius: BorderRadius.circular(12)),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                ClipRRect(
                                  borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                                  child: m.thumbnail != null
                                    ? CachedNetworkImage(imageUrl: m.thumbnail!, width: 130, height: 160, fit: BoxFit.cover, memCacheWidth: 390, memCacheHeight: 480, filterQuality: FilterQuality.medium, cacheManager: AdizaCacheManager(),
                                        errorWidget: (_, __, ___) => Container(width: 130, height: 160, color: AppTheme.shimmerBase, child: const Icon(Icons.movie_rounded, color: AppTheme.textMuted)))
                                    : Container(width: 130, height: 160, color: AppTheme.shimmerBase, child: const Icon(Icons.movie_rounded, color: AppTheme.textMuted)),
                                ),
                                Padding(
                                  padding: const EdgeInsets.all(8),
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Text(m.title, style: const TextStyle(color: AppTheme.textPrimary, fontSize: 11, fontWeight: FontWeight.w600), maxLines: 1, overflow: TextOverflow.ellipsis),
                                      if (m.year != null)
                                        Text(m.year!, style: const TextStyle(color: AppTheme.textMuted, fontSize: 10)),
                                    ],
                                  ),
                                ),
                              ],
                            ),
                          ),
                        );
                      },
                    ),
                  ),
                  const SizedBox(height: 32),
                ],
              ),
            ),
        ],
      ),
      ),
    );
  }

  void _showDownloadSheet(Movie movie) {
    final isTv = movie.isTvSeries;
    final season = isTv ? _selectedSeason : 0;
    final episode = isTv ? _selectedEpisode : 0;
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.black,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (_) => _SourcesSheet(
        movie: movie,
        season: isTv ? season : null,
        episode: isTv ? episode : null,
        loader: () => _client.getSources(widget.movie.id, season: season, episode: episode),
        downloadOnly: true,
      ),
    );
  }
}

class _ActionButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onTap;
  final Color? borderColor;

  const _ActionButton({required this.icon, required this.label, required this.color, required this.onTap, this.borderColor});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 14),
        decoration: BoxDecoration(
          color: color,
          borderRadius: BorderRadius.circular(14),
          border: borderColor != null ? Border.all(color: borderColor!) : null,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: Colors.white, size: 22),
            const SizedBox(height: 4),
            Text(label, style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.w600)),
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
            width: 130,
            child: Text('$label:', style: const TextStyle(color: AppTheme.textPrimary, fontWeight: FontWeight.w600, fontSize: 13)),
          ),
          Expanded(child: Text(value, style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13))),
        ],
      ),
    );
  }
}

class _CastSection extends StatelessWidget {
  final List<CastMember> cast;
  const _CastSection({required this.cast});

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('Cast', style: TextStyle(color: AppTheme.textPrimary, fontSize: 18, fontWeight: FontWeight.w700)),
        const SizedBox(height: 14),
        SizedBox(
          height: 196,
          child: ListView.builder(
            scrollDirection: Axis.horizontal,
            physics: const BouncingScrollPhysics(),
            itemCount: cast.length,
            itemBuilder: (_, i) {
              final member = cast[i];
              return Container(
                width: 120,
                margin: const EdgeInsets.only(right: 10),
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: AppTheme.card,
                  borderRadius: BorderRadius.circular(14),
                ),
                child: Column(
                  children: [
                    ClipRRect(
                      borderRadius: BorderRadius.circular(10),
                      child: SizedBox(
                        width: 104,
                        height: 120,
                        child: member.avatarUrl != null && member.avatarUrl!.isNotEmpty
                          ? CachedNetworkImage(
                              imageUrl: member.avatarUrl!,
                              fit: BoxFit.cover,
                              alignment: Alignment.topCenter,
                              memCacheWidth: 420,
                              maxWidthDiskCache: 600,
                              filterQuality: FilterQuality.high,
                              cacheManager: AdizaCacheManager(),
                              fadeInDuration: const Duration(milliseconds: 200),
                              placeholder: (_, __) => _castPlaceholder(member.name),
                              errorWidget: (_, __, ___) => _castPlaceholder(member.name),
                            )
                          : _castPlaceholder(member.name),
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      member.name,
                      style: const TextStyle(color: AppTheme.textPrimary, fontSize: 12, fontWeight: FontWeight.w700),
                      textAlign: TextAlign.center,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    if (member.character != null && member.character!.isNotEmpty) ...[
                      const SizedBox(height: 2),
                      Text(
                        member.character!,
                        style: const TextStyle(color: AppTheme.textMuted, fontSize: 10),
                        textAlign: TextAlign.center,
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ],
                ),
              );
            },
          ),
        ),
        Container(height: 3, margin: const EdgeInsets.only(top: 12, bottom: 16), width: 60, decoration: BoxDecoration(color: AppTheme.primary, borderRadius: BorderRadius.circular(2))),
      ],
    );
  }

  Widget _castPlaceholder(String name) {
    return Container(
      color: AppTheme.shimmerBase,
      child: Center(
        child: Text(
          name.isNotEmpty ? name[0].toUpperCase() : '?',
          style: const TextStyle(color: AppTheme.textSecondary, fontSize: 30, fontWeight: FontWeight.w700),
        ),
      ),
    );
  }
}

class _MetaRow extends StatelessWidget {
  final Movie movie;
  const _MetaRow({required this.movie});

  @override
  Widget build(BuildContext context) {
    return Wrap(
      spacing: 8, runSpacing: 6,
      children: [
        if (movie.rating != null) _Chip(icon: Icons.star_rounded, color: AppTheme.gold, label: movie.rating!),
        if (movie.year != null) _Chip(icon: Icons.calendar_today_rounded, color: AppTheme.textSecondary, label: movie.year!),
        _Chip(icon: movie.isTvSeries ? Icons.tv_rounded : Icons.movie_rounded, color: movie.isTvSeries ? AppTheme.accent : AppTheme.primary, label: movie.isTvSeries ? 'TV Series' : 'Movie'),
        if (movie.availableSubtitles.isNotEmpty) _Chip(icon: Icons.subtitles_rounded, color: Colors.green, label: '${movie.availableSubtitles.length} subs'),
      ],
    );
  }
}

class _Chip extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String label;
  const _Chip({required this.icon, required this.color, required this.label});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(color: AppTheme.card, borderRadius: BorderRadius.circular(8), border: Border.all(color: AppTheme.border)),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 13, color: color),
          const SizedBox(width: 5),
          Text(label, style: TextStyle(color: color, fontSize: 12, fontWeight: FontWeight.w600)),
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
        style: const TextStyle(fontSize: 13, height: 1.6),
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
            style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.6),
            maxLines: _expanded ? null : 3,
            overflow: _expanded ? TextOverflow.visible : TextOverflow.ellipsis,
          ),
        ),
        if (_overflows) ...[
          const SizedBox(height: 6),
          GestureDetector(
            behavior: HitTestBehavior.opaque,
            onTap: () => setState(() => _expanded = !_expanded),
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 5, horizontal: 2),
              child: Text(
                _expanded ? 'Show less ▲' : 'Read more ▼',
                style: const TextStyle(
                  color: AppTheme.primary,
                  fontSize: 12,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ),
        ],
      ],
    );
  }
}

class _EpisodesSection extends StatelessWidget {
  final List<SeasonInfo> seasons;
  final int selectedSeason;
  final int selectedEpisode;
  final Function(int) onSeasonChanged;
  final Function(int) onEpisodeTap;

  const _EpisodesSection({required this.seasons, required this.selectedSeason, required this.selectedEpisode, required this.onSeasonChanged, required this.onEpisodeTap});

  @override
  Widget build(BuildContext context) {
    final currentSeason = seasons.firstWhere((s) => s.season == selectedSeason, orElse: () => seasons.first);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('Episodes', style: TextStyle(color: AppTheme.textPrimary, fontSize: 18, fontWeight: FontWeight.w700)),
        const SizedBox(height: 12),
        if (seasons.length > 1)
          SizedBox(
            height: 38,
            child: ListView.builder(
              scrollDirection: Axis.horizontal,
              itemCount: seasons.length,
              itemBuilder: (_, i) {
                final s = seasons[i];
                final selected = s.season == selectedSeason;
                return Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: GestureDetector(
                    onTap: () => onSeasonChanged(s.season),
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                      decoration: BoxDecoration(
                        color: selected ? AppTheme.primary : AppTheme.card,
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: selected ? AppTheme.primary : AppTheme.border),
                      ),
                      child: Text('Season ${s.season}', style: TextStyle(color: selected ? Colors.white : AppTheme.textSecondary, fontSize: 13, fontWeight: FontWeight.w600)),
                    ),
                  ),
                );
              },
            ),
          ),
        const SizedBox(height: 12),
        if (currentSeason.episodes.isNotEmpty)
          ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: currentSeason.episodes.length,
            separatorBuilder: (_, __) => const Divider(color: AppTheme.border, height: 1),
            itemBuilder: (_, i) {
              final ep = currentSeason.episodes[i];
              final selected = ep.number == selectedEpisode;
              return InkWell(
                onTap: () => onEpisodeTap(ep.number),
                borderRadius: BorderRadius.circular(8),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 10),
                  decoration: BoxDecoration(
                    color: selected ? AppTheme.primary.withOpacity(0.12) : Colors.transparent,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      Container(
                        width: 36,
                        height: 36,
                        decoration: BoxDecoration(
                          color: selected ? AppTheme.primary : AppTheme.card,
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(color: selected ? AppTheme.primary : AppTheme.border),
                        ),
                        child: Center(
                          child: Text(
                            '${ep.number}',
                            style: TextStyle(
                              color: selected ? Colors.white : AppTheme.textSecondary,
                              fontSize: 13,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              ep.title,
                              style: TextStyle(
                                color: selected ? AppTheme.primary : AppTheme.textPrimary,
                                fontSize: 14,
                                fontWeight: selected ? FontWeight.w700 : FontWeight.w500,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                            if (ep.overview != null && ep.overview!.isNotEmpty) ...[
                              const SizedBox(height: 2),
                              Text(
                                ep.overview!,
                                style: const TextStyle(color: AppTheme.textSecondary, fontSize: 11),
                                maxLines: 1,
                                overflow: TextOverflow.ellipsis,
                              ),
                            ],
                          ],
                        ),
                      ),
                      const SizedBox(width: 8),
                      if (ep.runtimeMinutes != null && ep.runtimeMinutes! > 0)
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                          decoration: BoxDecoration(
                            color: AppTheme.card,
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(color: AppTheme.border),
                          ),
                          child: Text(
                            '${ep.runtimeMinutes}m',
                            style: const TextStyle(color: AppTheme.textSecondary, fontSize: 11, fontWeight: FontWeight.w600),
                          ),
                        ),
                      const SizedBox(width: 4),
                      Icon(
                        Icons.play_circle_outline_rounded,
                        color: selected ? AppTheme.primary : AppTheme.textSecondary,
                        size: 22,
                      ),
                    ],
                  ),
                ),
              );
            },
          )
        else
          GridView.builder(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(crossAxisCount: 5, childAspectRatio: 1.4, crossAxisSpacing: 8, mainAxisSpacing: 8),
            itemCount: currentSeason.maxEpisode,
            itemBuilder: (_, i) {
              final ep = i + 1;
              final selected = ep == selectedEpisode;
              return GestureDetector(
                onTap: () => onEpisodeTap(ep),
                child: Container(
                  decoration: BoxDecoration(
                    color: selected ? AppTheme.primary : AppTheme.card,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: selected ? AppTheme.primary : AppTheme.border),
                  ),
                  child: Center(child: Text('$ep', style: TextStyle(color: selected ? Colors.white : AppTheme.textSecondary, fontSize: 13, fontWeight: FontWeight.w600))),
                ),
              );
            },
          ),
        const SizedBox(height: 20),
      ],
    );
  }
}

class _SourcesSheet extends StatefulWidget {
  final Movie movie;
  final int? season;
  final int? episode;
  final List<SeasonInfo>? seasons;
  final Future<List<MovieSource>>? prewarm;
  final Future<List<MovieSource>> Function() loader;
  final bool downloadOnly;
  final BuildContext? outerContext;

  const _SourcesSheet({required this.movie, this.season, this.episode, this.seasons, this.prewarm, required this.loader, this.downloadOnly = false, this.outerContext});

  @override
  State<_SourcesSheet> createState() => _SourcesSheetState();
}

class _SourcesSheetState extends State<_SourcesSheet> {
  List<MovieSource> _sources = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load({bool ignorePrewarm = false}) async {
    setState(() { _loading = true; _error = null; });
    try {
      // If a pre-warmed future is available, await it directly — it's already in
      // flight (or complete) so the sheet resolves with zero extra network time.
      // On retry we always use the fresh loader so a bad prewarm doesn't loop.
      final sources = await (!ignorePrewarm && widget.prewarm != null
          ? widget.prewarm!
          : widget.loader());
      if (mounted) setState(() { _sources = sources; _loading = false; });
    } catch (e) {
      // Prewarm may have failed (e.g. stale session); fall back to a fresh load.
      if (!ignorePrewarm && widget.prewarm != null) {
        return _load(ignorePrewarm: true);
      }
      if (mounted) setState(() { _error = e.toString().replaceFirst('Exception: ', ''); _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final count = _sources.length;
    return DraggableScrollableSheet(
      initialChildSize: count > 4 ? 0.6 : 0.45,
      minChildSize: 0.25,
      maxChildSize: 0.85,
      expand: false,
      builder: (_, ctrl) => Container(
        decoration: const BoxDecoration(
          color: Colors.black,
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
        child: ListView(
          controller: ctrl,
          padding: const EdgeInsets.fromLTRB(16, 20, 16, 32),
          children: [
            Center(child: Container(width: 40, height: 4, decoration: BoxDecoration(color: AppTheme.border, borderRadius: BorderRadius.circular(2)))),
            const SizedBox(height: 16),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(widget.downloadOnly ? 'Select Quality to Download' : 'Select Quality to Watch',
                  style: const TextStyle(color: AppTheme.textPrimary, fontSize: 17, fontWeight: FontWeight.w700)),
                if (widget.season != null)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(color: AppTheme.card, borderRadius: BorderRadius.circular(8), border: Border.all(color: AppTheme.border)),
                    child: Text('S${widget.season} E${widget.episode}', style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13, fontWeight: FontWeight.w600)),
                  ),
              ],
            ),
            const SizedBox(height: 12),
            if (_loading)
              const Padding(padding: EdgeInsets.symmetric(vertical: 32), child: Center(child: CircularProgressIndicator(color: AppTheme.primary)))
            else if (_error != null)
              _errorState()
            else if (_sources.isEmpty)
              _emptyState()
            else
              ..._sources.map((s) => _SourceTile(source: s, movie: widget.movie, season: widget.season, episode: widget.episode, seasons: widget.seasons, allSources: _sources, downloadOnly: widget.downloadOnly, castContext: widget.outerContext)),
          ],
        ),
      ),
    );
  }

  Widget _errorState() => Padding(
    padding: const EdgeInsets.symmetric(vertical: 16),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      const Icon(Icons.error_outline_rounded, color: AppTheme.primary, size: 36),
      const SizedBox(height: 10),
      SelectableText(_error ?? '', style: const TextStyle(color: AppTheme.textMuted, fontSize: 11, height: 1.5)),
      const SizedBox(height: 14),
      ElevatedButton.icon(onPressed: _load, icon: const Icon(Icons.refresh_rounded, size: 18), label: const Text('Retry'), style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary, foregroundColor: Colors.white)),
    ]),
  );

  Widget _emptyState() => Padding(
    padding: const EdgeInsets.symmetric(vertical: 24),
    child: Center(child: Column(children: [
      const Icon(Icons.cloud_off_rounded, color: AppTheme.textMuted, size: 48),
      const SizedBox(height: 12),
      const Text('No streams found for this title.', style: TextStyle(color: AppTheme.textMuted)),
      const SizedBox(height: 4),
      const Text('Try another episode or check back later.', style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
      const SizedBox(height: 16),
      OutlinedButton.icon(onPressed: _load, icon: const Icon(Icons.refresh_rounded, size: 18), label: const Text('Try Again'), style: OutlinedButton.styleFrom(foregroundColor: AppTheme.primary, side: const BorderSide(color: AppTheme.primary))),
    ])),
  );
}

class _SourceTile extends StatelessWidget {
  final MovieSource source;
  final Movie movie;
  final int? season;
  final int? episode;
  final List<SeasonInfo>? seasons;
  final List<MovieSource>? allSources;
  final bool downloadOnly;
  final BuildContext? castContext;

  const _SourceTile({required this.source, required this.movie, this.season, this.episode, this.seasons, this.allSources, this.downloadOnly = false, this.castContext});

  void _startDownload(BuildContext context) {
    final manager = context.read<DownloadManager>();
    final alreadyRunning = manager.tasks.any(
        (t) => t.movieId == movie.id && t.quality == source.quality && t.isActive);
    if (alreadyRunning) return;
    manager.startDownload(
        movieId: movie.id,
        title: movie.title,
        quality: source.quality,
        url: source.directUrl,
        thumbnail: movie.thumbnail,
        referer: source.referer.isNotEmpty ? source.referer : null);
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: Colors.black,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: AppTheme.primary.withOpacity(0.28)),
      ),
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        splashColor: AppTheme.primary.withOpacity(0.08),
        onTap: () {
          if (downloadOnly) {
            _showTopToast(context, '${movie.title} ${source.quality} downloading…');
            Navigator.pop(context);
            _startDownload(context);
          } else {
            Navigator.pop(context);
            PlayerLauncher.launch(context, movie, source,
                season: season, episode: episode,
                seasons: seasons, allSources: allSources);
          }
        },
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
          child: Row(
            children: [
              Container(
                width: 50,
                height: 50,
                decoration: BoxDecoration(
                  color: qualityColor(source.quality).withOpacity(0.15),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: qualityColor(source.quality).withOpacity(0.5)),
                ),
                child: Icon(
                  downloadOnly ? Icons.download_rounded : qualityIcon(source.quality),
                  color: qualityColor(source.quality),
                  size: 26,
                ),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Text(
                          source.quality,
                          style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.w800),
                        ),
                        const SizedBox(width: 8),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                          decoration: BoxDecoration(
                            color: qualityColor(source.quality),
                            borderRadius: BorderRadius.circular(5),
                          ),
                          child: Text(
                            qualityLabel(source.quality),
                            style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.w700),
                          ),
                        ),
                      ],
                    ),
                    if (source.size > 0) ...[
                      const SizedBox(height: 3),
                      Text(
                        '${(source.size / 1024 / 1024).toStringAsFixed(0)} MB',
                        style: const TextStyle(color: Colors.white38, fontSize: 12),
                      ),
                    ],
                  ],
                ),
              ),
              if (!downloadOnly && castContext != null) ...[
                GestureDetector(
                  onTap: () {
                    final ctx = castContext!;
                    final url = source.directUrl;
                    final title = movie.title;
                    Navigator.pop(context);
                    showCastSheet(ctx, url, title);
                  },
                  child: const Padding(
                    padding: EdgeInsets.all(8),
                    child: Icon(Icons.cast_rounded, color: Colors.white54, size: 20),
                  ),
                ),
                const SizedBox(width: 2),
              ],
              _DownloadButton(source: source, movie: movie),
              if (!downloadOnly) ...[
                const SizedBox(width: 8),
                const Icon(Icons.chevron_right_rounded, color: Colors.white24, size: 22),
              ],
            ],
          ),
        ),
      ),
    );
  }
}

class _DownloadButton extends StatelessWidget {
  final MovieSource source;
  final Movie movie;
  final Color? color;
  const _DownloadButton({required this.source, required this.movie, this.color});

  @override
  Widget build(BuildContext context) {
    final manager = context.watch<DownloadManager>();
    final taskIdx = manager.tasks.indexWhere((t) => t.movieId == movie.id && t.quality == source.quality);
    final task = taskIdx >= 0 ? manager.tasks[taskIdx] : null;

    if (task != null && task.isDone) {
      return Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: Colors.white.withOpacity(0.1),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: Colors.white24),
        ),
        child: const Icon(Icons.check_circle_rounded, color: Colors.white, size: 20),
      );
    }
    if (task != null && task.isActive) {
      return GestureDetector(
        onTap: () => manager.pauseDownload(task.id),
        child: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: AppTheme.primary.withOpacity(0.15),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: AppTheme.primary.withOpacity(0.5)),
          ),
          child: SizedBox(
            width: 20, height: 20,
            child: Stack(children: [
              CircularProgressIndicator(value: task.progress, strokeWidth: 2, color: AppTheme.primary, backgroundColor: Colors.white12),
              const Center(child: Icon(Icons.pause_rounded, color: AppTheme.primary, size: 10)),
            ]),
          ),
        ),
      );
    }
    return GestureDetector(
      onTap: () {
        manager.startDownload(
            movieId: movie.id,
            title: movie.title,
            quality: source.quality,
            url: source.directUrl,
            thumbnail: movie.thumbnail,
            referer: source.referer.isNotEmpty ? source.referer : null);
        _showTopToast(context, '${movie.title} ${source.quality} downloading…');
      },
      child: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: AppTheme.primary.withOpacity(0.13),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: AppTheme.primary.withOpacity(0.45)),
        ),
        child: const Icon(Icons.download_rounded, color: AppTheme.primary, size: 20),
      ),
    );
  }
}
