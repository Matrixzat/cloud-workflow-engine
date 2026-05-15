import 'dart:async';
import 'dart:ui' as ui;
import 'dart:convert';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../api/models.dart';
import '../api/vod_client.dart';

import '../api/tmdb_service.dart';
import '../providers/app_provider.dart';
import '../providers/uganda_provider.dart';
import '../services/download_manager.dart';
import '../theme/app_theme.dart';
import '../utils/app_cache_manager.dart';
import '../widgets/content_section.dart';
import '../widgets/app_drawer.dart';
import 'detail_screen.dart';
import 'local_video_player_screen.dart';
import 'player_screen.dart';
import 'uganda_detail_screen.dart';
import 'uganda_genres_screen.dart';
import 'uganda_view_all_screen.dart';

final _ugR = String.fromCharCodes([104,116,116,112,115,58,47,47,109,117,110,111,119,97,116,99,104,46,111,114,103,47]);

// ── Entry point ────────────────────────────────────────────────────────────────
class UgandaHomeScreen extends StatelessWidget {
  final bool isRoot;
  final VoidCallback? onSwitchToMain;

  const UgandaHomeScreen({
    super.key,
    this.isRoot = false,
    this.onSwitchToMain,
  });

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => UgandaProvider(),
      child: _UgandaView(isRoot: isRoot, onSwitchToMain: onSwitchToMain),
    );
  }
}

// ── Main screen state ─────────────────────────────────────────────────────────
class _UgandaView extends StatefulWidget {
  final bool isRoot;
  final VoidCallback? onSwitchToMain;
  const _UgandaView({this.isRoot = false, this.onSwitchToMain});

  @override
  State<_UgandaView> createState() => _UgandaViewState();
}

class _UgandaViewState extends State<_UgandaView> {
  int _tab = 0;
  final GlobalKey<ScaffoldState> _scaffoldKey = GlobalKey<ScaffoldState>();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final p = context.read<UgandaProvider>();
      if (!p.loaded && !p.loading) p.loadHome();
    });
  }

  void _openDetail(Movie movie) {
    final provider = context.read<UgandaProvider>();
    final allMovies = provider.sections.expand((s) => s.movies).toList();
    final idx = allMovies.indexWhere((m) => m.id == movie.id);
    final related = allMovies
        .where((m) => m.id != movie.id)
        .take(12)
        .toList();
    final streamFuture = VodClient().getStream(movie.id);
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => UgandaDetailScreen(
          movie: movie,
          related: related,
          streamFuture: streamFuture,
          ugandaPlaylist: allMovies,
          ugandaIndex: idx >= 0 ? idx : 0,
        ),
      ),
    );
  }

  void _playDirect(Movie movie) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (_) => _UgandaStreamSheet(movie: movie),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      key: _scaffoldKey,
      backgroundColor: AppTheme.background,
      appBar: _buildAppBar(),
      drawer: widget.isRoot ? _buildRootDrawer(context) : null,
      body: IndexedStack(
        index: _tab,
        children: [
          _UgandaHomeTab(onMovieTap: _openDetail, onPlayDirect: _playDirect),
          _UgandaSearchTab(onMovieTap: _openDetail),
          _UgandaWatchlistTab(onMovieTap: _openDetail),
          const _UgandaWatchingTab(),
          const _UgandaDownloadsTab(),
        ],
      ),
      bottomNavigationBar: _buildBottomNav(),
    );
  }

  Widget _buildBottomNav() {
    return Container(
      decoration: const BoxDecoration(
        color: AppTheme.surface,
        boxShadow: [BoxShadow(color: Colors.black38, blurRadius: 12, offset: Offset(0, -2))],
      ),
      child: BottomNavigationBar(
        currentIndex: _tab,
        onTap: (i) => setState(() => _tab = i),
        items: const [
          BottomNavigationBarItem(
            icon: Icon(Icons.home_rounded),
            label: 'Home',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.search_rounded),
            label: 'Search',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.bookmark_rounded),
            label: 'Watchlist',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.play_circle_outline_rounded),
            label: 'Watching',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.download_rounded),
            label: 'Downloads',
          ),
        ],
        backgroundColor: AppTheme.surface,
        selectedItemColor: const Color(0xFFFCDC04),
        unselectedItemColor: AppTheme.textMuted,
        type: BottomNavigationBarType.fixed,
        selectedFontSize: 10,
        unselectedFontSize: 10,
        elevation: 0,
      ),
    );
  }

  Widget _buildRootDrawer(BuildContext context) {
    return AppDrawer(isUgandaRoot: true, onSwitchToMain: widget.onSwitchToMain);
  }

  AppBar _buildAppBar() {
    return AppBar(
      backgroundColor: AppTheme.background,
      elevation: 0,
      leading: widget.isRoot
          ? IconButton(
              icon: const Icon(Icons.menu_rounded, color: AppTheme.textPrimary, size: 26),
              onPressed: () => _scaffoldKey.currentState?.openDrawer(),
            )
          : IconButton(
              icon: const Icon(Icons.arrow_back_rounded, color: AppTheme.textPrimary, size: 24),
              onPressed: () => Navigator.pop(context),
            ),
      titleSpacing: 0,
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: const Color(0xFFFCDC04).withOpacity(0.15),
              borderRadius: BorderRadius.circular(5),
              border: Border.all(color: const Color(0xFFFCDC04).withOpacity(0.5)),
            ),
            child: const Text(
              'UG',
              style: TextStyle(
                color: Color(0xFFFCDC04),
                fontSize: 10,
                fontWeight: FontWeight.w900,
                letterSpacing: 0.5,
              ),
            ),
          ),
          const SizedBox(width: 8),
          RichText(
            text: const TextSpan(
              style: TextStyle(fontSize: 16, fontWeight: FontWeight.w900, letterSpacing: 0.3),
              children: [
                TextSpan(text: 'Uganda Cinema', style: TextStyle(color: Colors.white)),
                TextSpan(text: ' Plus', style: TextStyle(color: Color(0xFFFCDC04))),
              ],
            ),
          ),
        ],
      ),
      actions: [
        IconButton(
          icon: const Icon(Icons.grid_view_rounded, color: AppTheme.textMuted, size: 22),
          tooltip: 'Genres & Veejays',
          onPressed: () => Navigator.push(
            context,
            MaterialPageRoute(builder: (_) => const UgandaGenresScreen()),
          ),
        ),
      ],
    );
  }
}

// ── Home Tab ──────────────────────────────────────────────────────────────────
class _UgandaHomeTab extends StatefulWidget {
  final void Function(Movie) onMovieTap;
  final void Function(Movie) onPlayDirect;
  const _UgandaHomeTab({required this.onMovieTap, required this.onPlayDirect});

  @override
  State<_UgandaHomeTab> createState() => _UgandaHomeTabState();
}

class _UgExtra {
  final String title;
  final List<Movie> movies;
  final int pipeId;
  _UgExtra(this.title, this.movies, {this.pipeId = 0});
}

class _UgandaHomeTabState extends State<_UgandaHomeTab> {
  final ScrollController _scroll = ScrollController();
  bool _showScrollToTop = false;

  // ── Infinite scroll extras ──────────────────────────────────────────────────
  final List<_UgExtra> _extraSections = [];
  bool _loadingMore = false;
  int _extraPage = 2; // Start from page 2 (page 1 already in provider batch)
  bool _hasMoreContent = true;
  bool _loadScheduled = false;

  static const _ugGenres = [
    'action', 'comedy', 'drama', 'romance', 'thriller',
    'horror', 'sci-fi', 'crime', 'family', 'documentary',
    'animation', 'adventure', 'musical', 'war',
  ];
  static const _genreIdMap = {
    'action': 1, 'horror': 2, 'series': 5, 'adventure': 7,
    'love story': 8, 'comedy': 9, 'crime': 12, 'family': 13,
    'sci-fi': 14, 'romance': 15, 'animation': 20, 'drama': 17,
    'thriller': 19, 'sport': 18,
  };
  int _genreIndex = 0;

  @override
  void initState() {
    super.initState();
    _scroll.addListener(_onScroll);
  }

  void _onScroll() {
    final pixels = _scroll.position.pixels;
    final show = pixels > 500;
    if (show != _showScrollToTop) setState(() => _showScrollToTop = show);
    if (!_loadScheduled &&
        _hasMoreContent &&
        !_loadingMore &&
        pixels >= _scroll.position.maxScrollExtent - 800) {
      _loadScheduled = true;
      Future.delayed(const Duration(milliseconds: 150), () {
        _loadScheduled = false;
        _loadMoreContent();
      });
    }
  }

  Future<void> _loadMoreContent() async {
    if (_loadingMore || !_hasMoreContent) return;
    if (mounted) setState(() => _loadingMore = true);
    try {
      final genre = _ugGenres[_genreIndex % _ugGenres.length];
      final results = await VodClient().search(genre, page: _extraPage);
      if (!mounted) return;
      if (results.isEmpty) {
        // Try advancing genre index before giving up
        _genreIndex++;
        if (_genreIndex >= _ugGenres.length) {
          _hasMoreContent = false;
        }
      } else {
        // Dedup only against other infinite-scroll extras (not provider sections —
        // those are genre rows, search results are a separate content stream)
        final existing = {
          ..._extraSections.expand((s) => s.movies.map((m) => m.id)),
        };
        final fresh = results.where((m) => !existing.contains(m.id)).toList();
        if (fresh.isNotEmpty) {
          final gid = _genreIdMap[genre] ?? 0;
          setState(() {
            _extraSections.add(_UgExtra(
              '${genre[0].toUpperCase()}${genre.substring(1)} — Page $_extraPage',
              fresh,
              pipeId: gid,
            ));
          });
        }
        _extraPage++;
        if (_extraPage > 8) {
          _genreIndex++;
          _extraPage = 1;
        }
      }
    } catch (_) {}
    if (mounted) setState(() => _loadingMore = false);
  }

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        Consumer<UgandaProvider>(
          builder: (_, provider, __) {
            return RefreshIndicator(
              color: const Color(0xFFFCDC04),
              backgroundColor: AppTheme.surface,
              onRefresh: provider.refresh,
              child: Container(
                color: AppTheme.surface,
                child: CustomScrollView(
                  controller: _scroll,
                  physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
                  cacheExtent: 1500,
                  slivers: [
                    // Error banner
                    if (provider.error.isNotEmpty)
                      SliverToBoxAdapter(
                        child: Container(
                          margin: const EdgeInsets.fromLTRB(16, 12, 16, 0),
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.red.withOpacity(0.1),
                            borderRadius: BorderRadius.circular(10),
                            border: Border.all(color: Colors.red.withOpacity(0.3)),
                          ),
                          child: Row(children: [
                            const Icon(Icons.wifi_off_rounded, color: Colors.red, size: 16),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Text(
                                provider.error,
                                style: const TextStyle(color: Colors.red, fontSize: 12),
                              ),
                            ),
                            TextButton(
                              onPressed: provider.loadHome,
                              child: const Text('Retry', style: TextStyle(fontSize: 12)),
                            ),
                          ]),
                        ),
                      ),

                    // ── Featured Banner ─────────────────────────────────────
                    SliverToBoxAdapter(
                      child: _UgandaBanner(
                        movies: provider.featured,
                        loading: provider.loading && provider.featured.isEmpty,
                        onDetail: widget.onMovieTap,
                        onPlayDirect: widget.onPlayDirect,
                      ),
                    ),

                    // ── Genres & Veejays shortcut ───────────────────────────
                    SliverToBoxAdapter(
                      child: Padding(
                        padding: const EdgeInsets.fromLTRB(16, 4, 16, 4),
                        child: GestureDetector(
                          onTap: () => Navigator.push(
                            context,
                            MaterialPageRoute(builder: (_) => const UgandaGenresScreen()),
                          ),
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 13),
                            decoration: BoxDecoration(
                              gradient: LinearGradient(
                                colors: [
                                  const Color(0xFFFCDC04).withOpacity(0.18),
                                  const Color(0xFFFCDC04).withOpacity(0.06),
                                ],
                                begin: Alignment.centerLeft,
                                end: Alignment.centerRight,
                              ),
                              borderRadius: BorderRadius.circular(14),
                              border: Border.all(
                                color: const Color(0xFFFCDC04).withOpacity(0.3),
                              ),
                            ),
                            child: Row(children: [
                              Container(
                                padding: const EdgeInsets.all(8),
                                decoration: BoxDecoration(
                                  color: const Color(0xFFFCDC04).withOpacity(0.2),
                                  shape: BoxShape.circle,
                                ),
                                child: const Icon(
                                  Icons.grid_view_rounded,
                                  color: Color(0xFFFCDC04),
                                  size: 18,
                                ),
                              ),
                              const SizedBox(width: 12),
                              const Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      'Genres & Veejays',
                                      style: TextStyle(
                                        color: AppTheme.textPrimary,
                                        fontSize: 14,
                                        fontWeight: FontWeight.w700,
                                      ),
                                    ),
                                    Text(
                                      'Browse by category or narrator',
                                      style: TextStyle(
                                        color: AppTheme.textMuted,
                                        fontSize: 11,
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                              const Icon(
                                Icons.chevron_right_rounded,
                                color: Color(0xFFFCDC04),
                                size: 22,
                              ),
                            ]),
                          ),
                        ),
                      ),
                    ),

                    // ── Loading shimmer ─────────────────────────────────────
                    if (provider.loading && provider.sections.isEmpty)
                      const SliverToBoxAdapter(
                        child: ContentSection(
                          title: 'Loading Uganda Cinema Plus…',
                          isLoading: true,
                          rows: 2,
                        ),
                      ),

                    // ── Content sections ────────────────────────────────────
                    ...provider.sections.map((s) => SliverToBoxAdapter(
                      child: Consumer<AppProvider>(
                        builder: (_, ap, __) => ContentSection(
                          title: s.badge.isNotEmpty
                              ? '${s.title}  [${s.badge}]'
                              : s.title,
                          movies: s.movies,
                          isLoading: false,
                          rows: 2,
                          onMovieTap: widget.onMovieTap,
                          onViewAll: s.pipeId > 0
                              ? () => Navigator.push(
                                    context,
                                    MaterialPageRoute(
                                      builder: (_) => UgandaViewAllScreen(
                                        title: s.title,
                                        pipeType: s.pipeType,
                                        pipeId: s.pipeId,
                                        fallbackName: s.title,
                                      ),
                                    ),
                                  )
                              : null,
                          isWatchlisted: ap.isInWatchlist,
                          onWatchlist: ap.toggleWatchlist,
                        ),
                      ),
                    )),

                    // ── Infinite-scroll extra sections ──────────────────────
                    ..._extraSections.map((s) => SliverToBoxAdapter(
                      child: Consumer<AppProvider>(
                        builder: (_, ap, __) => ContentSection(
                          title: s.title,
                          movies: s.movies,
                          isLoading: false,
                          rows: 2,
                          onMovieTap: widget.onMovieTap,
                          onViewAll: s.pipeId > 0
                              ? () => Navigator.push(
                                    context,
                                    MaterialPageRoute(
                                      builder: (_) => UgandaViewAllScreen(
                                        title: s.title.split(' —').first,
                                        pipeType: 'g',
                                        pipeId: s.pipeId,
                                        fallbackName: s.title.split(' —').first,
                                      ),
                                    ),
                                  )
                              : null,
                          isWatchlisted: ap.isInWatchlist,
                          onWatchlist: ap.toggleWatchlist,
                        ),
                      ),
                    )),

                    // ── Load-more spinner / end indicator ───────────────────
                    SliverToBoxAdapter(
                      child: _loadingMore
                          ? const Padding(
                              padding: EdgeInsets.symmetric(vertical: 24),
                              child: Center(
                                child: SizedBox(
                                  width: 28,
                                  height: 28,
                                  child: CircularProgressIndicator(
                                    color: Color(0xFFFCDC04),
                                    strokeWidth: 2.5,
                                  ),
                                ),
                              ),
                            )
                          : !_hasMoreContent
                              ? const Padding(
                                  padding: EdgeInsets.symmetric(vertical: 20),
                                  child: Center(
                                    child: Text('You\'ve seen it all!',
                                        style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
                                  ),
                                )
                              : const SizedBox(height: 8),
                    ),

                    // ── Still loading initial sections spinner ───────────────
                    if (provider.loading && provider.sections.isNotEmpty)
                      SliverToBoxAdapter(
                        child: Padding(
                          padding: const EdgeInsets.symmetric(vertical: 24),
                          child: Center(
                            child: SizedBox(
                              width: 28,
                              height: 28,
                              child: CircularProgressIndicator(
                                color: const Color(0xFFFCDC04).withOpacity(0.8),
                                strokeWidth: 2.5,
                              ),
                            ),
                          ),
                        ),
                      ),

                    const SliverToBoxAdapter(child: SizedBox(height: 32)),
                  ],
                ),
              ),
            );
          },
        ),

        // ── Scroll-to-top FAB ───────────────────────────────────────────────
        Positioned(
          bottom: 28,
          right: 20,
          child: AnimatedOpacity(
            opacity: _showScrollToTop ? 1.0 : 0.0,
            duration: const Duration(milliseconds: 300),
            child: IgnorePointer(
              ignoring: !_showScrollToTop,
              child: GestureDetector(
                onTap: () => _scroll.animateTo(
                  0,
                  duration: const Duration(milliseconds: 500),
                  curve: Curves.easeOutCubic,
                ),
                child: Container(
                  width: 46,
                  height: 46,
                  decoration: BoxDecoration(
                    color: const Color(0xFFFCDC04),
                    shape: BoxShape.circle,
                    boxShadow: [
                      BoxShadow(
                        color: const Color(0xFFFCDC04).withOpacity(0.45),
                        blurRadius: 14,
                        offset: const Offset(0, 4),
                      ),
                    ],
                  ),
                  child: const Icon(
                    Icons.keyboard_arrow_up_rounded,
                    color: Colors.black,
                    size: 28,
                  ),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

// ── Featured Banner ───────────────────────────────────────────────────────────
class _UgandaBanner extends StatefulWidget {
  final List<Movie> movies;
  final bool loading;
  final void Function(Movie) onDetail;
  final void Function(Movie) onPlayDirect;

  const _UgandaBanner({
    required this.movies,
    required this.loading,
    required this.onDetail,
    required this.onPlayDirect,
  });

  @override
  State<_UgandaBanner> createState() => _UgandaBannerState();
}

class _UgandaBannerState extends State<_UgandaBanner> {
  late final PageController _pageCtrl = PageController(viewportFraction: 0.92, initialPage: 200);
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _timer = Timer.periodic(const Duration(seconds: 5), (_) {
      if (!mounted || widget.movies.isEmpty) return;
      _pageCtrl.nextPage(
        duration: const Duration(milliseconds: 700),
        curve: Curves.easeInOut,
      );
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    _pageCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (widget.loading) {
      return Container(
        height: 240,
        margin: const EdgeInsets.symmetric(vertical: 12),
        color: AppTheme.shimmerBase,
        child: const Center(
          child: SizedBox(
            width: 28,
            height: 28,
            child: CircularProgressIndicator(color: Color(0xFFFCDC04), strokeWidth: 2.5),
          ),
        ),
      );
    }

    if (widget.movies.isEmpty) return const SizedBox(height: 8);

    return SizedBox(
      height: 255,
      child: PageView.builder(
        controller: _pageCtrl,
        itemBuilder: (_, i) {
          final movie = widget.movies[i % widget.movies.length];
          return Padding(
            padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 10),
            child: ClipRRect(
              borderRadius: BorderRadius.circular(18),
              child: _UgandaBannerCardBg(
                movie: movie,
                child: Stack(
                fit: StackFit.expand,
                children: [
                  const SizedBox.expand(),

                  // Gradient overlay
                  Positioned.fill(
                    child: DecoratedBox(
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          begin: Alignment.topCenter,
                          end: Alignment.bottomCenter,
                          colors: [
                            Colors.transparent,
                            Colors.black.withOpacity(0.6),
                            Colors.black.withOpacity(0.92),
                          ],
                          stops: const [0.3, 0.65, 1.0],
                        ),
                      ),
                    ),
                  ),

                  // VJ badge top-left
                  if (movie.summary != null)
                    Positioned(
                      top: 12,
                      left: 12,
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                        decoration: BoxDecoration(
                          color: const Color(0xFFFCDC04).withOpacity(0.92),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          movie.summary!,
                          style: const TextStyle(
                            color: Colors.black,
                            fontSize: 10,
                            fontWeight: FontWeight.w800,
                          ),
                        ),
                      ),
                    ),

                  // Title + action buttons at bottom
                  Positioned(
                    bottom: 14,
                    left: 14,
                    right: 14,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          movie.title,
                          style: const TextStyle(
                            color: Colors.white,
                            fontSize: 16,
                            fontWeight: FontWeight.w800,
                            height: 1.2,
                            shadows: [Shadow(blurRadius: 8, color: Colors.black)],
                          ),
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 10),
                        Row(children: [
                          // Detail button
                          _BannerBtn(
                            label: 'Detail',
                            icon: Icons.info_outline_rounded,
                            outlined: true,
                            onTap: () => widget.onDetail(movie),
                          ),
                          const SizedBox(width: 8),
                          // Watch Now button
                          _BannerBtn(
                            label: 'Watch Now',
                            icon: Icons.play_arrow_rounded,
                            outlined: false,
                            onTap: () => widget.onPlayDirect(movie),
                          ),
                          const SizedBox(width: 8),
                          // Add to List button
                          Consumer<AppProvider>(
                            builder: (_, ap, __) => _BannerIconBtn(
                              icon: ap.isInWatchlist(movie.id)
                                  ? Icons.bookmark_rounded
                                  : Icons.bookmark_border_rounded,
                              active: ap.isInWatchlist(movie.id),
                              onTap: () => ap.toggleWatchlist(movie),
                            ),
                          ),
                        ]),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),
          );
        },
      ),
    );
  }
}

// ── TMDB backdrop background for each banner card ─────────────────────────────
class _UgandaBannerCardBg extends StatefulWidget {
  final Movie movie;
  final Widget child;
  const _UgandaBannerCardBg({required this.movie, required this.child});
  @override
  State<_UgandaBannerCardBg> createState() => _UgandaBannerCardBgState();
}

class _UgandaBannerCardBgState extends State<_UgandaBannerCardBg> {
  String _backdropUrl = '';

  @override
  void initState() {
    super.initState();
    _fetchBackdrop();
  }

  Future<void> _fetchBackdrop() async {
    final url = await TmdbService().getBackdrop(widget.movie.title);
    if (mounted && url.isNotEmpty) setState(() => _backdropUrl = url);
  }

  @override
  Widget build(BuildContext context) {
    final hasBd = _backdropUrl.isNotEmpty;
    final fallback = widget.movie.thumbnail;
    return Stack(
      fit: StackFit.expand,
      children: [
        if (hasBd)
          CachedNetworkImage(
            imageUrl: _backdropUrl,
            fit: BoxFit.cover,
            alignment: Alignment.center,
            filterQuality: FilterQuality.high,
            cacheManager: AdizaCacheManager(),
            placeholder: (_, __) => Container(color: AppTheme.shimmerBase),
            errorWidget: (_, __, ___) => Container(color: AppTheme.card),
          )
        else if (fallback != null) ...[
          ImageFiltered(
            imageFilter: ui.ImageFilter.blur(sigmaX: 28, sigmaY: 28),
            child: CachedNetworkImage(
              imageUrl: fallback,
              fit: BoxFit.cover,
              filterQuality: FilterQuality.low,
              cacheManager: AdizaCacheManager(),
              placeholder: (_, __) => Container(color: AppTheme.shimmerBase),
              errorWidget: (_, __, ___) => Container(color: AppTheme.card),
            ),
          ),
          CachedNetworkImage(
            imageUrl: fallback,
            fit: BoxFit.contain,
            alignment: Alignment.center,
            filterQuality: FilterQuality.high,
            cacheManager: AdizaCacheManager(),
            placeholder: (_, __) => const SizedBox.shrink(),
            errorWidget: (_, __, ___) => const SizedBox.shrink(),
          ),
        ] else
          Container(color: AppTheme.card),
        widget.child,
      ],
    );
  }
}

class _BannerBtn extends StatelessWidget {
  final String label;
  final IconData icon;
  final bool outlined;
  final VoidCallback onTap;

  const _BannerBtn({
    required this.label,
    required this.icon,
    required this.outlined,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
        decoration: BoxDecoration(
          color: outlined ? Colors.transparent : const Color(0xFFFCDC04),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: outlined ? Colors.white60 : const Color(0xFFFCDC04),
            width: 1.5,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 14, color: outlined ? Colors.white : Colors.black),
            const SizedBox(width: 5),
            Text(
              label,
              style: TextStyle(
                color: outlined ? Colors.white : Colors.black,
                fontSize: 12,
                fontWeight: FontWeight.w700,
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _BannerIconBtn extends StatelessWidget {
  final IconData icon;
  final bool active;
  final VoidCallback onTap;

  const _BannerIconBtn({required this.icon, required this.active, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: active ? const Color(0xFFFCDC04).withOpacity(0.2) : Colors.black38,
          shape: BoxShape.circle,
          border: Border.all(
            color: active ? const Color(0xFFFCDC04) : Colors.white38,
            width: 1.5,
          ),
        ),
        child: Icon(
          icon,
          size: 16,
          color: active ? const Color(0xFFFCDC04) : Colors.white,
        ),
      ),
    );
  }
}

// ── Search Tab ────────────────────────────────────────────────────────────────
class _UgandaSearchTab extends StatefulWidget {
  final void Function(Movie) onMovieTap;
  const _UgandaSearchTab({required this.onMovieTap});

  @override
  State<_UgandaSearchTab> createState() => _UgandaSearchTabState();
}

class _UgandaSearchTabState extends State<_UgandaSearchTab> {
  final TextEditingController _ctrl = TextEditingController();
  final FocusNode _focus = FocusNode();
  Timer? _debounce;
  bool _showSuggestions = false;

  @override
  void initState() {
    super.initState();
    _focus.addListener(() {
      setState(() {
        _showSuggestions = _focus.hasFocus && _ctrl.text.trim().length >= 2;
      });
    });
  }

  @override
  void dispose() {
    _ctrl.dispose();
    _focus.dispose();
    _debounce?.cancel();
    super.dispose();
  }

  void _onChanged(String val) {
    final provider = context.read<UgandaProvider>();
    // Immediately show spinner & clear stale results — no flash of "not found"
    provider.beginSearch(val);
    setState(() {
      _showSuggestions = _focus.hasFocus && val.trim().length >= 2;
    });
    // Then hit the API after a short debounce
    _debounce?.cancel();
    if (val.trim().isEmpty) return;
    _debounce = Timer(const Duration(milliseconds: 350), () {
      provider.search(val);
    });
  }

  void _pickSuggestion(Movie movie) {
    _ctrl.text = movie.title;
    _ctrl.selection = TextSelection.collapsed(offset: movie.title.length);
    setState(() => _showSuggestions = false);
    _debounce?.cancel();
    // Immediate search — no debounce when user explicitly picks a suggestion
    final provider = context.read<UgandaProvider>();
    provider.beginSearch(movie.title);
    provider.search(movie.title);
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              TextField(
                controller: _ctrl,
                focusNode: _focus,
                onChanged: _onChanged,
                style: const TextStyle(color: AppTheme.textPrimary),
                decoration: InputDecoration(
                  hintText: 'Search Uganda Cinema Plus…',
                  hintStyle: const TextStyle(color: AppTheme.textMuted),
                  prefixIcon: const Icon(Icons.search_rounded, color: AppTheme.textMuted),
                  suffixIcon: _ctrl.text.isNotEmpty
                      ? IconButton(
                          icon: const Icon(Icons.clear_rounded, color: AppTheme.textMuted),
                          onPressed: () {
                            _ctrl.clear();
                            _debounce?.cancel();
                            setState(() => _showSuggestions = false);
                            context.read<UgandaProvider>().clearSearch();
                          },
                        )
                      : null,
                  filled: true,
                  fillColor: AppTheme.card,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: BorderSide.none,
                  ),
                  contentPadding: const EdgeInsets.symmetric(vertical: 12),
                ),
              ),
              // ── Instant suggestions from already-loaded movies ──────────────
              if (_showSuggestions)
                Consumer<UgandaProvider>(
                  builder: (_, provider, __) {
                    final suggestions = provider.getSuggestions(_ctrl.text);
                    if (suggestions.isEmpty) return const SizedBox.shrink();
                    return Container(
                      margin: const EdgeInsets.only(top: 4),
                      decoration: BoxDecoration(
                        color: AppTheme.card,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                          color: const Color(0xFFFCDC04).withOpacity(0.25),
                        ),
                        boxShadow: [
                          BoxShadow(
                            color: Colors.black.withOpacity(0.4),
                            blurRadius: 12,
                            offset: const Offset(0, 4),
                          ),
                        ],
                      ),
                      child: Column(
                        mainAxisSize: MainAxisSize.min,
                        children: suggestions.asMap().entries.map((entry) {
                          final i = entry.key;
                          final m = entry.value;
                          return InkWell(
                            onTap: () => _pickSuggestion(m),
                            borderRadius: BorderRadius.circular(12),
                            child: Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 14,
                                vertical: 11,
                              ),
                              decoration: BoxDecoration(
                                border: i < suggestions.length - 1
                                    ? Border(
                                        bottom: BorderSide(
                                          color: Colors.white.withOpacity(0.06),
                                        ),
                                      )
                                    : null,
                              ),
                              child: Row(
                                children: [
                                  const Icon(
                                    Icons.movie_outlined,
                                    color: Color(0xFFFCDC04),
                                    size: 16,
                                  ),
                                  const SizedBox(width: 10),
                                  Expanded(
                                    child: Text(
                                      m.title,
                                      style: const TextStyle(
                                        color: AppTheme.textPrimary,
                                        fontSize: 13,
                                      ),
                                      maxLines: 1,
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                  ),
                                  if (m.summary != null)
                                    Text(
                                      m.summary!,
                                      style: const TextStyle(
                                        color: AppTheme.textMuted,
                                        fontSize: 11,
                                      ),
                                    ),
                                  const SizedBox(width: 4),
                                  const Icon(
                                    Icons.north_west_rounded,
                                    color: AppTheme.textMuted,
                                    size: 14,
                                  ),
                                ],
                              ),
                            ),
                          );
                        }).toList(),
                      ),
                    );
                  },
                ),
            ],
          ),
        ),
        const SizedBox(height: 8),
        Expanded(
          child: Consumer<UgandaProvider>(
            builder: (_, provider, __) {
              if (provider.loadingSearch) {
                return const Center(
                  child: CircularProgressIndicator(color: Color(0xFFFCDC04)),
                );
              }

              if (provider.lastQuery.isEmpty) {
                return Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.movie_filter_outlined,
                        color: AppTheme.textMuted.withOpacity(0.35),
                        size: 64,
                      ),
                      const SizedBox(height: 14),
                      const Text(
                        'Search Uganda Cinema Plus',
                        style: TextStyle(color: AppTheme.textMuted, fontSize: 14),
                      ),
                      const SizedBox(height: 4),
                      const Text(
                        'Action, Horror, Comedy, Series…',
                        style: TextStyle(color: AppTheme.textMuted, fontSize: 12),
                      ),
                    ],
                  ),
                );
              }

              if (provider.searchResults.isEmpty) {
                return Center(
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        Icons.search_off_rounded,
                        color: AppTheme.textMuted.withOpacity(0.4),
                        size: 52,
                      ),
                      const SizedBox(height: 12),
                      Text(
                        'No results for "${provider.lastQuery}"',
                        style: const TextStyle(
                          color: AppTheme.textMuted,
                          fontSize: 13,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 6),
                      const Text(
                        'Try a different title or keyword',
                        style: TextStyle(
                          color: AppTheme.textMuted,
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                );
              }

              return GridView.builder(
                padding: const EdgeInsets.fromLTRB(12, 4, 12, 24),
                physics: const BouncingScrollPhysics(
                    parent: AlwaysScrollableScrollPhysics()),
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                  crossAxisCount: 3,
                  childAspectRatio: 0.62,
                  crossAxisSpacing: 8,
                  mainAxisSpacing: 8,
                ),
                itemCount: provider.searchResults.length,
                itemBuilder: (_, i) {
                  final movie = provider.searchResults[i];
                  return GestureDetector(
                    onTap: () => widget.onMovieTap(movie),
                    child: _SearchMovieCard(movie: movie),
                  );
                },
              );
            },
          ),
        ),
      ],
    );
  }
}

class _SearchMovieCard extends StatelessWidget {
  final Movie movie;
  const _SearchMovieCard({required this.movie});

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        color: AppTheme.card,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Colors.white.withOpacity(0.05)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: ClipRRect(
              borderRadius: const BorderRadius.vertical(top: Radius.circular(10)),
              child: movie.thumbnail != null
                  ? LayoutBuilder(builder: (ctx, c) {
                      final dpr = MediaQuery.of(ctx).devicePixelRatio;
                      return CachedNetworkImage(
                        imageUrl: movie.thumbnail!,
                        width: double.infinity,
                        height: double.infinity,
                        fit: BoxFit.cover,
                        alignment: Alignment.topCenter,
                        memCacheWidth: (c.maxWidth * dpr).ceil(),
                        memCacheHeight: (c.maxHeight * dpr).ceil(),
                        filterQuality: FilterQuality.high,
                        placeholder: (_, __) => Container(color: AppTheme.shimmerBase),
                        errorWidget: (_, __, ___) => Container(
                          color: AppTheme.shimmerBase,
                          child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted),
                        ),
                      );
                    })
                  : Container(
                      color: AppTheme.shimmerBase,
                      child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted),
                    ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(6, 6, 6, 6),
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
        ],
      ),
    );
  }
}

// ── Watchlist Tab ─────────────────────────────────────────────────────────────
class _UgandaWatchlistTab extends StatelessWidget {
  final void Function(Movie) onMovieTap;
  const _UgandaWatchlistTab({required this.onMovieTap});

  @override
  Widget build(BuildContext context) {
    return Consumer<AppProvider>(
      builder: (_, provider, __) {
        if (provider.watchlist.isEmpty) {
          return const Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.bookmark_border_rounded, size: 72, color: AppTheme.textMuted),
                SizedBox(height: 16),
                Text(
                  'Your watchlist is empty',
                  style: TextStyle(color: AppTheme.textSecondary, fontSize: 16, fontWeight: FontWeight.w600),
                ),
                SizedBox(height: 8),
                Text(
                  'Add movies to watch later',
                  style: TextStyle(color: AppTheme.textMuted, fontSize: 13),
                ),
              ],
            ),
          );
        }
        return GridView.builder(
          padding: const EdgeInsets.all(12),
          physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
          gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 3,
            childAspectRatio: 0.62,
            crossAxisSpacing: 8,
            mainAxisSpacing: 8,
          ),
          itemCount: provider.watchlist.length,
          itemBuilder: (_, i) {
            final movie = provider.watchlist[i];
            return GestureDetector(
              onTap: () {
                // Uganda movies have no detailPath; navigate appropriately
                if (movie.detailPath == null || movie.detailPath!.isEmpty) {
                  onMovieTap(movie);
                } else {
                  provider.addToHistory(movie);
                  Navigator.push(
                    context,
                    MaterialPageRoute(builder: (_) => DetailScreen(movie: movie)),
                  );
                }
              },
              child: _WatchlistCard(
                movie: movie,
                onRemove: () => provider.toggleWatchlist(movie),
              ),
            );
          },
        );
      },
    );
  }
}

class _WatchlistCard extends StatelessWidget {
  final Movie movie;
  final VoidCallback onRemove;
  const _WatchlistCard({required this.movie, required this.onRemove});

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        Container(
          decoration: BoxDecoration(
            color: AppTheme.card,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Expanded(
                child: ClipRRect(
                  borderRadius: const BorderRadius.vertical(top: Radius.circular(10)),
                  child: movie.thumbnail != null
                      ? LayoutBuilder(builder: (ctx, c) {
                          final dpr = MediaQuery.of(ctx).devicePixelRatio;
                          return CachedNetworkImage(
                            imageUrl: movie.thumbnail!,
                            width: double.infinity,
                            height: double.infinity,
                            fit: BoxFit.cover,
                            alignment: Alignment.topCenter,
                            memCacheWidth: (c.maxWidth * dpr).ceil(),
                            memCacheHeight: (c.maxHeight * dpr).ceil(),
                            filterQuality: FilterQuality.high,
                            placeholder: (_, __) => Container(color: AppTheme.shimmerBase),
                            errorWidget: (_, __, ___) => Container(
                              color: AppTheme.shimmerBase,
                              child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted),
                            ),
                          );
                        })
                      : Container(
                          color: AppTheme.shimmerBase,
                          child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted),
                        ),
                ),
              ),
              Padding(
                padding: const EdgeInsets.fromLTRB(6, 5, 6, 6),
                child: Text(
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
              ),
            ],
          ),
        ),
        // Remove from watchlist button
        Positioned(
          top: 4,
          right: 4,
          child: GestureDetector(
            onTap: onRemove,
            child: Container(
              padding: const EdgeInsets.all(4),
              decoration: BoxDecoration(
                color: Colors.black54,
                shape: BoxShape.circle,
              ),
              child: const Icon(Icons.bookmark_rounded, color: Color(0xFFFCDC04), size: 14),
            ),
          ),
        ),
      ],
    );
  }
}

// ── Watching (Continue Watching) Tab ─────────────────────────────────────────
class _UgandaWatchingTab extends StatefulWidget {
  const _UgandaWatchingTab();

  @override
  State<_UgandaWatchingTab> createState() => _UgandaWatchingTabState();
}

class _UgandaWatchingTabState extends State<_UgandaWatchingTab> {
  List<_CWEntry> _entries = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final prefs = await SharedPreferences.getInstance();
      final keys = prefs.getKeys().where((k) => k.startsWith('resume_ug_')).toList();
      final entries = <_CWEntry>[];
      for (final key in keys) {
        final raw = prefs.getString(key);
        if (raw == null) continue;
        try {
          final m = jsonDecode(raw) as Map<String, dynamic>;
          entries.add(_CWEntry(
            prefKey: key,
            id: m['id']?.toString() ?? '',
            title: m['title']?.toString() ?? 'Unknown',
            thumb: m['thumb']?.toString() ?? '',
            subjectType: (m['type'] as num?)?.toInt() ?? 1,
            detailPath: m['detailPath']?.toString() ?? '',
            posSecs: (m['pos'] as num?)?.toInt() ?? 0,
            durSecs: (m['dur'] as num?)?.toInt() ?? 0,
            ts: (m['ts'] as num?)?.toInt() ?? 0,
          ));
        } catch (_) {}
      }
      entries.sort((a, b) => b.ts.compareTo(a.ts));
      if (!mounted) return;
      setState(() { _entries = entries; _loading = false; });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _remove(String key) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove(key);
    } catch (_) {}
    setState(() => _entries.removeWhere((e) => e.prefKey == key));
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: Color(0xFFFCDC04)));
    }

    if (_entries.isEmpty) {
      return const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.play_circle_outline_rounded, size: 72, color: AppTheme.textMuted),
            SizedBox(height: 16),
            Text(
              'Nothing in progress',
              style: TextStyle(color: AppTheme.textSecondary, fontSize: 16, fontWeight: FontWeight.w600),
            ),
            SizedBox(height: 8),
            Text(
              'Movies you start watching will appear here',
              style: TextStyle(color: AppTheme.textMuted, fontSize: 13),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      );
    }

    return RefreshIndicator(
      color: const Color(0xFFFCDC04),
      backgroundColor: AppTheme.surface,
      onRefresh: () => _load(),
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 32),
        physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
        itemCount: _entries.length,
        itemBuilder: (_, i) {
          final e = _entries[i];
          return _CWCard(
            entry: e,
            onTap: () {
              final movie = Movie(
                id: e.id,
                title: e.title,
                thumbnail: e.thumb.isNotEmpty ? e.thumb : null,
                subjectType: e.subjectType,
                detailPath: e.detailPath.isNotEmpty ? e.detailPath : null,
              );
              if (movie.detailPath == null || movie.detailPath!.isEmpty) {
                final streamFuture = VodClient().getStream(movie.id);
                Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => UgandaDetailScreen(
                    movie: movie,
                    streamFuture: streamFuture,
                    ugandaPlaylist: [movie],
                    ugandaIndex: 0,
                  )),
                ).then((_) => _load());
              } else {
                Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => DetailScreen(movie: movie)),
                ).then((_) => _load());
              }
            },
            onRemove: () => _remove(e.prefKey),
          );
        },
      ),
    );
  }
}

class _CWEntry {
  final String prefKey;
  final String id;
  final String title;
  final String thumb;
  final int subjectType;
  final String detailPath;
  final int posSecs;
  final int durSecs;
  final int ts;

  _CWEntry({
    required this.prefKey,
    required this.id,
    required this.title,
    required this.thumb,
    required this.subjectType,
    required this.detailPath,
    required this.posSecs,
    required this.durSecs,
    required this.ts,
  });

  double get progress => durSecs > 0 ? (posSecs / durSecs).clamp(0.0, 1.0) : 0.0;

  String get timeLeft {
    final rem = durSecs - posSecs;
    if (rem <= 0) return 'Completed';
    final m = rem ~/ 60;
    final s = (rem % 60).toString().padLeft(2, '0');
    return m > 0 ? '${m}m ${s}s left' : '${s}s left';
  }
}

class _CWCard extends StatelessWidget {
  final _CWEntry entry;
  final VoidCallback onTap;
  final VoidCallback onRemove;

  const _CWCard({required this.entry, required this.onTap, required this.onRemove});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 10),
        decoration: BoxDecoration(
          color: AppTheme.card,
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          children: [
            // Thumbnail
            ClipRRect(
              borderRadius: const BorderRadius.horizontal(left: Radius.circular(12)),
              child: entry.thumb.isNotEmpty
                  ? CachedNetworkImage(
                      imageUrl: entry.thumb,
                      width: 90,
                      height: 70,
                      fit: BoxFit.cover,
                      memCacheWidth: 360,
                      maxWidthDiskCache: 600,
                      filterQuality: FilterQuality.high,
                      errorWidget: (_, __, ___) => Container(
                        width: 90,
                        height: 70,
                        color: AppTheme.shimmerBase,
                        child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted),
                      ),
                    )
                  : Container(
                      width: 90,
                      height: 70,
                      color: AppTheme.shimmerBase,
                      child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted),
                    ),
            ),
            // Info
            Expanded(
              child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      entry.title,
                      style: const TextStyle(
                        color: AppTheme.textPrimary,
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 4),
                    if (entry.durSecs > 0)
                      LinearProgressIndicator(
                        value: entry.progress,
                        backgroundColor: AppTheme.border,
                        color: const Color(0xFFFCDC04),
                        minHeight: 2.5,
                      ),
                    const SizedBox(height: 4),
                    Text(
                      entry.timeLeft,
                      style: const TextStyle(color: AppTheme.textMuted, fontSize: 11),
                    ),
                  ],
                ),
              ),
            ),
            // Remove button
            IconButton(
              icon: const Icon(Icons.close_rounded, color: AppTheme.textMuted, size: 18),
              onPressed: onRemove,
              padding: const EdgeInsets.all(8),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Downloads Tab ─────────────────────────────────────────────────────────────
class _UgandaDownloadsTab extends StatelessWidget {
  const _UgandaDownloadsTab();

  @override
  Widget build(BuildContext context) {
    return Consumer<DownloadManager>(
      builder: (_, mgr, __) {
        final all = mgr.tasks;

        if (all.isEmpty) {
          return const Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.download_outlined, size: 72, color: AppTheme.textMuted),
                SizedBox(height: 16),
                Text(
                  'No downloads yet',
                  style: TextStyle(
                    color: AppTheme.textSecondary,
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                SizedBox(height: 8),
                Text(
                  'Download movies to watch offline',
                  style: TextStyle(color: AppTheme.textMuted, fontSize: 13),
                ),
              ],
            ),
          );
        }

        final active = all.where((t) =>
          t.status == DownloadStatus.downloading ||
          t.status == DownloadStatus.queued ||
          t.status == DownloadStatus.paused ||
          t.status == DownloadStatus.failed
        ).toList();

        final completed = all.where((t) => t.isDone).toList();

        return ListView(
          padding: const EdgeInsets.fromLTRB(12, 12, 12, 32),
          physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
          children: [
            if (active.isNotEmpty) ...[
              _SectionHeader(
                title: 'In Progress',
                count: active.length,
              ),
              const SizedBox(height: 8),
              ...active.map((t) => _DownloadCard(task: t, mgr: mgr)),
              const SizedBox(height: 16),
            ],
            if (completed.isNotEmpty) ...[
              _SectionHeader(
                title: 'Completed',
                count: completed.length,
              ),
              const SizedBox(height: 8),
              ...completed.map((t) => _DownloadCard(task: t, mgr: mgr)),
            ],
          ],
        );
      },
    );
  }
}

class _SectionHeader extends StatelessWidget {
  final String title;
  final int count;
  const _SectionHeader({required this.title, required this.count});

  @override
  Widget build(BuildContext context) {
    return Row(children: [
      Container(
        width: 4,
        height: 18,
        decoration: BoxDecoration(
          color: const Color(0xFFFCDC04),
          borderRadius: BorderRadius.circular(2),
        ),
      ),
      const SizedBox(width: 8),
      Text(
        '$title ($count)',
        style: const TextStyle(
          color: AppTheme.textPrimary,
          fontSize: 15,
          fontWeight: FontWeight.w700,
        ),
      ),
    ]);
  }
}

class _DownloadCard extends StatelessWidget {
  final DownloadTask task;
  final DownloadManager mgr;
  const _DownloadCard({required this.task, required this.mgr});

  @override
  Widget build(BuildContext context) {
    final isDone = task.isDone;
    final isActive = task.isActive;
    final isFailed = task.hasFailed;
    final color = isDone
        ? Colors.green
        : isActive
            ? const Color(0xFFFCDC04)
            : isFailed
                ? Colors.red
                : AppTheme.textMuted;

    return GestureDetector(
      onTap: isDone && task.filePath != null
          ? () => Navigator.push(
                context,
                MaterialPageRoute(
                  builder: (_) => LocalVideoPlayerScreen(
                    filePath: task.filePath!,
                    title: task.title,
                  ),
                ),
              )
          : null,
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: AppTheme.card,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withOpacity(0.2)),
        ),
        child: Row(children: [
          // Thumbnail
          if (task.thumbnail != null)
            ClipRRect(
              borderRadius: BorderRadius.circular(8),
              child: CachedNetworkImage(
                imageUrl: task.thumbnail!,
                width: 56,
                height: 56,
                fit: BoxFit.cover,
                memCacheWidth: 224,
                maxWidthDiskCache: 400,
                filterQuality: FilterQuality.high,
                errorWidget: (_, __, ___) => Container(
                  width: 56,
                  height: 56,
                  color: AppTheme.shimmerBase,
                ),
              ),
            )
          else
            Container(
              width: 56,
              height: 56,
              decoration: BoxDecoration(
                color: AppTheme.shimmerBase,
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.movie_outlined, color: AppTheme.textMuted, size: 28),
            ),
          const SizedBox(width: 12),
          // Info
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  task.title,
                  style: const TextStyle(
                    color: AppTheme.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 3),
                Text(
                  task.quality,
                  style: const TextStyle(
                    color: Color(0xFFFCDC04),
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const SizedBox(height: 5),
                if (isActive && task.totalBytes > 0)
                  LinearProgressIndicator(
                    value: task.progress,
                    backgroundColor: AppTheme.border,
                    color: const Color(0xFFFCDC04),
                    minHeight: 3,
                  ),
                const SizedBox(height: 4),
                Text(
                  isDone
                      ? 'Saved to device'
                      : isFailed
                          ? 'Failed — ${task.errorMessage ?? "Unknown error"}'
                          : task.progressText,
                  style: TextStyle(color: color, fontSize: 11),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          // Action buttons column
          Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Status action: pause / resume / retry / play
              if (isActive)
                _actionBtn(Icons.pause_rounded, AppTheme.gold, () => mgr.pauseDownload(task.id))
              else if (task.status == DownloadStatus.paused)
                _actionBtn(Icons.play_arrow_rounded, const Color(0xFFFCDC04), () => mgr.resumeDownload(task.id))
              else if (isFailed)
                _actionBtn(Icons.refresh_rounded, Colors.orange, () => mgr.resumeDownload(task.id))
              else if (isDone)
                _actionBtn(Icons.play_circle_fill_rounded, Colors.green, null),
              const SizedBox(height: 6),
              // Delete / cancel — always visible
              _actionBtn(
                isDone ? Icons.delete_outline_rounded : Icons.close_rounded,
                Colors.red,
                () => _confirmDelete(context, mgr),
              ),
            ],
          ),
        ]),
      ),
    );
  }

  Widget _actionBtn(IconData icon, Color color, VoidCallback? onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(7),
        decoration: BoxDecoration(
          color: color.withOpacity(0.15),
          borderRadius: BorderRadius.circular(9),
          border: Border.all(color: color.withOpacity(0.4)),
        ),
        child: Icon(icon, color: color, size: 20),
      ),
    );
  }

  void _confirmDelete(BuildContext context, DownloadManager mgr) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppTheme.surface,
        title: Text(task.isDone ? 'Delete Download?' : 'Cancel Download?'),
        content: Text(
          task.isDone
              ? 'This will remove the file from your device.'
              : 'This will cancel and delete the partial file.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Keep')),
          TextButton(
            onPressed: () {
              Navigator.pop(context);
              if (task.isDone) {
                mgr.deleteDownload(task.id);
              } else {
                mgr.cancelDownload(task.id);
              }
            },
            child: Text(
              task.isDone ? 'Delete' : 'Cancel Download',
              style: const TextStyle(color: Colors.red, fontWeight: FontWeight.w700),
            ),
          ),
        ],
      ),
    );
  }
}

// ── Stream sheet (direct play from banner) ────────────────────────────────────
class _UgandaStreamSheet extends StatefulWidget {
  final Movie movie;
  const _UgandaStreamSheet({required this.movie});

  @override
  State<_UgandaStreamSheet> createState() => _UgandaStreamSheetState();
}

class _UgandaStreamSheetState extends State<_UgandaStreamSheet> {
  VodStream? _stream;
  String? _error;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _fetch();
  }

  Future<void> _fetch() async {
    setState(() { _error = null; _loading = true; });
    try {
      final s = await VodClient().getStream(widget.movie.id);
      if (!mounted) return;
      setState(() { _stream = s; _loading = false; });
    } catch (e) {
      if (!mounted) return;
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  void _play() {
    final s = _stream!;
    final movie = Movie(
      id: widget.movie.id,
      title: s.title.isNotEmpty ? s.title : widget.movie.title,
      thumbnail: s.image.isNotEmpty ? s.image : widget.movie.thumbnail,
      summary: s.vj.isNotEmpty ? 'By ${s.vj}' : widget.movie.summary,
      subjectType: 1,
    );
    final source = MovieSource(
      id: widget.movie.id,
      quality: s.vj.isNotEmpty ? s.vj : 'Uganda HD',
      directUrl: s.url,
      referer: _ugR,
    );
    Navigator.pop(context);
    Navigator.push(
      context,
      MaterialPageRoute(builder: (_) => PlayerScreen(movie: movie, source: source, noRelated: true)),
    );
  }

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.48,
      minChildSize: 0.3,
      maxChildSize: 0.75,
      expand: false,
      builder: (_, ctrl) => Container(
        decoration: const BoxDecoration(
          color: Colors.black,
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
        child: ListView(
          controller: ctrl,
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 32),
          children: [
            Center(
              child: Container(
                margin: const EdgeInsets.symmetric(vertical: 12),
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            Text(
              widget.movie.title,
              style: const TextStyle(
                color: Colors.white,
                fontWeight: FontWeight.w800,
                fontSize: 18,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 4),
            const Text(
              'Uganda Cinema Plus',
              style: TextStyle(color: Color(0xFFFCDC04), fontSize: 12, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 20),
            if (_loading) ...[
              const Center(
                child: Column(
                  children: [
                    SizedBox(
                      width: 32,
                      height: 32,
                      child: CircularProgressIndicator(color: Color(0xFFFCDC04), strokeWidth: 2.5),
                    ),
                    SizedBox(height: 12),
                    Text(
                      'Fetching stream…',
                      style: TextStyle(color: AppTheme.textMuted, fontSize: 13),
                    ),
                  ],
                ),
              ),
            ],
            if (_error != null) ...[
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: Colors.red.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: Colors.red.withOpacity(0.3)),
                ),
                child: Column(children: [
                  const Icon(Icons.error_outline_rounded, color: Colors.red, size: 28),
                  const SizedBox(height: 8),
                  Text(
                    _error!,
                    style: const TextStyle(color: AppTheme.textMuted, fontSize: 12),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 12),
                  ElevatedButton(
                    onPressed: _fetch,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.red.shade800,
                      foregroundColor: Colors.white,
                    ),
                    child: const Text('Retry'),
                  ),
                ]),
              ),
            ],
            if (_stream != null && !_loading) ...[
              Container(
                decoration: BoxDecoration(
                  color: const Color(0xFF1A1A2E),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: const Color(0xFFFCDC04).withOpacity(0.5)),
                ),
                padding: const EdgeInsets.all(14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    if (_stream!.vj.isNotEmpty)
                      Text(
                        'Narrated by VJ ${_stream!.vj}',
                        style: const TextStyle(
                          color: Color(0xFFFCDC04),
                          fontWeight: FontWeight.w700,
                          fontSize: 13,
                        ),
                      ),
                    if (_stream!.duration.isNotEmpty) ...[
                      const SizedBox(height: 4),
                      Text(
                        'Duration: ${_stream!.duration}',
                        style: const TextStyle(color: AppTheme.textMuted, fontSize: 12),
                      ),
                    ],
                    if (_stream!.size.isNotEmpty) ...[
                      const SizedBox(height: 2),
                      Text(
                        'Size: ${_stream!.size}',
                        style: const TextStyle(color: AppTheme.textMuted, fontSize: 12),
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _play,
                  icon: const Icon(Icons.play_arrow_rounded, size: 22),
                  label: const Text(
                    'Watch Now',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800),
                  ),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFFCDC04),
                    foregroundColor: Colors.black,
                    padding: const EdgeInsets.symmetric(vertical: 15),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
                  ),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
