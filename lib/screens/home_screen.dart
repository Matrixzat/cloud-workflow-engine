import 'dart:async';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:cached_network_image/cached_network_image.dart';
import '../utils/app_cache_manager.dart';
import 'package:provider/provider.dart';
import '../api/models.dart';
import '../api/tmdb_service.dart';
import '../providers/app_provider.dart';
import '../services/download_manager.dart';
import '../theme/app_theme.dart';
import '../widgets/content_section.dart';
import '../widgets/app_drawer.dart';
import 'adult_home_screen.dart';
import 'football_screen.dart';
import 'uganda_home_screen.dart';
import 'detail_screen.dart';
import 'downloads_screen.dart';
import 'search_screen.dart';
import 'settings_screen.dart';
import 'view_all_screen.dart';
import 'continue_watching_screen.dart';
import 'watchlist_screen.dart';
import '../services/update_service.dart';

class HomeScreen extends StatefulWidget {
  final bool restoreAdult;
  final bool restoreFootball;
  const HomeScreen({super.key, this.restoreAdult = false, this.restoreFootball = false});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  int _currentIndex = 0;
  final GlobalKey<ScaffoldState> _scaffoldKey = GlobalKey<ScaffoldState>();
  final Set<int> _activatedIndices = {0};
  DateTime? _lastBackPressed;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      context.read<AppProvider>().loadHome();

      // Request gallery/media access at startup so downloads appear in gallery.
      // Runs after notification permission (which fires on first download).
      context.read<DownloadManager>().requestMediaPermissions();

      // Restore adult section if the user was there before the app was killed.
      // Done here (not in the splash) so the navigator context is always valid.
      if (widget.restoreAdult) {
        Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => const AdultHomeScreen()),
        );
      } else if (widget.restoreFootball) {
        Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => const FootballScreen()),
        );
      }
    });
  }

  void _openDetail(Movie movie) {
    context.read<AppProvider>().addToHistory(movie);
    Navigator.push(context, MaterialPageRoute(builder: (_) => DetailScreen(movie: movie)));
  }

  void _openViewAll(String title, List<Movie> movies, String sectionKey) {
    Navigator.push(context, MaterialPageRoute(builder: (_) => ViewAllScreen(title: title, initialMovies: movies, sectionKey: sectionKey)));
  }

  @override
  Widget build(BuildContext context) {
    final provider = context.watch<AppProvider>();
    final downloadManager = context.watch<DownloadManager>();
    final int totalDownloading = downloadManager.totalDownloading;

    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (didPop) return;
        final now = DateTime.now();
        final lastPress = _lastBackPressed;
        if (lastPress != null &&
            now.difference(lastPress) < const Duration(seconds: 2)) {
          // Second tap within 2 s — exit the app
          SystemNavigator.pop();
        } else {
          _lastBackPressed = now;
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(
              content: Text('Tap back again to exit'),
              duration: Duration(seconds: 2),
              behavior: SnackBarBehavior.floating,
            ),
          );
        }
      },
      child: Scaffold(
      key: _scaffoldKey,
      backgroundColor: AppTheme.background,
      drawer: AppDrawer(
        onTabSelect: (idx) {
          setState(() {
            _currentIndex = idx;
            _activatedIndices.add(idx);
          });
          context.read<AppProvider>().setIndex(idx);
        },
        onUgandaTap: () {
          Navigator.push(context, MaterialPageRoute(builder: (_) => const UgandaHomeScreen()));
        },
      ),
      appBar: _buildAppBar(_currentIndex),
      body: IndexedStack(
        index: _currentIndex,
        children: [
          _HomeTab(onMovieTap: _openDetail, onViewAll: _openViewAll),
          if (_activatedIndices.contains(1)) const SearchScreen() else const SizedBox.shrink(),
          if (_activatedIndices.contains(2)) const WatchlistScreen() else const SizedBox.shrink(),
          if (_activatedIndices.contains(3)) const ContinueWatchingScreen() else const SizedBox.shrink(),
          if (_activatedIndices.contains(4)) const DownloadsScreen() else const SizedBox.shrink(),
        ],
      ),
      bottomNavigationBar: Container(
        decoration: const BoxDecoration(
          color: AppTheme.surface,
          boxShadow: [BoxShadow(color: Colors.black38, blurRadius: 12, offset: Offset(0, -2))],
        ),
        child: BottomNavigationBar(
          currentIndex: _currentIndex,
          onTap: (i) {
            setState(() {
              _currentIndex = i;
              _activatedIndices.add(i);
            });
            provider.setIndex(i);
          },
          items: [
            const BottomNavigationBarItem(icon: Icon(Icons.home_rounded), label: 'Home'),
            const BottomNavigationBarItem(icon: Icon(Icons.search_rounded), label: 'Search'),
            const BottomNavigationBarItem(icon: Icon(Icons.bookmark_rounded), label: 'Watchlist'),
            const BottomNavigationBarItem(icon: Icon(Icons.play_circle_outline_rounded), label: 'Watching'),
            BottomNavigationBarItem(
              icon: Stack(
                clipBehavior: Clip.none,
                children: [
                  const Icon(Icons.download_rounded),
                  if (totalDownloading > 0)
                    Positioned(
                      right: -4, top: -4,
                      child: Container(
                        width: 14, height: 14,
                        decoration: const BoxDecoration(color: AppTheme.primary, shape: BoxShape.circle),
                        child: Center(child: Text('$totalDownloading', style: const TextStyle(fontSize: 9, color: Colors.white, fontWeight: FontWeight.w700))),
                      ),
                    ),
                ],
              ),
              label: 'Downloads',
            ),
          ],
          backgroundColor: AppTheme.surface,
          selectedItemColor: AppTheme.primary,
          unselectedItemColor: AppTheme.textMuted,
          type: BottomNavigationBarType.fixed,
          selectedFontSize: 11,
          unselectedFontSize: 11,
          elevation: 0,
        ),
      ),
    ),   // end Scaffold
    );   // end PopScope
  }

  AppBar _buildAppBar(int idx) {
    return AppBar(
      backgroundColor: AppTheme.background,
      elevation: 0,
      leading: IconButton(
        icon: const Icon(Icons.menu_rounded, color: AppTheme.textPrimary, size: 26),
        onPressed: () => _scaffoldKey.currentState?.openDrawer(),
      ),
      titleSpacing: 0,
      title: RichText(
        text: const TextSpan(
          style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900, letterSpacing: 0.3),
          children: [
            TextSpan(text: 'Adiza ', style: TextStyle(color: Colors.white)),
            TextSpan(text: 'Moviez', style: TextStyle(color: AppTheme.primary)),
            TextSpan(text: ' Box', style: TextStyle(color: Colors.white)),
          ],
        ),
      ),
      actions: [
        IconButton(
          icon: const Icon(Icons.search_rounded, size: 26),
          onPressed: () => setState(() { _currentIndex = 1; _activatedIndices.add(1); }),
        ),
      ],
    );
  }
}

class _ExtraSection {
  final String title;
  final List<Movie> movies;
  final String sectionKey;
  const _ExtraSection(this.title, this.movies, this.sectionKey);
}

class _HomeTab extends StatefulWidget {
  final Function(Movie) onMovieTap;
  final Function(String, List<Movie>, String) onViewAll;
  const _HomeTab({required this.onMovieTap, required this.onViewAll});

  @override
  State<_HomeTab> createState() => _HomeTabState();
}

class _HomeTabState extends State<_HomeTab> {
  final ScrollController _scrollController = ScrollController();
  final _refreshKey = GlobalKey<RefreshIndicatorState>();
  final List<_ExtraSection> _extraSections = [];
  bool _loadingMore = false;
  int _extraIndex = 0;


  static const List<_SectionDef> _infiniteQueue = [
    _SectionDef('Thriller', 'thriller'),
    _SectionDef('Comedy Movies', 'comedy'),
    _SectionDef('Drama Series', 'drama'),
    _SectionDef('Sci-Fi', 'sci-fi'),
    _SectionDef('Crime & Mystery', 'crime'),
    _SectionDef('Family Movies', 'family'),
    _SectionDef('Documentary', 'documentary'),
    _SectionDef('War Movies', 'war'),
    _SectionDef('Western', 'western'),
    _SectionDef('Biography', 'biography'),
    _SectionDef('Musical', 'musical'),
    _SectionDef('Fantasy', 'fantasy'),
    _SectionDef('Superhero', 'superhero'),
    _SectionDef('True Crime', 'true crime'),
    _SectionDef('Teen Drama', 'teen'),
    _SectionDef('Historical', 'historical'),
    _SectionDef('Sports Movies', 'sports'),
    _SectionDef('Holiday Movies', 'holiday'),
    _SectionDef('Trending Page 2', 'trending_p2'),
    _SectionDef('Trending Page 3', 'trending_p3'),
    _SectionDef('Trending Page 4', 'trending_p4'),
    _SectionDef('Trending Page 5', 'trending_p5'),
    _SectionDef('Trending Page 6', 'trending_p6'),
    _SectionDef('Trending Page 7', 'trending_p7'),
    _SectionDef('Trending Page 8', 'trending_p8'),
    _SectionDef('Trending Page 9', 'trending_p9'),
    _SectionDef('Trending Page 10', 'trending_p10'),
  ];

  bool _showScrollToTop = false;

  @override
  void initState() {
    super.initState();
    _scrollController.addListener(_onScroll);
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  void _onScroll() {
    final pixels = _scrollController.position.pixels;
    final showBtn = pixels > 500;
    if (showBtn != _showScrollToTop) setState(() => _showScrollToTop = showBtn);
    if (pixels >= _scrollController.position.maxScrollExtent - 600) {
      _loadMoreSections();
    }
  }

  void _scrollToTop() {
    _scrollController.animateTo(0, duration: const Duration(milliseconds: 500), curve: Curves.easeOutCubic);
  }

  Future<void> _loadMoreSections() async {
    if (_loadingMore) return;
    setState(() => _loadingMore = true);
    try {
      final client = context.read<AppProvider>().client;
      final def = _infiniteQueue[_extraIndex % _infiniteQueue.length];
      List<Movie> movies;
      if (def.key.startsWith('trending_p')) {
        final pageNum = int.parse(def.key.replaceAll('trending_p', ''));
        movies = await client.getTrending(page: pageNum, perPage: 20);
      } else {
        movies = await client.getGenre(def.key, perPage: 20);
      }
      if (movies.isNotEmpty) {
        final allIds = {
          ..._extraSections.expand((s) => s.movies.map((m) => m.id)),
        };
        final fresh = movies.where((m) => !allIds.contains(m.id)).toList();
        if (fresh.isNotEmpty) {
          _extraSections.add(_ExtraSection(def.title, fresh, def.key));
        }
      }
      _extraIndex++;
    } catch (_) {}
    if (mounted) setState(() => _loadingMore = false);
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        Consumer<AppProvider>(
          builder: (_, provider, __) {
            final loading = provider.loadingHome;
            return RefreshIndicator(
              key: _refreshKey,
              color: AppTheme.primary,
              backgroundColor: AppTheme.surface,
              onRefresh: () async {
                setState(() { _extraSections.clear(); _extraIndex = 0; });
                await provider.loadHome();
              },
              child: Container(
                color: AppTheme.surface,
                child: CustomScrollView(
              controller: _scrollController,
              physics: const BouncingScrollPhysics(
                  parent: AlwaysScrollableScrollPhysics()),
              cacheExtent: 800,
              slivers: [
                if (provider.error.isNotEmpty)
                  SliverToBoxAdapter(
                    child: Container(
                      margin: const EdgeInsets.all(16),
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(color: Colors.red.withOpacity(0.1), borderRadius: BorderRadius.circular(10), border: Border.all(color: Colors.red.withOpacity(0.3))),
                      child: Row(children: [
                        const Icon(Icons.wifi_off_rounded, color: Colors.red, size: 16),
                        const SizedBox(width: 8),
                        Expanded(child: Text(provider.error, style: const TextStyle(color: Colors.red, fontSize: 12))),
                        TextButton(onPressed: provider.loadHome, child: const Text('Retry', style: TextStyle(fontSize: 12))),
                      ]),
                    ),
                  ),
                SliverToBoxAdapter(
                    child: _MovieCarouselBanner(movies: provider.trending)),
                _section(provider, 'Trending Now', provider.trending, loading: loading, sectionKey: 'trending'),
                _section(provider, 'New Releases 2026', provider.newReleases, sectionKey: 'new'),
                _section(provider, 'Action Movies', provider.action, sectionKey: 'action'),
                _section(provider, 'Romance', provider.romance, sectionKey: 'romance'),
                ...provider.homeSections.map((s) => _section(provider, s.title, s.items, sectionKey: s.title.toLowerCase().split(' ').first)),
                _section(provider, 'Nollywood', provider.nollywood, badge: 'NG', sectionKey: 'nollywood'),
                _section(provider, 'K-Drama', provider.kDrama, badge: 'KR', sectionKey: 'k-drama'),
                _section(provider, 'SA Drama', provider.saDrama, badge: 'SA', sectionKey: 'sa drama'),
                _section(provider, 'Anime', provider.anime, sectionKey: 'anime'),
                _section(provider, 'Horror Movies', provider.horror, sectionKey: 'horror'),
                _section(provider, 'Adventure Movies', provider.adventure, sectionKey: 'adventure'),
                _section(provider, 'Hot Short TV', provider.shortTV, sectionKey: 'short tv'),
                ..._extraSections.map((s) => _section(provider, s.title, s.movies, sectionKey: s.sectionKey)),
                SliverToBoxAdapter(
                  child: _loadingMore
                      ? Padding(
                          padding: const EdgeInsets.symmetric(vertical: 24),
                          child: Center(child: SizedBox(width: 28, height: 28, child: CircularProgressIndicator(color: AppTheme.primary, strokeWidth: 2.5))),
                        )
                      : const SizedBox(height: 24),
                ),
              ],
            ),
          ),
        );
          },
        ),
        Positioned(
          bottom: 28, right: 20,
          child: AnimatedOpacity(
            opacity: _showScrollToTop ? 1.0 : 0.0,
            duration: const Duration(milliseconds: 300),
            child: IgnorePointer(
              ignoring: !_showScrollToTop,
              child: GestureDetector(
                onTap: _scrollToTop,
                child: Container(
                  width: 46, height: 46,
                  decoration: BoxDecoration(
                    color: AppTheme.primary,
                    shape: BoxShape.circle,
                    boxShadow: [BoxShadow(color: AppTheme.primary.withOpacity(0.45), blurRadius: 14, offset: const Offset(0, 4))],
                  ),
                  child: const Icon(Icons.keyboard_arrow_up_rounded, color: Colors.white, size: 28),
                ),
              ),
            ),
          ),
        ),
      ],
    );
  }

  SliverToBoxAdapter _section(AppProvider provider, String title, List<Movie> movies, {bool loading = false, String? badge, String sectionKey = 'trending'}) {
    if (!loading && movies.isEmpty) return const SliverToBoxAdapter(child: SizedBox.shrink());
    return SliverToBoxAdapter(
      child: ContentSection(
        title: badge != null ? '$title  [$badge]' : title,
        movies: movies,
        isLoading: loading && movies.isEmpty,
        rows: 2,
        onMovieTap: widget.onMovieTap,
        onViewAll: movies.isNotEmpty ? () => widget.onViewAll(title, movies, sectionKey) : null,
        isWatchlisted: provider.isInWatchlist,
        onWatchlist: provider.toggleWatchlist,
      ),
    );
  }
}

class _SectionDef {
  final String title;
  final String key;
  const _SectionDef(this.title, this.key);
}
// ══════════════════════════════════════════════════════════════════════════════
// OnStream-style Featured Banner
// ══════════════════════════════════════════════════════════════════════════════
class _MovieCarouselBanner extends StatefulWidget {
  final List<Movie> movies;
  const _MovieCarouselBanner({required this.movies});

  @override
  State<_MovieCarouselBanner> createState() => _MovieCarouselBannerState();
}

class _MovieCarouselBannerState extends State<_MovieCarouselBanner>
    with WidgetsBindingObserver {
  late PageController _pageCtrl;
  Timer? _timer;
  int _currentPage = 500;
  static const int _startPage = 500;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _pageCtrl = PageController(viewportFraction: 0.92, initialPage: _startPage);
    _startTimer();
  }

  void _startTimer() {
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(seconds: 5), (_) {
      if (!mounted || widget.movies.isEmpty) return;
      _pageCtrl.nextPage(
        duration: const Duration(milliseconds: 700),
        curve: Curves.easeInOut,
      );
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused || state == AppLifecycleState.inactive) {
      _timer?.cancel();
    } else if (state == AppLifecycleState.resumed) {
      _startTimer();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _timer?.cancel();
    _pageCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final movies = widget.movies;

    if (movies.isEmpty) {
      return Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          SizedBox(
            height: 280,
            child: PageView.builder(
              physics: const NeverScrollableScrollPhysics(),
              controller: PageController(viewportFraction: 0.92),
              itemCount: 4,
              itemBuilder: (_, __) => Padding(
                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 6),
                child: Container(
                  decoration: BoxDecoration(
                    color: AppTheme.shimmerBase,
                    borderRadius: BorderRadius.circular(16),
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 14),
          Container(
            width: 130, height: 14,
            margin: const EdgeInsets.only(bottom: 6),
            decoration: BoxDecoration(color: AppTheme.shimmerBase, borderRadius: BorderRadius.circular(7)),
          ),
          Container(
            width: 90, height: 11,
            decoration: BoxDecoration(color: AppTheme.shimmerBase, borderRadius: BorderRadius.circular(5)),
          ),
          const SizedBox(height: 16),
        ],
      );
    }

    final active = movies[_currentPage % movies.length];

    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        SizedBox(
          height: 280,
          child: PageView.builder(
            controller: _pageCtrl,
            physics: const BouncingScrollPhysics(),
            onPageChanged: (i) => setState(() => _currentPage = i),
            itemBuilder: (context, index) {
              final movie = movies[index % movies.length];
              final isActive = (index % movies.length) == (_currentPage % movies.length);
              return GestureDetector(
                onTap: () => Navigator.of(context).push(
                  MaterialPageRoute(builder: (_) => DetailScreen(movie: movie)),
                ),
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 300),
                  margin: EdgeInsets.symmetric(
                    horizontal: 5,
                    vertical: isActive ? 4 : 16,
                  ),
                  child: _BannerCard(movie: movie, isActive: isActive),
                ),
              );
            },
          ),
        ),

        const SizedBox(height: 12),

        // Title
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16),
          child: AnimatedSwitcher(
            duration: const Duration(milliseconds: 250),
            child: Text(
              active.title,
              key: ValueKey(active.title),
              textAlign: TextAlign.center,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(
                color: AppTheme.textPrimary,
                fontSize: 18,
                fontWeight: FontWeight.w800,
                letterSpacing: -0.2,
              ),
            ),
          ),
        ),

        const SizedBox(height: 5),

        // Genre / type row
        AnimatedSwitcher(
          duration: const Duration(milliseconds: 250),
          child: Row(
            key: ValueKey(active.title + 'meta'),
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text(
                active.isMovie ? 'Movie' : 'TV Series',
                style: const TextStyle(color: AppTheme.textMuted, fontSize: 12, fontWeight: FontWeight.w500),
              ),
              if (active.genres.isNotEmpty) ...[
                const Padding(
                  padding: EdgeInsets.symmetric(horizontal: 6),
                  child: Text('·', style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
                ),
                Flexible(
                  child: Text(
                    active.genres.take(3).join(' · '),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(color: AppTheme.textMuted, fontSize: 12),
                  ),
                ),
              ],
            ],
          ),
        ),

        const SizedBox(height: 14),

        // Action buttons
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Row(
            children: [
              // Detail
              Expanded(
                flex: 1,
                child: GestureDetector(
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => DetailScreen(movie: active)),
                  ),
                  child: Container(
                    height: 42,
                    decoration: BoxDecoration(
                      color: AppTheme.card,
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: AppTheme.border),
                    ),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: const [
                        Icon(Icons.info_outline_rounded, color: AppTheme.textSecondary, size: 16),
                        SizedBox(height: 2),
                        Text('Detail', style: TextStyle(color: AppTheme.textSecondary, fontSize: 10, fontWeight: FontWeight.w600)),
                      ],
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              // Watch Now
              Expanded(
                flex: 3,
                child: GestureDetector(
                  onTap: () => Navigator.of(context).push(
                    MaterialPageRoute(builder: (_) => DetailScreen(movie: active)),
                  ),
                  child: Container(
                    height: 42,
                    decoration: BoxDecoration(
                      color: AppTheme.primary,
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: const Center(
                      child: Text(
                        'WATCH NOW',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 13,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 0.8,
                        ),
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              // Add to list
              Expanded(
                flex: 1,
                child: Consumer<AppProvider>(
                  builder: (ctx, p, _) {
                    final inList = p.watchlist.any((m) => m.id == active.id);
                    return GestureDetector(
                      onTap: () {
                        p.toggleWatchlist(active);
                      },
                      child: Container(
                        height: 42,
                        decoration: BoxDecoration(
                          color: inList ? AppTheme.primary.withOpacity(0.15) : AppTheme.card,
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: inList ? AppTheme.primary.withOpacity(0.5) : AppTheme.border),
                        ),
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              inList ? Icons.bookmark_rounded : Icons.bookmark_border_rounded,
                              color: inList ? AppTheme.primary : AppTheme.textSecondary,
                              size: 16,
                            ),
                            const SizedBox(height: 2),
                            Text(
                              inList ? 'Saved' : 'Add List',
                              style: TextStyle(
                                color: inList ? AppTheme.primary : AppTheme.textSecondary,
                                fontSize: 10,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ],
                        ),
                      ),
                    );
                  },
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 8),
      ],
    );
  }
}

class _BannerCard extends StatefulWidget {
  final Movie movie;
  final bool isActive;
  const _BannerCard({required this.movie, required this.isActive});

  @override
  State<_BannerCard> createState() => _BannerCardState();
}

class _BannerCardState extends State<_BannerCard> {
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
    final fallback = widget.movie.bannerImage ?? widget.movie.thumbnail;
    final hasBd = _backdropUrl.isNotEmpty;
    return ClipRRect(
      borderRadius: BorderRadius.circular(16),
      child: AnimatedOpacity(
        opacity: widget.isActive ? 1.0 : 0.5,
        duration: const Duration(milliseconds: 300),
        child: Stack(
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
                errorWidget: (_, __, ___) => Container(color: AppTheme.shimmerBase),
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
                  errorWidget: (_, __, ___) => Container(color: AppTheme.shimmerBase),
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
              Container(color: AppTheme.shimmerBase),
            Container(color: Colors.black.withOpacity(0.28)),
          ],
        ),
      ),
    );
  }
}
