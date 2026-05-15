import 'dart:async';
import 'dart:math';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../services/adult_cache.dart';
import '../services/adult_service.dart';
import '../services/download_manager.dart';
import '../widgets/adult_preview_thumb.dart';
import 'adult_player_screen.dart';
import 'downloads_screen.dart';

// ── All categories ─────────────────────────────────────────────────────────────

const _kCategories = [
  ('amateur',     'Amateur'),
  ('milf',        'MILF'),
  ('teen',        'Teen'),
  ('lesbian',     'Lesbian'),
  ('anal',        'Anal'),
  ('big tits',    'Big Tits'),
  ('big ass',     'Big Ass'),
  ('blowjob',     'Blowjob'),
  ('pov',         'POV'),
  ('creampie',    'Creampie'),
  ('cumshot',     'Cumshot'),
  ('threesome',   'Threesome'),
  ('gangbang',    'Gangbang'),
  ('interracial', 'Interracial'),
  ('massage',     'Massage'),
  ('public',      'Public'),
  ('squirt',      'Squirt'),
  ('orgasm',      'Orgasm'),
  ('facial',      'Facial'),
  ('hardcore',    'Hardcore'),
  ('rough',       'Rough'),
  ('deepthroat',  'Deepthroat'),
  ('doggystyle',  'Doggystyle'),
  ('cowgirl',     'Cowgirl'),
  ('african',     'African'),
  ('ghana',       'Ghana'),
  ('nigerian',    'Nigerian'),
  ('kenyan',      'Kenyan'),
  ('south african','South African'),
  ('ebony',       'Ebony'),
  ('black',       'Black'),
  ('african leak','African Leak'),
  ('naija',       'Naija'),
  ('nollywood',   'Nollywood'),
  ('asian',       'Asian'),
  ('japanese',    'Japanese'),
  ('korean',      'Korean'),
  ('chinese',     'Chinese'),
  ('thai',        'Thai'),
  ('filipina',    'Filipina'),
  ('latina',      'Latina'),
  ('brazilian',   'Brazilian'),
  ('mexican',     'Mexican'),
  ('russian',     'Russian'),
  ('german',      'German'),
  ('french',      'French'),
  ('british',     'British'),
  ('czech',       'Czech'),
  ('italian',     'Italian'),
  ('indian',      'Indian'),
  ('arab',        'Arab'),
  ('desi',        'Desi'),
  ('pakistani',   'Pakistani'),
  ('blonde',      'Blonde'),
  ('brunette',    'Brunette'),
  ('bbw',         'BBW'),
  ('petite',      'Petite'),
  ('curvy',       'Curvy'),
  ('thick',       'Thick'),
  ('mature',      'Mature'),
  ('granny',      'Granny'),
  ('cougar',      'Cougar'),
  ('stepmom',     'Stepmom'),
  ('stepsister',  'Stepsister'),
  ('teacher',     'Teacher'),
  ('nurse',       'Nurse'),
  ('homemade',    'Homemade'),
  ('leaked',      'Leaked'),
  ('webcam',      'Webcam'),
  ('casting',     'Casting'),
  ('bondage',     'Bondage'),
  ('bdsm',        'BDSM'),
  ('feet',        'Feet'),
  ('femdom',      'Femdom'),
  ('hentai',      'Hentai'),
  ('anime',       'Anime'),
  ('orgy',        'Orgy'),
];


// ── Screen ────────────────────────────────────────────────────────────────────

class AdultHomeScreen extends StatefulWidget {
  const AdultHomeScreen({super.key});

  @override
  State<AdultHomeScreen> createState() => _AdultHomeScreenState();
}

class _AdultHomeScreenState extends State<AdultHomeScreen> {
  final _service             = AdultService();
  final _scrollCtrl          = ScrollController();
  final _searchScrollCtrl    = ScrollController();
  final _searchCtrl          = TextEditingController();
  final _refreshKey          = GlobalKey<RefreshIndicatorState>();
  Timer? _debounce;

  // Featured banner (first loaded batch)
  List<AdultVideo> _featured = [];
  bool _featuredLoaded = false;

  // Home sections (category rows)
  final List<(String, String, List<AdultVideo>)> _sections = [];
  int  _sectionIdx    = 0;
  bool _loadingMore   = false;
  bool _showScrollTop = false;

  // Infinite scroll beyond all categories
  final _random         = Random();
  List<int> _extraShuffled = [];
  int  _extraIdx        = 0;
  int  _extraPage       = 1;

  // Order in which categories are loaded; shuffled on each refresh
  List<int> _categoryOrder = [];
  // Page offset applied to every initial section fetch; randomised on refresh
  int _pageOffset = 0;

  // Search state
  bool _searching         = false;
  bool _searchLoading     = false;
  bool _searchLoadingMore = false;
  bool _searchHasMore     = true;
  bool _searchShowTop     = false;
  int  _searchPage        = 1;
  List<AdultVideo> _searchResults = [];
  String _searchQuery = '';
  final List<String> _searchHistory = [];

  @override
  void initState() {
    super.initState();
    SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
      statusBarColor: Colors.transparent,
      statusBarIconBrightness: Brightness.light,
    ));
    _scrollCtrl.addListener(_onScroll);
    _searchScrollCtrl.addListener(_onSearchScroll);
    _categoryOrder = List.generate(_kCategories.length, (i) => i);
    _loadInitial();
    // Clear old cached thumbnails / GIFs every 7 days automatically
    maybeAutoCleanAdultCache();
    // Remember that user is in the adult section across app restarts
    SharedPreferences.getInstance()
        .then((p) => p.setString('last_section', 'adult'));
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _scrollCtrl.dispose();
    _searchScrollCtrl.dispose();
    _searchCtrl.dispose();
    super.dispose();
  }

  // ── Data loading ─────────────────────────────────────────────────────────────

  Future<void> _loadInitial() async {
    // Load featured + first 3 sections in parallel
    await Future.wait([
      _loadFeatured(),
      _loadNextSection(),
      _loadNextSection(),
      _loadNextSection(),
    ]);
  }

  Future<void> _loadFeatured() async {
    // On refresh (_pageOffset > 0) pick a random category + random page so
    // the featured banner shows genuinely different videos each time.
    final String cat;
    final int page;
    if (_pageOffset > 0) {
      cat  = _kCategories[_random.nextInt(_kCategories.length)].$1;
      page = _pageOffset;
    } else {
      cat  = 'amateur';
      page = 1;
    }
    final videos = await _service.search(cat, page: page);
    if (mounted && videos.isNotEmpty) {
      setState(() {
        _featured     = videos.take(6).toList();
        _featuredLoaded = true;
      });
    }
  }

  Future<void> _loadNextSection() async {
    String key;
    String label;
    int page;

    if (_sectionIdx < _categoryOrder.length) {
      // Walk categories in the current order (shuffled on each refresh)
      final catIdx = _categoryOrder[_sectionIdx++];
      final cat    = _kCategories[catIdx];
      key   = cat.$1;
      label = cat.$2;
      // Use the page offset so every refresh starts at a different page
      page  = _pageOffset > 0 ? _pageOffset + _random.nextInt(3) : 1;
    } else {
      // After all categories shown, cycle randomly with increasing pages
      if (_extraShuffled.isEmpty || _extraIdx >= _extraShuffled.length) {
        _extraShuffled = List.generate(_kCategories.length, (i) => i)
          ..shuffle(_random);
        _extraIdx = 0;
        _extraPage++;
      }
      final catIdx = _extraShuffled[_extraIdx++];
      key   = _kCategories[catIdx].$1;
      label = _kCategories[catIdx].$2;
      page  = _extraPage;
    }

    final videos = await _service.search(key, page: page);
    if (mounted && videos.isNotEmpty) {
      setState(() => _sections.add((key, label, videos)));
    }
  }

  void _onScroll() {
    final px = _scrollCtrl.position.pixels;
    final show = px > 400;
    if (show != _showScrollTop) setState(() => _showScrollTop = show);
    if (px >= _scrollCtrl.position.maxScrollExtent - 600 && !_loadingMore) {
      _loadMoreSections();
    }
  }

  Future<void> _loadMoreSections() async {
    if (_loadingMore) return;
    setState(() => _loadingMore = true);
    await _loadNextSection();
    if (mounted) setState(() => _loadingMore = false);
  }

  // ── Search scroll listener ────────────────────────────────────────────────────
  void _onSearchScroll() {
    final px  = _searchScrollCtrl.position.pixels;
    final max = _searchScrollCtrl.position.maxScrollExtent;
    // Show/hide scroll-to-top
    final showTop = px > 400;
    if (showTop != _searchShowTop) setState(() => _searchShowTop = showTop);
    // Infinite scroll — load more when within 400px of bottom
    if (px >= max - 400 && !_searchLoadingMore && _searchHasMore && _searchQuery.isNotEmpty) {
      _loadMoreSearchResults();
    }
  }

  Future<void> _loadMoreSearchResults() async {
    if (_searchLoadingMore || !_searchHasMore) return;
    setState(() => _searchLoadingMore = true);
    final next = _searchPage + 1;
    final more = await _service.search(_searchQuery, page: next);
    if (!mounted) return;
    setState(() {
      _searchPage = next;
      _searchResults.addAll(more);
      _searchLoadingMore = false;
      _searchHasMore = more.length >= 20;
    });
  }

  Future<void> _refresh() async {
    // Pick a fresh random page (2-6) so every pull-to-refresh loads different
    // videos.  Also shuffle the category order so sections appear in a new
    // sequence each time.
    final newOffset = _random.nextInt(5) + 2;            // 2 … 6
    final newOrder  = List.generate(_kCategories.length, (i) => i)
        ..shuffle(_random);
    setState(() {
      _sections.clear();
      _sectionIdx      = 0;
      _featured        = [];
      _featuredLoaded  = false;
      _extraShuffled   = [];
      _extraIdx        = 0;
      _extraPage       = 1;
      _pageOffset      = newOffset;
      _categoryOrder   = newOrder;
    });
    await _loadInitial();
  }

  // ── Search ───────────────────────────────────────────────────────────────────

  // Called on every keystroke — debounces 480 ms like movie search
  void _onSearchChanged(String value) {
    _debounce?.cancel();
    setState(() {}); // Refresh clear button visibility
    if (value.trim().isEmpty) {
      // Back to "history" state — clear results but stay in search mode
      setState(() { _searchQuery = ''; _searchResults = []; _searchLoading = false; });
      return;
    }
    setState(() => _searchLoading = true);
    _debounce = Timer(const Duration(milliseconds: 480), () {
      _runSearch(value.trim());
    });
  }

  // Called on keyboard "Search" submit
  void _submitSearch(String q) {
    _debounce?.cancel();
    final trimmed = q.trim();
    if (trimmed.isEmpty) return;
    FocusScope.of(context).unfocus();
    _runSearch(trimmed);
  }

  // Actual API call — shared by debounce and submit
  Future<void> _runSearch(String trimmed) async {
    if (!mounted) return;
    setState(() {
      _searchQuery       = trimmed;
      _searchLoading     = true;
      _searchResults     = [];
      _searchPage        = 1;
      _searchHasMore     = true;
      _searchLoadingMore = false;
      _searchShowTop     = false;
    });
    // Add to history (no duplicates, newest first)
    _searchHistory.remove(trimmed);
    _searchHistory.insert(0, trimmed);
    if (_searchHistory.length > 10) _searchHistory.removeLast();

    final results = await _service.search(trimmed, page: 1);
    if (mounted) setState(() {
      _searchResults = results;
      _searchLoading = false;
      _searchHasMore = results.length >= 20;
    });
  }

  void _applyHistoryQuery(String q) {
    _searchCtrl.text = q;
    _searchCtrl.selection = TextSelection.collapsed(offset: q.length);
    FocusScope.of(context).unfocus();
    _runSearch(q);
  }

  void _clearSearch() {
    _debounce?.cancel();
    _searchCtrl.clear();
    FocusScope.of(context).unfocus();
    setState(() {
      _searching     = false;
      _searchResults = [];
      _searchQuery   = '';
      _searchLoading = false;
    });
  }

  // ── Exit confirmation ─────────────────────────────────────────────────────────

  Future<void> _confirmExit() async {
    final confirmed = await showDialog<bool>(
      context: context,
      barrierColor: const Color(0xBF000000),
      builder: (ctx) => Dialog(
        backgroundColor: Colors.transparent,
        insetPadding: const EdgeInsets.symmetric(horizontal: 32),
        child: Container(
          decoration: BoxDecoration(
            color: Colors.black,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: Colors.white10),
          ),
          padding: const EdgeInsets.fromLTRB(28, 36, 28, 24),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            const _ExitIconAnimated(),
            const SizedBox(height: 20),
            const Text(
              'Leave Adult Section?',
              textAlign: TextAlign.center,
              style: TextStyle(
                color: Colors.white,
                fontSize: 20,
                fontWeight: FontWeight.w800,
                letterSpacing: 0.2,
              ),
            ),
            const SizedBox(height: 12),
            const Text(
              'Are you sure you want to exit back\nto Adiza Moviez Box?',
              textAlign: TextAlign.center,
              style: TextStyle(
                color: Colors.white60,
                fontSize: 14,
                height: 1.55,
              ),
            ),
            const SizedBox(height: 28),
            SizedBox(
              width: double.infinity,
              height: 50,
              child: ElevatedButton(
                onPressed: () => Navigator.pop(ctx, true),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFFE50914),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12)),
                  elevation: 0,
                ),
                child: const Text(
                  'Exit to Adiza Moviez Box',
                  style: TextStyle(
                    color: Colors.white,
                    fontSize: 15,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ),
            ),
            const SizedBox(height: 10),
            SizedBox(
              width: double.infinity,
              height: 46,
              child: TextButton(
                onPressed: () => Navigator.pop(ctx, false),
                style: TextButton.styleFrom(
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12)),
                ),
                child: const Text(
                  'Stay Here',
                  style: TextStyle(
                    color: Colors.white54,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ),
          ]),
        ),
      ),
    );
    if (confirmed == true && mounted) {
      SharedPreferences.getInstance()
          .then((p) => p.setString('last_section', 'home'));
      Navigator.pop(context);
    }
  }

  // ── Navigation ────────────────────────────────────────────────────────────────

  void _openVideo(AdultVideo video) {
    Navigator.push(context, MaterialPageRoute(builder: (_) => AdultPlayerScreen(video: video)));
  }

  void _openCategory(String key, String label) {
    Navigator.push(context, MaterialPageRoute(
      builder: (_) => _AdultCategoryScreen(service: _service, query: key, title: label),
    ));
  }

  void _showCategoriesModal() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (_) => _CategoriesModal(onTap: (key, label) {
        Navigator.pop(context);
        _openCategory(key, label);
      }),
    );
  }

  // ── Build ─────────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (didPop) return;
        if (_searching) {
          _clearSearch();
        } else {
          _confirmExit();
        }
      },
      child: Scaffold(
        backgroundColor: Colors.black,
        appBar: _buildAppBar(),
        body: _searching ? _buildSearchBody() : _buildHomeBody(),
      ),
    );
  }

  AppBar _buildAppBar() {
    return AppBar(
      backgroundColor: Colors.black,
      elevation: 0,
      leading: IconButton(
        icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 20),
        onPressed: _searching ? _clearSearch : _confirmExit,
      ),
      titleSpacing: 0,
      title: _searching
          ? TextField(
              controller: _searchCtrl,
              autofocus: true,
              style: const TextStyle(color: Colors.white, fontSize: 15),
              decoration: const InputDecoration(
                hintText: 'Search…',
                hintStyle: TextStyle(color: Colors.white38),
                border: InputBorder.none,
              ),
              textInputAction: TextInputAction.search,
              onSubmitted: _submitSearch,
              onChanged: _onSearchChanged,
            )
          : RichText(
              text: const TextSpan(
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.w900, letterSpacing: 0.2),
                children: [
                  TextSpan(text: 'Adult ', style: TextStyle(color: Colors.white)),
                  TextSpan(text: 'Fantasy', style: TextStyle(color: Color(0xFFE50914))),
                  TextSpan(text: ' World', style: TextStyle(color: Colors.white)),
                ],
              ),
            ),
      actions: [
        if (_searching && _searchCtrl.text.isNotEmpty)
          IconButton(
            icon: const Icon(Icons.clear, color: Colors.white38, size: 20),
            onPressed: _clearSearch,
          )
        else
          IconButton(
            icon: const Icon(Icons.search_rounded, color: Colors.white, size: 24),
            onPressed: () => setState(() => _searching = true),
          ),
      ],
    );
  }

  // ── Home body (banner + sections) ────────────────────────────────────────────

  Widget _buildHomeBody() {
    return Stack(children: [
      RefreshIndicator(
        key: _refreshKey,
        color: const Color(0xFFE50914),
        backgroundColor: Colors.black,
        onRefresh: _refresh,
        child: CustomScrollView(
          controller: _scrollCtrl,
          cacheExtent: 800,
          physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
          slivers: [
            // Featured banner
            SliverToBoxAdapter(child: _AdultFeaturedBanner(
              videos: _featured,
              loaded: _featuredLoaded,
              onTap: _openVideo,
            )),
            // Search bar + categories chips
            SliverToBoxAdapter(child: _SearchBar(
              onSearchTap: () => setState(() => _searching = true),
              onCategoriesTap: _showCategoriesModal,
            )),
            // Category sections
            ..._sections.map((s) {
              final (key, label, videos) = s;
              return SliverToBoxAdapter(child: _AdultSection(
                title: label,
                videos: videos,
                onVideoTap: _openVideo,
                onSeeAll: () => _openCategory(key, label),
              ));
            }),
            // Loading / end
            SliverToBoxAdapter(
              child: _loadingMore
                  ? const Padding(
                      padding: EdgeInsets.symmetric(vertical: 24),
                      child: Center(child: SizedBox(width: 28, height: 28,
                          child: CircularProgressIndicator(color: Color(0xFFE50914), strokeWidth: 2.5))),
                    )
                  : const SizedBox(height: 40),
            ),
          ],
        ),
      ),
      // ── Download status pill (Lima-bar style) ─────────────────────────────
      Positioned(
        bottom: 86, left: 48, right: 48,
        child: Consumer<DownloadManager>(
          builder: (_, mgr, __) {
            final active = mgr.tasks.where((t) =>
              t.status == DownloadStatus.downloading ||
              t.status == DownloadStatus.queued ||
              t.status == DownloadStatus.paused
            ).toList();
            final bool visible = active.isNotEmpty;
            final double progress = visible
                ? active.fold<double>(0, (s, t) => s + t.progress) / active.length
                : 0;
            return AnimatedOpacity(
              opacity: visible ? 1.0 : 0.0,
              duration: const Duration(milliseconds: 350),
              child: IgnorePointer(
                ignoring: !visible,
                child: GestureDetector(
                  onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const DownloadsScreen())),
                  child: Container(
                    height: 46,
                    decoration: BoxDecoration(
                      color: Colors.black,
                      borderRadius: BorderRadius.circular(14),
                      border: Border.all(color: const Color(0xFFE50914).withOpacity(0.65), width: 1.5),
                      boxShadow: const [BoxShadow(color: Colors.black87, blurRadius: 22, offset: Offset(0, 5))],
                    ),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(13),
                      child: Stack(
                        fit: StackFit.expand,
                        children: [
                          // Red fill that grows with download progress
                          Align(
                            alignment: Alignment.centerLeft,
                            child: FractionallySizedBox(
                              widthFactor: progress.clamp(0.0, 1.0),
                              child: Container(color: const Color(0xFFE50914).withOpacity(0.13)),
                            ),
                          ),
                          // Row: icon · text · count badge · chevron
                          Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 14),
                            child: Row(
                              children: [
                                const Icon(Icons.download_rounded, color: Color(0xFFE50914), size: 19),
                                const SizedBox(width: 10),
                                Expanded(
                                  child: Text(
                                    active.length == 1
                                        ? '1 download in progress…'
                                        : '${active.length} downloads in progress…',
                                    style: const TextStyle(
                                      color: Colors.white,
                                      fontSize: 12.5,
                                      fontWeight: FontWeight.w600,
                                      letterSpacing: 0.1,
                                    ),
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                  ),
                                ),
                                const SizedBox(width: 8),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                                  decoration: BoxDecoration(
                                    color: const Color(0xFFE50914),
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                  child: Text(
                                    '${(progress * 100).round()}%',
                                    style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.w700),
                                  ),
                                ),
                                const SizedBox(width: 6),
                                const Icon(Icons.chevron_right_rounded, color: Colors.white54, size: 18),
                              ],
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            );
          },
        ),
      ),
      // Scroll-to-top button
      Positioned(
        bottom: 72, right: 20,
        child: AnimatedOpacity(
          opacity: _showScrollTop ? 1.0 : 0.0,
          duration: const Duration(milliseconds: 300),
          child: IgnorePointer(
            ignoring: !_showScrollTop,
            child: GestureDetector(
              onTap: () => _scrollCtrl.animateTo(0,
                  duration: const Duration(milliseconds: 500), curve: Curves.easeOutCubic),
              child: Container(
                width: 44, height: 44,
                decoration: BoxDecoration(
                  color: const Color(0xFFE50914), shape: BoxShape.circle,
                  boxShadow: [BoxShadow(color: const Color(0xFFE50914).withOpacity(0.45), blurRadius: 14, offset: const Offset(0, 4))],
                ),
                child: const Icon(Icons.keyboard_arrow_up_rounded, color: Colors.white, size: 26),
              ),
            ),
          ),
        ),
      ),
    ]);
  }

  // ── Search results body ───────────────────────────────────────────────────────

  Widget _buildSearchBody() {
    // ── Empty field: show history + popular suggestions ──
    if (_searchCtrl.text.trim().isEmpty) {
      return _buildSearchSuggestions();
    }

    // ── Loading skeletons ──
    if (_searchLoading) {
      return GridView.builder(
        padding: const EdgeInsets.all(10),
        gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
            crossAxisCount: 3, mainAxisSpacing: 8, crossAxisSpacing: 8, childAspectRatio: 0.62),
        itemCount: 9,
        itemBuilder: (_, __) => const _VideoSkeleton(),
      );
    }

    // ── No results ──
    if (_searchResults.isEmpty && _searchQuery.isNotEmpty) {
      return Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
        const Icon(Icons.search_off_rounded, color: Colors.white24, size: 48),
        const SizedBox(height: 12),
        Text('No results for "$_searchQuery"',
            style: const TextStyle(color: Colors.white38, fontSize: 14)),
        const SizedBox(height: 8),
        const Text('Try a different keyword', style: TextStyle(color: Colors.white24, fontSize: 12)),
      ]));
    }

    // ── Results grid with infinite scroll + FAB ──
    return Stack(children: [
      Column(children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 4),
          child: Row(children: [
            Expanded(child: Text('Results for "$_searchQuery"',
                style: const TextStyle(color: Colors.white70, fontSize: 13, fontWeight: FontWeight.w600))),
            Text('${_searchResults.length} videos',
                style: const TextStyle(color: Colors.white38, fontSize: 11)),
          ]),
        ),
        Expanded(
          child: GridView.builder(
            controller: _searchScrollCtrl,
            physics: const BouncingScrollPhysics(),
            padding: const EdgeInsets.fromLTRB(10, 4, 10, 60),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                crossAxisCount: 3, mainAxisSpacing: 8, crossAxisSpacing: 8, childAspectRatio: 0.62),
            // +1 row of skeletons at end while loading more
            itemCount: _searchResults.length + (_searchLoadingMore ? 3 : 0),
            itemBuilder: (_, i) {
              if (i >= _searchResults.length) return const _VideoSkeleton();
              return _VideoGridCard(
                  video: _searchResults[i], onTap: () => _openVideo(_searchResults[i]));
            },
          ),
        ),
      ]),
      // Scroll-to-top FAB
      Positioned(
        bottom: 72, right: 18,
        child: AnimatedOpacity(
          opacity: _searchShowTop ? 1.0 : 0.0,
          duration: const Duration(milliseconds: 300),
          child: IgnorePointer(
            ignoring: !_searchShowTop,
            child: GestureDetector(
              onTap: () => _searchScrollCtrl.animateTo(0,
                  duration: const Duration(milliseconds: 500), curve: Curves.easeOutCubic),
              child: Container(
                width: 44, height: 44,
                decoration: BoxDecoration(
                  color: const Color(0xFFE50914), shape: BoxShape.circle,
                  boxShadow: [BoxShadow(color: const Color(0xFFE50914).withOpacity(0.45),
                      blurRadius: 14, offset: const Offset(0, 4))],
                ),
                child: const Icon(Icons.keyboard_arrow_up_rounded, color: Colors.white, size: 26),
              ),
            ),
          ),
        ),
      ),
    ]);
  }

  // ── Suggestions panel (history + popular) ────────────────────────────────────

  static const _kPopularSearches = [
    'Ghana girl', 'Naija leak', 'African amateur', 'Ebony thick',
    'Nigerian homemade', 'MILF BBW', 'Ghanaian celebrity', 'Kenyan leaked',
    'South African', 'Busty amateur', 'Doggy style', 'Webcam teen',
  ];

  Widget _buildSearchSuggestions() {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 40),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        // ── Recent searches ──
        if (_searchHistory.isNotEmpty) ...[
          const Padding(
            padding: EdgeInsets.only(bottom: 8),
            child: Row(children: [
              Icon(Icons.history_rounded, color: Colors.white38, size: 15),
              SizedBox(width: 6),
              Text('Recent Searches', style: TextStyle(color: Colors.white54, fontSize: 12, fontWeight: FontWeight.w600)),
            ]),
          ),
          ..._searchHistory.map((q) => GestureDetector(
            onTap: () => _applyHistoryQuery(q),
            child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 10),
              child: Row(children: [
                const Icon(Icons.history_rounded, color: Colors.white24, size: 18),
                const SizedBox(width: 12),
                Expanded(child: Text(q, style: const TextStyle(color: Colors.white, fontSize: 14))),
                const Icon(Icons.north_west_rounded, color: Colors.white24, size: 15),
              ]),
            ),
          )),
          const Divider(color: Colors.white10, height: 24),
        ],

        // ── Popular searches ──
        const Padding(
          padding: EdgeInsets.only(bottom: 10),
          child: Row(children: [
            Icon(Icons.local_fire_department_rounded, color: Color(0xFFE50914), size: 15),
            SizedBox(width: 6),
            Text('Popular Searches', style: TextStyle(color: Colors.white54, fontSize: 12, fontWeight: FontWeight.w600)),
          ]),
        ),
        Wrap(
          spacing: 8, runSpacing: 8,
          children: _kPopularSearches.map((q) => GestureDetector(
            onTap: () {
              _searchCtrl.text = q;
              _onSearchChanged(q);
            },
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
              decoration: BoxDecoration(
                color: Colors.black,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: Colors.white12),
              ),
              child: Row(mainAxisSize: MainAxisSize.min, children: [
                const Icon(Icons.search_rounded, color: Colors.white38, size: 13),
                const SizedBox(width: 5),
                Text(q, style: const TextStyle(color: Colors.white70, fontSize: 12, fontWeight: FontWeight.w500)),
              ]),
            ),
          )).toList(),
        ),
      ]),
    );
  }
}

// ── Featured banner ───────────────────────────────────────────────────────────

class _AdultFeaturedBanner extends StatefulWidget {
  final List<AdultVideo> videos;
  final bool loaded;
  final ValueChanged<AdultVideo> onTap;
  const _AdultFeaturedBanner({required this.videos, required this.loaded, required this.onTap});

  @override
  State<_AdultFeaturedBanner> createState() => _AdultFeaturedBannerState();
}

class _AdultFeaturedBannerState extends State<_AdultFeaturedBanner> {
  late PageController _pageCtrl;
  Timer? _timer;
  int _current = 0;

  @override
  void initState() {
    super.initState();
    _pageCtrl = PageController(viewportFraction: 0.92, initialPage: 500);
    _timer = Timer.periodic(const Duration(seconds: 5), (_) {
      if (!mounted || widget.videos.isEmpty) return;
      _pageCtrl.nextPage(duration: const Duration(milliseconds: 700), curve: Curves.easeInOut);
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    _pageCtrl.dispose();
    super.dispose();
  }

  void _showInfoSheet(BuildContext context, AdultVideo video) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.black,
      useSafeArea: true,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(18))),
      builder: (sheetCtx) => Padding(
        padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
        child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
          // Handle
          Center(child: Container(width: 36, height: 4,
              decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2)))),
          const SizedBox(height: 16),
          // Thumbnail + core info side by side
          Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            if (video.thumbnail.isNotEmpty)
              ClipRRect(
                borderRadius: BorderRadius.circular(10),
                child: SizedBox(
                  width: 110, height: 75,
                  child: CachedNetworkImage(imageUrl: video.thumbnail, fit: BoxFit.cover,
                      filterQuality: FilterQuality.high,
                      memCacheWidth: 220, memCacheHeight: 150,
                      placeholder: (_, __) => Container(color: const Color(0xFF111111)),
                      errorWidget: (_, __, ___) => Container(color: const Color(0xFF111111))),
                ),
              ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(video.title, maxLines: 3, overflow: TextOverflow.ellipsis,
                    style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w700, height: 1.3)),
                const SizedBox(height: 8),
                if (video.duration.isNotEmpty) Row(children: [
                  const Icon(Icons.access_time_rounded, color: Colors.white38, size: 13),
                  const SizedBox(width: 4),
                  Text(video.duration, style: const TextStyle(color: Colors.white54, fontSize: 12)),
                ]),
                if (video.views.isNotEmpty) ...[
                  const SizedBox(height: 4),
                  Row(children: [
                    const Icon(Icons.visibility_outlined, color: Colors.white38, size: 13),
                    const SizedBox(width: 4),
                    Text(video.views, style: const TextStyle(color: Colors.white54, fontSize: 12)),
                  ]),
                ],
              ]),
            ),
          ]),
          const SizedBox(height: 20),
          // Watch Now button
          SizedBox(
            width: double.infinity,
            height: 44,
            child: ElevatedButton.icon(
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFE50914),
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
              icon: const Icon(Icons.play_arrow_rounded, size: 20),
              label: const Text('Watch Now', style: TextStyle(fontWeight: FontWeight.w700, fontSize: 14)),
              onPressed: () { Navigator.pop(sheetCtx); widget.onTap(video); },
            ),
          ),
        ]),
      ),
    );
  }

  void _showMoreSheet(BuildContext context, AdultVideo video) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.black,
      useSafeArea: true,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(18))),
      builder: (ctx) => SafeArea(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Container(width: 36, height: 4,
              margin: const EdgeInsets.only(top: 12, bottom: 4),
              decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2))),
          // Video title mini header
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 4),
            child: Text(video.title, maxLines: 1, overflow: TextOverflow.ellipsis,
                style: const TextStyle(color: Colors.white54, fontSize: 12)),
          ),
          const Divider(color: Colors.white10, height: 1),
          ListTile(
            leading: Container(
              width: 36, height: 36,
              decoration: BoxDecoration(color: const Color(0xFFE50914), borderRadius: BorderRadius.circular(8)),
              child: const Icon(Icons.play_arrow_rounded, color: Colors.white, size: 20),
            ),
            title: const Text('Watch Now', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w600)),
            onTap: () { Navigator.pop(ctx); widget.onTap(video); },
          ),
          const SizedBox(height: 8),
        ]),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.loaded || widget.videos.isEmpty) {
      return Column(mainAxisSize: MainAxisSize.min, children: [
        SizedBox(
          height: 240,
          child: PageView.builder(
            physics: const NeverScrollableScrollPhysics(),
            controller: PageController(viewportFraction: 0.92),
            itemCount: 3,
            itemBuilder: (_, __) => Padding(
              padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 6),
              child: Container(decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(14))),
            ),
          ),
        ),
        const SizedBox(height: 10),
        Container(width: 140, height: 13, margin: const EdgeInsets.only(bottom: 5),
            decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(6))),
        Container(width: 90, height: 10,
            decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(5))),
        const SizedBox(height: 14),
      ]);
    }

    final active = widget.videos[_current % widget.videos.length];

    return Column(mainAxisSize: MainAxisSize.min, children: [
      SizedBox(
        height: 240,
        child: PageView.builder(
          controller: _pageCtrl,
          physics: const BouncingScrollPhysics(),
          onPageChanged: (i) => setState(() => _current = i),
          itemBuilder: (_, idx) {
            final video = widget.videos[idx % widget.videos.length];
            final isActive = (idx % widget.videos.length) == (_current % widget.videos.length);
            return GestureDetector(
              onTap: () => widget.onTap(video),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 300),
                margin: EdgeInsets.symmetric(horizontal: 5, vertical: isActive ? 4 : 14),
                child: ClipRRect(
                  borderRadius: BorderRadius.circular(14),
                  child: Stack(fit: StackFit.expand, children: [
                    AnimatedOpacity(
                      opacity: isActive ? 1.0 : 0.5,
                      duration: const Duration(milliseconds: 300),
                      child: video.thumbnail.isNotEmpty
                          ? CachedNetworkImage(imageUrl: video.thumbnail, fit: BoxFit.cover,
                              filterQuality: FilterQuality.high,
                              placeholder: (_, __) => Container(color: Colors.black),
                              errorWidget: (_, __, ___) => Container(color: Colors.black))
                          : Container(color: Colors.black),
                    ),
                    Container(decoration: const BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.topCenter, end: Alignment.bottomCenter,
                        colors: [Colors.transparent, Colors.black87], stops: [0.4, 1.0]),
                    )),
                    // 18+ badge
                    Positioned(top: 8, left: 8, child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 3),
                      decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(4)),
                      child: const Text('18+', style: TextStyle(color: Color(0xFFE50914), fontSize: 9, fontWeight: FontWeight.w900)),
                    )),
                    // Duration
                    if (video.duration.isNotEmpty)
                      Positioned(bottom: 8, right: 8, child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                        decoration: BoxDecoration(color: Colors.black87, borderRadius: BorderRadius.circular(4)),
                        child: Text(video.duration, style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.w600)),
                      )),
                  ]),
                ),
              ),
            );
          },
        ),
      ),
      const SizedBox(height: 10),
      // Title
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16),
        child: AnimatedSwitcher(
          duration: const Duration(milliseconds: 250),
          child: Text(active.title,
            key: ValueKey(active.title),
            textAlign: TextAlign.center, maxLines: 1, overflow: TextOverflow.ellipsis,
            style: const TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w800, letterSpacing: -0.2),
          ),
        ),
      ),
      const SizedBox(height: 5),
      // Views + actions
      AnimatedSwitcher(
        duration: const Duration(milliseconds: 250),
        child: Padding(
          key: ValueKey(active.title + 'meta'),
          padding: const EdgeInsets.symmetric(horizontal: 24),
          child: Row(children: [
            Expanded(
              child: GestureDetector(
                onTap: () => _showInfoSheet(context, active),
                child: Container(
                  height: 40,
                  decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: Colors.white12)),
                  child: const Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                    Icon(Icons.info_outline_rounded, color: Colors.white54, size: 15),
                    SizedBox(height: 2),
                    Text('Info', style: TextStyle(color: Colors.white54, fontSize: 9, fontWeight: FontWeight.w600)),
                  ]),
                ),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              flex: 3,
              child: GestureDetector(
                onTap: () => widget.onTap(active),
                child: Container(
                  height: 40,
                  decoration: BoxDecoration(color: const Color(0xFFE50914), borderRadius: BorderRadius.circular(10)),
                  child: const Center(child: Text('WATCH NOW',
                      style: TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w800, letterSpacing: 0.8))),
                ),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: GestureDetector(
                onTap: () => _showMoreSheet(context, active),
                child: Container(
                  height: 40,
                  decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: Colors.white12)),
                  child: const Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                    Icon(Icons.more_horiz_rounded, color: Colors.white54, size: 18),
                    SizedBox(height: 1),
                    Text('More', style: TextStyle(color: Colors.white54, fontSize: 9, fontWeight: FontWeight.w600)),
                  ]),
                ),
              ),
            ),
          ]),
        ),
      ),
      const SizedBox(height: 12),
    ]);
  }
}

// ── Search bar + category chips row ──────────────────────────────────────────

class _SearchBar extends StatelessWidget {
  final VoidCallback onSearchTap;
  final VoidCallback onCategoriesTap;
  const _SearchBar({required this.onSearchTap, required this.onCategoriesTap});

  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      // Search bar
      GestureDetector(
        onTap: onSearchTap,
        child: Container(
          margin: const EdgeInsets.fromLTRB(12, 4, 12, 10),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
          decoration: BoxDecoration(
            color: Colors.black,
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: Colors.white12),
          ),
          child: Row(children: [
            const Icon(Icons.search_rounded, color: Colors.white38, size: 20),
            const SizedBox(width: 10),
            const Expanded(child: Text('Search videos…', style: TextStyle(color: Colors.white38, fontSize: 14))),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(color: const Color(0xFFE50914).withOpacity(0.15), borderRadius: BorderRadius.circular(6)),
              child: const Text('Search', style: TextStyle(color: Color(0xFFE50914), fontSize: 11, fontWeight: FontWeight.w700)),
            ),
          ]),
        ),
      ),
      // Categories label row
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 4, 12, 8),
        child: Row(children: [
          const Icon(Icons.category_rounded, color: Colors.white, size: 14),
          const SizedBox(width: 6),
          const Text('Categories',
              style: TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w700)),
          const Spacer(),
          GestureDetector(
            onTap: onCategoriesTap,
            child: const Row(children: [
              Text('See All',
                  style: TextStyle(
                      color: Color(0xFFE50914), fontSize: 12, fontWeight: FontWeight.w600)),
              Icon(Icons.chevron_right_rounded, color: Color(0xFFE50914), size: 16),
            ]),
          ),
        ]),
      ),
      // Only first 4 categories shown as chips
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 0, 12, 10),
        child: Row(children: List.generate(4, (i) {
          final (key, label) = _kCategories[i];
          return Expanded(
            child: Padding(
              padding: EdgeInsets.only(right: i < 3 ? 8 : 0),
              child: GestureDetector(
                onTap: () => Navigator.push(context, MaterialPageRoute(
                  builder: (_) => _AdultCategoryScreen(
                      service: AdultService(), query: key, title: label),
                )),
                child: Container(
                  padding: const EdgeInsets.symmetric(vertical: 8),
                  decoration: BoxDecoration(
                    color: Colors.black,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: Colors.white24),
                  ),
                  alignment: Alignment.center,
                  child: Text(label,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(
                          color: Colors.white, fontSize: 12, fontWeight: FontWeight.w600)),
                ),
              ),
            ),
          );
        })),
      ),
    ]);
  }
}

// ── Horizontal section row ────────────────────────────────────────────────────

class _AdultSection extends StatelessWidget {
  final String title;
  final List<AdultVideo> videos;
  final ValueChanged<AdultVideo> onVideoTap;
  final VoidCallback onSeeAll;
  const _AdultSection({required this.title, required this.videos, required this.onVideoTap, required this.onSeeAll});

  @override
  Widget build(BuildContext context) {
    if (videos.isEmpty) return const SizedBox.shrink();
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 14, 12, 8),
        child: Row(children: [
          Text(title, style: const TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.w800)),
          const Spacer(),
          GestureDetector(
            onTap: onSeeAll,
            child: const Row(children: [
              Text('See All', style: TextStyle(color: Color(0xFFE50914), fontSize: 12, fontWeight: FontWeight.w600)),
              Icon(Icons.chevron_right_rounded, color: Color(0xFFE50914), size: 18),
            ]),
          ),
        ]),
      ),
      SizedBox(
        height: 190,
        child: ListView.separated(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 12),
          separatorBuilder: (_, __) => const SizedBox(width: 10),
          itemCount: videos.length,
          itemBuilder: (_, i) => _VideoHorizontalCard(video: videos[i], onTap: () => onVideoTap(videos[i])),
        ),
      ),
      const SizedBox(height: 6),
    ]);
  }
}

// ── Horizontal card (in section rows) ────────────────────────────────────────

class _VideoHorizontalCard extends StatelessWidget {
  final AdultVideo video;
  final VoidCallback onTap;
  const _VideoHorizontalCard({required this.video, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: SizedBox(
        width: 140,
        child: Container(
          decoration: BoxDecoration(
            color: Colors.black, borderRadius: BorderRadius.circular(10),
            border: Border.all(color: Colors.white10),
          ),
          clipBehavior: Clip.hardEdge,
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(child: Stack(fit: StackFit.expand, children: [
              AdultPreviewThumb(
                thumbnail: video.thumbnail,
                previewGif: video.previewGif,
              ),
              Container(decoration: const BoxDecoration(
                gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter,
                    colors: [Colors.transparent, Colors.black54], stops: [0.5, 1.0]),
              )),
              const Center(child: Icon(Icons.play_circle_fill_rounded, color: Colors.white60, size: 34)),
              if (video.duration.isNotEmpty)
                Positioned(bottom: 4, right: 5, child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                  decoration: BoxDecoration(color: Colors.black87, borderRadius: BorderRadius.circular(3)),
                  child: Text(video.duration, style: const TextStyle(color: Colors.white, fontSize: 9, fontWeight: FontWeight.w600)),
                )),
            ])),
            Padding(
              padding: const EdgeInsets.fromLTRB(6, 5, 6, 6),
              child: Text(video.title, maxLines: 2, overflow: TextOverflow.ellipsis,
                  style: const TextStyle(color: Colors.white, fontSize: 10.5, fontWeight: FontWeight.w500, height: 1.3)),
            ),
          ]),
        ),
      ),
    );
  }
}

// ── Grid card (search results) ────────────────────────────────────────────────

class _VideoGridCard extends StatelessWidget {
  final AdultVideo video;
  final VoidCallback onTap;
  const _VideoGridCard({required this.video, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        decoration: BoxDecoration(
          color: Colors.black, borderRadius: BorderRadius.circular(10),
          border: Border.all(color: Colors.white10),
        ),
        clipBehavior: Clip.hardEdge,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Expanded(child: Stack(fit: StackFit.expand, children: [
            AdultPreviewThumb(
              thumbnail: video.thumbnail,
              previewGif: video.previewGif,
            ),
            const Center(child: Icon(Icons.play_circle_fill_rounded, color: Colors.white60, size: 40)),
            if (video.duration.isNotEmpty)
              Positioned(bottom: 5, right: 6, child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                decoration: BoxDecoration(color: Colors.black87, borderRadius: BorderRadius.circular(4)),
                child: Text(video.duration, style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.w600)),
              )),
          ])),
          Padding(
            padding: const EdgeInsets.fromLTRB(8, 6, 8, 8),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(video.title, maxLines: 2, overflow: TextOverflow.ellipsis,
                  style: const TextStyle(color: Colors.white, fontSize: 11.5, fontWeight: FontWeight.w500, height: 1.3)),
              if (video.views.isNotEmpty) ...[
                const SizedBox(height: 3),
                Text(video.views, style: const TextStyle(color: Colors.white38, fontSize: 10)),
              ],
            ]),
          ),
        ]),
      ),
    );
  }
}

// ── Video skeleton ────────────────────────────────────────────────────────────

class _VideoSkeleton extends StatelessWidget {
  const _VideoSkeleton();
  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(color: Colors.black, borderRadius: BorderRadius.circular(10)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Expanded(child: Container(decoration: const BoxDecoration(
            color: Colors.black, borderRadius: BorderRadius.vertical(top: Radius.circular(10))))),
        Padding(
          padding: const EdgeInsets.all(8),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Container(height: 10, width: double.infinity, color: Colors.black),
            const SizedBox(height: 5),
            Container(height: 10, width: 80, color: Colors.black),
          ]),
        ),
      ]),
    );
  }
}

// ── Categories modal ──────────────────────────────────────────────────────────

class _CategoriesModal extends StatelessWidget {
  final void Function(String key, String label) onTap;
  const _CategoriesModal({required this.onTap});

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: BoxConstraints(maxHeight: MediaQuery.of(context).size.height * 0.88),
      decoration: const BoxDecoration(
        color: Colors.black,
        borderRadius: BorderRadius.vertical(top: Radius.circular(22)),
      ),
      child: Column(children: [
        // Drag handle
        Container(
          width: 40, height: 4,
          margin: const EdgeInsets.only(top: 12, bottom: 14),
          decoration: BoxDecoration(
              color: Colors.white24, borderRadius: BorderRadius.circular(2))),
        // Header
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
          child: Row(children: [
            Container(
              padding: const EdgeInsets.all(7),
              decoration: BoxDecoration(
                color: const Color(0xFFE50914).withOpacity(0.15),
                borderRadius: BorderRadius.circular(10),
              ),
              child: const Icon(Icons.local_fire_department_rounded,
                  color: Color(0xFFE50914), size: 20),
            ),
            const SizedBox(width: 12),
            const Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('Browse Categories',
                    style: TextStyle(
                        color: Colors.white, fontSize: 17, fontWeight: FontWeight.w800)),
                Text('Tap a category to explore',
                    style: TextStyle(color: Colors.white38, fontSize: 11)),
              ]),
            ),
            GestureDetector(
              onTap: () => Navigator.pop(context),
              child: Container(
                padding: const EdgeInsets.all(6),
                decoration: BoxDecoration(
                    color: Colors.white10,
                    borderRadius: BorderRadius.circular(8)),
                child: const Icon(Icons.close_rounded, color: Colors.white54, size: 18),
              ),
            ),
          ]),
        ),
        const Divider(color: Colors.white12, height: 1),
        // Grid of all categories
        Expanded(
          child: GridView.builder(
            padding: const EdgeInsets.fromLTRB(14, 16, 14, 28),
            gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
              crossAxisCount: 3,
              childAspectRatio: 2.4,
              mainAxisSpacing: 10,
              crossAxisSpacing: 10,
            ),
            itemCount: _kCategories.length,
            itemBuilder: (_, i) {
              final (key, label) = _kCategories[i];
              // Alternate a subtle accent on every 5th chip to break monotony
              final isAccent = i % 7 == 0;
              return GestureDetector(
                onTap: () => onTap(key, label),
                child: Container(
                  decoration: BoxDecoration(
                    color: isAccent
                        ? const Color(0xFFE50914).withOpacity(0.12)
                        : const Color(0xFF1E1E1E),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(
                        color: isAccent
                            ? const Color(0xFFE50914).withOpacity(0.35)
                            : Colors.white12),
                  ),
                  alignment: Alignment.center,
                  padding: const EdgeInsets.symmetric(horizontal: 6),
                  child: Text(
                    label,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      color: isAccent ? const Color(0xFFFF4040) : Colors.white,
                      fontSize: 12,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              );
            },
          ),
        ),
      ]),
    );
  }
}

// ── Category screen (full grid) ───────────────────────────────────────────────

class _AdultCategoryScreen extends StatefulWidget {
  final AdultService service;
  final String query;
  final String title;
  const _AdultCategoryScreen({required this.service, required this.query, required this.title});

  @override
  State<_AdultCategoryScreen> createState() => _AdultCategoryScreenState();
}

class _AdultCategoryScreenState extends State<_AdultCategoryScreen> {
  final _scrollCtrl = ScrollController();
  List<AdultVideo> _videos = [];
  bool _loading      = true;
  bool _loadingMore  = false;
  bool _showScrollTop = false;
  int  _page    = 1;
  bool _hasMore = true;

  @override
  void initState() {
    super.initState();
    _scrollCtrl.addListener(_onScroll);
    _load();
  }

  @override
  void dispose() { _scrollCtrl.dispose(); super.dispose(); }

  void _onScroll() {
    final px  = _scrollCtrl.position.pixels;
    final max = _scrollCtrl.position.maxScrollExtent;
    // Scroll-to-top visibility
    final show = px > 400;
    if (show != _showScrollTop) setState(() => _showScrollTop = show);
    // Infinite scroll
    if (px >= max - 300 && !_loadingMore && _hasMore) {
      _loadMore();
    }
  }

  Future<void> _load() async {
    final results = await widget.service.search(widget.query, page: 1);
    if (mounted) setState(() { _videos = results; _loading = false; _hasMore = results.length >= 20; });
  }

  Future<void> _loadMore() async {
    if (_loadingMore || !_hasMore) return;
    setState(() => _loadingMore = true);
    final next = _page + 1;
    final results = await widget.service.search(widget.query, page: next);
    if (mounted) setState(() {
      _page = next; _videos.addAll(results); _loadingMore = false; _hasMore = results.length >= 20;
    });
  }

  void _openVideo(AdultVideo video) {
    Navigator.push(context, MaterialPageRoute(builder: (_) => AdultPlayerScreen(video: video)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        backgroundColor: Colors.black, elevation: 0,
        leading: IconButton(
            icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white, size: 20),
            onPressed: () => Navigator.pop(context)),
        title: Text(widget.title,
            style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w800, fontSize: 17)),
      ),
      body: Stack(children: [
        _loading
            ? GridView.builder(
                padding: const EdgeInsets.all(10),
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 3, mainAxisSpacing: 8, crossAxisSpacing: 8, childAspectRatio: 0.62),
                itemCount: 9,
                itemBuilder: (_, __) => const _VideoSkeleton())
            : GridView.builder(
                controller: _scrollCtrl,
                physics: const BouncingScrollPhysics(),
                padding: const EdgeInsets.fromLTRB(10, 10, 10, 70),
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 3, mainAxisSpacing: 8, crossAxisSpacing: 8, childAspectRatio: 0.62),
                itemCount: _videos.length + (_loadingMore ? 3 : 0),
                itemBuilder: (_, i) {
                  if (i >= _videos.length) return const _VideoSkeleton();
                  return _VideoGridCard(video: _videos[i], onTap: () => _openVideo(_videos[i]));
                }),
        // Scroll-to-top FAB
        Positioned(
          bottom: 72, right: 18,
          child: AnimatedOpacity(
            opacity: _showScrollTop ? 1.0 : 0.0,
            duration: const Duration(milliseconds: 300),
            child: IgnorePointer(
              ignoring: !_showScrollTop,
              child: GestureDetector(
                onTap: () => _scrollCtrl.animateTo(0,
                    duration: const Duration(milliseconds: 500), curve: Curves.easeOutCubic),
                child: Container(
                  width: 44, height: 44,
                  decoration: BoxDecoration(
                    color: const Color(0xFFE50914), shape: BoxShape.circle,
                    boxShadow: [BoxShadow(color: const Color(0xFFE50914).withOpacity(0.45),
                        blurRadius: 14, offset: const Offset(0, 4))],
                  ),
                  child: const Icon(Icons.keyboard_arrow_up_rounded, color: Colors.white, size: 26),
                ),
              ),
            ),
          ),
        ),
      ]),
    );
  }
}

// ── Animated exit icon for the leave-section dialog ───────────────────────────
class _ExitIconAnimated extends StatefulWidget {
  const _ExitIconAnimated();
  @override
  State<_ExitIconAnimated> createState() => _ExitIconAnimatedState();
}

class _ExitIconAnimatedState extends State<_ExitIconAnimated>
    with TickerProviderStateMixin {
  late final AnimationController _entryCtrl;
  late final AnimationController _pulseCtrl;
  late final Animation<double> _entryAnim;
  late final Animation<double> _pulseAnim;

  @override
  void initState() {
    super.initState();
    _entryCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 700));
    _entryAnim =
        CurvedAnimation(parent: _entryCtrl, curve: Curves.elasticOut);

    _pulseCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1500));
    _pulseAnim = Tween<double>(begin: 0.94, end: 1.06)
        .animate(CurvedAnimation(parent: _pulseCtrl, curve: Curves.easeInOut));

    _entryCtrl.forward().then((_) {
      if (mounted) _pulseCtrl.repeat(reverse: true);
    });
  }

  @override
  void dispose() {
    _entryCtrl.dispose();
    _pulseCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([_entryAnim, _pulseAnim]),
      builder: (_, __) {
        final pulse = _pulseCtrl.isAnimating ? _pulseAnim.value : 1.0;
        final scale = _entryAnim.value * pulse;
        final glowAlpha = (80 * pulse).round().clamp(40, 110);
        return Transform.scale(
          scale: scale,
          child: Container(
            width: 84, height: 84,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: const RadialGradient(colors: [
                Color(0x55E50914),
                Color(0x0AE50914),
              ]),
              boxShadow: [
                BoxShadow(
                  color: Color.fromARGB(glowAlpha, 0xE5, 0x09, 0x14),
                  blurRadius: 26,
                  spreadRadius: 4,
                ),
              ],
            ),
            child: const Icon(
              Icons.power_settings_new_rounded,
              color: Color(0xFFE50914),
              size: 42,
            ),
          ),
        );
      },
    );
  }
}
