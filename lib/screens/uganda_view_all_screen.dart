import 'dart:convert';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../api/models.dart';
import '../api/vod_client.dart';
import '../theme/app_theme.dart';
import 'uganda_detail_screen.dart';

class UgandaViewAllScreen extends StatefulWidget {
  final String title;
  final String pipeType;
  final int pipeId;
  final String? fallbackName;

  const UgandaViewAllScreen({
    super.key,
    required this.title,
    required this.pipeType,
    required this.pipeId,
    this.fallbackName,
  });

  @override
  State<UgandaViewAllScreen> createState() => _UgandaViewAllScreenState();
}

class _UgandaViewAllScreenState extends State<UgandaViewAllScreen> {
  final List<Movie> _movies = [];
  final ScrollController _scroll = ScrollController();

  bool _loading   = false;
  bool _fetchActive = false; // hard concurrent-fetch lock
  bool _hasMore   = true;
  String? _error;

  // ── Phase 1: cursor-based grid ──────────────────────────────────────────
  String? _lastFetchId;

  // ── Phase 2: search fallback (when grid pipe is exhausted) ─────────────
  bool _inSearchFallback = false;
  int  _searchPage = 1;

  String get _cacheKey => 'ug_viewall_${widget.pipeType}_${widget.pipeId}_v1';
  String get _searchQuery => widget.fallbackName ?? widget.title;

  @override
  void initState() {
    super.initState();
    _scroll.addListener(_onScroll);
    _initLoad();
  }

  @override
  void dispose() {
    _scroll.dispose();
    super.dispose();
  }

  Future<void> _initLoad() async {
    final hadCache = await _restoreFirstPage();
    if (hadCache) {
      _loadMore(isBackground: true);
    } else {
      _loadMore();
    }
  }

  Future<bool> _restoreFirstPage() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_cacheKey);
      if (raw == null || raw.isEmpty) return false;
      final list = (jsonDecode(raw) as List)
          .map((e) => Movie.fromJson(e as Map<String, dynamic>))
          .toList();
      if (list.isEmpty) return false;
      if (mounted) setState(() { _movies.addAll(list); });
      return true;
    } catch (_) { return false; }
  }

  void _onScroll() {
    final pos = _scroll.position;
    // Only fire when content overflows the viewport and we are near the bottom
    if (!_fetchActive && _hasMore &&
        pos.maxScrollExtent > 0 &&
        pos.pixels >= pos.maxScrollExtent - 300) {
      _loadMore();
    }
  }

  Future<void> _loadMore({bool isBackground = false}) async {
    if (_fetchActive) return;
    _fetchActive = true;

    final isFirstPage = !_inSearchFallback && _lastFetchId == null;

    // Only show spinner when the user can see it
    if (!isBackground || !isFirstPage) {
      if (mounted) setState(() { _loading = true; _error = null; });
    }

    try {
      if (_inSearchFallback) {
        await _loadSearchPage();
      } else {
        await _loadGridPage(isFirstPage: isFirstPage);
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = _movies.isEmpty ? e.toString() : null;
      });
    } finally {
      _fetchActive = false;
    }

    // If content still doesn't fill the viewport, keep loading automatically
    _loadMoreIfNeeded();
  }

  // ── Phase 1: fetch from the grid pipe ───────────────────────────────────
  Future<void> _loadGridPage({required bool isFirstPage}) async {
    final result = await VodClient().getGrid(
      pipeType: widget.pipeType,
      pipeId: widget.pipeId,
      lastFetchId: _lastFetchId,
      fallbackName: widget.fallbackName,
    );
    if (!mounted) return;

    // Deduplicate against what we already have
    final existingIds = _movies.map((m) => m.id).toSet();
    final fresh = result.movies.where((m) => !existingIds.contains(m.id)).toList();

    setState(() {
      if (isFirstPage) _movies.clear();
      _movies.addAll(fresh);
      _lastFetchId = result.lastFetchId;
      _loading = false;

      if (result.hasMore && result.movies.isNotEmpty) {
        _hasMore = true; // more grid pages available
      } else {
        // Grid pipe exhausted — switch to search fallback if we have a name
        if (_searchQuery.isNotEmpty) {
          _inSearchFallback = true;
          _searchPage = 1;
          _hasMore = true; // search can still provide more
        } else {
          _hasMore = false;
        }
      }
    });

    // Persist first page to cache
    if (isFirstPage && _movies.isNotEmpty) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(
          _cacheKey, jsonEncode(_movies.map((m) => m.toJson()).toList()));
    }
  }

  // ── Phase 2: search fallback ─────────────────────────────────────────────
  Future<void> _loadSearchPage() async {
    final results = await VodClient().search(_searchQuery, page: _searchPage);
    if (!mounted) return;

    final existingIds = _movies.map((m) => m.id).toSet();
    final fresh = results.where((m) => !existingIds.contains(m.id)).toList();

    setState(() {
      _movies.addAll(fresh);
      _loading = false;
      if (results.length >= 20) {
        _searchPage++;
        _hasMore = true;
      } else if (fresh.isNotEmpty) {
        _searchPage++;
        _hasMore = false; // last partial page
      } else {
        _hasMore = false; // nothing new — truly exhausted
      }
    });
  }

  // Proactively keep loading if the content doesn't yet fill the screen
  void _loadMoreIfNeeded() {
    if (!_hasMore) return;
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || !_hasMore || _fetchActive) return;
      final pos = _scroll.hasClients ? _scroll.position : null;
      if (pos == null || pos.maxScrollExtent <= 0) {
        _loadMore();
      }
    });
  }

  void _openDetail(Movie movie) {
    final related = _movies.where((m) => m.id != movie.id).take(12).toList();
    final streamFuture = VodClient().getStream(movie.id);
    Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => UgandaDetailScreen(
          movie: movie,
          related: related,
          streamFuture: streamFuture,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.background,
      appBar: AppBar(
        backgroundColor: AppTheme.background,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_rounded, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              widget.title,
              style: const TextStyle(
                color: AppTheme.textPrimary,
                fontWeight: FontWeight.w800,
                fontSize: 17,
              ),
            ),
            const Text(
              'Uganda Cinema Plus',
              style: TextStyle(
                color: Color(0xFFFCDC04),
                fontSize: 10,
                fontWeight: FontWeight.w600,
              ),
            ),
          ],
        ),
      ),
      body: _movies.isEmpty && _loading
          ? const Center(
              child: CircularProgressIndicator(color: Color(0xFFFCDC04)))
          : _movies.isEmpty && _error != null
              ? Center(
                  child: Padding(
                    padding: const EdgeInsets.all(32),
                    child: Column(mainAxisSize: MainAxisSize.min, children: [
                      const Icon(Icons.wifi_off_rounded,
                          color: Colors.red, size: 48),
                      const SizedBox(height: 14),
                      Text(
                        _error!,
                        textAlign: TextAlign.center,
                        style: const TextStyle(
                            color: AppTheme.textMuted, fontSize: 13),
                      ),
                      const SizedBox(height: 14),
                      ElevatedButton(
                        onPressed: _loadMore,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFFFCDC04),
                          foregroundColor: Colors.black,
                        ),
                        child: const Text('Retry'),
                      ),
                    ]),
                  ),
                )
              : _movies.isEmpty
                  ? const Center(
                      child: Text(
                        'No movies found',
                        style:
                            TextStyle(color: AppTheme.textMuted, fontSize: 14),
                      ),
                    )
                  : GridView.builder(
                      controller: _scroll,
                      padding: const EdgeInsets.fromLTRB(12, 8, 12, 32),
                      physics: const BouncingScrollPhysics(
                          parent: AlwaysScrollableScrollPhysics()),
                      gridDelegate:
                          const SliverGridDelegateWithFixedCrossAxisCount(
                        crossAxisCount: 3,
                        childAspectRatio: 0.62,
                        crossAxisSpacing: 8,
                        mainAxisSpacing: 8,
                      ),
                      itemCount: _movies.length + (_hasMore ? 1 : 0),
                      itemBuilder: (_, i) {
                        if (i >= _movies.length) {
                          // Loader cell — also triggers the next page fetch
                          // the moment it becomes visible to the user.
                          WidgetsBinding.instance.addPostFrameCallback((_) {
                            if (mounted && !_fetchActive && _hasMore) {
                              _loadMore();
                            }
                          });
                          return const Center(
                            child: Padding(
                              padding: EdgeInsets.all(12),
                              child: SizedBox(
                                width: 24,
                                height: 24,
                                child: CircularProgressIndicator(
                                  color: Color(0xFFFCDC04),
                                  strokeWidth: 2,
                                ),
                              ),
                            ),
                          );
                        }
                        final movie = _movies[i];
                        return GestureDetector(
                          onTap: () => _openDetail(movie),
                          child: _UgandaGridCard(movie: movie),
                        );
                      },
                    ),
    );
  }
}

class _UgandaGridCard extends StatelessWidget {
  final Movie movie;
  const _UgandaGridCard({required this.movie});

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
              borderRadius:
                  const BorderRadius.vertical(top: Radius.circular(10)),
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
                        placeholder: (_, __) =>
                            Container(color: AppTheme.shimmerBase),
                        errorWidget: (_, __, ___) => Container(
                          color: AppTheme.shimmerBase,
                          child: const Icon(Icons.movie_outlined,
                              color: AppTheme.textMuted),
                        ),
                      );
                    })
                  : Container(
                      color: AppTheme.shimmerBase,
                      child: const Icon(Icons.movie_outlined,
                          color: AppTheme.textMuted),
                    ),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(6, 5, 6, 6),
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
