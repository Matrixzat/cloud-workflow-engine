import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../api/models.dart';
import '../api/moviebox_client.dart';
import '../providers/app_provider.dart';
import '../theme/app_theme.dart';
import '../widgets/movie_card.dart';
import '../widgets/shimmer_card.dart';
import 'detail_screen.dart';

class ViewAllScreen extends StatefulWidget {
  final String title;
  final List<Movie> initialMovies;
  final String sectionKey;
  final int subjectType;

  const ViewAllScreen({
    super.key,
    required this.title,
    required this.initialMovies,
    this.sectionKey = 'trending',
    this.subjectType = 0,
  });

  @override
  State<ViewAllScreen> createState() => _ViewAllScreenState();
}

class _ViewAllScreenState extends State<ViewAllScreen> {
  final MovieBoxClient _client = MovieBoxClient();
  final ScrollController _scrollController = ScrollController();

  List<Movie> _movies = [];
  bool _loadingMore = false;
  bool _hasMore = true;
  int _page = 2;
  bool _initialLoading = false;

  String get _cacheKey => 'mb_viewall_${widget.sectionKey}_v1';

  @override
  void initState() {
    super.initState();
    if (widget.initialMovies.isNotEmpty) {
      _movies = List.from(widget.initialMovies);
      _page = 2;
    } else {
      _page = 1;
      _loadInitial();
    }
    _scrollController.addListener(_onScroll);
  }

  @override
  void dispose() {
    _scrollController.dispose();
    super.dispose();
  }

  Future<void> _loadInitial() async {
    // Show cached page 1 instantly, then refresh silently
    final hadCache = await _restoreCache();
    if (hadCache) { _refreshSilently(); return; }
    setState(() => _initialLoading = true);
    try {
      final more = await _fetchPage(1);
      if (mounted) {
        setState(() { _movies = more; _page = 2; if (more.length < 20) _hasMore = false; _initialLoading = false; });
        _saveCache(more);
      }
    } catch (_) {
      if (mounted) setState(() { _hasMore = false; _initialLoading = false; });
    }
  }

  Future<bool> _restoreCache() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_cacheKey);
      if (raw == null || raw.isEmpty) return false;
      final list = (jsonDecode(raw) as List).map((e) => Movie.fromJson(e as Map<String, dynamic>)).toList();
      if (list.isEmpty) return false;
      if (mounted) setState(() { _movies = list; _page = 2; });
      return true;
    } catch (_) { return false; }
  }

  Future<void> _refreshSilently() async {
    try {
      final more = await _fetchPage(1);
      if (!mounted || more.isEmpty) return;
      setState(() { _movies = more; _page = 2; if (more.length < 20) _hasMore = false; });
      _saveCache(more);
    } catch (_) {}
  }

  Future<void> _saveCache(List<Movie> movies) async {
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_cacheKey, jsonEncode(movies.map((m) => m.toJson()).toList()));
    } catch (_) {}
  }

  void _onScroll() {
    if (_scrollController.position.pixels >= _scrollController.position.maxScrollExtent - 400) {
      _loadMore();
    }
  }

  Future<List<Movie>> _fetchPage(int page) async {
    final key = widget.sectionKey.toLowerCase().trim();
    if (key == 'trending') {
      return _client.getTrending(page: page - 1, perPage: 24);
    } else if (key == 'new') {
      return _client.getNewReleases(page: page, perPage: 24);
    } else {
      return _client.getGenre(key, page: page, perPage: 24, subjectType: widget.subjectType);
    }
  }

  Future<void> _loadMore() async {
    if (_loadingMore || !_hasMore || _initialLoading) return;
    setState(() => _loadingMore = true);
    try {
      final more = await _fetchPage(_page);
      if (more.isEmpty) {
        _hasMore = false;
      } else {
        final existingIds = _movies.map((m) => m.id).toSet();
        final newMovies = more.where((m) => !existingIds.contains(m.id)).toList();
        if (newMovies.isEmpty) {
          _hasMore = false;
        } else {
          _movies.addAll(newMovies);
          _page++;
          if (more.length < 20) _hasMore = false;
        }
      }
    } catch (_) {
      _hasMore = false;
    }
    if (mounted) setState(() => _loadingMore = false);
  }

  void _openDetail(Movie movie) {
    context.read<AppProvider>().addToHistory(movie);
    Navigator.push(context, MaterialPageRoute(builder: (_) => DetailScreen(movie: movie)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.background,
      appBar: AppBar(
        backgroundColor: AppTheme.background,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_rounded),
          onPressed: () => Navigator.pop(context),
        ),
        title: Row(
          children: [
            Container(
              width: 4,
              height: 20,
              decoration: BoxDecoration(
                color: AppTheme.primary,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                widget.title,
                style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700),
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
      body: _initialLoading
          ? GridView.builder(
              padding: const EdgeInsets.fromLTRB(12, 12, 12, 32),
              gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                crossAxisCount: 3,
                childAspectRatio: 0.58,
                crossAxisSpacing: 10,
                mainAxisSpacing: 10,
              ),
              itemCount: 12,
              itemBuilder: (_, __) => const ShimmerCard(),
            )
          : Consumer<AppProvider>(
              builder: (_, provider, __) {
                return GridView.builder(
                  controller: _scrollController,
                  physics: const BouncingScrollPhysics(
                      parent: AlwaysScrollableScrollPhysics()),
                  cacheExtent: 400,
                  padding: const EdgeInsets.fromLTRB(12, 12, 12, 32),
                  gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 3,
                    childAspectRatio: 0.58,
                    crossAxisSpacing: 10,
                    mainAxisSpacing: 10,
                  ),
                  itemCount: _movies.length + (_loadingMore ? 6 : 0),
                  itemBuilder: (context, i) {
                    if (i >= _movies.length) {
                      return const ShimmerCard();
                    }
                    final movie = _movies[i];
                    return MovieCard(
                      movie: movie,
                      onTap: () => _openDetail(movie),
                      isWatchlisted: provider.isInWatchlist(movie.id),
                      onWatchlist: () => provider.toggleWatchlist(movie),
                    );
                  },
                );
              },
            ),
    );
  }
}
