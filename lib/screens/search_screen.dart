import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../api/models.dart';
import '../providers/app_provider.dart';
import '../theme/app_theme.dart';
import '../widgets/movie_card.dart';
import '../widgets/shimmer_card.dart';
import 'detail_screen.dart';

class SearchScreen extends StatefulWidget {
  const SearchScreen({super.key});

  @override
  State<SearchScreen> createState() => _SearchScreenState();
}

class _SearchScreenState extends State<SearchScreen> {
  final TextEditingController _controller = TextEditingController();
  final FocusNode _focusNode = FocusNode();
  final ScrollController _scrollCtrl = ScrollController();
  Timer? _debounce;
  int _selectedType = 0;
  bool _isTyping = false;

  static const List<Map<String, dynamic>> _filters = [
    {'label': 'All', 'value': 0},
    {'label': 'Movies', 'value': 1},
    {'label': 'TV Series', 'value': 2},
  ];

  @override
  void initState() {
    super.initState();
    _scrollCtrl.addListener(_onScroll);
    _controller.addListener(() {
      setState(() => _isTyping = _controller.text.isNotEmpty);
    });
  }

  void _onScroll() {
    if (_scrollCtrl.position.pixels >= _scrollCtrl.position.maxScrollExtent - 400) {
      context.read<AppProvider>().loadMoreSearch();
    }
  }

  void _onChanged(String value) {
    _debounce?.cancel();
    if (value.trim().isEmpty) {
      context.read<AppProvider>().searchContent('');
      return;
    }
    _debounce = Timer(const Duration(milliseconds: 480), () {
      context.read<AppProvider>().searchContent(value, type: _selectedType);
      context.read<AppProvider>().addSearchHistory(value);
    });
  }

  void _submitSearch(String value) {
    _debounce?.cancel();
    if (value.trim().isEmpty) return;
    _focusNode.unfocus();
    context.read<AppProvider>().searchContent(value, type: _selectedType);
    context.read<AppProvider>().addSearchHistory(value);
  }

  void _applyQuery(String query) {
    _controller.text = query;
    _controller.selection = TextSelection.collapsed(offset: query.length);
    setState(() => _isTyping = true);
    _focusNode.unfocus();
    context.read<AppProvider>().searchContent(query, type: _selectedType);
    context.read<AppProvider>().addSearchHistory(query);
  }

  void _onFilterChanged(int type) {
    setState(() => _selectedType = type);
    if (_controller.text.isNotEmpty) {
      context.read<AppProvider>().searchContent(_controller.text, type: type);
    }
  }

  void _openDetail(Movie movie) {
    context.read<AppProvider>().addToHistory(movie);
    Navigator.push(
        context, MaterialPageRoute(builder: (_) => DetailScreen(movie: movie)));
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _controller.dispose();
    _focusNode.dispose();
    _scrollCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.background,
      appBar: AppBar(
        backgroundColor: AppTheme.background,
        elevation: 0,
        title: TextField(
          controller: _controller,
          focusNode: _focusNode,
          onChanged: _onChanged,
          onSubmitted: _submitSearch,
          textInputAction: TextInputAction.search,
          autofocus: false,
          style: const TextStyle(color: AppTheme.textPrimary, fontSize: 16),
          decoration: InputDecoration(
            hintText: 'Search movies, TV series...',
            hintStyle: const TextStyle(color: AppTheme.textMuted),
            border: InputBorder.none,
            enabledBorder: InputBorder.none,
            focusedBorder: InputBorder.none,
            prefixIcon:
                const Icon(Icons.search_rounded, color: AppTheme.textMuted),
            suffixIcon: _isTyping
                ? IconButton(
                    icon: const Icon(Icons.close_rounded,
                        color: AppTheme.textMuted),
                    onPressed: () {
                      _controller.clear();
                      context.read<AppProvider>().searchContent('');
                    },
                  )
                : null,
          ),
        ),
      ),
      body: Column(
        children: [
          // Filter chips
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 10),
            child: Row(
              children: _filters.map((f) {
                final selected = _selectedType == f['value'];
                return Padding(
                  padding: const EdgeInsets.only(right: 8),
                  child: GestureDetector(
                    onTap: () => _onFilterChanged(f['value'] as int),
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 16, vertical: 7),
                      decoration: BoxDecoration(
                        color: selected ? AppTheme.primary : AppTheme.card,
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(
                            color: selected
                                ? AppTheme.primary
                                : AppTheme.border),
                      ),
                      child: Text(
                        f['label'] as String,
                        style: TextStyle(
                          color: selected
                              ? Colors.white
                              : AppTheme.textSecondary,
                          fontSize: 13,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ),
                );
              }).toList(),
            ),
          ),

          // Body
          Expanded(
            child: Consumer<AppProvider>(
              builder: (_, provider, __) {
                // Loading initial search
                if (provider.loadingSearch) {
                  return const Padding(
                    padding: EdgeInsets.all(16),
                    child: ShimmerGrid(count: 9),
                  );
                }

                // Empty query → show history + popular
                if (_controller.text.isEmpty) {
                  return _SearchLanding(
                    onTap: _applyQuery,
                    history: provider.searchHistory,
                    onRemoveHistory: provider.removeSearchHistory,
                    onClearHistory: provider.clearSearchHistory,
                  );
                }

                // No results
                if (provider.searchResults.isEmpty) {
                  return Center(
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.search_off_rounded,
                            color: AppTheme.textMuted, size: 60),
                        const SizedBox(height: 14),
                        Text(
                          'No results for "${_controller.text}"',
                          style: const TextStyle(
                              color: AppTheme.textMuted, fontSize: 15),
                        ),
                      ],
                    ),
                  );
                }

                // Results grid with infinite scroll
                return GridView.builder(
                  controller: _scrollCtrl,
                  padding: const EdgeInsets.fromLTRB(14, 4, 14, 80),
                  physics: const BouncingScrollPhysics(
                      parent: AlwaysScrollableScrollPhysics()),
                  gridDelegate:
                      const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 3,
                    childAspectRatio: 0.58,
                    crossAxisSpacing: 10,
                    mainAxisSpacing: 10,
                  ),
                  itemCount: provider.searchResults.length +
                      (provider.searchHasMore ? 3 : 0),
                  itemBuilder: (_, i) {
                    if (i >= provider.searchResults.length) {
                      return const ShimmerCard();
                    }
                    final movie = provider.searchResults[i];
                    return MovieGridCard(
                      movie: movie,
                      onTap: () => _openDetail(movie),
                      isWatchlisted: provider.isInWatchlist(movie.id),
                      onWatchlist: () => provider.toggleWatchlist(movie),
                    );
                  },
                );
              },
            ),
          ),
        ],
      ),
    );
  }
}

// ── Search landing (history + popular) ────────────────────────────────────────
class _SearchLanding extends StatefulWidget {
  final Function(String) onTap;
  final List<String> history;
  final Function(String) onRemoveHistory;
  final VoidCallback onClearHistory;

  const _SearchLanding({
    required this.onTap,
    required this.history,
    required this.onRemoveHistory,
    required this.onClearHistory,
  });

  @override
  State<_SearchLanding> createState() => _SearchLandingState();
}

class _SearchLandingState extends State<_SearchLanding> {
  List<Movie> _popular = [];
  bool _loading = true;

  static const _cacheKey   = 'mb_popular_searches_v1';
  static const _cacheTsKey = 'mb_popular_searches_v1_ts';
  static const _cacheTtlMs = 6 * 60 * 60 * 1000; // 6 hours

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    // Show cached instantly, then silently refresh if stale
    final hadCache = await _restoreCache();
    if (hadCache) { _refreshSilently(); return; }
    await _fetchAndSave();
  }

  Future<bool> _restoreCache() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_cacheKey);
      if (raw == null || raw.isEmpty) return false;
      final list = (jsonDecode(raw) as List)
          .map((e) => Movie.fromJson(e as Map<String, dynamic>))
          .toList();
      if (list.isEmpty) return false;
      if (mounted) setState(() { _popular = list; _loading = false; });
      return true;
    } catch (_) { return false; }
  }

  Future<void> _refreshSilently() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final ts = prefs.getInt(_cacheTsKey) ?? 0;
      if (DateTime.now().millisecondsSinceEpoch - ts < _cacheTtlMs) return;
    } catch (_) {}
    await _fetchAndSave();
  }

  Future<void> _fetchAndSave() async {
    try {
      final results = await context.read<AppProvider>().client.getPopularSearches();
      if (!mounted) return;
      setState(() { _popular = results; _loading = false; });
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_cacheKey, jsonEncode(results.map((m) => m.toJson()).toList()));
      await prefs.setInt(_cacheTsKey, DateTime.now().millisecondsSinceEpoch);
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 4, 16, 32),
      physics: const BouncingScrollPhysics(
          parent: AlwaysScrollableScrollPhysics()),
      children: [
        // ── Recent searches ────────────────────────────────────────────────
        if (widget.history.isNotEmpty) ...[
          Row(
            children: [
              const Icon(Icons.history_rounded,
                  color: AppTheme.textMuted, size: 16),
              const SizedBox(width: 6),
              const Text('Recent Searches',
                  style: TextStyle(
                      color: AppTheme.textSecondary,
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.3)),
              const Spacer(),
              GestureDetector(
                onTap: widget.onClearHistory,
                child: const Text('Clear all',
                    style: TextStyle(
                        color: AppTheme.primary,
                        fontSize: 12,
                        fontWeight: FontWeight.w500)),
              ),
            ],
          ),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: widget.history
                .map((q) => _HistoryChip(
                      query: q,
                      onTap: () => widget.onTap(q),
                      onRemove: () => widget.onRemoveHistory(q),
                    ))
                .toList(),
          ),
          const SizedBox(height: 24),
        ],

        // ── Popular searches ────────────────────────────────────────────────
        if (_loading)
          const Center(
            child: Padding(
              padding: EdgeInsets.symmetric(vertical: 24),
              child: CircularProgressIndicator(
                  color: AppTheme.primary, strokeWidth: 2),
            ),
          )
        else if (_popular.isNotEmpty) ...[
          Row(children: const [
            Icon(Icons.trending_up_rounded,
                color: AppTheme.textMuted, size: 16),
            SizedBox(width: 6),
            Text('Popular Searches',
                style: TextStyle(
                    color: AppTheme.textSecondary,
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 0.3)),
          ]),
          const SizedBox(height: 10),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: _popular
                .map((m) => GestureDetector(
                      onTap: () => widget.onTap(m.title),
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 14, vertical: 8),
                        decoration: BoxDecoration(
                          color: AppTheme.card,
                          borderRadius: BorderRadius.circular(20),
                          border: Border.all(color: AppTheme.border),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.trending_up_rounded,
                                size: 13, color: AppTheme.primary),
                            const SizedBox(width: 6),
                            Text(m.title,
                                style: const TextStyle(
                                    color: AppTheme.textSecondary,
                                    fontSize: 13)),
                          ],
                        ),
                      ),
                    ))
                .toList(),
          ),
        ],
      ],
    );
  }
}

class _HistoryChip extends StatelessWidget {
  final String query;
  final VoidCallback onTap;
  final VoidCallback onRemove;

  const _HistoryChip({
    required this.query,
    required this.onTap,
    required this.onRemove,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.only(left: 12, top: 7, bottom: 7, right: 6),
        decoration: BoxDecoration(
          color: AppTheme.card,
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: AppTheme.border),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.history_rounded,
                size: 13, color: AppTheme.textMuted),
            const SizedBox(width: 6),
            Text(query,
                style: const TextStyle(
                    color: AppTheme.textPrimary, fontSize: 13)),
            const SizedBox(width: 6),
            GestureDetector(
              onTap: onRemove,
              behavior: HitTestBehavior.opaque,
              child: const Padding(
                padding: EdgeInsets.all(3),
                child: Icon(Icons.close_rounded,
                    size: 12, color: AppTheme.textMuted),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
