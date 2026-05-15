import 'dart:convert';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../api/vod_client.dart';
import '../theme/app_theme.dart';
import '../utils/app_cache_manager.dart';
import 'uganda_view_all_screen.dart';

class UgandaGenresScreen extends StatefulWidget {
  const UgandaGenresScreen({super.key});

  @override
  State<UgandaGenresScreen> createState() => _UgandaGenresScreenState();
}

class _UgandaGenresScreenState extends State<UgandaGenresScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 2, vsync: this);
  List<VodGenre> _genres = [];
  List<VodVj> _vjs = [];
  bool _loading = true;
  String? _error;

  static const _cacheKey    = 'ug_genres_v2';
  static const _cacheTsKey  = 'ug_genres_v2_ts';
  static const _cacheTtlMs  = 12 * 60 * 60 * 1000; // 12 hours

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _tabs.dispose();
    super.dispose();
  }

  Future<void> _load({bool forceRefresh = false}) async {
    // 1. Try cache first — show instantly with no spinner
    if (!forceRefresh) {
      final hadCache = await _restoreFromCache();
      if (hadCache) {
        _refreshSilently();
        return;
      }
    }
    // 2. No cache — show spinner and fetch
    if (mounted) setState(() { _error = null; _loading = true; });
    await _fetchAndSave();
  }

  Future<bool> _restoreFromCache() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw   = prefs.getString(_cacheKey);
      final ts    = prefs.getInt(_cacheTsKey) ?? 0;
      if (raw == null || raw.isEmpty) return false;
      final data  = jsonDecode(raw) as Map<String, dynamic>;
      final genres = (data['genres'] as List? ?? []).map((e) => VodGenre.fromJson(e as Map<String, dynamic>)).toList();
      final vjs    = (data['vjs']    as List? ?? []).map((e) => VodVj.fromJson(e    as Map<String, dynamic>)).toList();
      if (genres.isEmpty && vjs.isEmpty) return false;
      if (mounted) setState(() { _genres = genres; _vjs = vjs; _loading = false; });
      // Return true even if stale — we'll refresh silently
      return true;
    } catch (_) { return false; }
  }

  Future<void> _refreshSilently() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final ts    = prefs.getInt(_cacheTsKey) ?? 0;
      if (DateTime.now().millisecondsSinceEpoch - ts < _cacheTtlMs) return;
    } catch (_) {}
    await _fetchAndSave();
  }

  Future<void> _fetchAndSave() async {
    try {
      final b = await VodClient().getBrowse();
      if (!mounted) return;

      final client = VodClient();
      Future<bool> hasMovies(String pipeType, int pipeId) async {
        try { return (await client.getGrid(pipeType: pipeType, pipeId: pipeId)).movies.isNotEmpty; }
        catch (_) { return false; }
      }

      final genreChecks = await Future.wait(b.genres.map((g) => hasMovies('g', g.id)));
      final vjChecks    = await Future.wait(b.vjs.map((v)    => hasMovies('p', v.id)));
      if (!mounted) return;

      final genres = [for (var i = 0; i < b.genres.length; i++) if (genreChecks[i]) b.genres[i]];
      final vjs    = [for (var i = 0; i < b.vjs.length;    i++) if (vjChecks[i])    b.vjs[i]];

      setState(() { _genres = genres; _vjs = vjs; _loading = false; _error = null; });

      // Persist to cache
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_cacheKey, jsonEncode({
        'genres': genres.map((g) => {'id': g.id, 'name': g.name}).toList(),
        'vjs':    vjs.map((v)    => {'id': v.id, 'name': v.name, 'icon': v.icon}).toList(),
      }));
      await prefs.setInt(_cacheTsKey, DateTime.now().millisecondsSinceEpoch);
    } catch (e) {
      if (!mounted) return;
      if (_genres.isEmpty) setState(() { _error = e.toString(); _loading = false; });
    }
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
        title: const Text(
          'Genres & Veejays',
          style: TextStyle(color: AppTheme.textPrimary, fontWeight: FontWeight.w800),
        ),
        bottom: TabBar(
          controller: _tabs,
          indicatorColor: const Color(0xFFFCDC04),
          indicatorWeight: 3,
          labelColor: const Color(0xFFFCDC04),
          unselectedLabelColor: AppTheme.textMuted,
          labelStyle: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13),
          unselectedLabelStyle: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
          tabs: const [Tab(text: 'Genres'), Tab(text: 'Veejays')],
        ),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(color: Color(0xFFFCDC04)))
          : _error != null
              ? Center(
                  child: Padding(
                    padding: const EdgeInsets.all(32),
                    child: Column(mainAxisSize: MainAxisSize.min, children: [
                      const Icon(Icons.wifi_off_rounded, color: Colors.red, size: 48),
                      const SizedBox(height: 14),
                      Text(
                        _error!,
                        style: const TextStyle(color: AppTheme.textMuted, fontSize: 13),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 16),
                      ElevatedButton(
                        onPressed: _load,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: const Color(0xFFFCDC04),
                          foregroundColor: Colors.black,
                        ),
                        child: const Text('Retry'),
                      ),
                    ]),
                  ),
                )
              : TabBarView(
                  controller: _tabs,
                  children: [
                    _GenreGrid(genres: _genres),
                    _VjGrid(vjs: _vjs),
                  ],
                ),
    );
  }
}

// ── Genre grid ────────────────────────────────────────────────────────────────

class _GenreGrid extends StatelessWidget {
  final List<VodGenre> genres;
  const _GenreGrid({required this.genres});

  static const _colors = [
    Color(0xFFE53935), Color(0xFF8E24AA), Color(0xFF1E88E5),
    Color(0xFF43A047), Color(0xFFFF8C00), Color(0xFF00ACC1),
    Color(0xFFD81B60), Color(0xFF6D4C41), Color(0xFF3949AB),
    Color(0xFF00897B), Color(0xFF7CB342), Color(0xFFEF6C00),
    Color(0xFF546E7A), Color(0xFF8D6E63), Color(0xFF5E35B1),
    Color(0xFFF4511E), Color(0xFF039BE5), Color(0xFFAD1457),
  ];

  @override
  Widget build(BuildContext context) {
    return GridView.builder(
      padding: const EdgeInsets.all(16),
      physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        childAspectRatio: 2.6,
        crossAxisSpacing: 12,
        mainAxisSpacing: 12,
      ),
      itemCount: genres.length,
      itemBuilder: (_, i) {
        final g = genres[i];
        final color = _colors[i % _colors.length];
        return GestureDetector(
          onTap: () => Navigator.push(
            context,
            MaterialPageRoute(
              builder: (_) => UgandaViewAllScreen(
                title: g.name,
                pipeType: 'g',
                pipeId: g.id,
                fallbackName: g.name,
              ),
            ),
          ),
          child: Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [color.withOpacity(0.9), color.withOpacity(0.6)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Center(
              child: Row(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Text(
                    g.name,
                    style: const TextStyle(
                      color: Colors.white,
                      fontSize: 15,
                      fontWeight: FontWeight.w800,
                      shadows: [Shadow(blurRadius: 6, color: Colors.black45)],
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(width: 6),
                  const Icon(
                    Icons.chevron_right_rounded,
                    color: Colors.white70,
                    size: 18,
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

// ── VJ grid ───────────────────────────────────────────────────────────────────

class _VjGrid extends StatelessWidget {
  final List<VodVj> vjs;
  const _VjGrid({required this.vjs});

  static bool _isGenericIcon(String url) =>
      url.isEmpty || url.endsWith('vj.png');

  @override
  Widget build(BuildContext context) {
    return GridView.builder(
      padding: const EdgeInsets.all(16),
      physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        childAspectRatio: 2.0,
        crossAxisSpacing: 12,
        mainAxisSpacing: 12,
      ),
      itemCount: vjs.length,
      itemBuilder: (_, i) {
        final vj = vjs[i];
        return GestureDetector(
          onTap: () => Navigator.push(
            context,
            MaterialPageRoute(
              builder: (_) => UgandaViewAllScreen(
                title: 'By ${vj.name}',
                pipeType: 'p',
                pipeId: vj.id,
                fallbackName: vj.name,
              ),
            ),
          ),
          child: Container(
            decoration: BoxDecoration(
              color: AppTheme.card,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: const Color(0xFFFCDC04).withOpacity(0.2)),
            ),
            child: Row(
              children: [
                const SizedBox(width: 12),
                // Avatar — use real photo only when it's not the generic vj.png
                ClipRRect(
                  borderRadius: BorderRadius.circular(26),
                  child: _isGenericIcon(vj.icon)
                      ? _vjPlaceholder(vj.name)
                      : CachedNetworkImage(
                          imageUrl: vj.icon,
                          cacheManager: AdizaCacheManager(),
                          width: 48,
                          height: 48,
                          fit: BoxFit.cover,
                          memCacheWidth: 192,
                          memCacheHeight: 192,
                          filterQuality: FilterQuality.high,
                          fadeInDuration: const Duration(milliseconds: 180),
                          placeholder: (_, __) => _vjShimmer(),
                          errorWidget: (_, __, ___) => _vjPlaceholder(vj.name),
                        ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        vj.name,
                        style: const TextStyle(
                          color: AppTheme.textPrimary,
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 2),
                      const Text(
                        'Veejay',
                        style: TextStyle(
                          color: Color(0xFFFCDC04),
                          fontSize: 10,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ],
                  ),
                ),
                const Icon(Icons.chevron_right_rounded, color: AppTheme.textMuted, size: 18),
                const SizedBox(width: 6),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _vjPlaceholder(String name) {
    return Container(
      width: 48,
      height: 48,
      decoration: BoxDecoration(
        color: const Color(0xFFFCDC04).withOpacity(0.15),
        shape: BoxShape.circle,
        border: Border.all(color: const Color(0xFFFCDC04).withOpacity(0.4)),
      ),
      child: Center(
        child: Text(
          name.isNotEmpty ? name[0].toUpperCase() : 'V',
          style: const TextStyle(
            color: Color(0xFFFCDC04),
            fontSize: 18,
            fontWeight: FontWeight.w800,
          ),
        ),
      ),
    );
  }

  Widget _vjShimmer() {
    return Container(
      width: 48,
      height: 48,
      decoration: BoxDecoration(
        color: Colors.white10,
        shape: BoxShape.circle,
      ),
    );
  }
}
