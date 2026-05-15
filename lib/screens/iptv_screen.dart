import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import '../services/iptv_service.dart';
import '../theme/app_theme.dart';
import 'iptv_player_screen.dart';

class IptvScreen extends StatefulWidget {
  const IptvScreen({super.key});

  @override
  State<IptvScreen> createState() => _IptvScreenState();
}

class _IptvScreenState extends State<IptvScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabCtrl;
  final Map<String, List<IptvChannel>> _loaded = {};
  final Map<String, bool> _loading = {};
  final Map<String, String?> _error = {};
  String _search = '';
  final _searchCtrl = TextEditingController();
  bool _showSearch = false;

  @override
  void initState() {
    super.initState();
    _tabCtrl = TabController(length: kIptvCategories.length, vsync: this);
    _tabCtrl.addListener(_onTabChange);
    _fetchCategory(kIptvCategories[0].id);
  }

  void _onTabChange() {
    if (_tabCtrl.indexIsChanging) return;
    final cat = kIptvCategories[_tabCtrl.index].id;
    if (!_loaded.containsKey(cat)) _fetchCategory(cat);
  }

  Future<void> _fetchCategory(String id) async {
    if (_loading[id] == true) return;
    setState(() { _loading[id] = true; _error[id] = null; });
    try {
      final channels = await IptvService.fetchCategory(id);
      if (mounted) setState(() { _loaded[id] = channels; });
    } catch (e) {
      if (mounted) setState(() { _error[id] = e.toString(); });
    } finally {
      if (mounted) setState(() { _loading[id] = false; });
    }
  }

  @override
  void dispose() {
    _tabCtrl.dispose();
    _searchCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.background,
      appBar: AppBar(
        backgroundColor: AppTheme.surface,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_rounded, color: Colors.white),
          onPressed: () => Navigator.pop(context),
        ),
        title: _showSearch
            ? TextField(
                controller: _searchCtrl,
                autofocus: true,
                style: const TextStyle(color: Colors.white, fontSize: 15),
                decoration: const InputDecoration(
                  hintText: 'Search channels…',
                  hintStyle: TextStyle(color: AppTheme.textMuted),
                  border: InputBorder.none,
                ),
                onChanged: (v) => setState(() => _search = v.toLowerCase()),
              )
            : Row(
                children: [
                  Container(
                    width: 28, height: 28,
                    decoration: BoxDecoration(
                      color: const Color(0xFF0052CC),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    alignment: Alignment.center,
                    child: const Text('TV', style: TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.w900)),
                  ),
                  const SizedBox(width: 10),
                  const Text('Live TV', style: TextStyle(color: Colors.white, fontSize: 17, fontWeight: FontWeight.w700)),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                    decoration: BoxDecoration(
                      color: Colors.red.withOpacity(0.15),
                      borderRadius: BorderRadius.circular(4),
                      border: Border.all(color: Colors.red.withOpacity(0.4)),
                    ),
                    child: const Text('LIVE', style: TextStyle(color: Colors.red, fontSize: 9, fontWeight: FontWeight.w800)),
                  ),
                ],
              ),
        actions: [
          IconButton(
            icon: Icon(
              _showSearch ? Icons.close_rounded : Icons.search_rounded,
              color: Colors.white,
            ),
            onPressed: () {
              setState(() {
                _showSearch = !_showSearch;
                if (!_showSearch) {
                  _search = '';
                  _searchCtrl.clear();
                }
              });
            },
          ),
          IconButton(
            icon: const Icon(Icons.refresh_rounded, color: Colors.white),
            onPressed: () {
              final cat = kIptvCategories[_tabCtrl.index].id;
              IptvService.clearCache();
              _loaded.remove(cat);
              _fetchCategory(cat);
            },
          ),
        ],
        bottom: PreferredSize(
          preferredSize: const Size.fromHeight(44),
          child: TabBar(
            controller: _tabCtrl,
            isScrollable: true,
            indicatorColor: AppTheme.primary,
            indicatorWeight: 2.5,
            labelColor: Colors.white,
            unselectedLabelColor: AppTheme.textMuted,
            labelStyle: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
            unselectedLabelStyle: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            tabAlignment: TabAlignment.start,
            tabs: kIptvCategories.map((c) => Tab(
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(c.icon, size: 15),
                  const SizedBox(width: 5),
                  Text(c.label),
                ],
              ),
            )).toList(),
          ),
        ),
      ),
      body: TabBarView(
        controller: _tabCtrl,
        children: kIptvCategories.map((cat) => _CategoryTab(
          key: ValueKey(cat.id),
          category: cat,
          channels: _loaded[cat.id] ?? [],
          loading: _loading[cat.id] ?? false,
          error: _error[cat.id],
          search: _search,
          onRetry: () => _fetchCategory(cat.id),
        )).toList(),
      ),
    );
  }
}

// ── Per-category tab ──────────────────────────────────────────────────────────

class _CategoryTab extends StatelessWidget {
  final IptvCategory category;
  final List<IptvChannel> channels;
  final bool loading;
  final String? error;
  final String search;
  final VoidCallback onRetry;

  const _CategoryTab({
    super.key,
    required this.category,
    required this.channels,
    required this.loading,
    this.error,
    required this.search,
    required this.onRetry,
  });

  @override
  Widget build(BuildContext context) {
    if (loading && channels.isEmpty) return const _ShimmerList();

    if (error != null && channels.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.wifi_off_rounded, color: AppTheme.textMuted, size: 48),
            const SizedBox(height: 12),
            const Text('Failed to load channels', style: TextStyle(color: AppTheme.textPrimary, fontSize: 15)),
            const SizedBox(height: 4),
            const Text('Check your connection', style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
            const SizedBox(height: 16),
            TextButton(
              onPressed: onRetry,
              child: const Text('Retry', style: TextStyle(color: AppTheme.primary)),
            ),
          ],
        ),
      );
    }

    final filtered = search.isEmpty
        ? channels
        : channels.where((c) => c.name.toLowerCase().contains(search)).toList();

    if (filtered.isEmpty) {
      return Center(
        child: Text(
          search.isNotEmpty ? 'No channels match "$search"' : 'No channels available',
          style: const TextStyle(color: AppTheme.textMuted, fontSize: 14),
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: filtered.length,
      itemBuilder: (context, i) {
        final ch = filtered[i];
        return _ChannelTile(
          channel: ch,
          onTap: () => Navigator.push(
            context,
            MaterialPageRoute(builder: (_) => IptvPlayerScreen(
              channel: ch,
              playlist: filtered,
              initialIndex: i,
            )),
          ),
        );
      },
    );
  }
}

// ── Channel tile ──────────────────────────────────────────────────────────────

class _ChannelTile extends StatelessWidget {
  final IptvChannel channel;
  final VoidCallback onTap;

  const _ChannelTile({required this.channel, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        child: Row(
          children: [
            // Logo
            Container(
              width: 52, height: 52,
              decoration: BoxDecoration(
                color: AppTheme.card,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppTheme.border),
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(7),
                child: channel.logo.isNotEmpty
                    ? CachedNetworkImage(
                        imageUrl: channel.logo,
                        fit: BoxFit.contain,
                        placeholder: (_, __) => const Icon(Icons.tv_rounded, color: AppTheme.textMuted, size: 24),
                        errorWidget: (_, __, ___) => const Icon(Icons.tv_rounded, color: AppTheme.textMuted, size: 24),
                      )
                    : const Icon(Icons.tv_rounded, color: AppTheme.textMuted, size: 24),
              ),
            ),
            const SizedBox(width: 14),
            // Name + meta
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    channel.name,
                    style: const TextStyle(color: AppTheme.textPrimary, fontSize: 14, fontWeight: FontWeight.w600),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 4),
                  Row(children: [
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                      decoration: BoxDecoration(
                        color: Colors.red.withOpacity(0.15),
                        borderRadius: BorderRadius.circular(3),
                      ),
                      child: const Text('LIVE', style: TextStyle(color: Colors.red, fontSize: 8, fontWeight: FontWeight.w900)),
                    ),
                    if (channel.quality.isNotEmpty) ...[
                      const SizedBox(width: 6),
                      Text(channel.quality, style: const TextStyle(color: AppTheme.textMuted, fontSize: 11)),
                    ],
                  ]),
                ],
              ),
            ),
            const Icon(Icons.play_circle_rounded, color: AppTheme.primary, size: 30),
          ],
        ),
      ),
    );
  }
}

// ── Shimmer skeleton ──────────────────────────────────────────────────────────

class _ShimmerList extends StatelessWidget {
  const _ShimmerList();

  @override
  Widget build(BuildContext context) {
    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: 12,
      itemBuilder: (_, __) => Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(
          children: [
            Container(
              width: 52, height: 52,
              decoration: BoxDecoration(
                color: AppTheme.shimmerBase,
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(height: 13, width: 180, decoration: BoxDecoration(color: AppTheme.shimmerBase, borderRadius: BorderRadius.circular(4))),
                  const SizedBox(height: 8),
                  Container(height: 10, width: 80, decoration: BoxDecoration(color: AppTheme.shimmerBase, borderRadius: BorderRadius.circular(4))),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
