import 'dart:async';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../services/football_service.dart';
import '../theme/app_theme.dart';
import 'football_player_screen.dart';

// ─── Screen ───────────────────────────────────────────────────────────────────

class FootballScreen extends StatefulWidget {
  const FootballScreen({super.key});
  @override
  State<FootballScreen> createState() => _FootballScreenState();
}

class _FootballScreenState extends State<FootballScreen> {
  final _service    = FootballService();
  List<FootballMatch> _all   = [];
  List<FootballMatch> _shown = [];
  bool    _loading = true;
  String? _error;
  String  _filter  = 'all';
  String  _search  = '';
  final   _searchCtrl = TextEditingController();
  final   _scrollCtrl = ScrollController();
  bool    _showScrollTop = false;

  @override
  void initState() {
    super.initState();
    _scrollCtrl.addListener(() {
      final show = _scrollCtrl.offset > 180;
      if (show != _showScrollTop) setState(() => _showScrollTop = show);
    });
    SharedPreferences.getInstance()
        .then((p) => p.setString('last_section', 'football'));
    _load();
  }

  @override
  void dispose() {
    SharedPreferences.getInstance()
        .then((p) => p.setString('last_section', 'home'));
    _searchCtrl.dispose();
    _scrollCtrl.dispose();
    super.dispose();
  }

  void _scrollToTop() {
    _scrollCtrl.animateTo(0,
      duration: const Duration(milliseconds: 450),
      curve: Curves.easeOutCubic);
  }

  // ── Data ───────────────────────────────────────────────────────────────────

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final m = await _service.fetchMatches();
      if (!mounted) return;
      setState(() { _all = m; _loading = false; });
      _apply();
    } catch (e) {
      if (!mounted) return;
      setState(() { _loading = false; _error = e.toString(); });
    }
  }

  void _apply() {
    var list = _all;
    if (_filter == 'live')     list = list.where((m) => m.isLive).toList();
    if (_filter == 'upcoming') list = list.where((m) => m.isUpcoming).toList();
    if (_search.isNotEmpty) {
      final q = _search.toLowerCase();
      list = list.where((m) =>
        m.title.toLowerCase().contains(q) ||
        m.homeTeam.toLowerCase().contains(q) ||
        m.awayTeam.toLowerCase().contains(q) ||
        m.category.toLowerCase().contains(q)).toList();
    }
    setState(() => _shown = list);
  }

  // ── Group by date ──────────────────────────────────────────────────────────

  List<_Item> _buildItems() {
    final groups = <String, List<FootballMatch>>{};
    final order  = <String>[];
    for (final m in _shown) {
      final key = '${m.date.year}-${m.date.month.toString().padLeft(2,'0')}-${m.date.day.toString().padLeft(2,'0')}';
      if (!groups.containsKey(key)) { groups[key] = []; order.add(key); }
      groups[key]!.add(m);
    }
    final items = <_Item>[];
    for (final key in order) {
      final date = groups[key]!.first.date;
      items.add(_DateHeaderItem(date));
      final matches = groups[key]!;
      for (var i = 0; i < matches.length; i += 2) {
        items.add(_RowItem(
          matches[i],
          i + 1 < matches.length ? matches[i + 1] : null,
        ));
      }
    }
    return items;
  }

  // ── Navigation ─────────────────────────────────────────────────────────────

  Future<void> _open(FootballMatch match) async {
    if (match.sources.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('No streams available for this match yet')));
      return;
    }
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (_) => const Center(
        child: CircularProgressIndicator(color: AppTheme.primary)),
    );
    try {
      final streams = await _service.fetchStreams(match.sources.first);
      if (!mounted) return;
      Navigator.pop(context);
      if (streams.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('No streams available for this match yet')));
        return;
      }
      Navigator.push(context, MaterialPageRoute(
        builder: (_) => FootballPlayerScreen(match: match, streams: streams)));
    } catch (e) {
      if (!mounted) return;
      Navigator.pop(context);
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Stream unavailable. Try another match or check your connection.')));
    }
  }

  // ── Build ──────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final liveCount = _all.where((m) => m.isLive).length;
    final items     = _buildItems();

    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) async {
        if (didPop) return;
        final exit = await showDialog<bool>(
          context: context,
          barrierColor: Colors.black87,
          builder: (_) => const _ExitDialog(),
        );
        if ((exit ?? false) && context.mounted) Navigator.of(context).pop();
      },
      child: Scaffold(
      backgroundColor: Colors.black,
      floatingActionButton: AnimatedSlide(
        offset: _showScrollTop ? Offset.zero : const Offset(0, 2),
        duration: const Duration(milliseconds: 280),
        curve: Curves.easeOutCubic,
        child: AnimatedOpacity(
          opacity: _showScrollTop ? 1.0 : 0.0,
          duration: const Duration(milliseconds: 280),
          child: FloatingActionButton.small(
            onPressed: _scrollToTop,
            backgroundColor: const Color(0xFF00C853),
            foregroundColor: Colors.black,
            tooltip: 'Scroll to top',
            child: const Icon(Icons.keyboard_arrow_up_rounded, size: 26),
          ),
        ),
      ),
      body: CustomScrollView(
        controller: _scrollCtrl,
        slivers: [

          // ── App bar ──────────────────────────────────────────────────────
          SliverAppBar(
            backgroundColor: Colors.black,
            expandedHeight: 140,
            pinned: true,
            elevation: 0,
            leading: IconButton(
              icon: const Icon(Icons.arrow_back_rounded, color: Colors.white),
              onPressed: () => Navigator.pop(context),
            ),
            actions: [
              IconButton(
                icon: const Icon(Icons.refresh_rounded, color: Colors.white),
                onPressed: _load,
              ),
            ],
            flexibleSpace: FlexibleSpaceBar(
              background: Container(
                decoration: const BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [Color(0xFF001800), Colors.black],
                  ),
                ),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.end,
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: [
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 18, vertical: 6),
                      decoration: BoxDecoration(
                        color: const Color(0xFF00C853).withOpacity(0.15),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(
                          color: const Color(0xFF00C853).withOpacity(0.6),
                          width: 1.5),
                      ),
                      child: const Text('ADIZA',
                        style: TextStyle(
                          color: Color(0xFF00C853),
                          fontSize: 20,
                          fontWeight: FontWeight.w900,
                          letterSpacing: 5,
                        )),
                    ),
                    const SizedBox(height: 6),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.sports_soccer_rounded,
                            color: Color(0xFF00C853), size: 18),
                        const SizedBox(width: 7),
                        const Text('Live Football Matches',
                          style: TextStyle(
                            color: Colors.white,
                            fontSize: 20,
                            fontWeight: FontWeight.w800,
                            letterSpacing: -0.3,
                          )),
                      ],
                    ),
                    const SizedBox(height: 4),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        if (liveCount > 0) ...[
                          const _PulseDot(color: Color(0xFF00C853)),
                          const SizedBox(width: 5),
                          Text('$liveCount live now',
                            style: const TextStyle(
                                color: Color(0xFF00C853), fontSize: 11,
                                fontWeight: FontWeight.w600)),
                          const SizedBox(width: 10),
                        ],
                        if (!_loading)
                          Text('${_all.length} matches',
                            style: const TextStyle(
                                color: AppTheme.textMuted, fontSize: 11)),
                      ],
                    ),
                    const SizedBox(height: 10),
                  ],
                ),
              ),
            ),
          ),

          // ── Sliding banner ───────────────────────────────────────────────
          const SliverToBoxAdapter(child: _FbSliderBanner()),

          // ── Search + filter ──────────────────────────────────────────────
          SliverToBoxAdapter(
            child: Column(children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
                child: TextField(
                  controller: _searchCtrl,
                  style: const TextStyle(color: Colors.white, fontSize: 14),
                  decoration: InputDecoration(
                    hintText: 'Search team, country or competition…',
                    hintStyle: const TextStyle(
                        color: AppTheme.textMuted, fontSize: 13),
                    prefixIcon: const Icon(Icons.search_rounded,
                        color: AppTheme.textMuted, size: 20),
                    suffixIcon: _search.isNotEmpty
                        ? IconButton(
                            icon: const Icon(Icons.close_rounded,
                                color: AppTheme.textMuted, size: 18),
                            onPressed: () {
                              _searchCtrl.clear();
                              setState(() => _search = '');
                              _apply();
                            })
                        : null,
                    contentPadding: const EdgeInsets.symmetric(vertical: 11),
                    filled: true,
                    fillColor: const Color(0xFF0E0E0E),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(color: Color(0xFF1E1E1E)),
                    ),
                    enabledBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(color: Color(0xFF1E1E1E)),
                    ),
                    focusedBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: const BorderSide(
                          color: Color(0xFF00C853), width: 1.5),
                    ),
                  ),
                  onChanged: (v) { setState(() => _search = v); _apply(); },
                ),
              ),
              SizedBox(
                height: 36,
                child: ListView(
                  scrollDirection: Axis.horizontal,
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  children: [
                    _Chip(label: 'All', value: 'all',
                        current: _filter,
                        onTap: (v) { setState(() => _filter = v); _apply(); _scrollToTop(); }),
                    const SizedBox(width: 8),
                    _Chip(label: 'Live Now', value: 'live',
                        pulse: true,
                        current: _filter,
                        onTap: (v) { setState(() => _filter = v); _apply(); _scrollToTop(); }),
                    const SizedBox(width: 8),
                    _Chip(label: 'Upcoming', value: 'upcoming',
                        icon: Icons.schedule_rounded,
                        current: _filter,
                        onTap: (v) { setState(() => _filter = v); _apply(); _scrollToTop(); }),
                    const SizedBox(width: 8),
                    _Chip(label: 'Popular', value: 'popular',
                        icon: Icons.local_fire_department_rounded,
                        iconColor: Colors.amber,
                        current: _filter,
                        onTap: (v) {
                          setState(() => _filter = v);
                          var list = _all.where((m) => m.popular).toList();
                          if (_search.isNotEmpty) {
                            final q = _search.toLowerCase();
                            list = list.where((m) =>
                              m.title.toLowerCase().contains(q) ||
                              m.homeTeam.toLowerCase().contains(q) ||
                              m.awayTeam.toLowerCase().contains(q)).toList();
                          }
                          setState(() => _shown = list);
                          _scrollToTop();
                        }),
                  ],
                ),
              ),
              const SizedBox(height: 8),
            ]),
          ),

          // ── Body ─────────────────────────────────────────────────────────
          if (_loading)
            const SliverFillRemaining(child: _Shimmer())
          else if (_error != null)
            SliverFillRemaining(child: _ErrorView(onRetry: _load))
          else if (_shown.isEmpty)
            SliverFillRemaining(child: _EmptyView(search: _search))
          else
            SliverPadding(
              padding: const EdgeInsets.fromLTRB(12, 0, 12, 40),
              sliver: SliverList(
                delegate: SliverChildBuilderDelegate(
                  (ctx, i) {
                    final item = items[i];
                    if (item is _DateHeaderItem) {
                      return _DateHeader(date: item.date);
                    }
                    final row = item as _RowItem;
                    return _MatchRow(
                      left: row.left, right: row.right,
                      onTapLeft:  () => _open(row.left),
                      onTapRight: row.right != null
                          ? () => _open(row.right!) : null,
                    );
                  },
                  childCount: items.length,
                ),
              ),
            ),
        ],
      ),
    ),   // Scaffold
    );   // PopScope
  }
}

// ─── Exit dialog ───────────────────────────────────────────────────────────────

class _ExitDialog extends StatelessWidget {
  const _ExitDialog();

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: const EdgeInsets.symmetric(horizontal: 40),
      child: Container(
        decoration: BoxDecoration(
          color: const Color(0xFF0D0D0D),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: const Color(0xFF00C853).withOpacity(0.35)),
        ),
        padding: const EdgeInsets.fromLTRB(28, 32, 28, 24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // ── ADIZA badge ──────────────────────────────────────────────
            RichText(
              textAlign: TextAlign.center,
              text: const TextSpan(
                children: [
                  TextSpan(
                    text: 'ADIZA',
                    style: TextStyle(
                      color: Color(0xFF00C853),
                      fontSize: 32,
                      fontWeight: FontWeight.w900,
                      letterSpacing: 6,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 4),
            const Text(
              'MOVIEZ BOX',
              style: TextStyle(
                color: Colors.white38,
                fontSize: 10,
                fontWeight: FontWeight.w600,
                letterSpacing: 4,
              ),
            ),
            const SizedBox(height: 24),
            const Icon(Icons.sports_soccer_rounded,
                color: Color(0xFF00C853), size: 40),
            const SizedBox(height: 16),
            const Text(
              'Leave Live Football?',
              style: TextStyle(
                color: Colors.white,
                fontSize: 18,
                fontWeight: FontWeight.w700,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 8),
            const Text(
              'Are you sure you want to go back?\nLive matches are waiting!',
              style: TextStyle(
                color: Colors.white54,
                fontSize: 13,
                height: 1.5,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 28),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: () => Navigator.of(context).pop(false),
                    style: OutlinedButton.styleFrom(
                      side: const BorderSide(color: Color(0xFF00C853)),
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12)),
                    ),
                    child: const Text('Stay',
                        style: TextStyle(
                            color: Color(0xFF00C853),
                            fontWeight: FontWeight.w700)),
                  ),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: ElevatedButton(
                    onPressed: () => Navigator.of(context).pop(true),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: const Color(0xFF00C853),
                      foregroundColor: Colors.black,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(12)),
                    ),
                    child: const Text('Exit',
                        style: TextStyle(fontWeight: FontWeight.w800)),
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

// ─── Data items ────────────────────────────────────────────────────────────────

abstract class _Item {}
class _DateHeaderItem extends _Item {
  final DateTime date;
  _DateHeaderItem(this.date);
}
class _RowItem extends _Item {
  final FootballMatch left;
  final FootballMatch? right;
  _RowItem(this.left, this.right);
}

// ─── Date header ───────────────────────────────────────────────────────────────

class _DateHeader extends StatelessWidget {
  final DateTime date;
  const _DateHeader({required this.date});

  @override
  Widget build(BuildContext context) {
    final now = DateTime.now();
    const days   = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
    const months = ['JAN','FEB','MAR','APR','MAY','JUN',
                    'JUL','AUG','SEP','OCT','NOV','DEC'];
    final dayStr = (date.day == now.day && date.month == now.month)
        ? 'TODAY'
        : days[date.weekday - 1].toUpperCase();

    return Padding(
      padding: const EdgeInsets.only(top: 22, bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.baseline,
        textBaseline: TextBaseline.alphabetic,
        children: [
          Text('${date.day}',
            style: const TextStyle(color: Colors.white,
                fontSize: 42, fontWeight: FontWeight.w900, height: 1)),
          const SizedBox(width: 10),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(dayStr,
                style: const TextStyle(color: Colors.white,
                    fontSize: 15, fontWeight: FontWeight.w700)),
              Text(months[date.month - 1],
                style: const TextStyle(color: AppTheme.textMuted,
                    fontSize: 12, fontWeight: FontWeight.w600)),
            ],
          ),
        ],
      ),
    );
  }
}

// ─── Match row (2 cards) ────────────────────────────────────────────────────────

class _MatchRow extends StatelessWidget {
  final FootballMatch  left;
  final FootballMatch? right;
  final VoidCallback   onTapLeft;
  final VoidCallback?  onTapRight;
  const _MatchRow({required this.left, this.right,
      required this.onTapLeft, this.onTapRight});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 14),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(child: _MatchCard(match: left,  onTap: onTapLeft)),
          const SizedBox(width: 10),
          Expanded(child: right != null
            ? _MatchCard(match: right!, onTap: onTapRight!)
            : const SizedBox()),
        ],
      ),
    );
  }
}

// ─── Match card ────────────────────────────────────────────────────────────────

class _MatchCard extends StatelessWidget {
  final FootballMatch match;
  final VoidCallback  onTap;
  const _MatchCard({required this.match, required this.onTap});

  String _time(DateTime dt) {
    final h    = dt.hour;
    final m    = dt.minute.toString().padLeft(2, '0');
    final amPm = h >= 12 ? 'PM' : 'AM';
    final disp = (h % 12 == 0 ? 12 : h % 12).toString();
    return '$disp:$m $amPm';
  }

  @override
  Widget build(BuildContext context) {
    final live   = match.isLive;
    final poster = match.poster;

    return GestureDetector(
      onTap: onTap,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Card image ──────────────────────────────────────────────────
          AspectRatio(
            aspectRatio: 1.25,
            child: ClipRRect(
              borderRadius: BorderRadius.circular(12),
              child: Stack(
                fit: StackFit.expand,
                children: [

                  // Background: poster or dark gradient fallback
                  if (poster != null)
                    CachedNetworkImage(
                      imageUrl: poster,
                      fit: BoxFit.cover,
                      placeholder: (_, __) => Container(color: const Color(0xFF111111)),
                      errorWidget: (_, __, ___) => _FallbackBg(match: match),
                    )
                  else
                    _FallbackBg(match: match),

                  // Dark gradient overlay (bottom-heavy)
                  Container(
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        begin: Alignment.topCenter,
                        end: Alignment.bottomCenter,
                        colors: [
                          Colors.transparent,
                          Colors.black.withOpacity(0.55),
                          Colors.black.withOpacity(0.85),
                        ],
                        stops: const [0.0, 0.55, 1.0],
                      ),
                    ),
                  ),

                  // Top-left: time badge
                  Positioned(
                    top: 8, left: 8,
                    child: Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 7, vertical: 4),
                      decoration: BoxDecoration(
                        color: Colors.black.withOpacity(0.78),
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(_time(match.date),
                        style: const TextStyle(
                          color: Colors.white, fontSize: 11,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 0.2)),
                    ),
                  ),

                  // Top-right: LIVE badge
                  if (live)
                    Positioned(
                      top: 8, right: 8,
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 7, vertical: 4),
                        decoration: BoxDecoration(
                          color: Colors.red,
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: const Text('LIVE',
                          style: TextStyle(
                            color: Colors.white, fontSize: 10,
                            fontWeight: FontWeight.w900,
                            letterSpacing: 1.0)),
                      ),
                    )
                  else if (match.popular)
                    Positioned(
                      top: 8, right: 8,
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 7, vertical: 4),
                        decoration: BoxDecoration(
                          color: Colors.amber.withOpacity(0.9),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: const Icon(Icons.star_rounded,
                            color: Colors.white, size: 12),
                      ),
                    ),

                  // Bottom: two team logos side by side
                  Positioned(
                    bottom: 8, left: 0, right: 0,
                    child: Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        _SmallLogo(url: match.homeBadgeUrl),
                        Container(
                          margin: const EdgeInsets.symmetric(horizontal: 6),
                          child: const Text('vs',
                            style: TextStyle(
                              color: Colors.white70, fontSize: 10,
                              fontWeight: FontWeight.w700)),
                        ),
                        _SmallLogo(url: match.awayBadgeUrl),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ),

          // ── Title + category below card ──────────────────────────────────
          const SizedBox(height: 6),
          Text(
            match.homeTeam.isNotEmpty && match.awayTeam.isNotEmpty
                ? '${match.homeTeam} vs. ${match.awayTeam}'
                : match.title,
            maxLines: 2,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(
              color: Colors.white, fontSize: 12,
              fontWeight: FontWeight.w700, height: 1.35),
          ),
          const SizedBox(height: 2),
          Text(match.category,
            style: const TextStyle(
              color: AppTheme.textMuted, fontSize: 11,
              fontWeight: FontWeight.w500)),
        ],
      ),
    );
  }
}

// ─── Fallback card background ──────────────────────────────────────────────────

class _FallbackBg extends StatelessWidget {
  final FootballMatch match;
  const _FallbackBg({required this.match});

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: match.isLive
              ? [const Color(0xFF00280A), const Color(0xFF001005)]
              : [const Color(0xFF141414), const Color(0xFF0A0A0A)],
        ),
      ),
      child: Center(
        child: Icon(Icons.sports_soccer_rounded,
          color: match.isLive
              ? const Color(0xFF00C853).withOpacity(0.2)
              : Colors.white.withOpacity(0.06),
          size: 40),
      ),
    );
  }
}

// ─── Small team logo ───────────────────────────────────────────────────────────

class _SmallLogo extends StatelessWidget {
  final String? url;
  const _SmallLogo({this.url});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 40, height: 40,
      padding: const EdgeInsets.all(6),
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.08),
        shape: BoxShape.circle,
        border: Border.all(
            color: Colors.white.withOpacity(0.25), width: 1.2),
      ),
      child: ClipOval(
        child: url != null
            ? CachedNetworkImage(
                imageUrl: url!,
                fit: BoxFit.contain,
                placeholder: (_, __) => const Icon(Icons.sports_soccer_rounded,
                    color: Color(0xFF555555), size: 16),
                errorWidget: (_, __, ___) => const Icon(Icons.sports_soccer_rounded,
                    color: Color(0xFF555555), size: 16),
              )
            : const Icon(Icons.sports_soccer_rounded,
                color: Color(0xFF555555), size: 16),
      ),
    );
  }
}

// ─── Filter chip ───────────────────────────────────────────────────────────────

class _Chip extends StatelessWidget {
  final String label, value, current;
  final IconData? icon;
  final Color? iconColor;
  final bool pulse;
  final ValueChanged<String> onTap;
  const _Chip({required this.label, required this.value, required this.current,
      required this.onTap, this.icon, this.iconColor, this.pulse = false});

  @override
  Widget build(BuildContext context) {
    final sel = value == current;
    return GestureDetector(
      onTap: () => onTap(value),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 160),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
        decoration: BoxDecoration(
          color: sel ? const Color(0xFF00C853) : const Color(0xFF0E0E0E),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
              color: sel ? const Color(0xFF00C853) : const Color(0xFF1E1E1E)),
        ),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          if (pulse) ...[
            _PulseDot(color: sel ? Colors.white : const Color(0xFF00C853)),
            const SizedBox(width: 5),
          ] else if (icon != null) ...[
            Icon(icon, size: 11,
              color: sel ? Colors.white
                  : (iconColor ?? AppTheme.textMuted)),
            const SizedBox(width: 5),
          ],
          Text(label,
            style: TextStyle(
              color: sel ? Colors.white : AppTheme.textSecondary,
              fontSize: 12,
              fontWeight: sel ? FontWeight.w700 : FontWeight.w500)),
        ]),
      ),
    );
  }
}

// ── Pulsing live dot ───────────────────────────────────────────────────────────

class _PulseDot extends StatefulWidget {
  final Color color;
  const _PulseDot({required this.color});
  @override
  State<_PulseDot> createState() => _PulseDotState();
}

class _PulseDotState extends State<_PulseDot>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;
  late final Animation<double> _scale;
  late final Animation<double> _opacity;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 900),
    )..repeat(reverse: true);
    _scale   = Tween(begin: 0.6, end: 1.0).animate(
        CurvedAnimation(parent: _ctrl, curve: Curves.easeInOut));
    _opacity = Tween(begin: 0.4, end: 1.0).animate(
        CurvedAnimation(parent: _ctrl, curve: Curves.easeInOut));
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _ctrl,
      builder: (_, __) => Opacity(
        opacity: _opacity.value,
        child: Transform.scale(
          scale: _scale.value,
          child: Container(
            width: 8, height: 8,
            decoration: BoxDecoration(
              color: widget.color,
              shape: BoxShape.circle,
              boxShadow: [BoxShadow(
                color: widget.color.withOpacity(0.6),
                blurRadius: 4, spreadRadius: 1)],
            ),
          ),
        ),
      ),
    );
  }
}

// ─── Shimmer ───────────────────────────────────────────────────────────────────

class _Shimmer extends StatefulWidget {
  const _Shimmer();
  @override
  State<_Shimmer> createState() => _ShimmerState();
}

class _ShimmerState extends State<_Shimmer>
    with SingleTickerProviderStateMixin {
  late AnimationController _ctrl;
  late Animation<double>   _anim;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1200))
      ..repeat();
    _anim = Tween<double>(begin: -1.5, end: 1.5)
        .animate(CurvedAnimation(parent: _ctrl, curve: Curves.easeInOut));
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 12),
      child: Column(children: [
        // Fake date header
        Padding(
          padding: const EdgeInsets.only(top: 22, bottom: 12),
          child: AnimatedBuilder(
            animation: _anim,
            builder: (_, __) => Container(
              width: 120, height: 42,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(8),
                gradient: LinearGradient(
                  begin: Alignment(_anim.value - 1, 0),
                  end:   Alignment(_anim.value + 1, 0),
                  colors: const [Color(0xFF0A0A0A),Color(0xFF1A1A1A),Color(0xFF0A0A0A)],
                ),
              ),
            ),
          ),
        ),
        // Fake grid rows
        for (var r = 0; r < 3; r++) ...[
          Row(children: [
            for (var c = 0; c < 2; c++) ...[
              Expanded(
                child: AnimatedBuilder(
                  animation: _anim,
                  builder: (_, __) => AspectRatio(
                    aspectRatio: 1.25,
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(12),
                      child: Container(
                        decoration: BoxDecoration(
                          gradient: LinearGradient(
                            begin: Alignment(_anim.value - 1, 0),
                            end:   Alignment(_anim.value + 1, 0),
                            colors: const [Color(0xFF0A0A0A),Color(0xFF1A1A1A),Color(0xFF0A0A0A)],
                          ),
                        ),
                      ),
                    ),
                  ),
                ),
              ),
              if (c == 0) const SizedBox(width: 10),
            ],
          ]),
          const SizedBox(height: 14),
        ],
      ]),
    );
  }
}

// ─── Error view ────────────────────────────────────────────────────────────────

class _ErrorView extends StatelessWidget {
  final VoidCallback onRetry;
  const _ErrorView({required this.onRetry});
  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        const Icon(Icons.wifi_off_rounded,
            color: AppTheme.textMuted, size: 56),
        const SizedBox(height: 14),
        const Text('Could not load matches',
          style: TextStyle(color: Colors.white, fontSize: 17,
              fontWeight: FontWeight.w700)),
        const SizedBox(height: 6),
        const Text('Check your internet and try again',
          style: TextStyle(color: AppTheme.textMuted, fontSize: 13)),
        const SizedBox(height: 22),
        ElevatedButton.icon(
          style: ElevatedButton.styleFrom(
            backgroundColor: AppTheme.primary,
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
            shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(10)),
          ),
          icon: const Icon(Icons.refresh_rounded, color: Colors.white),
          label: const Text('Retry',
            style: TextStyle(color: Colors.white, fontWeight: FontWeight.w700)),
          onPressed: onRetry,
        ),
      ]),
    );
  }
}

// ─── Football Slider Banner ────────────────────────────────────────────────────

class _FbSliderBanner extends StatefulWidget {
  const _FbSliderBanner();
  @override
  State<_FbSliderBanner> createState() => _FbSliderBannerState();
}

class _FbSliderBannerState extends State<_FbSliderBanner>
    with WidgetsBindingObserver {
  static const _slides = [
    'assets/fb_slide1.webp',
    'assets/fb_slide2.jpg',
    'assets/fb_slide3.jpg',
    'assets/fb_slide4.jpg',
    'assets/fb_slide5.jpg',
    'assets/fb_slide6.jpg',
    'assets/fb_slide7.jpg',
    'assets/fb_slide8.jpg',
    'assets/fb_slide9.jpg',
    'assets/fb_slide10.jpg',
    'assets/fb_slide11.jpg',
  ];
  static const _startPage = 300;

  late final PageController _ctrl;
  Timer? _timer;
  int _current = _startPage;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _ctrl = PageController(initialPage: _startPage);
    _startTimer();
  }

  void _startTimer() {
    _timer?.cancel();
    _timer = Timer.periodic(const Duration(seconds: 4), (_) {
      if (!mounted) return;
      _ctrl.nextPage(
        duration: const Duration(milliseconds: 600),
        curve: Curves.easeInOut,
      );
    });
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.inactive) {
      _timer?.cancel();
    } else if (state == AppLifecycleState.resumed) {
      _startTimer();
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _timer?.cancel();
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final idx = _current % _slides.length;
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        SizedBox(
          height: 175,
          child: PageView.builder(
            controller: _ctrl,
            onPageChanged: (i) => setState(() => _current = i),
            itemBuilder: (_, index) {
              final asset = _slides[index % _slides.length];
              final isActive = (index % _slides.length) == idx;
              return AnimatedScale(
                scale: isActive ? 1.0 : 0.95,
                duration: const Duration(milliseconds: 350),
                curve: Curves.easeOut,
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 8),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(14),
                    child: Image.asset(
                      asset,
                      fit: BoxFit.cover,
                      width: double.infinity,
                    ),
                  ),
                ),
              );
            },
          ),
        ),
        const SizedBox(height: 8),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: List.generate(_slides.length, (i) {
            final active = i == idx;
            return AnimatedContainer(
              duration: const Duration(milliseconds: 300),
              margin: const EdgeInsets.symmetric(horizontal: 3),
              width: active ? 18 : 6,
              height: 6,
              decoration: BoxDecoration(
                color: active
                    ? const Color(0xFF00C853)
                    : Colors.white.withOpacity(0.3),
                borderRadius: BorderRadius.circular(3),
              ),
            );
          }),
        ),
        const SizedBox(height: 4),
      ],
    );
  }
}

// ─── Empty view ────────────────────────────────────────────────────────────────

class _EmptyView extends StatelessWidget {
  final String search;
  const _EmptyView({required this.search});
  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        const Icon(Icons.sports_soccer_rounded,
            color: AppTheme.textMuted, size: 60),
        const SizedBox(height: 14),
        Text(
          search.isNotEmpty
              ? 'No matches found for "$search"'
              : 'No matches right now',
          style: const TextStyle(color: Colors.white,
              fontSize: 16, fontWeight: FontWeight.w700),
          textAlign: TextAlign.center),
        const SizedBox(height: 6),
        const Text('Pull down to refresh or try a different filter',
          style: TextStyle(color: AppTheme.textMuted, fontSize: 13)),
      ]),
    );
  }
}
