import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:provider/provider.dart';
import 'package:url_launcher/url_launcher.dart';
import '../api/models.dart';
import '../providers/app_provider.dart';
import '../theme/app_theme.dart';
import '../screens/adult_home_screen.dart';
import '../screens/football_screen.dart';
import '../screens/home_screen.dart';
import '../screens/view_all_screen.dart';
import '../screens/search_screen.dart';
import '../screens/watchlist_screen.dart';
import '../screens/downloads_screen.dart';
import '../screens/continue_watching_screen.dart';
import '../screens/iptv_screen.dart';
import '../screens/settings_screen.dart';

// ── Shared app drawer ─────────────────────────────────────────────────────────
//
// Used by both HomeScreen (isUgandaRoot=false) and UgandaHomeScreen root
// (isUgandaRoot=true).
//
// Callbacks (all optional):
//   onTabSelect   – switches a HomeScreen tab (non-root only)
//   onUgandaTap   – opens Uganda screen (non-root only)
//   onSwitchToMain – switches from Uganda root back to main
// ─────────────────────────────────────────────────────────────────────────────

class AppDrawer extends StatelessWidget {
  final bool isUgandaRoot;
  final void Function(int)? onTabSelect;
  final VoidCallback? onUgandaTap;
  final VoidCallback? onSwitchToMain;

  const AppDrawer({
    super.key,
    this.isUgandaRoot = false,
    this.onTabSelect,
    this.onUgandaTap,
    this.onSwitchToMain,
  });

  void _nav(BuildContext context, int idx) {
    Navigator.pop(context);
    if (isUgandaRoot) {
      switch (idx) {
        case 0:
          // Navigate using the live drawer context — onSwitchToMain may carry
          // a stale splash-screen context that was replaced via pushReplacement.
          Navigator.push(context, MaterialPageRoute(builder: (_) => const HomeScreen()));
        case 1:
          Navigator.push(context, MaterialPageRoute(builder: (_) => const SearchScreen()));
        case 2:
          Navigator.push(context, MaterialPageRoute(builder: (_) => const WatchlistScreen()));
        case 3:
          Navigator.push(context, MaterialPageRoute(builder: (_) => const ContinueWatchingScreen()));
        case 4:
          Navigator.push(context, MaterialPageRoute(builder: (_) => const DownloadsScreen()));
      }
    } else {
      onTabSelect?.call(idx);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Drawer(
      backgroundColor: AppTheme.surface,
      child: SafeArea(
        child: Column(
          children: [
            // ── Header ────────────────────────────────────────────────────
            Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [AppTheme.primary.withOpacity(0.2), AppTheme.background],
                ),
              ),
              child: Row(
                children: [
                  const _AnimatedIconBox(),
                  Expanded(
                    child: Center(
                      child: FittedBox(
                        fit: BoxFit.scaleDown,
                        child: RichText(
                          maxLines: 1,
                          text: const TextSpan(
                            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w900),
                            children: [
                              TextSpan(text: 'Adiza ', style: TextStyle(color: Colors.white)),
                              TextSpan(text: 'Moviez', style: TextStyle(color: AppTheme.primary)),
                              TextSpan(text: ' Box', style: TextStyle(color: Colors.white)),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ),
                  const _AnimatedIconBox(),
                ],
              ),
            ),

            // ── Nav items ─────────────────────────────────────────────────
            Expanded(
              child: ListView(
                padding: const EdgeInsets.symmetric(vertical: 8),
                children: [
                  _DrawerTile(
                    icon: Icons.smart_display_rounded,
                    label: 'Moviez Box',
                    badge: 'MAIN',
                    onTap: () => _nav(context, 0),
                  ),
                  _DrawerTile(
                    icon: Icons.search_rounded,
                    label: 'Search',
                    onTap: () => _nav(context, 1),
                  ),
                  _DrawerTile(
                    icon: Icons.bookmark_rounded,
                    label: 'Watchlist',
                    onTap: () => _nav(context, 2),
                  ),
                  _DrawerTile(
                    icon: Icons.play_circle_outline_rounded,
                    label: 'Continue Watching',
                    onTap: () => _nav(context, 3),
                  ),
                  _DrawerTile(
                    icon: Icons.download_rounded,
                    label: 'Downloads',
                    onTap: () => _nav(context, 4),
                  ),
                  const Divider(color: AppTheme.border, height: 24, indent: 16, endIndent: 16),
                  _AdultDrawerTile(drawerContext: context),
                  _FootballDrawerTile(drawerContext: context),
                  _IptvDrawerTile(drawerContext: context),
                  _UgandaDrawerTile(
                    drawerContext: context,
                    isUgandaRoot: isUgandaRoot,
                    onTapOverride: isUgandaRoot ? onSwitchToMain : onUgandaTap,
                  ),
                  _DrawerTile(
                    icon: Icons.movie_outlined,
                    label: 'Movies',
                    badge: 'FILM',
                    onTap: () {
                      Navigator.pop(context);
                      Navigator.push(context, MaterialPageRoute(
                        builder: (_) => const ViewAllScreen(
                          title: 'Movies',
                          initialMovies: [],
                          sectionKey: 'movie',
                          subjectType: 1,
                        ),
                      ));
                    },
                  ),
                  _DrawerTile(
                    icon: Icons.tv_rounded,
                    label: 'TV Series',
                    badge: 'TV',
                    onTap: () {
                      Navigator.pop(context);
                      Navigator.push(context, MaterialPageRoute(
                        builder: (_) => const ViewAllScreen(
                          title: 'TV Series',
                          initialMovies: [],
                          sectionKey: 'series',
                          subjectType: 2,
                        ),
                      ));
                    },
                  ),
                  _DrawerTile(
                    icon: Icons.public_rounded,
                    label: 'Nollywood',
                    onTap: () {
                      final movies = isUgandaRoot ? const <Movie>[] : context.read<AppProvider>().nollywood;
                      Navigator.pop(context);
                      Navigator.push(context, MaterialPageRoute(
                        builder: (_) => ViewAllScreen(
                          title: 'Nollywood',
                          initialMovies: movies,
                          sectionKey: 'nollywood',
                        ),
                      ));
                    },
                  ),
                  _DrawerTile(
                    icon: Icons.flag_rounded,
                    label: 'K-Drama',
                    onTap: () {
                      final movies = isUgandaRoot ? const <Movie>[] : context.read<AppProvider>().kDrama;
                      Navigator.pop(context);
                      Navigator.push(context, MaterialPageRoute(
                        builder: (_) => ViewAllScreen(
                          title: 'K-Drama',
                          initialMovies: movies,
                          sectionKey: 'k-drama',
                        ),
                      ));
                    },
                  ),
                ],
              ),
            ),

            // ── Footer ────────────────────────────────────────────────────
            const Divider(color: AppTheme.border, height: 1),
            _DrawerTile(
              icon: Icons.settings_suggest_rounded,
              label: 'Settings & About',
              onTap: () {
                Navigator.pop(context);
                showModalBottomSheet(
                  context: context,
                  isScrollControlled: true,
                  useSafeArea: true,
                  backgroundColor: Colors.transparent,
                  builder: (_) => const SettingsModal(),
                );
              },
            ),
            _DrawerTile(
              icon: Icons.groups_rounded,
              label: 'Join our community',
              onTap: () {
                Navigator.pop(context);
                showModalBottomSheet(
                  context: context,
                  backgroundColor: Colors.black,
                  shape: const RoundedRectangleBorder(
                    borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
                  ),
                  builder: (_) => const _CommunitySheet(),
                );
              },
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
              child: Column(children: [
                const Text('Version 4.1.0', style: TextStyle(color: AppTheme.textMuted, fontSize: 11)),
                const SizedBox(height: 2),
                Text('Made by Matrix Dev', style: TextStyle(color: Colors.white.withOpacity(0.7), fontSize: 11)),
              ]),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Animated icon box (drawer header) ────────────────────────────────────────

class _AnimatedIconBox extends StatefulWidget {
  const _AnimatedIconBox();
  @override
  State<_AnimatedIconBox> createState() => _AnimatedIconBoxState();
}

class _AnimatedIconBoxState extends State<_AnimatedIconBox>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 2400))
      ..repeat();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    const double boxSize = 48;
    const rainbowHues = [0.0, 30.0, 60.0, 120.0, 210.0, 270.0, 320.0];
    final particles = [
      (dx: -22.0, dy: -22.0, delay: 0.00, size: 7.0, hue: rainbowHues[0]),
      (dx: 0.0, dy: -28.0, delay: 0.20, size: 9.0, hue: rainbowHues[1]),
      (dx: 22.0, dy: -22.0, delay: 0.40, size: 6.0, hue: rainbowHues[2]),
      (dx: -28.0, dy: 0.0, delay: 0.60, size: 7.0, hue: rainbowHues[3]),
      (dx: 28.0, dy: 0.0, delay: 0.80, size: 8.0, hue: rainbowHues[4]),
      (dx: -18.0, dy: 22.0, delay: 0.15, size: 6.0, hue: rainbowHues[5]),
      (dx: 18.0, dy: 22.0, delay: 0.55, size: 7.0, hue: rainbowHues[6]),
    ];
    return SizedBox(
      width: boxSize + 28,
      height: boxSize + 28,
      child: Stack(
        alignment: Alignment.center,
        clipBehavior: Clip.none,
        children: [
          Container(
            width: boxSize,
            height: boxSize,
            decoration: BoxDecoration(
              color: AppTheme.primary,
              borderRadius: BorderRadius.circular(10),
              boxShadow: [
                BoxShadow(
                    color: AppTheme.primary.withOpacity(0.5), blurRadius: 14)
              ],
            ),
            child: const Icon(Icons.smart_display_rounded,
                color: Colors.white, size: 28),
          ),
          ...particles.map((p) => AnimatedBuilder(
                animation: _ctrl,
                builder: (_, __) {
                  final t = (_ctrl.value + p.delay) % 1.0;
                  final opacity = t < 0.4
                      ? (t / 0.4).clamp(0.0, 1.0)
                      : t < 0.7
                          ? 1.0
                          : ((1.0 - t) / 0.3).clamp(0.0, 1.0);
                  final progress = Curves.easeOut.transform(t);
                  final hue = (p.hue + t * 360.0) % 360.0;
                  final color = HSVColor.fromAHSV(1.0, hue, 1.0, 1.0).toColor();
                  return Positioned(
                    left: (boxSize / 2 + 14) + p.dx * progress - p.size / 2,
                    top: (boxSize / 2 + 14) + p.dy * progress - p.size / 2,
                    child: Opacity(
                      opacity: opacity,
                      child: Icon(
                        Icons.star_rounded,
                        color: color,
                        size: p.size * (0.5 + progress * 0.5),
                      ),
                    ),
                  );
                },
              )),
        ],
      ),
    );
  }
}

// ── Generic drawer tile ───────────────────────────────────────────────────────

class _DrawerTile extends StatelessWidget {
  final IconData icon;
  final String label;
  final String? badge;
  final Color? iconColor;
  final VoidCallback? onTap;
  const _DrawerTile(
      {required this.icon,
      required this.label,
      this.badge,
      this.iconColor,
      this.onTap});

  @override
  Widget build(BuildContext context) {
    final Color ic = iconColor ?? AppTheme.textSecondary;
    return ListTile(
      leading: Icon(icon, color: ic, size: 22),
      title: Row(
        children: [
          Text(label,
              style: const TextStyle(
                  color: AppTheme.textPrimary,
                  fontSize: 14,
                  fontWeight: FontWeight.w500)),
          if (badge != null) ...[
            const SizedBox(width: 8),
            Container(
              padding:
                  const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: ic.withOpacity(0.15),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: ic.withOpacity(0.3)),
              ),
              child: Text(badge!,
                  style: TextStyle(
                      color: ic,
                      fontSize: 9,
                      fontWeight: FontWeight.w700)),
            ),
          ],
        ],
      ),
      onTap: onTap,
      dense: true,
    );
  }
}

// ── Adult content tile ────────────────────────────────────────────────────────

class _AdultDrawerTile extends StatelessWidget {
  final BuildContext drawerContext;
  const _AdultDrawerTile({required this.drawerContext});

  @override
  Widget build(BuildContext ctx) {
    return ListTile(
      leading: Container(
        width: 28,
        height: 28,
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(5),
        ),
        alignment: Alignment.center,
        child: const Text('18+',
            style: TextStyle(
                color: Color(0xFFE50914),
                fontSize: 9,
                fontWeight: FontWeight.w900,
                letterSpacing: -0.5)),
      ),
      title: const Text('Adult Content',
          style: TextStyle(
              color: Colors.white,
              fontSize: 14,
              fontWeight: FontWeight.w500)),
      onTap: () {
        Navigator.pop(drawerContext);
        Navigator.push(drawerContext,
            MaterialPageRoute(builder: (_) => const AdultHomeScreen()));
      },
      dense: true,
    );
  }
}

// ── Football tile ─────────────────────────────────────────────────────────────

class _FootballDrawerTile extends StatelessWidget {
  final BuildContext drawerContext;
  const _FootballDrawerTile({required this.drawerContext});

  @override
  Widget build(BuildContext ctx) {
    return ListTile(
      leading: Container(
        width: 28,
        height: 28,
        decoration: BoxDecoration(
          gradient: const LinearGradient(
            colors: [Color(0xFF00C853), Color(0xFF1B5E20)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(5),
        ),
        alignment: Alignment.center,
        child: const Icon(Icons.sports_soccer_rounded,
            color: Colors.white, size: 16),
      ),
      title: Row(
        children: [
          const Text('Live Football',
              style: TextStyle(
                  color: Colors.white,
                  fontSize: 14,
                  fontWeight: FontWeight.w500)),
          const SizedBox(width: 8),
          Container(
            padding:
                const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: const Color(0xFF00C853).withOpacity(0.2),
              borderRadius: BorderRadius.circular(4),
            ),
            child: const Text('LIVE',
                style: TextStyle(
                    color: Color(0xFF00C853),
                    fontSize: 9,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 0.5)),
          ),
        ],
      ),
      onTap: () {
        Navigator.pop(drawerContext);
        Navigator.push(drawerContext,
            MaterialPageRoute(builder: (_) => const FootballScreen()));
      },
      dense: true,
    );
  }
}

// ── IPTV / Live TV tile ───────────────────────────────────────────────────────

class _IptvDrawerTile extends StatelessWidget {
  final BuildContext drawerContext;
  const _IptvDrawerTile({required this.drawerContext});

  @override
  Widget build(BuildContext ctx) {
    return ListTile(
      leading: Container(
        width: 28,
        height: 28,
        decoration: BoxDecoration(
          gradient: const LinearGradient(
            colors: [Color(0xFF0052CC), Color(0xFF00B4D8)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(5),
        ),
        alignment: Alignment.center,
        child: const Text(
          'TV',
          style: TextStyle(color: Colors.white, fontSize: 9, fontWeight: FontWeight.w900, letterSpacing: -0.3),
        ),
      ),
      title: Row(
        children: [
          const Text('Live TV',
              style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w500)),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: Colors.red.withOpacity(0.15),
              borderRadius: BorderRadius.circular(4),
            ),
            child: const Text('LIVE',
                style: TextStyle(color: Colors.red, fontSize: 9, fontWeight: FontWeight.w800, letterSpacing: 0.5)),
          ),
        ],
      ),
      onTap: () {
        Navigator.pop(drawerContext);
        Navigator.push(drawerContext, MaterialPageRoute(builder: (_) => const IptvScreen()));
      },
      dense: true,
    );
  }
}

// ── Uganda Movies tile ────────────────────────────────────────────────────────
//
// When [isUgandaRoot] is true (Uganda is the default screen) and [onTapOverride]
// is provided, tapping this tile calls [onTapOverride] (switches to main Adiza
// content) instead of pushing UgandaHomeScreen.

class _UgandaDrawerTile extends StatelessWidget {
  final BuildContext drawerContext;
  final bool isUgandaRoot;
  final VoidCallback? onTapOverride;

  const _UgandaDrawerTile({
    required this.drawerContext,
    this.isUgandaRoot = false,
    this.onTapOverride,
  });

  @override
  Widget build(BuildContext ctx) {
    return ListTile(
      leading: Container(
        width: 28,
        height: 28,
        decoration: BoxDecoration(
          gradient: const LinearGradient(
            colors: [Color(0xFFFCDC04), Color(0xFF000000)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ),
          borderRadius: BorderRadius.circular(5),
        ),
        alignment: Alignment.center,
        child: const Text(
          'UG',
          style: TextStyle(
            color: Colors.white,
            fontSize: 9,
            fontWeight: FontWeight.w900,
            letterSpacing: -0.3,
            shadows: [Shadow(color: Colors.black, blurRadius: 4)],
          ),
        ),
      ),
      title: Row(
        children: [
          const Text('Uganda Cinema Plus',
              style: TextStyle(
                  color: Colors.white,
                  fontSize: 14,
                  fontWeight: FontWeight.w500)),
          const SizedBox(width: 8),
          Container(
            padding:
                const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: const Color(0xFFFCDC04).withOpacity(0.2),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(
              isUgandaRoot ? 'MAIN' : 'UG',
              style: TextStyle(
                  color: isUgandaRoot
                      ? AppTheme.primary
                      : const Color(0xFFFCDC04),
                  fontSize: 9,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 0.5),
            ),
          ),
        ],
      ),
      onTap: () {
        Navigator.pop(drawerContext);
        if (onTapOverride != null) {
          onTapOverride!();
        }
        // If not root and no override, caller didn't provide onTapOverride
        // (home_screen passes it directly via onUgandaTap → handled by AppDrawer)
      },
      dense: true,
    );
  }
}

// ── Community sheet ───────────────────────────────────────────────────────────

class _CommunitySheet extends StatelessWidget {
  static const _whatsappUrl =
      'https://chat.whatsapp.com/Iz8jA4DdW9qCQpR0YbMlnz';
  static const _telegramUrl = 'https://t.me/reversemoda';

  static const _whatsappSvg =
      '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">'
      '<path fill="#25D366" d="M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893a11.821 11.821 0 00-3.48-8.413z"/>'
      '</svg>';

  static const _telegramSvg =
      '<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">'
      '<path fill="#2AABEE" d="M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z"/>'
      '</svg>';

  const _CommunitySheet();

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 0, 20, 36),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 12),
          Container(
              width: 40,
              height: 4,
              decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(2))),
          const SizedBox(height: 20),
          const Icon(Icons.groups_rounded, color: AppTheme.primary, size: 36),
          const SizedBox(height: 10),
          const Text('Join Our Community',
              style: TextStyle(
                  color: Colors.white,
                  fontSize: 18,
                  fontWeight: FontWeight.w800)),
          const SizedBox(height: 6),
          const Text('Connect with us on WhatsApp and Telegram',
              style: TextStyle(color: Colors.white54, fontSize: 13)),
          const SizedBox(height: 24),
          Row(
            children: [
              Expanded(
                  child: _DrawerSocialBtn(
                      svgString: _whatsappSvg,
                      label: 'WhatsApp',
                      color: const Color(0xFF25D366),
                      url: _whatsappUrl)),
              const SizedBox(width: 12),
              Expanded(
                  child: _DrawerSocialBtn(
                      svgString: _telegramSvg,
                      label: 'Telegram',
                      color: const Color(0xFF2AABEE),
                      url: _telegramUrl)),
            ],
          ),
        ],
      ),
    );
  }
}

class _DrawerSocialBtn extends StatelessWidget {
  final String svgString;
  final String label;
  final Color color;
  final String url;
  const _DrawerSocialBtn(
      {required this.svgString,
      required this.label,
      required this.color,
      required this.url});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () async {
        final uri = Uri.parse(url);
        if (await canLaunchUrl(uri)) {
          await launchUrl(uri, mode: LaunchMode.externalApplication);
        }
      },
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 16),
        decoration: BoxDecoration(
          color: color.withOpacity(0.12),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: color.withOpacity(0.5), width: 1.5),
          boxShadow: [
            BoxShadow(
                color: color.withOpacity(0.15),
                blurRadius: 10,
                offset: const Offset(0, 4))
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 52,
              height: 52,
              decoration: BoxDecoration(
                  color: color,
                  shape: BoxShape.circle,
                  boxShadow: [
                    BoxShadow(color: color.withOpacity(0.4), blurRadius: 12)
                  ]),
              padding: const EdgeInsets.all(12),
              child: SvgPicture.string(svgString,
                  width: 28,
                  height: 28,
                  colorFilter: const ColorFilter.mode(
                      Colors.white, BlendMode.srcIn)),
            ),
            const SizedBox(height: 10),
            Text(label,
                style: TextStyle(
                    color: color,
                    fontSize: 13,
                    fontWeight: FontWeight.w800)),
            const SizedBox(height: 2),
            Text('Tap to join',
                style: TextStyle(
                    color: color.withOpacity(0.6), fontSize: 11)),
          ],
        ),
      ),
    );
  }
}
