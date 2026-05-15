import 'dart:io';
import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';
import '../theme/app_theme.dart';
import 'home_screen.dart';
import 'uganda_home_screen.dart';

class SettingsModal extends StatelessWidget {
  const SettingsModal({super.key});

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.92,
      minChildSize: 0.5,
      maxChildSize: 0.97,
      builder: (_, controller) => Container(
        decoration: const BoxDecoration(
          color: AppTheme.background,
          borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
        ),
        child: Column(
          children: [
            const SizedBox(height: 10),
            Container(
              width: 40, height: 4,
              decoration: BoxDecoration(color: AppTheme.textMuted.withOpacity(0.4), borderRadius: BorderRadius.circular(2)),
            ),
            const SizedBox(height: 12),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Row(
                children: [
                  const Text('Settings & About', style: TextStyle(color: AppTheme.textPrimary, fontSize: 18, fontWeight: FontWeight.w800)),
                  const Spacer(),
                  GestureDetector(
                    onTap: () => Navigator.pop(context),
                    child: Container(
                      padding: const EdgeInsets.all(6),
                      decoration: BoxDecoration(color: AppTheme.card, shape: BoxShape.circle),
                      child: const Icon(Icons.close_rounded, color: AppTheme.textMuted, size: 18),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 8),
            Expanded(
              child: ListView(
                controller: controller,
                padding: const EdgeInsets.symmetric(vertical: 4),
                children: [
                  _sectionHeader('Preferences'),
                  const _DefaultScreenTile(),
                  _sectionDivider(),
                  _sectionHeader('Developer'),
                  _tile(context, Icons.terminal_rounded, 'Meet the Developer', 'Matrix Dev · ReversalX', iconColor: AppTheme.accent, onTap: () => _showDeveloperSheet(context)),
                  _sectionDivider(),
                  FutureBuilder<PackageInfo>(
                    future: PackageInfo.fromPlatform(),
                    builder: (ctx, snap) {
                      final ver = snap.data?.version ?? '…';
                      return _tile(ctx, Icons.info_outline_rounded, 'About Adiza Moviez Box',
                          'Version $ver — Premium streaming app', onTap: () => _showAbout(context));
                    },
                  ),
                  _sectionDivider(),
                  _sectionHeader('Storage'),
                  const _CacheStorageTile(),
                  _sectionDivider(),
                  _sectionHeader('Support'),
                  _tile(context, Icons.bug_report_outlined, 'Report a Bug', 'Message us on Telegram', iconColor: Colors.orange, onTap: () => _reportBug(context)),
                  _tile(context, Icons.help_outline_rounded, 'FAQ & Help', 'Common questions answered', onTap: () => _showFAQ(context)),
                  _sectionDivider(),
                  _sectionHeader('Legal'),
                  _tile(context, Icons.shield_outlined, 'Privacy Policy', 'How we handle your data', iconColor: Colors.blue, onTap: () => _showPrivacyPolicy(context)),
                  _tile(context, Icons.gavel_rounded, 'Terms of Service', 'Usage guidelines and terms', iconColor: Colors.green, onTap: () => _showTerms(context)),
                  _tile(context, Icons.info_outline_rounded, 'Disclaimer', 'Content licensing information', iconColor: Colors.purple, onTap: () => _showDisclaimer(context)),
                  const SizedBox(height: 32),
                  const Center(
                    child: Text('Made with passion by ReversalX', style: TextStyle(color: AppTheme.textMuted, fontSize: 11)),
                  ),
                  const SizedBox(height: 24),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _sectionHeader(String title) => Padding(
    padding: const EdgeInsets.fromLTRB(18, 14, 18, 6),
    child: Text(title.toUpperCase(), style: const TextStyle(color: AppTheme.textMuted, fontSize: 10, fontWeight: FontWeight.w700, letterSpacing: 1.4)),
  );

  Widget _sectionDivider() => const Divider(color: AppTheme.border, height: 1, indent: 16, endIndent: 16);

  Widget _tile(BuildContext context, IconData icon, String title, String subtitle, {VoidCallback? onTap, Color? iconColor}) {
    return ListTile(
      leading: Container(
        padding: const EdgeInsets.all(8),
        decoration: BoxDecoration(
          color: (iconColor ?? AppTheme.primary).withOpacity(0.12),
          borderRadius: BorderRadius.circular(10),
        ),
        child: Icon(icon, color: iconColor ?? AppTheme.primary, size: 20),
      ),
      title: Text(title, style: const TextStyle(color: AppTheme.textPrimary, fontSize: 14, fontWeight: FontWeight.w500)),
      subtitle: Text(subtitle, style: const TextStyle(color: AppTheme.textMuted, fontSize: 12)),
      trailing: const Icon(Icons.chevron_right_rounded, color: AppTheme.textMuted, size: 18),
      onTap: onTap,
    );
  }

  void _showDeveloperSheet(BuildContext context) {
    showModalBottomSheet(
      context: context,
      backgroundColor: AppTheme.surface,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(24))),
      builder: (_) => Padding(
        padding: const EdgeInsets.fromLTRB(24, 16, 24, 40),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(width: 36, height: 4, decoration: BoxDecoration(color: AppTheme.border, borderRadius: BorderRadius.circular(2))),
            const SizedBox(height: 24),
            ClipRRect(
              borderRadius: BorderRadius.circular(16),
              child: Image.asset(
                'assets/developer.jpg',
                width: 110, height: 110,
                fit: BoxFit.cover,
                errorBuilder: (_, __, ___) => Container(
                  width: 110, height: 110,
                  decoration: BoxDecoration(color: AppTheme.card, borderRadius: BorderRadius.circular(16)),
                  child: const Icon(Icons.person_rounded, color: AppTheme.accent, size: 50),
                ),
              ),
            ),
            const SizedBox(height: 14),
            const Text('ReversalX', style: TextStyle(color: AppTheme.textPrimary, fontSize: 18, fontWeight: FontWeight.w800)),
            const SizedBox(height: 6),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
              decoration: BoxDecoration(color: AppTheme.accent.withOpacity(0.12), borderRadius: BorderRadius.circular(20), border: Border.all(color: AppTheme.accent.withOpacity(0.35))),
              child: const Text('Matrix Dev', style: TextStyle(color: AppTheme.accent, fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 0.5)),
            ),
            const SizedBox(height: 16),
            const Text(
              'Full-stack developer specialising in API engineering, web scraping, mobile apps & custom streaming platforms.\n\nCreator of Adiza Moviez Box.',
              textAlign: TextAlign.center,
              style: TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.6),
            ),
            const SizedBox(height: 20),
            Wrap(
              spacing: 8, runSpacing: 8,
              alignment: WrapAlignment.center,
              children: const [_Skill('Flutter'), _Skill('APIs'), _Skill('Web Scraping'), _Skill('Streaming'), _Skill('Bots')],
            ),
            const SizedBox(height: 24),
            SizedBox(
              width: double.infinity,
              child: OutlinedButton(
                onPressed: () async {
                  final uri = Uri.parse('https://t.me/matrix99bot');
                  if (await canLaunchUrl(uri)) launchUrl(uri, mode: LaunchMode.externalApplication);
                },
                style: OutlinedButton.styleFrom(
                  foregroundColor: AppTheme.accent,
                  side: const BorderSide(color: AppTheme.accent, width: 1.2),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                ),
                child: const Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Icon(Icons.telegram, size: 18),
                    SizedBox(width: 8),
                    Text('Contact on Telegram'),
                    SizedBox(width: 8),
                    Icon(Icons.telegram, size: 18),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showAbout(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (_) => const _AboutSheet(),
    );
  }

  void _showPrivacyPolicy(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (_) => const _PrivacySheet(),
    );
  }

  void _showTerms(BuildContext context) => _showInfoSheet(context, 'Terms of Service', [
    _InfoItem('Use', 'This app is for personal, non-commercial use only.'),
    _InfoItem('Content', 'All content is provided by third-party APIs. We do not host any media files.'),
    _InfoItem('Copyright', 'All movie and TV content is owned by their respective copyright holders.'),
    _InfoItem('Disclaimer', 'This app is not affiliated with any movie studio or streaming platform.'),
  ]);

  void _showDisclaimer(BuildContext context) => _showInfoSheet(context, 'Disclaimer', [
    _InfoItem('Notice', 'Adiza Moviez Box is an independent app that aggregates publicly available streaming content. We do not host or distribute any media files.'),
    _InfoItem('Rights', 'All content rights belong to their respective owners.'),
    _InfoItem('DMCA', 'For DMCA or copyright concerns, contact us via Report a Bug.'),
  ]);

  void _showFAQ(BuildContext context) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      useSafeArea: true,
      builder: (_) => const _FAQSheet(),
    );
  }

  void _showInfoSheet(BuildContext context, String title, List<_InfoItem> items) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: AppTheme.surface,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (_) => DraggableScrollableSheet(
        initialChildSize: 0.6,
        minChildSize: 0.3,
        maxChildSize: 0.9,
        expand: false,
        builder: (_, ctrl) => Column(
          children: [
            const SizedBox(height: 10),
            Container(width: 40, height: 4, decoration: BoxDecoration(color: AppTheme.textMuted.withOpacity(0.4), borderRadius: BorderRadius.circular(2))),
            const SizedBox(height: 14),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Text(title, style: const TextStyle(color: AppTheme.textPrimary, fontSize: 16, fontWeight: FontWeight.w800)),
            ),
            const SizedBox(height: 12),
            Expanded(
              child: ListView.separated(
                controller: ctrl,
                padding: const EdgeInsets.fromLTRB(20, 4, 20, 32),
                itemCount: items.length,
                separatorBuilder: (_, __) => const SizedBox(height: 14),
                itemBuilder: (_, i) => Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(items[i].title, style: const TextStyle(color: AppTheme.primary, fontSize: 13, fontWeight: FontWeight.w700)),
                    const SizedBox(height: 4),
                    Text(items[i].body, style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.55)),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _reportBug(BuildContext context) async {
    final uri = Uri.parse('https://t.me/matrix99bot');
    try {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    } catch (_) {
      try { await launchUrl(uri, mode: LaunchMode.inAppBrowserView); } catch (_) {}
    }
  }

}

class _InfoItem {
  final String title;
  final String body;
  const _InfoItem(this.title, this.body);
}


class _Skill extends StatelessWidget {
  final String label;
  const _Skill(this.label);

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: AppTheme.shimmerBase,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(label, style: const TextStyle(color: AppTheme.textSecondary, fontSize: 10, fontWeight: FontWeight.w600)),
    );
  }
}


// ══════════════════════════════════════════════════════════════════════════════
// Cache & Storage Tile
// ══════════════════════════════════════════════════════════════════════════════
class _CacheStorageTile extends StatefulWidget {
  const _CacheStorageTile();

  @override
  State<_CacheStorageTile> createState() => _CacheStorageTileState();
}

class _CacheStorageTileState extends State<_CacheStorageTile> {
  String _cacheSize = 'Calculating…';
  bool _isClearing = false;
  bool _isCalculating = true;

  @override
  void initState() {
    super.initState();
    _calculateCacheSize();
  }

  Future<void> _calculateCacheSize() async {
    if (mounted) setState(() => _isCalculating = true);
    try {
      int total = 0;
      // Temp cache (CachedNetworkImage stores here)
      try {
        final tmp = await getTemporaryDirectory();
        total += await _dirSize(tmp);
      } catch (_) {}
      // App support cache
      try {
        final support = await getApplicationSupportDirectory();
        total += await _dirSize(support);
      } catch (_) {}
      if (mounted) setState(() {
        _cacheSize = _formatSize(total);
        _isCalculating = false;
      });
    } catch (_) {
      if (mounted) setState(() {
        _cacheSize = '0 B';
        _isCalculating = false;
      });
    }
  }

  Future<int> _dirSize(Directory dir) async {
    int total = 0;
    try {
      await for (final entity in dir.list(recursive: true, followLinks: false)) {
        if (entity is File) {
          try { total += await entity.length(); } catch (_) {}
        }
      }
    } catch (_) {}
    return total;
  }

  String _formatSize(int bytes) {
    if (bytes <= 0) return '0 B';
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  Future<void> _clearCache(BuildContext ctx) async {
    // Confirm
    final confirmed = await showDialog<bool>(
      context: ctx,
      builder: (_) => AlertDialog(
        backgroundColor: AppTheme.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(18)),
        title: const Text('Clear Cache?', style: TextStyle(color: Colors.white, fontWeight: FontWeight.w800, fontSize: 16)),
        content: const Text(
          'This will remove all cached images and temporary files.\nYou may notice slightly longer load times until content re-caches.',
          style: TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.5),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(_, false),
            child: const Text('Cancel', style: TextStyle(color: AppTheme.textMuted)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(_, true),
            child: const Text('Clear', style: TextStyle(color: Colors.orange, fontWeight: FontWeight.w700)),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() => _isClearing = true);
    try {
      // Clear Flutter's in-memory image cache
      PaintingBinding.instance.imageCache.clear();
      PaintingBinding.instance.imageCache.clearLiveImages();

      // Wipe temp directory contents
      try {
        final tmp = await getTemporaryDirectory();
        for (final entity in tmp.listSync(recursive: false)) {
          try {
            if (entity is File) entity.deleteSync();
            else if (entity is Directory) entity.deleteSync(recursive: true);
          } catch (_) {}
        }
      } catch (_) {}

      // Wipe app support cache directory
      try {
        final support = await getApplicationSupportDirectory();
        final cacheDir = Directory('${support.path}/cache');
        if (cacheDir.existsSync()) cacheDir.deleteSync(recursive: true);
      } catch (_) {}

      await _calculateCacheSize();

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: const Row(children: [
            Icon(Icons.check_circle_rounded, color: Colors.white, size: 18),
            SizedBox(width: 10),
            Text('Cache cleared successfully', style: TextStyle(fontWeight: FontWeight.w600)),
          ]),
          backgroundColor: const Color(0xFF1DB954),
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          margin: const EdgeInsets.all(16),
          duration: const Duration(seconds: 2),
        ));
      }
    } catch (_) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: const Text('Failed to clear cache'),
          backgroundColor: Colors.red.shade700,
          behavior: SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          margin: const EdgeInsets.all(16),
        ));
      }
    } finally {
      if (mounted) setState(() => _isClearing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.fromLTRB(16, 4, 16, 4),
      child: Container(
        decoration: BoxDecoration(
          color: AppTheme.card,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: Colors.white.withOpacity(0.05)),
        ),
        child: Column(
          children: [
            // Cache row
            ListTile(
              contentPadding: const EdgeInsets.fromLTRB(14, 4, 14, 4),
              leading: Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.orange.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(Icons.storage_rounded, color: Colors.orange, size: 20),
              ),
              title: const Text('Cached Data', style: TextStyle(color: AppTheme.textPrimary, fontSize: 14, fontWeight: FontWeight.w600)),
              subtitle: Text(
                _isCalculating ? 'Calculating…' : _cacheSize,
                style: TextStyle(
                  color: _isCalculating ? AppTheme.textMuted : Colors.orange.shade300,
                  fontSize: 12,
                  fontWeight: FontWeight.w500,
                ),
              ),
              trailing: _isClearing
                  ? const SizedBox(
                      width: 22, height: 22,
                      child: CircularProgressIndicator(strokeWidth: 2.5, color: Colors.orange))
                  : GestureDetector(
                      onTap: () => _clearCache(context),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
                        decoration: BoxDecoration(
                          color: Colors.orange.withOpacity(0.15),
                          borderRadius: BorderRadius.circular(10),
                          border: Border.all(color: Colors.orange.withOpacity(0.5)),
                        ),
                        child: const Text('Clear', style: TextStyle(
                          color: Colors.orange,
                          fontSize: 12,
                          fontWeight: FontWeight.w700,
                        )),
                      ),
                    ),
            ),
            // Divider
            const Divider(height: 1, color: Colors.white10, indent: 14, endIndent: 14),
            // Image cache row
            ListTile(
              contentPadding: const EdgeInsets.fromLTRB(14, 2, 14, 4),
              leading: Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: Colors.blue.withOpacity(0.10),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: const Icon(Icons.image_outlined, color: Colors.blue, size: 20),
              ),
              title: const Text('Image Cache', style: TextStyle(color: AppTheme.textPrimary, fontSize: 14, fontWeight: FontWeight.w600)),
              subtitle: Text(
                '${PaintingBinding.instance.imageCache.currentSize} images in memory',
                style: const TextStyle(color: AppTheme.textMuted, fontSize: 12),
              ),
              trailing: GestureDetector(
                onTap: () {
                  PaintingBinding.instance.imageCache.clear();
                  PaintingBinding.instance.imageCache.clearLiveImages();
                  setState(() {});
                  ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                    content: const Row(children: [
                      Icon(Icons.check_circle_rounded, color: Colors.white, size: 18),
                      SizedBox(width: 10),
                      Text('Image cache cleared', style: TextStyle(fontWeight: FontWeight.w600)),
                    ]),
                    backgroundColor: Colors.blue.shade700,
                    behavior: SnackBarBehavior.floating,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                    margin: const EdgeInsets.all(16),
                    duration: const Duration(seconds: 2),
                  ));
                },
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
                  decoration: BoxDecoration(
                    color: Colors.blue.withOpacity(0.10),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: Colors.blue.withOpacity(0.4)),
                  ),
                  child: const Text('Clear', style: TextStyle(color: Colors.blue, fontSize: 12, fontWeight: FontWeight.w700)),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ── About Sheet ──────────────────────────────────────────────────────────────
class _AboutSheet extends StatefulWidget {
  const _AboutSheet();
  @override
  State<_AboutSheet> createState() => _AboutSheetState();
}

class _AboutSheetState extends State<_AboutSheet> {
  String _version = '…';

  @override
  void initState() {
    super.initState();
    PackageInfo.fromPlatform().then((info) {
      if (mounted) setState(() => _version = info.version);
    });
  }

  // ignore: unused_field
  static const _whatsapp = 'https://chat.whatsapp.com/Iz8jA4DdW9qCQpR0YbMlnz';
  // ignore: unused_field
  static const _telegram = 'https://t.me/reversemoda';

  // ignore: unused_element
  Future<void> _openUrl(String url) async {
    final uri = Uri.parse(url);
    try {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.88,
      minChildSize: 0.55,
      maxChildSize: 0.97,
      expand: false,
      builder: (_, ctrl) => Container(
        decoration: const BoxDecoration(
          color: Color(0xFF000000),
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        child: ListView(
          controller: ctrl,
          padding: EdgeInsets.zero,
          children: [
            // ── Handle ──────────────────────────────────────────────────
            const SizedBox(height: 12),
            Center(child: Container(
              width: 40, height: 4,
              decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2)),
            )),
            const SizedBox(height: 24),

            // ── Header / Logo ────────────────────────────────────────────
            Container(
              margin: const EdgeInsets.symmetric(horizontal: 20),
              padding: const EdgeInsets.all(24),
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [Color(0xFF1A1A35), Color(0xFF0F0F20)],
                ),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: AppTheme.primary.withOpacity(0.25)),
              ),
              child: Column(children: [
                Container(
                  width: 80, height: 80,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(20),
                    boxShadow: [BoxShadow(color: AppTheme.primary.withOpacity(0.35), blurRadius: 20, spreadRadius: 2)],
                  ),
                  clipBehavior: Clip.antiAlias,
                  child: Image.asset('assets/icons/icon_default.png', fit: BoxFit.cover,
                      errorBuilder: (_, __, ___) => Container(
                        color: AppTheme.primary.withOpacity(0.15),
                        child: const Icon(Icons.movie_rounded, color: AppTheme.primary, size: 40),
                      )),
                ),
                const SizedBox(height: 16),
                const Text('Adiza Moviez Box',
                    style: TextStyle(color: Colors.white, fontSize: 22, fontWeight: FontWeight.w900, letterSpacing: 0.3)),
                const SizedBox(height: 4),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                  decoration: BoxDecoration(
                    color: AppTheme.primary.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(color: AppTheme.primary.withOpacity(0.3)),
                  ),
                  child: Text('Version $_version  •  Universal (32 & 64-bit)',
                      style: const TextStyle(color: AppTheme.primary, fontSize: 11.5, fontWeight: FontWeight.w600)),
                ),
                const SizedBox(height: 12),
                const Text(
                  'Your premium gateway to unlimited streaming — Nollywood, Hollywood, K-Drama, Anime, SA Drama and more, all in HD.',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.55),
                ),
              ]),
            ),

            const SizedBox(height: 20),

            // ── Developer ────────────────────────────────────────────────
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const _SectionLabel(label: 'DEVELOPER'),
                const SizedBox(height: 10),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: AppTheme.card,
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: AppTheme.border),
                  ),
                  child: Row(children: [
                    Container(
                      width: 46, height: 46,
                      decoration: BoxDecoration(
                        gradient: LinearGradient(
                          colors: [AppTheme.primary, AppTheme.primary.withOpacity(0.6)],
                        ),
                        shape: BoxShape.circle,
                      ),
                      child: const Center(child: Text('M', style: TextStyle(color: Colors.white, fontSize: 20, fontWeight: FontWeight.w900))),
                    ),
                    const SizedBox(width: 14),
                    const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text('Matrix Dev', style: TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.w700)),
                      SizedBox(height: 2),
                      Text('Mobile Software Engineer · Verified Creator', style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
                    ])),
                    const Icon(Icons.verified_rounded, color: AppTheme.primary, size: 20),
                  ]),
                ),
              ]),
            ),

            const SizedBox(height: 20),

            // ── Features ─────────────────────────────────────────────────
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const _SectionLabel(label: 'FEATURES'),
                const SizedBox(height: 10),
                Wrap(spacing: 10, runSpacing: 10, children: const [
                  _FeatureChip(icon: Icons.hd_rounded, label: 'HD Streaming'),
                  _FeatureChip(icon: Icons.subtitles_rounded, label: 'Subtitles'),
                  _FeatureChip(icon: Icons.download_rounded, label: 'Downloads'),
                  _FeatureChip(icon: Icons.bookmark_rounded, label: 'Watchlist'),
                  _FeatureChip(icon: Icons.history_rounded, label: 'Watch History'),
                  _FeatureChip(icon: Icons.play_circle_outline_rounded, label: 'Resume'),
                  _FeatureChip(icon: Icons.language_rounded, label: 'Multi-Language'),
                  _FeatureChip(icon: Icons.speed_rounded, label: 'Playback Speed'),
                ]),
              ]),
            ),

            const SizedBox(height: 20),

            // ── Legal ────────────────────────────────────────────────────
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 20),
              child: Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: AppTheme.card,
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: AppTheme.border),
                ),
                child: Row(children: [
                  const Icon(Icons.info_outline_rounded, color: AppTheme.textMuted, size: 16),
                  const SizedBox(width: 10),
                  Expanded(child: Text(
                    'All movie and TV content is sourced externally. Adiza Moviez Box does not host any media files. All rights belong to their respective owners.',
                    style: const TextStyle(color: AppTheme.textMuted, fontSize: 11, height: 1.55),
                  )),
                ]),
              ),
            ),

            const SizedBox(height: 32),

            // ── Footer ───────────────────────────────────────────────────
            Center(child: Column(children: [
              Text('© ${DateTime.now().year} Matrix Dev',
                  style: const TextStyle(color: AppTheme.textMuted, fontSize: 12)),
              const SizedBox(height: 4),
              const Text('Made with ♥ for African streaming',
                  style: TextStyle(color: AppTheme.textMuted, fontSize: 11)),
            ])),
            const SizedBox(height: 24),
          ],
        ),
      ),
    );
  }
}

// ── Privacy Policy Sheet ─────────────────────────────────────────────────────
class _PrivacySheet extends StatelessWidget {
  const _PrivacySheet();

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.88,
      minChildSize: 0.5,
      maxChildSize: 0.97,
      expand: false,
      builder: (_, ctrl) => Container(
        decoration: const BoxDecoration(
          color: Color(0xFF000000),
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        child: ListView(
          controller: ctrl,
          padding: EdgeInsets.fromLTRB(20, 0, 20, MediaQuery.of(context).viewPadding.bottom + 24),
          children: [
            const SizedBox(height: 12),
            Center(child: Container(
              width: 40, height: 4,
              decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2)),
            )),
            const SizedBox(height: 20),

            // Header
            Row(children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: AppTheme.primary.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Icon(Icons.privacy_tip_rounded, color: AppTheme.primary, size: 22),
              ),
              const SizedBox(width: 14),
              const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('Privacy Policy', style: TextStyle(color: Colors.white, fontSize: 20, fontWeight: FontWeight.w900)),
                Text('Last updated: March 2026', style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
              ])),
            ]),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppTheme.primary.withOpacity(0.06),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppTheme.primary.withOpacity(0.15)),
              ),
              child: const Text(
                'Your privacy matters to us. This policy explains clearly and transparently how Adiza Moviez Box handles information.',
                style: TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.55),
              ),
            ),

            const SizedBox(height: 24),
            const _PrivacySection(
              icon: Icons.person_off_rounded,
              color: Color(0xFF4AADF4),
              title: '1. No Personal Data Collected',
              body: 'We do not collect, store, or process any personally identifiable information. You do not need to create an account or provide any personal details to use this app.\n\nYour watchlist, download history, and watch progress are stored exclusively on your device using local storage (SharedPreferences). This data never leaves your device.',
            ),
            const _PrivacySection(
              icon: Icons.wifi_rounded,
              color: Color(0xFF7B61FF),
              title: '2. Network Requests',
              body: 'The app connects to external content servers to retrieve titles, metadata, streaming links, and subtitle files. These requests do not include any user credentials or identifiers.\n\nCertain requests are securely routed through a relay service to ensure reliability. No personal data is included in any of these requests.',
            ),
            const _PrivacySection(
              icon: Icons.folder_rounded,
              color: Color(0xFFFFA726),
              title: '3. Local Storage & Downloads',
              body: 'Downloaded video files are saved directly to your device\'s gallery and Downloads folder, where they are accessible like any other media file. You retain full control over these files and can delete them at any time from within the app.\n\nNo files are uploaded to any server.',
            ),
            const _PrivacySection(
              icon: Icons.cookie_rounded,
              color: Color(0xFF66BB6A),
              title: '4. Session Cookies',
              body: 'Temporary session cookies may be used when accessing content servers. These are standard HTTP session tokens required for content access and are not used to identify or track individual users.',
            ),
            const _PrivacySection(
              icon: Icons.share_rounded,
              color: Color(0xFFEC407A),
              title: '5. Third-Party Services',
              body: 'Content is sourced from external providers. We do not control the privacy or data practices of those external services. All movie and TV content rights belong to their respective copyright holders.\n\nAdiza Moviez Box does not host, store, or distribute any media files.',
            ),
            const _PrivacySection(
              icon: Icons.child_care_rounded,
              color: Color(0xFFAB47BC),
              title: '6. Children\'s Privacy',
              body: 'This app is not directed at children under the age of 13. We do not knowingly collect any information from children. If you believe a child has used this app, no personal data would have been collected.',
            ),
            const _PrivacySection(
              icon: Icons.update_rounded,
              color: Color(0xFF26C6DA),
              title: '7. Changes to This Policy',
              body: 'We may update this Privacy Policy from time to time. Any changes will be reflected in the app update release notes. Continued use of the app after changes constitutes acceptance of the updated policy.',
            ),
            const _PrivacySection(
              icon: Icons.contact_support_rounded,
              color: AppTheme.primary,
              title: '8. Contact',
              body: 'For any privacy-related questions or DMCA concerns, use the "Report a Bug" option in the Settings menu to reach us directly.\n\nWe take all concerns seriously and respond promptly.',
            ),

            const SizedBox(height: 24),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppTheme.card,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppTheme.border),
              ),
              child: const Row(children: [
                Icon(Icons.verified_user_rounded, color: AppTheme.primary, size: 16),
                SizedBox(width: 10),
                Expanded(child: Text(
                  'By using Adiza Moviez Box, you acknowledge that you have read and understood this Privacy Policy.',
                  style: TextStyle(color: AppTheme.textMuted, fontSize: 11.5, height: 1.5),
                )),
              ]),
            ),
            const SizedBox(height: 32),
          ],
        ),
      ),
    );
  }
}

class _SectionLabel extends StatelessWidget {
  final String label;
  const _SectionLabel({required this.label});
  @override
  Widget build(BuildContext context) => Text(label,
      style: const TextStyle(color: AppTheme.textMuted, fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 1.1));
}

class _FeatureChip extends StatelessWidget {
  final IconData icon;
  final String label;
  const _FeatureChip({required this.icon, required this.label});
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
    decoration: BoxDecoration(
      color: AppTheme.card,
      borderRadius: BorderRadius.circular(20),
      border: Border.all(color: AppTheme.border),
    ),
    child: Row(mainAxisSize: MainAxisSize.min, children: [
      Icon(icon, color: AppTheme.primary, size: 14),
      const SizedBox(width: 6),
      Text(label, style: const TextStyle(color: AppTheme.textPrimary, fontSize: 12, fontWeight: FontWeight.w600)),
    ]),
  );
}

// ignore: unused_element
class _AboutCommunityCard extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String title;
  final String subtitle;
  final VoidCallback onTap;
  const _AboutCommunityCard({required this.icon, required this.color, required this.title, required this.subtitle, required this.onTap});
  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: color.withOpacity(0.07),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: color.withOpacity(0.25)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(color: color.withOpacity(0.15), shape: BoxShape.circle),
          child: Icon(icon, color: color, size: 18),
        ),
        const SizedBox(height: 10),
        Text(title, style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w700)),
        const SizedBox(height: 2),
        Text(subtitle, style: const TextStyle(color: AppTheme.textMuted, fontSize: 11)),
        const SizedBox(height: 8),
        Row(children: [
          Text('Join now', style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w600)),
          const SizedBox(width: 2),
          Icon(Icons.arrow_forward_ios_rounded, color: color, size: 9),
        ]),
      ]),
    ),
  );
}

class _PrivacySection extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String title;
  final String body;
  const _PrivacySection({required this.icon, required this.color, required this.title, required this.body});
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 20),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        Container(
          padding: const EdgeInsets.all(7),
          decoration: BoxDecoration(color: color.withOpacity(0.12), borderRadius: BorderRadius.circular(9)),
          child: Icon(icon, color: color, size: 16),
        ),
        const SizedBox(width: 10),
        Expanded(child: Text(title,
            style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w700))),
      ]),
      const SizedBox(height: 8),
      Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: const Color(0xFF13132A),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: Colors.white.withOpacity(0.06)),
        ),
        child: Text(body,
            style: const TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.6)),
      ),
    ]),
  );
}

// ── FAQ Sheet ──────────────────────────────────────────────────────────────────

class _FAQEntry {
  final String q;
  final String a;
  const _FAQEntry({required this.q, required this.a});
}

class _FAQSheet extends StatelessWidget {
  const _FAQSheet();

  @override
  Widget build(BuildContext context) {
    return DraggableScrollableSheet(
      initialChildSize: 0.92,
      minChildSize: 0.5,
      maxChildSize: 0.97,
      expand: false,
      builder: (_, ctrl) => Container(
        decoration: const BoxDecoration(
          color: Color(0xFF000000),
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        child: ListView(
          controller: ctrl,
          padding: EdgeInsets.fromLTRB(20, 0, 20, MediaQuery.of(context).viewPadding.bottom + 32),
          children: [
            const SizedBox(height: 12),
            Center(child: Container(
              width: 40, height: 4,
              decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2)),
            )),
            const SizedBox(height: 20),
            Row(children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: AppTheme.accent.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: const Icon(Icons.help_rounded, color: AppTheme.accent, size: 22),
              ),
              const SizedBox(width: 14),
              const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('FAQ & Help', style: TextStyle(color: Colors.white, fontSize: 20, fontWeight: FontWeight.w900)),
                Text('Answers to common questions', style: TextStyle(color: AppTheme.textMuted, fontSize: 12)),
              ])),
            ]),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppTheme.accent.withOpacity(0.06),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: AppTheme.accent.withOpacity(0.15)),
              ),
              child: const Text(
                'Tap any question to expand the answer. If you still need help, use the contact card at the bottom.',
                style: TextStyle(color: AppTheme.textSecondary, fontSize: 13, height: 1.55),
              ),
            ),
            const SizedBox(height: 28),
            const _FAQCategory(
              icon: Icons.play_circle_outline_rounded,
              color: AppTheme.primary,
              label: 'Playback',
              items: [
                _FAQEntry(
                  q: 'Video won\'t play or keeps loading?',
                  a: 'Tap Watch again — the app automatically retries with different CDN servers. If it still fails, the content may be temporarily unavailable or geo-restricted in your region. Try again after a few minutes.',
                ),
                _FAQEntry(
                  q: 'Video buffers constantly?',
                  a: 'Inside the player, tap the ⚙ settings icon and switch to a lower quality (e.g. 720p instead of 1080p). A lower bitrate greatly reduces buffering on slower connections.',
                ),
                _FAQEntry(
                  q: 'No audio or subtitles missing?',
                  a: 'Tap the subtitle/caption icon inside the player to select your language. Some titles have multiple audio tracks — use the player settings menu to switch. If no subtitles appear, they may not be available for that title.',
                ),
              ],
            ),
            const SizedBox(height: 20),
            const _FAQCategory(
              icon: Icons.download_rounded,
              color: Color(0xFF4AADF4),
              label: 'Downloads',
              items: [
                _FAQEntry(
                  q: 'How do I download a movie or episode?',
                  a: 'Open any movie or TV episode and tap the Download button. Select your preferred quality (e.g. 720p, 1080p). The download runs in the background and you\'ll be notified when it finishes.',
                ),
                _FAQEntry(
                  q: 'Where are my downloaded files?',
                  a: 'Open the Downloads tab in the bottom navigation bar to see all your downloads. Files are also saved to your phone\'s gallery and Downloads folder, so you can access them from any media app or file manager.',
                ),
                _FAQEntry(
                  q: 'Download stuck or failed?',
                  a: 'Cancel and retry. Make sure you have enough free storage space. If the issue continues, go to Settings → Storage and clear the image cache, then restart the app and try again.',
                ),
              ],
            ),
            const SizedBox(height: 20),
            const _FAQCategory(
              icon: Icons.explore_outlined,
              color: Color(0xFF66BB6A),
              label: 'Content & Navigation',
              items: [
                _FAQEntry(
                  q: 'How do I find Nollywood or K-Drama?',
                  a: 'Scroll down on the Home tab — there are dedicated sections for Nollywood and K-Drama. You can also open the side drawer (☰) and tap Nollywood or K-Drama to go there directly.',
                ),
                _FAQEntry(
                  q: 'How do I watch a trailer?',
                  a: 'On any movie\'s detail page, tap the orange "Watch Trailer" button located just below the title and rating. Trailers open inside the built-in player.',
                ),
                _FAQEntry(
                  q: 'How do I save to my Watchlist?',
                  a: 'Tap the bookmark icon on any movie card on the home screen, or tap it on the movie\'s detail page. Your Watchlist is stored locally on your device and accessible from the Watchlist tab.',
                ),
              ],
            ),
            const SizedBox(height: 20),
            const _FAQCategory(
              icon: Icons.settings_outlined,
              color: Color(0xFFFFA726),
              label: 'App & Technical',
              items: [
                _FAQEntry(
                  q: 'Images not loading or look broken?',
                  a: 'Go to Settings → Storage → tap Clear next to Image Cache. This resets all cached thumbnails and forces a fresh reload. Restart the app after clearing.',
                ),
                _FAQEntry(
                  q: 'App feels slow or laggy?',
                  a: 'Clear the image cache in Settings and restart the app. Ensure your device has enough free storage — Android performs best with at least 1 GB of free space available.',
                ),
                _FAQEntry(
                  q: 'My Continue Watching history disappeared?',
                  a: 'Watch history is stored locally on your device only. If you cleared app data via Android Settings or reinstalled the app, this history will have been reset. There is no cloud sync.',
                ),
              ],
            ),
            const SizedBox(height: 32),
            GestureDetector(
              onTap: () async {
                final uri = Uri.parse('https://t.me/matrix99bot');
                try {
                  await launchUrl(uri, mode: LaunchMode.externalApplication);
                } catch (_) {
                  try { await launchUrl(uri, mode: LaunchMode.inAppBrowserView); } catch (_) {}
                }
              },
              child: Container(
                padding: const EdgeInsets.all(18),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [AppTheme.primary.withOpacity(0.18), AppTheme.primary.withOpacity(0.06)],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: AppTheme.primary.withOpacity(0.3)),
                ),
                child: Row(children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: AppTheme.primary.withOpacity(0.15),
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.support_agent_rounded, color: AppTheme.primary, size: 22),
                  ),
                  const SizedBox(width: 14),
                  const Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text('Still need help?', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w800)),
                    SizedBox(height: 2),
                    Text('Message us on Telegram — we respond fast.', style: TextStyle(color: AppTheme.textSecondary, fontSize: 12, height: 1.4)),
                  ])),
                  const SizedBox(width: 8),
                  const Icon(Icons.arrow_forward_ios_rounded, color: AppTheme.primary, size: 14),
                ]),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _FAQCategory extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String label;
  final List<_FAQEntry> items;
  const _FAQCategory({required this.icon, required this.color, required this.label, required this.items});

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Row(children: [
        Container(
          padding: const EdgeInsets.all(6),
          decoration: BoxDecoration(color: color.withOpacity(0.12), borderRadius: BorderRadius.circular(8)),
          child: Icon(icon, color: color, size: 14),
        ),
        const SizedBox(width: 8),
        Text(label.toUpperCase(), style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1.2)),
      ]),
      const SizedBox(height: 10),
      ...items.map((e) => Padding(
        padding: const EdgeInsets.only(bottom: 8),
        child: _FAQTile(entry: e, accentColor: color),
      )),
    ],
  );
}

class _FAQTile extends StatefulWidget {
  final _FAQEntry entry;
  final Color accentColor;
  const _FAQTile({required this.entry, required this.accentColor});
  @override
  State<_FAQTile> createState() => _FAQTileState();
}

class _FAQTileState extends State<_FAQTile> {
  bool _open = false;

  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: () => setState(() => _open = !_open),
    child: AnimatedContainer(
      duration: const Duration(milliseconds: 250),
      curve: Curves.easeInOut,
      decoration: BoxDecoration(
        color: _open ? widget.accentColor.withOpacity(0.07) : Colors.black,
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: _open ? widget.accentColor.withOpacity(0.3) : AppTheme.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 14, 14, 14),
            child: Row(children: [
              Expanded(
                child: Text(widget.entry.q, style: TextStyle(
                  color: _open ? Colors.white : AppTheme.textPrimary,
                  fontSize: 13.5,
                  fontWeight: FontWeight.w600,
                  height: 1.4,
                )),
              ),
              const SizedBox(width: 8),
              AnimatedRotation(
                turns: _open ? 0.5 : 0.0,
                duration: const Duration(milliseconds: 250),
                child: Icon(Icons.expand_more_rounded, color: _open ? widget.accentColor : AppTheme.textMuted, size: 20),
              ),
            ]),
          ),
          AnimatedCrossFade(
            firstChild: const SizedBox(width: double.infinity),
            secondChild: Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
              child: Text(widget.entry.a, style: const TextStyle(
                color: AppTheme.textSecondary,
                fontSize: 13,
                height: 1.6,
              )),
            ),
            crossFadeState: _open ? CrossFadeState.showSecond : CrossFadeState.showFirst,
            duration: const Duration(milliseconds: 220),
          ),
        ],
      ),
    ),
  );
}

// ── Default Screen Preference Tile ────────────────────────────────────────────
class _DefaultScreenTile extends StatefulWidget {
  const _DefaultScreenTile();

  @override
  State<_DefaultScreenTile> createState() => _DefaultScreenTileState();
}

class _DefaultScreenTileState extends State<_DefaultScreenTile> {
  static const _kPrefKey = 'default_screen';

  String _current = 'main'; // 'main' or 'uganda'
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    if (!mounted) return;
    setState(() {
      _current = prefs.getString(_kPrefKey) ?? 'main';
      _loading = false;
    });
  }

  Future<void> _save(String value) async {
    if (value == _current) return;
    setState(() => _current = value);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_kPrefKey, value);
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            const SizedBox(
              width: 16, height: 16,
              child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
            ),
            const SizedBox(width: 12),
            Text(
              value == 'uganda'
                  ? 'Switching to Uganda Cinema Plus…'
                  : 'Switching to Moviez Box…',
            ),
          ],
        ),
        behavior: SnackBarBehavior.floating,
        duration: const Duration(milliseconds: 900),
      ),
    );
    await Future.delayed(const Duration(milliseconds: 950));
    if (!mounted) return;
    // RestartWidget.restartApp() climbs the widget tree — it cannot reach the
    // RestartWidget ancestor from inside a bottom-sheet modal route. Instead,
    // use the root navigator to clear all routes and push the correct home screen.
    Navigator.of(context, rootNavigator: true).pushAndRemoveUntil(
      MaterialPageRoute(
        builder: (_) => value == 'uganda'
            ? const UgandaHomeScreen(isRoot: true)
            : const HomeScreen(),
      ),
      (_) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const SizedBox(
        height: 72,
        child: Center(child: SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2))),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(18, 8, 18, 10),
          child: Text(
            'Choose which screen opens when you launch the app.',
            style: TextStyle(color: AppTheme.textMuted.withOpacity(0.7), fontSize: 12),
          ),
        ),
        _OptionTile(
          label: 'Moviez Box',
          subtitle: 'Main movies & TV (default)',
          icon: Icons.smart_display_rounded,
          iconColor: AppTheme.primary,
          selected: _current == 'main',
          onTap: () => _save('main'),
        ),
        _OptionTile(
          label: 'Uganda Cinema Plus',
          subtitle: 'Local Uganda films',
          icon: Icons.movie_filter_rounded,
          iconColor: const Color(0xFFFCDC04),
          selected: _current == 'uganda',
          onTap: () => _save('uganda'),
        ),
        const SizedBox(height: 4),
      ],
    );
  }
}

class _OptionTile extends StatelessWidget {
  final String label;
  final String subtitle;
  final IconData icon;
  final Color iconColor;
  final bool selected;
  final VoidCallback onTap;

  const _OptionTile({
    required this.label,
    required this.subtitle,
    required this.icon,
    required this.iconColor,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 4),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        decoration: BoxDecoration(
          color: selected ? iconColor.withOpacity(0.08) : AppTheme.card,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: selected ? iconColor.withOpacity(0.6) : AppTheme.border,
            width: selected ? 1.5 : 1.0,
          ),
        ),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: iconColor.withOpacity(0.12),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Icon(icon, color: iconColor, size: 20),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(label, style: TextStyle(color: selected ? Colors.white : AppTheme.textPrimary, fontSize: 14, fontWeight: FontWeight.w600)),
                  const SizedBox(height: 2),
                  Text(subtitle, style: const TextStyle(color: AppTheme.textMuted, fontSize: 11)),
                ],
              ),
            ),
            AnimatedContainer(
              duration: const Duration(milliseconds: 200),
              width: 20, height: 20,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: selected ? iconColor : Colors.transparent,
                border: Border.all(color: selected ? iconColor : AppTheme.textMuted, width: 2),
              ),
              child: selected
                  ? const Icon(Icons.check_rounded, color: Colors.black, size: 13)
                  : null,
            ),
          ],
        ),
      ),
    );
  }
}
