import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/update_service.dart';
import '../theme/app_theme.dart';
import 'update_screen.dart';

class AppManagerScreen extends StatefulWidget {
  const AppManagerScreen({super.key});

  @override
  State<AppManagerScreen> createState() => _AppManagerScreenState();
}

class _AppManagerScreenState extends State<AppManagerScreen> {
  bool _loading = true;
  bool _checking = false;
  String _currentVersion = '';
  String _currentBuild   = '';
  Map<String, dynamic>? _latest;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final info    = await PackageInfo.fromPlatform();
      final release = await UpdateService.fetchLatestRelease();
      if (!mounted) return;
      setState(() {
        _currentVersion = info.version;
        _currentBuild   = info.buildNumber;
        _latest         = release;
        _loading        = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() { _loading = false; _error = e.toString(); });
    }
  }

  Future<void> _checkUpdate() async {
    if (_checking) return;
    setState(() { _checking = true; _error = null; });
    try {
      final release = await UpdateService.fetchLatestRelease();
      if (!mounted) return;
      setState(() { _checking = false; _latest = release; });

      if (release == null) {
        _showSnack('Could not fetch release info', isError: true);
        return;
      }

      final currentCode = int.tryParse(_currentBuild) ?? 0;
      final remoteCode  = release['version_code'] as int;

      if (remoteCode <= currentCode) {
        _showSnack('You\'re on the latest version ✓');
        return;
      }

      if (!mounted) return;
      Navigator.of(context).push(PageRouteBuilder(
        opaque: true,
        barrierDismissible: false,
        pageBuilder: (_, __, ___) => UpdateScreen(
          apkUrl:      release['apk_url']      as String,
          versionName: release['version_name'] as String,
          changelog:   release['changelog']    as String,
          updateSize:  release['update_size']  as String,
          force:       release['force']        as bool,
        ),
        transitionsBuilder: (_, anim, __, child) =>
            FadeTransition(opacity: anim, child: child),
        transitionDuration: const Duration(milliseconds: 200),
      ));
    } catch (_) {
      if (!mounted) return;
      setState(() { _checking = false; });
      _showSnack('Check failed — try again', isError: true);
    }
  }

  void _showSnack(String msg, {bool isError = false}) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      backgroundColor: isError ? const Color(0xFFC90000) : const Color(0xFF1E293B),
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
    ));
  }

  Future<void> _openReleases() async {
    final uri = Uri.parse(UpdateService.releasesPageUrl);
    if (await canLaunchUrl(uri)) {
      await launchUrl(uri, mode: LaunchMode.externalApplication);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF080C14),
      appBar: AppBar(
        backgroundColor: const Color(0xFF111827),
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back_ios_new_rounded,
              size: 18, color: AppTheme.textPrimary),
          onPressed: () => Navigator.pop(context),
        ),
        title: Row(
          children: [
            Container(
              width: 30, height: 30,
              decoration: BoxDecoration(
                gradient: const LinearGradient(
                  colors: [Color(0xFFE50914), Color(0xFFB00710)],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
                borderRadius: BorderRadius.circular(8),
              ),
              child: const Icon(Icons.system_update_rounded,
                  color: Colors.white, size: 16),
            ),
            const SizedBox(width: 10),
            Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                const Text('App Manager',
                    style: TextStyle(
                        color: AppTheme.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w700)),
                Text('github.com/${UpdateService.githubOwner}',
                    style: TextStyle(
                        color: AppTheme.textMuted.withOpacity(0.6),
                        fontSize: 10)),
              ],
            ),
          ],
        ),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh_rounded,
                color: AppTheme.textSecondary, size: 22),
            onPressed: _loading ? null : _load,
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: _loading
          ? const Center(
              child: CircularProgressIndicator(color: AppTheme.primary))
          : _buildBody(),
    );
  }

  Widget _buildBody() {
    final currentCode = int.tryParse(_currentBuild) ?? 0;
    final remoteCode  = (_latest?['version_code'] as int?) ?? 0;
    final hasUpdate   = remoteCode > currentCode && _latest != null;
    final upToDate    = _latest != null && remoteCode <= currentCode;

    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Current version card ────────────────────────────────────────
          _SectionCard(
            children: [
              _InfoRow(
                icon: Icons.phone_android_rounded,
                label: 'Current Version',
                value: 'v$_currentVersion  (build $_currentBuild)',
                valueColor: Colors.white70,
              ),
              if (_latest != null) ...[
                const Divider(color: Color(0xFF1E293B), height: 24),
                _InfoRow(
                  icon: Icons.cloud_rounded,
                  label: 'Latest Release',
                  value: 'v${_latest!['version_name']}',
                  valueColor: hasUpdate
                      ? const Color(0xFF44DD88)
                      : Colors.white70,
                ),
                if (_latest!['published_at'] != null &&
                    (_latest!['published_at'] as String).isNotEmpty) ...[
                  const SizedBox(height: 6),
                  _InfoRow(
                    icon: Icons.calendar_today_rounded,
                    label: 'Released',
                    value: _formatDate(_latest!['published_at'] as String),
                    valueColor: const Color(0xFF888888),
                  ),
                ],
                if ((_latest!['update_size'] as String).isNotEmpty) ...[
                  const SizedBox(height: 6),
                  _InfoRow(
                    icon: Icons.download_rounded,
                    label: 'Size',
                    value: _latest!['update_size'] as String,
                    valueColor: const Color(0xFF888888),
                  ),
                ],
              ],
              if (_error != null) ...[
                const Divider(color: Color(0xFF1E293B), height: 24),
                Row(
                  children: [
                    const Icon(Icons.warning_amber_rounded,
                        color: Color(0xFFFF4444), size: 16),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text('Could not fetch release info',
                          style: TextStyle(
                              color: Colors.white.withOpacity(0.5),
                              fontSize: 12)),
                    ),
                  ],
                ),
              ],
            ],
          ),

          // ── Status badge ─────────────────────────────────────────────────
          if (upToDate)
            _StatusBadge(
              icon: Icons.check_circle_rounded,
              text: "You're up to date",
              color: const Color(0xFF44DD88),
              bg: const Color(0xFF0D2A1A),
            )
          else if (hasUpdate)
            _StatusBadge(
              icon: Icons.new_releases_rounded,
              text: 'Update available — v${_latest!['version_name']}',
              color: const Color(0xFFFF4444),
              bg: const Color(0xFF1A0000),
            ),

          const SizedBox(height: 20),

          // ── Changelog ────────────────────────────────────────────────────
          if (_latest != null &&
              (_latest!['changelog'] as String).isNotEmpty) ...[
            const Text('RELEASE NOTES',
                style: TextStyle(
                    color: Color(0xFF888888),
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 1.2)),
            const SizedBox(height: 10),
            _SectionCard(
              children: [
                Text(
                  _latest!['changelog'] as String,
                  style: const TextStyle(
                      color: Color(0xFFCCCCCC), fontSize: 13, height: 1.7),
                ),
              ],
            ),
            const SizedBox(height: 20),
          ],

          // ── Action buttons ───────────────────────────────────────────────
          if (hasUpdate)
            SizedBox(
              width: double.infinity,
              height: 50,
              child: ElevatedButton.icon(
                onPressed: _checking ? null : _checkUpdate,
                icon: _checking
                    ? const SizedBox(
                        width: 18, height: 18,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: Colors.white))
                    : const Icon(Icons.download_rounded,
                        color: Colors.white, size: 20),
                label: Text(
                    _checking ? 'Checking…' : 'Download Update',
                    style: const TextStyle(
                        color: Colors.white,
                        fontSize: 14,
                        fontWeight: FontWeight.w700)),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFFC90000),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12)),
                ),
              ),
            )
          else
            SizedBox(
              width: double.infinity,
              height: 50,
              child: OutlinedButton.icon(
                onPressed: _checking ? null : _checkUpdate,
                icon: _checking
                    ? const SizedBox(
                        width: 18, height: 18,
                        child: CircularProgressIndicator(
                            strokeWidth: 2, color: AppTheme.primary))
                    : const Icon(Icons.search_rounded,
                        color: AppTheme.primary, size: 20),
                label: Text(
                    _checking ? 'Checking…' : 'Check for Update',
                    style: const TextStyle(
                        color: AppTheme.primary, fontSize: 14)),
                style: OutlinedButton.styleFrom(
                  side: BorderSide(
                      color: AppTheme.primary.withOpacity(0.4), width: 1),
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12)),
                ),
              ),
            ),

          const SizedBox(height: 12),

          SizedBox(
            width: double.infinity,
            height: 46,
            child: TextButton.icon(
              onPressed: _openReleases,
              icon: const Icon(Icons.open_in_new_rounded,
                  color: Color(0xFF888888), size: 18),
              label: const Text('View All Releases on GitHub',
                  style:
                      TextStyle(color: Color(0xFF888888), fontSize: 13)),
              style: TextButton.styleFrom(
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(12)),
              ),
            ),
          ),

          const SizedBox(height: 32),
        ],
      ),
    );
  }

  String _formatDate(String iso) {
    try {
      final dt = DateTime.parse(iso).toLocal();
      const m = ['Jan','Feb','Mar','Apr','May','Jun',
                  'Jul','Aug','Sep','Oct','Nov','Dec'];
      return '${m[dt.month - 1]} ${dt.day}, ${dt.year}';
    } catch (_) {
      return iso;
    }
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

class _SectionCard extends StatelessWidget {
  final List<Widget> children;
  const _SectionCard({required this.children});

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        margin: const EdgeInsets.only(bottom: 14),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: const Color(0xFF111827),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: const Color(0xFF1E293B), width: 1),
        ),
        child: Column(
            crossAxisAlignment: CrossAxisAlignment.start, children: children),
      );
}

class _InfoRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  final Color valueColor;

  const _InfoRow({
    required this.icon,
    required this.label,
    required this.value,
    required this.valueColor,
  });

  @override
  Widget build(BuildContext context) => Row(
        children: [
          Icon(icon, color: const Color(0xFF555555), size: 16),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label,
                    style: const TextStyle(
                        color: Color(0xFF555555), fontSize: 11)),
                const SizedBox(height: 2),
                Text(value,
                    style: TextStyle(
                        color: valueColor,
                        fontSize: 13,
                        fontWeight: FontWeight.w600)),
              ],
            ),
          ),
        ],
      );
}

class _StatusBadge extends StatelessWidget {
  final IconData icon;
  final String text;
  final Color color;
  final Color bg;

  const _StatusBadge({
    required this.icon,
    required this.text,
    required this.color,
    required this.bg,
  });

  @override
  Widget build(BuildContext context) => Container(
        width: double.infinity,
        margin: const EdgeInsets.only(bottom: 14),
        padding:
            const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: BoxDecoration(
          color: bg,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: color.withOpacity(0.3), width: 1),
        ),
        child: Row(
          children: [
            Icon(icon, color: color, size: 18),
            const SizedBox(width: 10),
            Expanded(
                child: Text(text,
                    style: TextStyle(
                        color: color,
                        fontSize: 13,
                        fontWeight: FontWeight.w600))),
          ],
        ),
      );
}
