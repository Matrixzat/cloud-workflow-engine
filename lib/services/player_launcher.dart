import 'package:flutter/material.dart';
import '../api/models.dart';
import '../theme/app_theme.dart';
import '../screens/player_screen.dart';

class PlayerLauncher {
  static Future<void> launch(
    BuildContext context,
    Movie movie,
    MovieSource source, {
    int? season,
    int? episode,
    List<SeasonInfo>? seasons,
    List<MovieSource>? allSources,
  }) async {
    final navigator = Navigator.of(context);
    String? selectedSubtitleLang;
    if (source.subtitleUrls.isNotEmpty) {
      if (!context.mounted) return;
      final result = await _showSubtitleChooser(context, movie, source);
      if (result == '__cancel__') return;
      selectedSubtitleLang = (result == null || result == '') ? null : result;
    }

    navigator.push(
      MaterialPageRoute(
        builder: (_) => PlayerScreen(
          movie: movie,
          source: source,
          season: season,
          episode: episode,
          seasons: seasons,
          allSources: allSources,
          preSelectedSubtitle: selectedSubtitleLang,
        ),
      ),
    );
  }

  static Future<String?> _showSubtitleChooser(
    BuildContext context,
    Movie movie,
    MovieSource source,
  ) async {
    return showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      isDismissible: false,
      enableDrag: false,
      backgroundColor: Colors.transparent,
      builder: (_) => _SubtitleChooserSheet(movie: movie, source: source),
    );
  }
}

// ── Subtitle Chooser Sheet ────────────────────────────────────────────────────
class _SubtitleChooserSheet extends StatefulWidget {
  final Movie movie;
  final MovieSource source;
  const _SubtitleChooserSheet({required this.movie, required this.source});

  @override
  State<_SubtitleChooserSheet> createState() => _SubtitleChooserSheetState();
}

class _SubtitleChooserSheetState extends State<_SubtitleChooserSheet> {
  String _selected = '';

  @override
  Widget build(BuildContext context) {
    final langs = widget.source.subtitleUrls.keys.toList()..sort();
    final typeLabel = widget.movie.isMovie ? 'Movie' : 'TV Series';

    return Container(
      decoration: const BoxDecoration(
        color: Colors.black,
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      padding: EdgeInsets.only(
          bottom: MediaQuery.of(context).viewInsets.bottom +
              MediaQuery.of(context).padding.bottom),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 12),
          Container(
            width: 36, height: 4,
            decoration: BoxDecoration(color: AppTheme.border, borderRadius: BorderRadius.circular(2)),
          ),
          const SizedBox(height: 16),
          Text(
            'Play "$typeLabel"',
            style: const TextStyle(color: AppTheme.textMuted, fontSize: 12, fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 4),
          const Text(
            'Choose subtitle',
            style: TextStyle(color: AppTheme.textPrimary, fontSize: 20, fontWeight: FontWeight.w800),
          ),
          const SizedBox(height: 16),
          Flexible(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 16),
              child: Column(
                children: [
                  _SubOption(
                    label: 'None',
                    icon: Icons.subtitles_off_outlined,
                    selected: _selected == '',
                    onTap: () => setState(() => _selected = ''),
                  ),
                  const SizedBox(height: 8),
                  ...langs.map((lang) => Padding(
                    padding: const EdgeInsets.only(bottom: 8),
                    child: _SubOption(
                      label: lang,
                      icon: Icons.subtitles_rounded,
                      selected: _selected == lang,
                      onTap: () => setState(() => _selected = lang),
                    ),
                  )),
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          Divider(color: AppTheme.border, height: 1),
          const SizedBox(height: 12),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Row(
              children: [
                Expanded(
                  child: GestureDetector(
                    onTap: () => Navigator.pop(context, '__cancel__'),
                    child: Container(
                      height: 50,
                      decoration: BoxDecoration(
                        color: AppTheme.card,
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: AppTheme.border),
                      ),
                      child: const Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(Icons.chevron_left_rounded, color: AppTheme.textSecondary, size: 20),
                          SizedBox(width: 4),
                          Text('Back', style: TextStyle(color: AppTheme.textSecondary, fontSize: 14, fontWeight: FontWeight.w600)),
                        ],
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  flex: 2,
                  child: GestureDetector(
                    onTap: () => Navigator.pop(context, _selected),
                    child: Container(
                      height: 50,
                      decoration: BoxDecoration(
                        color: AppTheme.primary,
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: const Row(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Text('Select and Play', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w800)),
                          SizedBox(width: 6),
                          Icon(Icons.play_arrow_rounded, color: Colors.white, size: 20),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

class _SubOption extends StatelessWidget {
  final String label;
  final IconData icon;
  final bool selected;
  final VoidCallback onTap;

  const _SubOption({
    required this.label,
    required this.icon,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: selected ? AppTheme.primary.withOpacity(0.10) : AppTheme.card,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: selected ? AppTheme.primary : AppTheme.border,
            width: selected ? 1.8 : 1,
          ),
        ),
        child: Row(
          children: [
            Icon(icon, color: selected ? AppTheme.primary : Colors.white, size: 20),
            const SizedBox(width: 14),
            Expanded(
              child: Text(
                label,
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 15,
                  fontWeight: selected ? FontWeight.w700 : FontWeight.w400,
                ),
              ),
            ),
            AnimatedContainer(
              duration: const Duration(milliseconds: 180),
              width: 22, height: 22,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: selected ? AppTheme.primary : Colors.transparent,
                border: Border.all(
                  color: selected ? AppTheme.primary : AppTheme.textMuted,
                  width: 2,
                ),
              ),
              child: selected
                ? const Icon(Icons.check, color: Colors.white, size: 13)
                : null,
            ),
          ],
        ),
      ),
    );
  }
}
