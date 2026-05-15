import 'dart:io';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'package:cached_network_image/cached_network_image.dart';
import '../utils/app_cache_manager.dart';
import '../services/download_manager.dart';
import '../theme/app_theme.dart';
import 'local_video_player_screen.dart';

class DownloadsScreen extends StatefulWidget {
  const DownloadsScreen({super.key});

  @override
  State<DownloadsScreen> createState() => _DownloadsScreenState();
}

class _DownloadsScreenState extends State<DownloadsScreen> with SingleTickerProviderStateMixin {
  late TabController _tabController;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppTheme.background,
      appBar: AppBar(
        backgroundColor: AppTheme.background,
        title: const Text('Downloads'),
        automaticallyImplyLeading: false,
        bottom: TabBar(
          controller: _tabController,
          indicatorColor: AppTheme.primary,
          labelColor: AppTheme.primary,
          unselectedLabelColor: AppTheme.textMuted,
          tabs: const [
            Tab(text: 'Downloading'),
            Tab(text: 'Completed'),
          ],
        ),
      ),
      body: Consumer<DownloadManager>(
        builder: (_, manager, __) {
          return TabBarView(
            controller: _tabController,
            children: [
              _DownloadingTab(manager: manager),
              _CompletedTab(manager: manager),
            ],
          );
        },
      ),
    );
  }
}

class _DownloadingTab extends StatelessWidget {
  final DownloadManager manager;
  const _DownloadingTab({required this.manager});

  @override
  Widget build(BuildContext context) {
    final tasks = manager.tasks.where((t) =>
      t.status == DownloadStatus.downloading ||
      t.status == DownloadStatus.paused ||
      t.status == DownloadStatus.queued ||
      t.status == DownloadStatus.failed
    ).toList();

    if (tasks.isEmpty) {
      return _EmptyState(
        icon: Icons.download_outlined,
        title: 'No active downloads',
        subtitle: 'Tap the download icon on any video\nto save it for offline viewing',
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(12),
      physics: const BouncingScrollPhysics(
          parent: AlwaysScrollableScrollPhysics()),
      itemCount: tasks.length,
      itemBuilder: (_, i) => _ActiveDownloadCard(task: tasks[i], manager: manager),
    );
  }
}

class _CompletedTab extends StatelessWidget {
  final DownloadManager manager;
  const _CompletedTab({required this.manager});

  @override
  Widget build(BuildContext context) {
    final tasks = manager.completed;
    if (tasks.isEmpty) {
      return _EmptyState(
        icon: Icons.check_circle_outline_rounded,
        title: 'No completed downloads',
        subtitle: 'Your downloaded videos will\nappear here when ready',
      );
    }
    return ListView.builder(
      padding: const EdgeInsets.all(12),
      physics: const BouncingScrollPhysics(
          parent: AlwaysScrollableScrollPhysics()),
      itemCount: tasks.length,
      itemBuilder: (_, i) => _CompletedDownloadCard(task: tasks[i], manager: manager),
    );
  }
}

class _ActiveDownloadCard extends StatelessWidget {
  final DownloadTask task;
  final DownloadManager manager;
  const _ActiveDownloadCard({required this.task, required this.manager});

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTheme.card,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppTheme.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              _Thumbnail(thumbnail: task.thumbnail),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(task.title, style: const TextStyle(color: AppTheme.textPrimary, fontWeight: FontWeight.w600, fontSize: 14), maxLines: 2, overflow: TextOverflow.ellipsis),
                    const SizedBox(height: 4),
                    Row(children: [
                      _QualityBadge(quality: task.quality),
                      const SizedBox(width: 8),
                      _StatusBadge(status: task.status),
                    ]),
                    if (task.hasFailed && task.errorMessage != null) ...[
                      const SizedBox(height: 4),
                      Text(
                        task.errorMessage!,
                        style: const TextStyle(color: Colors.red, fontSize: 10),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ],
                ),
              ),
              _ActionButtons(task: task, manager: manager),
            ],
          ),
          if (task.status == DownloadStatus.downloading || task.status == DownloadStatus.paused) ...[
            const SizedBox(height: 10),
            ClipRRect(
              borderRadius: BorderRadius.circular(4),
              child: LinearProgressIndicator(
                value: task.progress,
                backgroundColor: AppTheme.border,
                valueColor: AlwaysStoppedAnimation<Color>(
                  task.status == DownloadStatus.paused ? AppTheme.gold : AppTheme.primary,
                ),
                minHeight: 4,
              ),
            ),
            const SizedBox(height: 6),
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                Text(task.progressText, style: const TextStyle(color: AppTheme.textMuted, fontSize: 11)),
                Text('${(task.progress * 100).toStringAsFixed(0)}%', style: TextStyle(
                  color: task.status == DownloadStatus.paused ? AppTheme.gold : AppTheme.primary,
                  fontSize: 11, fontWeight: FontWeight.w600,
                )),
              ],
            ),
          ],
        ],
      ),
    );
  }
}

class _CompletedDownloadCard extends StatelessWidget {
  final DownloadTask task;
  final DownloadManager manager;
  const _CompletedDownloadCard({required this.task, required this.manager});

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppTheme.card,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppTheme.border),
      ),
      child: Row(
        children: [
          _Thumbnail(thumbnail: task.thumbnail),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(task.title, style: const TextStyle(color: AppTheme.textPrimary, fontWeight: FontWeight.w600, fontSize: 14), maxLines: 2, overflow: TextOverflow.ellipsis),
                const SizedBox(height: 4),
                _QualityBadge(quality: task.quality),
                const SizedBox(height: 4),
                Text(
                  task.filePath?.split('/').last ?? '',
                  style: const TextStyle(color: AppTheme.textMuted, fontSize: 10),
                  maxLines: 1, overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Play button
              GestureDetector(
                onTap: () async {
                  if (task.filePath == null) return;
                  final file = File(task.filePath!);
                  if (await file.exists()) {
                    if (context.mounted) {
                      Navigator.push(
                        context,
                        MaterialPageRoute(
                          builder: (_) => LocalVideoPlayerScreen(
                            filePath: task.filePath!,
                            title: task.title,
                          ),
                        ),
                      );
                    }
                  } else {
                    if (context.mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                        content: Text('File no longer exists on device'),
                        backgroundColor: Colors.red,
                      ));
                    }
                  }
                },
                child: Container(
                  padding: const EdgeInsets.all(8),
                  margin: const EdgeInsets.only(left: 4),
                  decoration: BoxDecoration(
                    color: AppTheme.primary.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: AppTheme.primary.withOpacity(0.35)),
                  ),
                  child: const Icon(Icons.play_arrow_rounded, color: AppTheme.primary, size: 22),
                ),
              ),
              const SizedBox(width: 6),
              // Delete button
              GestureDetector(
                onTap: () => manager.deleteDownload(task.id),
                child: Container(
                  padding: const EdgeInsets.all(8),
                  margin: const EdgeInsets.only(left: 4),
                  decoration: BoxDecoration(
                    color: Colors.red.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: Colors.red.withOpacity(0.35)),
                  ),
                  child: const Icon(Icons.delete_outline_rounded, color: Colors.red, size: 22),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _ActionButtons extends StatelessWidget {
  final DownloadTask task;
  final DownloadManager manager;
  const _ActionButtons({required this.task, required this.manager});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        // Pause button — visible only while actively downloading
        if (task.status == DownloadStatus.downloading)
          _iconBtn(Icons.pause_rounded, AppTheme.gold, () => manager.pauseDownload(task.id)),
        // Resume button — shown when paused or failed
        if (task.status == DownloadStatus.paused || task.status == DownloadStatus.failed)
          _iconBtn(Icons.play_arrow_rounded, Colors.green, () => manager.resumeDownload(task.id)),
        const SizedBox(width: 6),
        // Cancel / delete — always visible
        _iconBtn(Icons.delete_outline_rounded, Colors.red, () => _confirmCancel(context)),
      ],
    );
  }

  Widget _iconBtn(IconData icon, Color color, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(8),
        margin: const EdgeInsets.only(left: 4),
        decoration: BoxDecoration(
          color: color.withOpacity(0.15),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: color.withOpacity(0.35)),
        ),
        child: Icon(icon, color: color, size: 22),
      ),
    );
  }

  void _confirmCancel(BuildContext context) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppTheme.surface,
        title: const Text('Cancel Download?'),
        content: const Text('This will remove the download and delete the partial file.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Keep')),
          TextButton(
            onPressed: () { Navigator.pop(context); manager.cancelDownload(task.id); },
            child: const Text('Cancel Download', style: TextStyle(color: Colors.red, fontWeight: FontWeight.w700)),
          ),
        ],
      ),
    );
  }
}

class _Thumbnail extends StatelessWidget {
  final String? thumbnail;
  const _Thumbnail({this.thumbnail});

  @override
  Widget build(BuildContext context) {
    return ClipRRect(
      borderRadius: BorderRadius.circular(8),
      child: Container(
        width: 52, height: 72,
        color: AppTheme.shimmerBase,
        child: thumbnail != null
            ? CachedNetworkImage(imageUrl: thumbnail!, fit: BoxFit.cover, memCacheWidth: 312, memCacheHeight: 432, filterQuality: FilterQuality.medium, cacheManager: AdizaCacheManager(), errorWidget: (_, __, ___) => const Icon(Icons.movie_outlined, color: AppTheme.textMuted, size: 24))
            : const Icon(Icons.movie_outlined, color: AppTheme.textMuted, size: 24),
      ),
    );
  }
}

class _QualityBadge extends StatelessWidget {
  final String quality;
  const _QualityBadge({required this.quality});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(color: AppTheme.primary.withOpacity(0.2), borderRadius: BorderRadius.circular(4)),
      child: Text(quality, style: const TextStyle(color: AppTheme.primary, fontSize: 10, fontWeight: FontWeight.w600)),
    );
  }
}

class _StatusBadge extends StatelessWidget {
  final DownloadStatus status;
  const _StatusBadge({required this.status});

  @override
  Widget build(BuildContext context) {
    Color color;
    String label;
    switch (status) {
      case DownloadStatus.downloading: color = Colors.green; label = 'Downloading'; break;
      case DownloadStatus.paused: color = AppTheme.gold; label = 'Paused'; break;
      case DownloadStatus.failed: color = Colors.red; label = 'Failed'; break;
      default: color = AppTheme.textMuted; label = 'Queued'; break;
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(color: color.withOpacity(0.15), borderRadius: BorderRadius.circular(4)),
      child: Text(label, style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.w600)),
    );
  }
}

class _EmptyState extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  const _EmptyState({required this.icon, required this.title, required this.subtitle});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: AppTheme.textMuted, size: 64),
            const SizedBox(height: 16),
            Text(title, style: const TextStyle(color: AppTheme.textPrimary, fontSize: 16, fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            Text(subtitle, textAlign: TextAlign.center, style: const TextStyle(color: AppTheme.textMuted, fontSize: 13, height: 1.5)),
          ],
        ),
      ),
    );
  }
}
