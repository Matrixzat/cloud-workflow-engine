import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../api/models.dart';
import '../providers/app_provider.dart';
import '../theme/app_theme.dart';
import '../widgets/movie_card.dart';
import 'detail_screen.dart';

class WatchlistScreen extends StatelessWidget {
  const WatchlistScreen({super.key});

  void _openDetail(BuildContext context, Movie movie) {
    context.read<AppProvider>().addToHistory(movie);
    Navigator.push(context, MaterialPageRoute(builder: (_) => DetailScreen(movie: movie)));
  }

  @override
  Widget build(BuildContext context) {
    final standalone = Navigator.of(context).canPop();
    return Consumer<AppProvider>(
      builder: (_, provider, __) {
        final body = provider.watchlist.isEmpty
            ? const Center(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.bookmark_border_rounded, size: 72, color: AppTheme.textMuted),
                    SizedBox(height: 16),
                    Text('Your watchlist is empty', style: TextStyle(color: AppTheme.textSecondary, fontSize: 16, fontWeight: FontWeight.w600)),
                    SizedBox(height: 8),
                    Text('Save movies to watch later', style: TextStyle(color: AppTheme.textMuted, fontSize: 13)),
                  ],
                ),
              )
            : GridView.builder(
                padding: const EdgeInsets.all(16),
                physics: const BouncingScrollPhysics(parent: AlwaysScrollableScrollPhysics()),
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                  crossAxisCount: 3,
                  childAspectRatio: 0.62,
                  crossAxisSpacing: 10,
                  mainAxisSpacing: 10,
                ),
                itemCount: provider.watchlist.length,
                itemBuilder: (_, i) {
                  final movie = provider.watchlist[i];
                  return MovieGridCard(
                    movie: movie,
                    onTap: () => _openDetail(context, movie),
                    isWatchlisted: true,
                    onWatchlist: () => provider.toggleWatchlist(movie),
                  );
                },
              );

        if (standalone) {
          return Scaffold(
            backgroundColor: AppTheme.background,
            appBar: AppBar(
              backgroundColor: AppTheme.background,
              elevation: 0,
              leading: IconButton(
                icon: const Icon(Icons.arrow_back_rounded, color: AppTheme.textPrimary),
                onPressed: () => Navigator.pop(context),
              ),
              title: const Text(
                'Watchlist',
                style: TextStyle(color: AppTheme.textPrimary, fontSize: 18, fontWeight: FontWeight.w700),
              ),
            ),
            body: body,
          );
        }
        return body;
      },
    );
  }
}

class HistoryScreen extends StatelessWidget {
  const HistoryScreen({super.key});

  void _openDetail(BuildContext context, Movie movie) {
    context.read<AppProvider>().addToHistory(movie);
    Navigator.push(context, MaterialPageRoute(builder: (_) => DetailScreen(movie: movie)));
  }

  @override
  Widget build(BuildContext context) {
    return Consumer<AppProvider>(
      builder: (_, provider, __) {
        if (provider.history.isEmpty) {
          return const Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.history_rounded, size: 72, color: AppTheme.textMuted),
                SizedBox(height: 16),
                Text('No watch history', style: TextStyle(color: AppTheme.textSecondary, fontSize: 16, fontWeight: FontWeight.w600)),
                SizedBox(height: 8),
                Text('Movies you watch will appear here', style: TextStyle(color: AppTheme.textMuted, fontSize: 13)),
              ],
            ),
          );
        }
        return Column(
          children: [
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 0),
              child: Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Text('${provider.history.length} watched', style: const TextStyle(color: AppTheme.textMuted, fontSize: 13)),
                  TextButton.icon(
                    onPressed: () => _confirmClear(context, provider),
                    icon: const Icon(Icons.delete_outline_rounded, size: 16, color: AppTheme.primary),
                    label: const Text('Clear All', style: TextStyle(color: AppTheme.primary, fontSize: 13)),
                  ),
                ],
              ),
            ),
            Expanded(
              child: GridView.builder(
                padding: const EdgeInsets.all(16),
                physics: const BouncingScrollPhysics(
                    parent: AlwaysScrollableScrollPhysics()),
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                  crossAxisCount: 3,
                  childAspectRatio: 0.62,
                  crossAxisSpacing: 10,
                  mainAxisSpacing: 10,
                ),
                itemCount: provider.history.length,
                itemBuilder: (_, i) {
                  final movie = provider.history[i];
                  return MovieGridCard(
                    movie: movie,
                    onTap: () => _openDetail(context, movie),
                    isWatchlisted: provider.isInWatchlist(movie.id),
                    onWatchlist: () => provider.toggleWatchlist(movie),
                  );
                },
              ),
            ),
          ],
        );
      },
    );
  }

  void _confirmClear(BuildContext context, AppProvider provider) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        backgroundColor: AppTheme.surface,
        title: const Text('Clear History', style: TextStyle(color: AppTheme.textPrimary)),
        content: const Text('Remove all watch history?', style: TextStyle(color: AppTheme.textSecondary)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel', style: TextStyle(color: AppTheme.textMuted))),
          ElevatedButton(
            onPressed: () { provider.clearHistory(); Navigator.pop(context); },
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary),
            child: const Text('Clear'),
          ),
        ],
      ),
    );
  }
}
