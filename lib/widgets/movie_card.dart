import 'package:flutter/material.dart';
import 'package:cached_network_image/cached_network_image.dart';
import '../api/models.dart';
import '../theme/app_theme.dart';

class MovieCard extends StatelessWidget {
  final Movie movie;
  final VoidCallback onTap;
  final bool isWatchlisted;
  final VoidCallback? onWatchlist;

  const MovieCard({
    super.key,
    required this.movie,
    required this.onTap,
    this.isWatchlisted = false,
    this.onWatchlist,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        decoration: BoxDecoration(
          color: AppTheme.card,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: Colors.white.withOpacity(0.05)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(
              child: Stack(
                children: [
                  ClipRRect(
                    borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                    child: movie.thumbnail != null
                        ? LayoutBuilder(builder: (ctx, c) {
                            final dpr = MediaQuery.of(ctx).devicePixelRatio;
                            return CachedNetworkImage(
                              imageUrl: movie.thumbnail!,
                              width: double.infinity,
                              height: double.infinity,
                              fit: BoxFit.cover,
                              alignment: Alignment.topCenter,
                              memCacheWidth: (c.maxWidth * dpr).ceil(),
                              memCacheHeight: (c.maxHeight * dpr).ceil(),
                              filterQuality: FilterQuality.high,
                              placeholder: (_, __) => Container(color: AppTheme.shimmerBase),
                              errorWidget: (_, __, ___) => _placeholder(),
                            );
                          })
                        : _placeholder(),
                  ),
                  if (movie.rating != null)
                    Positioned(
                      top: 6,
                      left: 6,
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(
                          color: Colors.black.withOpacity(0.75),
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.star_rounded, color: AppTheme.gold, size: 12),
                            const SizedBox(width: 2),
                            Text(
                              movie.rating!,
                              style: const TextStyle(color: AppTheme.gold, fontSize: 10, fontWeight: FontWeight.w600),
                            ),
                          ],
                        ),
                      ),
                    ),
                  Positioned(
                    top: 4,
                    right: 4,
                    child: _typeTag(),
                  ),
                  if (onWatchlist != null)
                    Positioned(
                      bottom: 6,
                      right: 6,
                      child: GestureDetector(
                        onTap: onWatchlist,
                        child: Container(
                          padding: const EdgeInsets.all(5),
                          decoration: BoxDecoration(
                            color: Colors.black.withOpacity(0.7),
                            shape: BoxShape.circle,
                          ),
                          child: Icon(
                            isWatchlisted ? Icons.bookmark_rounded : Icons.bookmark_border_rounded,
                            color: isWatchlisted ? AppTheme.primary : Colors.white,
                            size: 16,
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(8, 8, 8, 8),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    movie.title,
                    style: const TextStyle(
                      color: AppTheme.textPrimary,
                      fontSize: 11.5,
                      fontWeight: FontWeight.w600,
                      height: 1.3,
                    ),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 3),
                  Text(
                    movie.year ?? '',
                    style: const TextStyle(color: AppTheme.textMuted, fontSize: 10),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _placeholder() {
    return Container(
      color: AppTheme.shimmerBase,
      child: const Center(
        child: Icon(Icons.movie_outlined, color: AppTheme.textMuted, size: 32),
      ),
    );
  }

  Widget _typeTag() {
    final isTV = movie.subjectType == 2;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
      decoration: BoxDecoration(
        color: isTV ? AppTheme.accent.withOpacity(0.85) : AppTheme.primary.withOpacity(0.85),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        isTV ? 'TV' : 'FILM',
        style: const TextStyle(color: Colors.white, fontSize: 9, fontWeight: FontWeight.w700),
      ),
    );
  }
}

class MovieGridCard extends StatelessWidget {
  final Movie movie;
  final VoidCallback onTap;
  final bool isWatchlisted;
  final VoidCallback? onWatchlist;

  const MovieGridCard({
    super.key,
    required this.movie,
    required this.onTap,
    this.isWatchlisted = false,
    this.onWatchlist,
  });

  @override
  Widget build(BuildContext context) {
    return MovieCard(
      movie: movie,
      onTap: onTap,
      isWatchlisted: isWatchlisted,
      onWatchlist: onWatchlist,
    );
  }
}
