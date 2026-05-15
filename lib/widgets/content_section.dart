import 'package:flutter/material.dart';
import '../api/models.dart';
import '../theme/app_theme.dart';
import 'movie_card.dart';
import 'shimmer_card.dart';

class ContentSection extends StatelessWidget {
  final String title;
  final List<Movie> movies;
  final bool isLoading;
  final VoidCallback? onViewAll;
  final Function(Movie)? onMovieTap;
  final Function(Movie)? onWatchlist;
  final bool Function(String)? isWatchlisted;
  final int rows;

  const ContentSection({
    super.key,
    required this.title,
    this.movies = const [],
    this.isLoading = false,
    this.onViewAll,
    this.onMovieTap,
    this.onWatchlist,
    this.isWatchlisted,
    this.rows = 2,
  });

  static const double _cardWidth  = 120.0;
  static const double _cardHeight = 170.0;
  static const double _spacing    = 8.0;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 20, 16, 12),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(children: [
                Container(
                  width: 4, height: 20,
                  decoration: BoxDecoration(
                      color: AppTheme.primary,
                      borderRadius: BorderRadius.circular(2)),
                ),
                const SizedBox(width: 10),
                Text(title,
                    style: const TextStyle(
                        color: AppTheme.textPrimary,
                        fontSize: 16,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 0.3)),
              ]),
              if (onViewAll != null)
                GestureDetector(
                  onTap: onViewAll,
                  child: Row(children: [
                    Text('View All',
                        style: TextStyle(
                            color: AppTheme.primary.withOpacity(0.9),
                            fontSize: 12,
                            fontWeight: FontWeight.w500)),
                    const SizedBox(width: 2),
                    Icon(Icons.chevron_right_rounded,
                        color: AppTheme.primary.withOpacity(0.9), size: 16),
                  ]),
                ),
            ],
          ),
        ),
        if (rows == 1)
          _SingleRow(
            movies: movies,
            isLoading: isLoading,
            onMovieTap: onMovieTap,
            onWatchlist: onWatchlist,
            isWatchlisted: isWatchlisted,
          )
        else
          _DoubleRow(
            movies: movies,
            isLoading: isLoading,
            onMovieTap: onMovieTap,
            onWatchlist: onWatchlist,
            isWatchlisted: isWatchlisted,
          ),
      ],
    );
  }
}

// ── Single row ────────────────────────────────────────────────────────────────
class _SingleRow extends StatelessWidget {
  final List<Movie> movies;
  final bool isLoading;
  final Function(Movie)? onMovieTap;
  final Function(Movie)? onWatchlist;
  final bool Function(String)? isWatchlisted;

  const _SingleRow({
    required this.movies,
    required this.isLoading,
    this.onMovieTap,
    this.onWatchlist,
    this.isWatchlisted,
  });

  @override
  Widget build(BuildContext context) {
    const h = ContentSection._cardHeight;
    if (isLoading) {
      return SizedBox(
        height: h,
        child: ListView.separated(
          scrollDirection: Axis.horizontal,
          physics: const BouncingScrollPhysics(),
          padding: const EdgeInsets.symmetric(horizontal: 16),
          cacheExtent: 400,
          itemCount: 6,
          separatorBuilder: (_, __) =>
              const SizedBox(width: ContentSection._spacing),
          itemBuilder: (_, __) =>
              const SizedBox(width: ContentSection._cardWidth, child: ShimmerCard()),
        ),
      );
    }
    if (movies.isEmpty) return const SizedBox.shrink();
    return SizedBox(
      height: h,
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        padding: const EdgeInsets.symmetric(horizontal: 16),
        cacheExtent: 1200,
        itemCount: movies.length,
        separatorBuilder: (_, __) =>
            const SizedBox(width: ContentSection._spacing),
        itemBuilder: (context, i) {
          final m = movies[i];
          return RepaintBoundary(
            child: SizedBox(
              width: ContentSection._cardWidth,
              child: MovieCard(
                movie: m,
                onTap: () => onMovieTap?.call(m),
                isWatchlisted: isWatchlisted?.call(m.id) ?? false,
                onWatchlist: () => onWatchlist?.call(m),
              ),
            ),
          );
        },
      ),
    );
  }
}

// ── Double row ────────────────────────────────────────────────────────────────
class _DoubleRow extends StatelessWidget {
  final List<Movie> movies;
  final bool isLoading;
  final Function(Movie)? onMovieTap;
  final Function(Movie)? onWatchlist;
  final bool Function(String)? isWatchlisted;

  const _DoubleRow({
    required this.movies,
    required this.isLoading,
    this.onMovieTap,
    this.onWatchlist,
    this.isWatchlisted,
  });

  @override
  Widget build(BuildContext context) {
    const h = ContentSection._cardHeight;
    const s = ContentSection._spacing;
    const w = ContentSection._cardWidth;

    if (isLoading) {
      return Column(children: [
        _shimmerRow(h, w, s),
        const SizedBox(height: s),
        _shimmerRow(h, w, s),
      ]);
    }

    if (movies.isEmpty) return const SizedBox.shrink();

    final mid = (movies.length / 2).ceil();
    final top = movies.sublist(0, mid);
    final bot = movies.sublist(mid);

    return Column(children: [
      _movieRow(top, h, w, s),
      const SizedBox(height: s),
      _movieRow(bot, h, w, s),
    ]);
  }

  Widget _shimmerRow(double h, double w, double s) {
    return SizedBox(
      height: h,
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        padding: const EdgeInsets.symmetric(horizontal: 16),
        cacheExtent: 400,
        itemCount: 5,
        separatorBuilder: (_, __) => SizedBox(width: s),
        itemBuilder: (_, __) =>
            SizedBox(width: w, child: const ShimmerCard()),
      ),
    );
  }

  Widget _movieRow(List<Movie> items, double h, double w, double s) {
    return SizedBox(
      height: h,
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        physics: const BouncingScrollPhysics(),
        padding: const EdgeInsets.symmetric(horizontal: 16),
        cacheExtent: 1200,
        itemCount: items.length,
        separatorBuilder: (_, __) => SizedBox(width: s),
        itemBuilder: (context, i) {
          final m = items[i];
          return RepaintBoundary(
            child: SizedBox(
              width: w,
              child: MovieCard(
                movie: m,
                onTap: () => onMovieTap?.call(m),
                isWatchlisted: isWatchlisted?.call(m.id) ?? false,
                onWatchlist: () => onWatchlist?.call(m),
              ),
            ),
          );
        },
      ),
    );
  }
}
