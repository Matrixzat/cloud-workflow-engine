import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import '../services/adult_cache.dart';

/// Simple HD thumbnail for adult content cards.
/// No video preview — just a crisp cached image with a black fallback.
class AdultPreviewThumb extends StatelessWidget {
  final String thumbnail;
  final String previewGif; // kept for API compatibility, ignored
  final BoxFit fit;

  const AdultPreviewThumb({
    super.key,
    required this.thumbnail,
    this.previewGif = '',
    this.fit = BoxFit.cover,
  });

  @override
  Widget build(BuildContext context) {
    if (thumbnail.isEmpty) return const ColoredBox(color: Colors.black);

    return CachedNetworkImage(
      imageUrl: thumbnail,
      cacheManager: AdultCacheManager(),
      fit: fit,
      filterQuality: FilterQuality.high,
      memCacheWidth: 420,
      fadeInDuration: const Duration(milliseconds: 180),
      placeholder: (_, __) => const ColoredBox(color: Color(0xFF111111)),
      errorWidget: (_, __, ___) => const ColoredBox(color: Colors.black),
    );
  }
}
