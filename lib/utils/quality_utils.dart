import 'package:flutter/material.dart';
import '../theme/app_theme.dart';

Color qualityColor(String quality) {
  final q = quality.toLowerCase().replaceAll('p', '').replaceAll(' ', '');
  if (q.contains('4k') || q.contains('2160') || q.contains('uhd')) return const Color(0xFFFFD700);
  if (q.contains('1080') || q.contains('fhd')) return const Color(0xFF4CAF50);
  if (q.contains('720') || q.contains('hd')) return const Color(0xFF2196F3);
  if (q.contains('480')) return const Color(0xFFFF9800);
  if (q.contains('360')) return const Color(0xFF78909C);
  if (q.contains('240')) return const Color(0xFF9E9E9E);
  return AppTheme.primary;
}

IconData qualityIcon(String quality) {
  final q = quality.toLowerCase().replaceAll('p', '').replaceAll(' ', '');
  if (q.contains('4k') || q.contains('2160') || q.contains('uhd')) return Icons.four_k;
  if (q.contains('1080') || q.contains('fhd')) return Icons.high_quality;
  if (q.contains('720') || q.contains('hd')) return Icons.hd;
  if (q.contains('480')) return Icons.sd;
  if (q.contains('360')) return Icons.videocam_rounded;
  if (q.contains('240')) return Icons.videocam_off_rounded;
  return Icons.play_circle_rounded;
}

String qualityLabel(String quality) {
  final q = quality.toLowerCase().replaceAll('p', '').replaceAll(' ', '');
  if (q.contains('4k') || q.contains('2160') || q.contains('uhd')) return '4K UHD';
  if (q.contains('1080') || q.contains('fhd')) return 'Full HD';
  if (q.contains('720') || q.contains('hd')) return 'HD';
  if (q.contains('480')) return 'SD';
  if (q.contains('360')) return 'Low';
  if (q.contains('240')) return 'Min';
  return 'Stream';
}
