import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../screens/update_screen.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Raw-JSON updater — reads adiza.moviz.box.json from your GitHub repo.
//
// HOW IT WORKS:
//   1. Place adiza.moviz.box.json at the ROOT of your GitHub repo (main branch).
//   2. Edit the JSON to set the new version_code, version_name, apk_url, etc.
//   3. Set "force_update": true for mandatory updates.
//   4. The app fetches the JSON on launch and prompts users if version_code is newer.
//
// SETUP: fill in githubOwner and githubRepo below — nothing else needed.
// ─────────────────────────────────────────────────────────────────────────────

class UpdateService {
  UpdateService._();

  static const String githubOwner = 'Matrix1999';
  static const String githubRepo  = 'Adiza-moviez-panel';

  static const String _jsonUrl =
      'https://raw.githubusercontent.com/$githubOwner/$githubRepo/main/adiza.moviz.box.json';

  static String get releasesPageUrl =>
      'https://github.com/$githubOwner/$githubRepo/releases';

  // ── Startup init ──────────────────────────────────────────────────────────
  /// Saves current build number so the background isolate can compare it.
  static Future<void> init() async {
    try {
      final info  = await PackageInfo.fromPlatform();
      final prefs = await SharedPreferences.getInstance();
      await prefs.setInt('current_version_code',
          int.tryParse(info.buildNumber) ?? 0);
    } catch (_) {}
  }

  // ── Foreground check ──────────────────────────────────────────────────────
  /// Fetches the JSON manifest and shows UpdateScreen if a newer version exists.
  static Future<void> checkAndPrompt(BuildContext context) async {
    try {
      final info        = await PackageInfo.fromPlatform();
      final currentCode = int.tryParse(info.buildNumber) ?? 0;

      final release = await fetchLatestRelease();
      if (release == null) return;
      if ((release['version_code'] as int) <= currentCode) return;
      if (!context.mounted) return;

      Navigator.of(context).push(PageRouteBuilder(
        opaque:             true,
        barrierDismissible: false,
        pageBuilder: (_, __, ___) => UpdateScreen(
          apkUrl:      release['apk_url']      as String,
          versionName: release['version_name'] as String,
          changelog:   release['changelog']    as String,
          updateSize:  release['update_size']  as String,
          versionCode: release['version_code'] as int,
          force:       release['force']        as bool,
        ),
        transitionsBuilder: (_, anim, __, child) =>
            FadeTransition(opacity: anim, child: child),
        transitionDuration: const Duration(milliseconds: 150),
      ));
    } catch (_) {}
  }

  // ── Manifest fetcher (shared by foreground check + AppManagerScreen) ───────
  /// Returns null when not configured, on network error, or if JSON is invalid.
  static Future<Map<String, dynamic>?> fetchLatestRelease() async {
    try {
      final client = HttpClient()
        ..connectionTimeout = const Duration(seconds: 15);

      final req = await client.getUrl(
        Uri.parse('${_jsonUrl}?t=${DateTime.now().millisecondsSinceEpoch}'),
      );
      req.headers
        ..set(HttpHeaders.userAgentHeader, 'AdizaMoviezBox')
        ..set(HttpHeaders.cacheControlHeader, 'no-cache, no-store')
        ..set('Pragma', 'no-cache');

      final res = await req.close();
      final raw = await res.transform(const Utf8Decoder()).join();
      client.close();

      if (res.statusCode != 200) return null;

      final json = jsonDecode(raw) as Map<String, dynamic>;

      final verCode  = (json['version_code'] as num?)?.toInt() ?? 0;
      final verName  = json['version_name']  as String? ?? '';
      final apkUrl   = json['apk_url']       as String? ?? '';
      final changelog = json['changelog']    as String? ?? '';
      final sizeStr  = json['update_size']   as String? ?? '';
      final isForce  = json['force_update']  as bool?   ?? false;

      return {
        'version_code': verCode,
        'version_name': verName,
        'apk_url':      apkUrl,
        'changelog':    changelog,
        'update_size':  sizeStr,
        'force':        isForce,
      };
    } catch (_) {
      return null;
    }
  }
}
