import 'dart:convert';
import 'dart:io';

import 'package:flutter_local_notifications/flutter_local_notifications.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:workmanager/workmanager.dart';

const kUpdateCheckTask = 'update_check';

// Must be a top-level function — WorkManager runs in a separate Dart isolate.
@pragma('vm:entry-point')
void callbackDispatcher() {
  Workmanager().executeTask((taskName, _) async {
    if (taskName == kUpdateCheckTask) await _checkForUpdate();
    return true;
  });
}

/// Runs in background — fetches adiza.moviz.box.json and fires a local
/// notification when a newer version is available.
Future<void> _checkForUpdate() async {
  // Mirror UpdateService constants (cannot import UpdateService in isolate).
  const githubOwner = 'Matrix1999';
  const githubRepo  = 'Adiza-moviez-panel';

  const jsonUrl =
      'https://raw.githubusercontent.com/$githubOwner/$githubRepo/main/adiza.moviz.box.json';

  try {
    final prefs       = await SharedPreferences.getInstance();
    final currentCode = prefs.getInt('current_version_code') ?? 0;

    // Fetch the update manifest
    final client = HttpClient()
      ..connectionTimeout = const Duration(seconds: 15);

    final req = await client.getUrl(
      Uri.parse('${jsonUrl}?t=${DateTime.now().millisecondsSinceEpoch}'),
    );
    req.headers
      ..set(HttpHeaders.userAgentHeader, 'AdizaMoviezBox/BG')
      ..set(HttpHeaders.cacheControlHeader, 'no-cache, no-store')
      ..set('Pragma', 'no-cache');

    final res = await req.close();
    final raw = await res.transform(const Utf8Decoder()).join();
    client.close();

    if (res.statusCode != 200) return;

    final json      = jsonDecode(raw) as Map<String, dynamic>;
    final remoteCode = (json['version_code'] as num?)?.toInt() ?? 0;
    final verName    = json['version_name'] as String? ?? '';

    if (remoteCode <= currentCode) return;

    // Already notified about this version?
    final notifiedCode = prefs.getInt('update_notif_code') ?? 0;
    if (notifiedCode >= remoteCode) return;
    await prefs.setInt('update_notif_code', remoteCode);

    // Fire local notification
    final plugin = FlutterLocalNotificationsPlugin();
    const init   = AndroidInitializationSettings('@mipmap/ic_launcher');
    await plugin.initialize(const InitializationSettings(android: init));
    await plugin
        .resolvePlatformSpecificImplementation<
            AndroidFlutterLocalNotificationsPlugin>()
        ?.createNotificationChannel(const AndroidNotificationChannel(
          'adiza_updates',
          'App Updates',
          description: 'Notifications about new app versions',
          importance: Importance.high,
        ));

    await plugin.show(
      8888,
      'Update Available — v$verName',
      'Open Adiza Moviez Box to download the latest update.',
      const NotificationDetails(
        android: AndroidNotificationDetails(
          'adiza_updates',
          'App Updates',
          channelDescription: 'Notifications about new app versions',
          importance: Importance.high,
          priority: Priority.high,
          icon: '@mipmap/ic_launcher',
        ),
      ),
    );
  } catch (_) {}
}
