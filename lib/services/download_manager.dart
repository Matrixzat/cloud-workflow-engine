import 'dart:convert';
import 'dart:io';
import 'package:background_downloader/background_downloader.dart' as bd;
import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

// Runtime-reconstructed — not visible as a literal in the DEX
final _xr  = String.fromCharCodes([104,116,116,112,115,58,47,47,104,53,46,97,111,110,101,114,111,111,109,46,99,111,109,47]);
final _ugR  = String.fromCharCodes([104,116,116,112,115,58,47,47,109,117,110,111,119,97,116,99,104,46,111,114,103,47]);
final _ugO  = String.fromCharCodes([104,116,116,112,115,58,47,47,109,117,110,111,119,97,116,99,104,46,111,114,103]);
final _mbR  = String.fromCharCodes([104,116,116,112,115,58,47,47,102,109,111,118,105,101,115,117,110,98,108,111,99,107,101,100,46,110,101,116,47]);
final _mbO  = String.fromCharCodes([104,116,116,112,115,58,47,47,102,109,111,118,105,101,115,117,110,98,108,111,99,107,101,100,46,110,101,116]);
final _ugK  = String.fromCharCodes([109,117,110,111,119,97,116,99,104]);

enum DownloadStatus { queued, downloading, paused, completed, failed, cancelled }

class DownloadTask {
  final String id;
  final String movieId;
  final String title;
  final String quality;
  final String url;
  final String? thumbnail;
  final String referer;
  String? filePath;
  int totalBytes;
  int downloadedBytes;
  DownloadStatus status;
  String? errorMessage;

  double get progress => totalBytes > 0 ? downloadedBytes / totalBytes : 0;

  String get progressText {
    if (totalBytes == 0) {
      return downloadedBytes > 0
          ? '${(downloadedBytes / 1024 / 1024).toStringAsFixed(1)} MB'
          : 'Starting…';
    }
    return '${(downloadedBytes / 1024 / 1024).toStringAsFixed(1)} / '
        '${(totalBytes / 1024 / 1024).toStringAsFixed(1)} MB';
  }

  // A task is "active" when it is queued OR actively downloading — used to
  // guard against starting duplicate downloads.
  bool get isActive =>
      status == DownloadStatus.downloading || status == DownloadStatus.queued;
  bool get isDone => status == DownloadStatus.completed;
  bool get hasFailed => status == DownloadStatus.failed;

  DownloadTask({
    required this.id,
    required this.movieId,
    required this.title,
    required this.quality,
    required this.url,
    this.thumbnail,
    this.referer = '',
    this.filePath,
    this.totalBytes = 0,
    this.downloadedBytes = 0,
    this.status = DownloadStatus.queued,
    this.errorMessage,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'movieId': movieId,
        'title': title,
        'quality': quality,
        'url': url,
        'thumbnail': thumbnail,
        'referer': referer,
        'filePath': filePath,
        'totalBytes': totalBytes,
        'downloadedBytes': downloadedBytes,
        'status': status.index,
        'errorMessage': errorMessage,
      };

  factory DownloadTask.fromJson(Map<String, dynamic> j) => DownloadTask(
        id: j['id'],
        movieId: j['movieId'],
        title: j['title'],
        quality: j['quality'],
        url: j['url'],
        thumbnail: j['thumbnail'],
        referer: j['referer'] ?? '',
        filePath: j['filePath'],
        totalBytes: j['totalBytes'] ?? 0,
        downloadedBytes: j['downloadedBytes'] ?? 0,
        status: DownloadStatus.values[j['status'] ?? 0],
        errorMessage: j['errorMessage'] as String?,
      );
}

// ─────────────────────────────────────────────────────────────────────────────
// DownloadManager — wraps background_downloader's native WorkManager engine.
//
// Downloads for MovieBox and Uganda run in completely separate groups so their
// CDN-specific Referer/Origin headers are never mixed up:
//
//   adiza_moviebox  →  MovieBox CDN  (fmoviesunblocked.net Referer/Origin)
//   adiza_uganda    →  Uganda CDN   (munowatch.org Referer/Origin)
//
// Everything happens on native Android WorkManager threads — zero Dart event-
// loop overhead — so users can scroll, navigate, and use the app freely while
// downloads run in the background.  Downloads survive the app being killed.
// ─────────────────────────────────────────────────────────────────────────────
class DownloadManager extends ChangeNotifier {
  static final DownloadManager _instance = DownloadManager._internal();
  factory DownloadManager() => _instance;
  DownloadManager._internal() {
    _init();
  }

  // ── Group names — one per CDN / Referer policy ───────────────────────────
  static const _mbGroup = 'adiza_moviebox';
  static const _ugGroup = 'adiza_uganda';

  // All downloads go to the Movies/AdizaMoviez folder on external storage.
  static const _dlSubDir = 'Movies/AdizaMoviez';

  final List<DownloadTask> _tasks = [];
  List<DownloadTask> get tasks => List.unmodifiable(_tasks);
  List<DownloadTask> get completed => _tasks.where((t) => t.isDone).toList();
  int get totalDownloading =>
      _tasks.where((t) => t.status == DownloadStatus.downloading).length;

  bool hasDownload(String movieId) =>
      _tasks.any((t) => t.movieId == movieId && (t.isDone || t.isActive));

  // UI rebuild throttle — only rebuild widgets every 200 ms during active
  // downloads so scrolling stays butter-smooth.
  final Map<String, DateTime> _lastUiUpdate = {};
  static const _uiInterval = Duration(milliseconds: 200);

  void _throttledNotify(String taskId) {
    final now = DateTime.now();
    final last = _lastUiUpdate[taskId];
    if (last == null || now.difference(last) >= _uiInterval) {
      _lastUiUpdate[taskId] = now;
      notifyListeners();
    }
  }

  // ── Initialisation ────────────────────────────────────────────────────────
  Future<void> _init() async {
    await _load();
    _setupNotifications();
    bd.FileDownloader().updates.listen(_onUpdate);
    // Restore tasks that the native layer is still running after an app restart
    _reconcileNativeQueue();
  }

  void _setupNotifications() {
    for (final group in [_mbGroup, _ugGroup]) {
      bd.FileDownloader().configureNotificationForGroup(
        group,
        running: const bd.TaskNotification(
          'Downloading — {displayName}',
          '{progress}',
        ),
        complete: const bd.TaskNotification(
          'Download Complete',
          '{displayName} saved to your device',
        ),
        error: const bd.TaskNotification(
          'Download Failed',
          '{displayName}',
        ),
        paused: const bd.TaskNotification(
          'Paused — {displayName}',
          'Tap Resume to continue',
        ),
        progressBar: true,
        tapOpensFile: false,
      );
    }
  }

  // After an app restart, native WorkManager may still have tasks running.
  // Reconcile those into our in-memory list so the Downloads tab is accurate.
  Future<void> _reconcileNativeQueue() async {
    try {
      final nativeTasks = [
        ...await bd.FileDownloader().allTasks(group: _mbGroup),
        ...await bd.FileDownloader().allTasks(group: _ugGroup),
      ];
      bool changed = false;
      for (final nt in nativeTasks) {
        final exists = _tasks.any((t) => t.id == nt.taskId);
        if (!exists) {
          final meta = _parseMeta(nt.metaData);
          final t = DownloadTask(
            id: nt.taskId,
            movieId: meta['movieId'] ?? nt.taskId,
            title: meta['title'] ?? nt.displayName,
            quality: meta['quality'] ?? '',
            url: nt.url,
            thumbnail: meta['thumbnail'],
            referer: meta['referer'] ?? '',
            status: DownloadStatus.downloading,
            filePath: _filePath(nt.filename),
          );
          _tasks.insert(0, t);
          changed = true;
        }
      }
      if (changed) {
        notifyListeners();
        _save();
      }
    } catch (_) {}
  }

  Map<String, dynamic> _parseMeta(String meta) {
    try {
      return jsonDecode(meta) as Map<String, dynamic>;
    } catch (_) {
      return {};
    }
  }

  // Computes the expected on-device path for a download.
  // background_downloader writes to BaseDirectory.externalStorage + _dlSubDir.
  String _filePath(String filename) =>
      '/storage/emulated/0/$_dlSubDir/$filename';

  // ── Native update callbacks ───────────────────────────────────────────────
  void _onUpdate(bd.TaskUpdate update) {
    if (update is bd.TaskStatusUpdate) {
      _onStatus(update);
    } else if (update is bd.TaskProgressUpdate) {
      _onProgress(update);
    }
  }

  void _onStatus(bd.TaskStatusUpdate u) {
    final idx = _tasks.indexWhere((t) => t.id == u.task.taskId);
    if (idx < 0) return;
    final task = _tasks[idx];

    switch (u.status) {
      case bd.TaskStatus.enqueued:
        task.status = DownloadStatus.queued;
      case bd.TaskStatus.running:
        task.status = DownloadStatus.downloading;
      case bd.TaskStatus.complete:
        task.status = DownloadStatus.completed;
        task.filePath ??= _filePath(u.task.filename);
        _save();
      case bd.TaskStatus.paused:
        task.status = DownloadStatus.paused;
        _save();
      case bd.TaskStatus.failed:
        task.status = DownloadStatus.failed;
        task.errorMessage = u.exception?.description ?? 'Download failed';
        _save();
      case bd.TaskStatus.canceled:
        // Already removed in cancelDownload(); just guard for safety
        if (idx >= 0) {
          _tasks.removeAt(idx);
          _save();
        }
      case bd.TaskStatus.waitingToRetry:
        task.status = DownloadStatus.downloading;
      case bd.TaskStatus.notFound:
        task.status = DownloadStatus.failed;
        task.errorMessage = 'Task not found in queue';
        _save();
    }
    notifyListeners();
  }

  void _onProgress(bd.TaskProgressUpdate u) {
    final idx = _tasks.indexWhere((t) => t.id == u.task.taskId);
    if (idx < 0) return;
    final task = _tasks[idx];
    if (u.expectedFileSize > 0) {
      task.totalBytes = u.expectedFileSize;
      task.downloadedBytes = (u.progress * u.expectedFileSize).round();
    } else if (u.progress > 0) {
      // No content-length — show a rough byte estimate via progress fraction
      task.downloadedBytes = (u.progress * 10 * 1024 * 1024).round();
    }
    _throttledNotify(task.id);
  }

  // ── Public API ────────────────────────────────────────────────────────────

  /// Start a download.  The [referer] field determines which CDN group is
  /// used — Uganda tasks go to [_ugGroup], MovieBox tasks to [_mbGroup].
  Future<void> startDownload({
    required String movieId,
    required String title,
    required String quality,
    required String url,
    String? thumbnail,
    String? referer,
  }) async {
    // ── Deduplication ────────────────────────────────────────────────────
    final existingIdx =
        _tasks.indexWhere((t) => t.movieId == movieId && t.quality == quality);
    if (existingIdx >= 0) {
      final ex = _tasks[existingIdx];
      if (ex.isDone &&
          ex.filePath != null &&
          await File(ex.filePath!).exists()) return;
      if (ex.isActive) return;
      if (ex.status == DownloadStatus.paused) {
        resumeDownload(ex.id);
        return;
      }
      await bd.FileDownloader().cancelTaskWithId(ex.id);
      _tasks.removeAt(existingIdx);
    }

    final safeTitle = title.replaceAll(RegExp(r'[\\/:*?"<>|]'), '_');
    final ext = url.contains('.mkv') ? 'mkv' : 'mp4';
    final fileName = '${safeTitle}_$quality.$ext';
    final taskId =
        '${movieId}_${quality}_${DateTime.now().millisecondsSinceEpoch}';

    final effectiveReferer =
        (referer != null && referer.isNotEmpty) ? referer : _xr;
    final effectiveUrl =
        url.startsWith('//') ? 'https:$url' : url.replaceAll(' ', '%20');

    // ── Per-source CDN routing ────────────────────────────────────────────
    // Uganda CDN (munowatch.org) and MovieBox CDN use different Referer/Origin.
    // BunnyCDN (b-cdn.net) rejects Referer/Origin — send no origin headers.
    final isUganda = effectiveReferer.contains(_ugK);
    final isBunnyCdn = effectiveUrl.contains('b-cdn.net');

    final headers = <String, String>{
      'User-Agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    };
    if (!isBunnyCdn) {
      // ── Uganda group: uses Uganda CDN referer/origin ──────────────────
      // ── MovieBox group: uses MovieBox CDN referer/origin ─────────────
      headers['Referer'] = isUganda ? effectiveReferer : _mbR;
      headers['Origin'] = isUganda ? _ugO : _mbO;
    }

    final meta = jsonEncode({
      'movieId': movieId,
      'title': title,
      'quality': quality,
      'thumbnail': thumbnail,
      'referer': effectiveReferer,
    });

    // ── Enqueue native WorkManager task ──────────────────────────────────
    final bdTask = bd.DownloadTask(
      taskId: taskId,
      url: effectiveUrl,
      filename: fileName,
      headers: headers,
      directory: _dlSubDir,
      baseDirectory: bd.BaseDirectory.applicationDocuments,
      // Each CDN gets its own group → own notification channel + own headers
      group: isUganda ? _ugGroup : _mbGroup,
      updates: bd.Updates.statusAndProgress,
      allowPause: true,
      retries: 10,
      metaData: meta,
      displayName: title,
    );

    final myTask = DownloadTask(
      id: taskId,
      movieId: movieId,
      title: title,
      quality: quality,
      url: effectiveUrl,
      thumbnail: thumbnail,
      referer: effectiveReferer,
      status: DownloadStatus.queued,
      filePath: _filePath(fileName),
    );

    _tasks.insert(0, myTask);
    notifyListeners();
    _save();

    await bd.FileDownloader().enqueue(bdTask);
  }

  Future<void> pauseDownload(String id) async {
    final idx = _tasks.indexWhere((t) => t.id == id);
    if (idx < 0) return;
    final task = _tasks[idx];
    if (!task.isActive) return;
    final native = await bd.FileDownloader().taskForId(id);
    if (native is bd.DownloadTask) {
      await bd.FileDownloader().pause(native);
    }
  }

  Future<void> resumeDownload(String id) async {
    final idx = _tasks.indexWhere((t) => t.id == id);
    if (idx < 0) return;
    final task = _tasks[idx];
    if (task.status != DownloadStatus.paused &&
        task.status != DownloadStatus.failed) return;

    // For paused tasks: try native resume (picks up where it left off)
    if (task.status == DownloadStatus.paused) {
      final native = await bd.FileDownloader().taskForId(id);
      if (native is bd.DownloadTask) {
        final resumed = await bd.FileDownloader().resume(native);
        if (resumed) {
          task.status = DownloadStatus.downloading;
          notifyListeners();
          return;
        }
      }
    }

    // For failed tasks or if native resume fails: re-enqueue from scratch
    await _reEnqueue(task);
  }

  Future<void> _reEnqueue(DownloadTask task) async {
    final safeTitle = task.title.replaceAll(RegExp(r'[\\/:*?"<>|]'), '_');
    final ext = task.url.contains('.mkv') ? 'mkv' : 'mp4';
    final fileName = '${safeTitle}_${task.quality}.$ext';

    final isUganda = task.referer.contains(_ugK);
    final isBunnyCdn = task.url.contains('b-cdn.net');

    final headers = <String, String>{
      'User-Agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    };
    if (!isBunnyCdn) {
      headers['Referer'] = isUganda ? task.referer : _mbR;
      headers['Origin'] = isUganda ? _ugO : _mbO;
    }

    final meta = jsonEncode({
      'movieId': task.movieId,
      'title': task.title,
      'quality': task.quality,
      'thumbnail': task.thumbnail,
      'referer': task.referer,
    });

    final bdTask = bd.DownloadTask(
      taskId: task.id,
      url: task.url,
      filename: fileName,
      headers: headers,
      directory: _dlSubDir,
      baseDirectory: bd.BaseDirectory.applicationDocuments,
      group: isUganda ? _ugGroup : _mbGroup,
      updates: bd.Updates.statusAndProgress,
      allowPause: true,
      retries: 10,
      metaData: meta,
      displayName: task.title,
    );

    task.status = DownloadStatus.queued;
    task.downloadedBytes = 0;
    notifyListeners();
    await bd.FileDownloader().enqueue(bdTask);
  }

  Future<void> cancelDownload(String id) async {
    final idx = _tasks.indexWhere((t) => t.id == id);
    if (idx < 0) return;
    final task = _tasks[idx];

    // Remove from UI immediately so it feels instant
    _tasks.removeAt(idx);
    notifyListeners();
    _save();

    // Cancel native task and clean up any partial file
    await bd.FileDownloader().cancelTaskWithId(id);
    if (task.filePath != null) {
      try {
        final f = File(task.filePath!);
        if (await f.exists()) await f.delete();
      } catch (_) {}
    }
  }

  void deleteDownload(String id) {
    final idx = _tasks.indexWhere((t) => t.id == id);
    if (idx < 0) return;
    final task = _tasks[idx];
    if (task.filePath != null) {
      final f = File(task.filePath!);
      f.exists().then((exists) {
        if (exists) f.delete();
      });
    }
    _tasks.removeAt(idx);
    notifyListeners();
    _save();
  }

  // ── Persistence ───────────────────────────────────────────────────────────
  Future<void> _load() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString('downloads_v2');
      if (raw == null) return;
      final list = jsonDecode(raw) as List;
      for (final j in list) {
        final t = DownloadTask.fromJson(Map<String, dynamic>.from(j));
        // Mark in-progress tasks as queued; background_downloader will report
        // the real status via the updates stream once it reconnects.
        if (t.status == DownloadStatus.downloading) {
          t.status = DownloadStatus.queued;
        }
        // If a completed task's file is gone, mark it failed
        if (t.isDone && t.filePath != null && !File(t.filePath!).existsSync()) {
          t.status = DownloadStatus.failed;
          t.errorMessage = 'File no longer on device';
        }
        _tasks.add(t);
      }
      notifyListeners();
    } catch (_) {}
  }

  Future<void> _save() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final saveable = _tasks
          .where((t) => t.status != DownloadStatus.cancelled)
          .toList();
      await prefs.setString(
          'downloads_v2',
          jsonEncode(saveable.map((t) => t.toJson()).toList()));
    } catch (_) {}
  }

  // Kept for call-site compatibility — background_downloader manages
  // notification and media permissions natively.
  Future<void> requestNotificationPermission() async {}
  Future<void> requestMediaPermissions() async {}
}
