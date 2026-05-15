import 'dart:async';
import 'dart:convert';
import '../widgets/adult_preview_thumb.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:screen_brightness/screen_brightness.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:video_player/video_player.dart';
import 'package:wakelock_plus/wakelock_plus.dart';
import '../services/adult_service.dart';
import '../services/download_manager.dart';
import '../theme/app_theme.dart';

class AdultPlayerScreen extends StatefulWidget {
  final AdultVideo video;
  const AdultPlayerScreen({super.key, required this.video});

  @override
  State<AdultPlayerScreen> createState() => _AdultPlayerScreenState();
}

class _AdultPlayerScreenState extends State<AdultPlayerScreen> {
  static const _mediaCh = MethodChannel('com.adiza.moviezbox/media');
  final _service = AdultService();

  // ── Video ──────────────────────────────────────────────────────────────────
  VideoPlayerController? _vpc;
  AdultVideoDetails? _details;
  List<HlsQuality> _hlsQualities = [];
  bool _isInitializing = true;
  String? _error;
  Timer? _positionTimer;
  Timer? _controlsTimer;
  Timer? _saveTimer;

  // ── ValueNotifiers ─────────────────────────────────────────────────────────
  final ValueNotifier<Duration> _pos      = ValueNotifier(Duration.zero);
  final ValueNotifier<Duration> _dur      = ValueNotifier(Duration.zero);
  final ValueNotifier<bool>     _playing  = ValueNotifier(false);
  final ValueNotifier<bool>     _ctrlsVis = ValueNotifier(true);

  // ── Player state ──────────────────────────────────────────────────────────
  bool   _isLocked     = false;
  bool   _isFullscreen = false;
  int    _aspectMode   = 0;   // 0=Fit  1=Fill  2=Stretch
  double _speed        = 1.0;
  double _volume       = 1.0;
  double _brightness   = 0.5;
  String _quality      = 'high';

  // ── Seek slider ────────────────────────────────────────────────────────────
  bool   _isSeeking    = false;
  double _seekDragFrac = 0.0;

  // ── Double-tap seek ────────────────────────────────────────────────────────
  String? _seekSide;
  int     _seekAcc = 0;
  Timer?  _seekClearTimer;

  // ── Tap-flash icon (brief play/pause icon on tap) ─────────────────────────
  bool    _showTapIcon   = false;
  bool    _tapIconIsPlay = false;
  Timer?  _tapIconTimer;
  // Captured in onTapDown so onTap can check whether the centre was hit
  Offset? _tapDownPos;

  // ── Brightness / volume swipe ─────────────────────────────────────────────
  bool    _isDragging   = false;
  String? _dragType;
  double  _dragValue    = 0.0;
  double  _dragStartY   = 0.0;
  double  _dragStartVal = 0.0;

  // ── Related videos ────────────────────────────────────────────────────────
  List<AdultVideo> _related      = [];
  bool _relatedLoading           = false;
  bool _relatedLoadingMore       = false;
  bool _relatedHasMore           = true;
  int  _relatedPage              = 1;
  String _relatedCategory        = 'amateur';
  bool _showScrollTop            = false;
  final _scrollCtrl = ScrollController();

  // ── Init ──────────────────────────────────────────────────────────────────
  @override
  void initState() {
    super.initState();
    SystemChrome.setPreferredOrientations([
      DeviceOrientation.portraitUp,
      DeviceOrientation.landscapeLeft,
      DeviceOrientation.landscapeRight,
    ]);
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
    WakelockPlus.enable();
    ScreenBrightness.instance.application
        .then((v) => _brightness = v).catchError((_) => 0.5);
    _scrollCtrl.addListener(_onPlayerScroll);
    _loadDetails();
    _loadRelated();
  }

  @override
  void dispose() {
    _saveCurrentPosition();
    _positionTimer?.cancel();
    _controlsTimer?.cancel();
    _saveTimer?.cancel();
    _seekClearTimer?.cancel();
    _tapIconTimer?.cancel();
    _vpc?.removeListener(_onVpc);
    _vpc?.dispose();
    _pos.dispose(); _dur.dispose(); _playing.dispose(); _ctrlsVis.dispose();
    _scrollCtrl.dispose();
    WakelockPlus.disable();
    ScreenBrightness.instance.resetApplicationScreenBrightness();
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
    SystemChrome.setPreferredOrientations([DeviceOrientation.portraitUp]);
    super.dispose();
  }

  // ── Resume / position persistence ─────────────────────────────────────────
  String get _resumeKey {
    final id = widget.video.pageUrl.isNotEmpty
        ? widget.video.pageUrl.hashCode.toString()
        : widget.video.title.hashCode.toString();
    return 'resume_adult_$id';
  }

  Future<int?> _loadSavedSeconds() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_resumeKey);
      if (raw == null) return null;
      final map = jsonDecode(raw) as Map<String, dynamic>;
      final v = (map['pos'] as num?)?.toInt() ?? 0;
      return v > 30 ? v : null;
    } catch (_) {
      return null;
    }
  }

  Future<void> _saveCurrentPosition() async {
    if (_vpc == null || !_vpc!.value.isInitialized) return;
    final pos = _vpc!.value.position;
    final dur = _vpc!.value.duration;
    if (dur.inSeconds < 1) return;
    try {
      final prefs = await SharedPreferences.getInstance();
      if (pos.inSeconds < 10 || (dur - pos).inSeconds < 60) {
        await prefs.remove(_resumeKey);
      } else {
        final payload = jsonEncode({
          'pos':     pos.inSeconds,
          'dur':     dur.inSeconds,
          'title':   _details?.title ?? widget.video.title,
          'thumb':   widget.video.thumbnail,
          'pageUrl': widget.video.pageUrl,
          'ts':      DateTime.now().millisecondsSinceEpoch,
        });
        await prefs.setString(_resumeKey, payload);
      }
    } catch (_) {}
  }

  // ── Load ──────────────────────────────────────────────────────────────────
  Future<void> _loadDetails() async {
    setState(() { _isInitializing = true; _error = null; });
    final details = await _service.getVideoDetails(widget.video.pageUrl);
    if (!mounted) return;
    if (details == null || !details.hasVideo) {
      setState(() { _isInitializing = false; _error = 'Could not load video.'; });
      return;
    }
    _details = details;

    // Parse HLS manifest for individual quality variants (360p/480p/720p/1080p)
    if (details.hlsUrl != null) {
      _hlsQualities = await _service.getHlsQualities(details.hlsUrl!);
    }
    if (!mounted) return;

    // Default quality: best HLS variant > high mp4 > low mp4 > hls adaptive
    if (_hlsQualities.isNotEmpty) {
      _quality = _hlsQualities.first.label;
    } else {
      _quality = details.highUrl != null ? 'high' : (details.lowUrl != null ? 'low' : 'hls');
    }
    await _initPlayer();
  }

  Future<void> _initPlayer() async {
    final url = _urlForQuality(_quality);
    if (url == null) {
      setState(() { _isInitializing = false; _error = 'No stream URL.'; });
      return;
    }

    // true on first load; false on quality-switch (want to keep playhead pos)
    final isInitialLoad = _vpc == null;
    final savedPos = _vpc?.value.position ?? Duration.zero;

    _positionTimer?.cancel();
    _saveTimer?.cancel();
    _vpc?.removeListener(_onVpc);
    await _vpc?.dispose();
    _vpc = null;

    final ctrl = VideoPlayerController.networkUrl(
      Uri.parse(url),
      httpHeaders: {'User-Agent': AdultService.userAgent},
    );
    try {
      await ctrl.initialize();
    } catch (_) {
      if (!mounted) return;
      ctrl.dispose();
      setState(() { _isInitializing = false; _error = 'Playback failed. Try another quality.'; });
      return;
    }
    if (!mounted) { ctrl.dispose(); return; }

    _vpc = ctrl;
    _vpc!.addListener(_onVpc);
    _vpc!.setVolume(_volume.clamp(0.0, 1.0));
    _vpc!.setPlaybackSpeed(_speed);
    _dur.value = _vpc!.value.duration;

    // On first load: restore from SharedPreferences.
    // On quality-switch: restore the live playhead position.
    int? resumeSecs;
    if (isInitialLoad) {
      resumeSecs = await _loadSavedSeconds();
      if (!mounted) { ctrl.dispose(); return; }
    }
    final seekTo = resumeSecs != null ? Duration(seconds: resumeSecs) : savedPos;
    if (seekTo > Duration.zero) await _vpc!.seekTo(seekTo);

    _vpc!.play();
    _playing.value = true;

    _positionTimer = Timer.periodic(const Duration(milliseconds: 500), (_) {
      if (_vpc == null || !_vpc!.value.isInitialized) return;
      final v = _vpc!.value;
      if (!_isSeeking) _pos.value = v.position;
      _playing.value = v.isPlaying;
    });

    // Auto-save watch position every 5 s
    _saveTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      _saveCurrentPosition();
    });

    setState(() => _isInitializing = false);
    _resetControls();

    // Show resume SnackBar so the user knows they were brought back to where
    // they left off, with an option to restart from the beginning.
    if (resumeSecs != null && mounted) {
      final mm = resumeSecs ~/ 60;
      final ss = (resumeSecs % 60).toString().padLeft(2, '0');
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text('Resumed from $mm:$ss'),
          duration: const Duration(seconds: 5),
          backgroundColor: Colors.black87,
          action: SnackBarAction(
            label: 'Restart',
            textColor: AppTheme.primary,
            onPressed: () {
              _vpc?.seekTo(Duration.zero);
              _pos.value = Duration.zero;
            },
          ),
        ),
      );
    }
  }

  void _onVpc() { if (_vpc != null) _playing.value = _vpc!.value.isPlaying; }

  void _onPlayerScroll() {
    final px  = _scrollCtrl.position.pixels;
    final max = _scrollCtrl.position.maxScrollExtent;
    // Show/hide scroll-to-top button
    final show = px > 300;
    if (show != _showScrollTop) setState(() => _showScrollTop = show);
    // Infinite scroll — load more related when within 400px of bottom
    if (px >= max - 400 && !_relatedLoadingMore && _relatedHasMore && !_relatedLoading) {
      _loadMoreRelated();
    }
  }

  Future<void> _loadRelated() async {
    setState(() => _relatedLoading = true);
    final t = widget.video.title.toLowerCase();
    const cats = ['amateur','milf','ebony','african','teen','asian','latina','indian'];
    _relatedCategory = cats.firstWhere((c) => t.contains(c), orElse: () => 'amateur');
    _relatedPage = 1;
    final res = await _service.search(_relatedCategory, page: 1);
    if (!mounted) return;
    setState(() {
      _related      = res.where((v) => v.pageUrl != widget.video.pageUrl).toList();
      _relatedLoading = false;
      _relatedHasMore = res.length >= 20;
    });
  }

  Future<void> _loadMoreRelated() async {
    if (_relatedLoadingMore || !_relatedHasMore) return;
    setState(() => _relatedLoadingMore = true);
    final next = _relatedPage + 1;
    final more = await _service.search(_relatedCategory, page: next);
    if (!mounted) return;
    setState(() {
      _relatedPage = next;
      _related.addAll(more.where((v) => v.pageUrl != widget.video.pageUrl));
      _relatedLoadingMore = false;
      _relatedHasMore = more.length >= 20;
    });
  }

  // ── Helpers ────────────────────────────────────────────────────────────────
  String? _urlForQuality(String q) {
    if (_details == null) return null;
    // HLS variant labels like '1080p', '720p', '480p', '360p'
    final hlsMatch = _hlsQualities.where((v) => v.label == q).toList();
    if (hlsMatch.isNotEmpty) return hlsMatch.first.url;
    switch (q) {
      case 'high': return _details!.highUrl ?? _details!.lowUrl ?? _details!.hlsUrl;
      case 'low':  return _details!.lowUrl  ?? _details!.highUrl ?? _details!.hlsUrl;
      case 'hls':  return _details!.hlsUrl  ?? _details!.highUrl ?? _details!.lowUrl;
      default:     return _details!.bestUrl;
    }
  }

  String _fmt(Duration d) {
    final h = d.inHours;
    final m = d.inMinutes.remainder(60).toString().padLeft(2, '0');
    final s = d.inSeconds.remainder(60).toString().padLeft(2, '0');
    return h > 0 ? '$h:$m:$s' : '$m:$s';
  }

  // ── Controls ──────────────────────────────────────────────────────────────
  void _resetControls() {
    _controlsTimer?.cancel();
    if (!_ctrlsVis.value) _ctrlsVis.value = true;
    _controlsTimer = Timer(const Duration(seconds: 5), () {
      if (!_isSeeking && !_isDragging) _ctrlsVis.value = false;
    });
  }

  void _togglePlay() {
    if (_vpc == null) return;
    final willPause = _vpc!.value.isPlaying;
    willPause ? _vpc!.pause() : _vpc!.play();
    _resetControls();
    // Flash the play/pause icon briefly then fade it away.
    _tapIconTimer?.cancel();
    setState(() { _showTapIcon = true; _tapIconIsPlay = !willPause; });
    _tapIconTimer = Timer(const Duration(milliseconds: 700), () {
      if (mounted) setState(() => _showTapIcon = false);
    });
  }

  void _toggleLock() {
    setState(() => _isLocked = !_isLocked);
    if (!_isLocked) _resetControls();
  }

  void _cycleAspect() {
    setState(() => _aspectMode = (_aspectMode + 1) % 3);
    _resetControls();
  }

  String get _aspectLabel => ['Fit', 'Fill', 'Stretch'][_aspectMode];
  String get _qualityLabel {
    // If it's an HLS variant label (e.g. '1080p'), show it directly
    if (_hlsQualities.any((q) => q.label == _quality)) return _quality;
    switch (_quality) {
      case 'high': return 'HD';
      case 'low':  return 'SD';
      default:     return 'HLS';
    }
  }

  void _seekBy(int secs) {
    if (_vpc == null) return;
    var np = _vpc!.value.position + Duration(seconds: secs);
    final tot = _vpc!.value.duration;
    if (np < Duration.zero) np = Duration.zero;
    if (np > tot) np = tot;
    _vpc!.seekTo(np);
    _pos.value = np;
    setState(() { _seekSide = secs < 0 ? 'left' : 'right'; _seekAcc += secs.abs(); });
    _seekClearTimer?.cancel();
    _seekClearTimer = Timer(const Duration(milliseconds: 850), () {
      if (mounted) setState(() { _seekSide = null; _seekAcc = 0; });
    });
    _resetControls();
  }

  void _applyVolumeAndBoost(double v) {
    _volume = v.clamp(0.0, 2.0);
    _vpc?.setVolume(_volume.clamp(0.0, 1.0));
    final gain = _volume > 1.0 ? ((_volume - 1.0) * 2000).round() : 0;
    _mediaCh.invokeMethod('setBoost', {'gain': gain}).catchError((_) {});
  }

  Future<void> _enterPip() async {
    try { await _mediaCh.invokeMethod<bool>('enterPip'); } catch (_) {}
  }

  // ── Fullscreen ─────────────────────────────────────────────────────────────
  void _enterFullscreen() {
    setState(() => _isFullscreen = true);
    SystemChrome.setPreferredOrientations([
      DeviceOrientation.landscapeLeft,
      DeviceOrientation.landscapeRight,
    ]);
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.immersiveSticky);
  }

  void _exitFullscreen() {
    setState(() => _isFullscreen = false);
    SystemChrome.setPreferredOrientations([
      DeviceOrientation.portraitUp,
      DeviceOrientation.landscapeLeft,
      DeviceOrientation.landscapeRight,
    ]);
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
  }

  // ── Quality sheet ─────────────────────────────────────────────────────────
  void _showQualitySheet() {
    if (_details == null) return;
    _controlsTimer?.cancel();

    // Build option list: prefer individual HLS variants; fall back to mp4 entries
    final opts = <MapEntry<String, String>>[];
    if (_hlsQualities.isNotEmpty) {
      for (final q in _hlsQualities) {
        final res = int.tryParse(q.label.replaceAll('p', '')) ?? 0;
        final badge = res >= 1080
            ? ' · Full HD'
            : res >= 720
                ? ' · HD'
                : res >= 480
                    ? ' · SD'
                    : '';
        opts.add(MapEntry(q.label, '${q.label}$badge'));
      }
      // Also offer the raw mp4 direct links as fallback options
      if (_details!.highUrl != null) opts.add(const MapEntry('high', 'Direct MP4 (High)'));
      if (_details!.lowUrl  != null) opts.add(const MapEntry('low',  'Direct MP4 (Low)'));
    } else {
      if (_details!.highUrl != null) opts.add(const MapEntry('high', 'High Quality'));
      if (_details!.lowUrl  != null) opts.add(const MapEntry('low',  'Low Quality'));
      if (_details!.hlsUrl  != null) opts.add(const MapEntry('hls',  'HLS Adaptive'));
    }

    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.black,
      isScrollControlled: true,
      useSafeArea: true,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(16))),
      builder: (_) => SafeArea(
        top: false,
        child: SingleChildScrollView(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Container(width: 36, height: 4, margin: const EdgeInsets.only(top: 10, bottom: 10),
                decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2))),
            const Padding(padding: EdgeInsets.fromLTRB(16, 0, 16, 10),
              child: Text('Select Quality', style: TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.w700))),
            ...opts.map((e) => ListTile(
              leading: Icon(e.key == _quality ? Icons.radio_button_checked : Icons.radio_button_off,
                  color: e.key == _quality ? AppTheme.primary : Colors.white38),
              title: Text(e.value, style: const TextStyle(color: Colors.white, fontSize: 14)),
              onTap: () async {
                Navigator.pop(context);
                if (e.key == _quality) return;
                setState(() { _quality = e.key; _isInitializing = true; _error = null; });
                await _initPlayer();
              },
            )),
            const SizedBox(height: 16),
          ]),
        ),
      ),
    );
  }

  // ── Speed sheet ───────────────────────────────────────────────────────────
  void _showSpeedSheet() {
    _controlsTimer?.cancel();
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.black,
      isScrollControlled: true,
      useSafeArea: true,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(16))),
      builder: (_) {
        const speeds = [0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0];
        return SafeArea(
          top: false,
          child: SingleChildScrollView(
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Container(width: 36, height: 4, margin: const EdgeInsets.only(top: 10, bottom: 10),
                  decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2))),
              const Padding(padding: EdgeInsets.fromLTRB(16, 0, 16, 10),
                child: Text('Playback Speed', style: TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.w700))),
              Padding(
                padding: const EdgeInsets.fromLTRB(16, 0, 16, 0),
                child: Wrap(
                  spacing: 10, runSpacing: 10,
                  alignment: WrapAlignment.center,
                  children: speeds.map((s) {
                    final sel = s == _speed;
                    return GestureDetector(
                      onTap: () {
                        Navigator.pop(context);
                        setState(() => _speed = s);
                        _vpc?.setPlaybackSpeed(s);
                      },
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 9),
                        decoration: BoxDecoration(
                          color: sel ? AppTheme.primary : const Color(0xFF222222),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: sel ? AppTheme.primary : Colors.white12),
                        ),
                        child: Text('${s}x', style: TextStyle(
                            color: sel ? Colors.white : Colors.white70,
                            fontWeight: sel ? FontWeight.w700 : FontWeight.w400)),
                      ),
                    );
                  }).toList(),
                ),
              ),
              const SizedBox(height: 20),
            ]),
          ),
        );
      },
    );
  }

  // ── Top toast (matches Movies-side style) ─────────────────────────────────
  void _showAdultTopToast(String message) {
    final overlay = Overlay.of(context, rootOverlay: true);
    late OverlayEntry entry;
    entry = OverlayEntry(
      builder: (_) => _AdultTopToast(message: message, onDone: () => entry.remove()),
    );
    overlay.insert(entry);
  }

  // ── Download ──────────────────────────────────────────────────────────────
  void _showDownloadSheet() {
    if (_details == null) return;
    _controlsTimer?.cancel();

    // Build download options:
    // Prefer resolution-specific direct MP4 URLs (1080p, 720p, 480p, 360p…)
    // Fall back to highUrl/lowUrl if none were found on the page.
    final List<({String url, String res})> opts;
    if (_details!.directUrls.isNotEmpty) {
      opts = _details!.directUrls.entries
          .map((e) => (url: e.value, res: e.key))
          .toList();
    } else {
      final highLabel = _hlsQualities.isNotEmpty ? _hlsQualities.first.label : 'HD';
      final lowLabel  = _hlsQualities.isNotEmpty ? _hlsQualities.last.label  : 'SD';
      opts = [
        if (_details!.highUrl != null) (url: _details!.highUrl!, res: highLabel),
        if (_details!.lowUrl  != null) (url: _details!.lowUrl!,  res: lowLabel),
      ];
    }
    if (opts.isEmpty) {
      _showAdultTopToast('No download URL available');
      return;
    }

    final title   = _details?.title ?? widget.video.title;
    final thumb   = widget.video.thumbnail;
    final manager = context.read<DownloadManager>();

    // sizes map url → resolved size string (null = still loading)
    final sizes    = <String, String?>{for (final o in opts) o.url: null};
    final fetching = <String>{};

    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.black,
      useSafeArea: true,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(16))),
      builder: (sheetCtx) => StatefulBuilder(
        builder: (innerCtx, setSS) {
          // Fire one HEAD request per URL; never fire the same URL twice
          for (final o in opts) {
            if (sizes[o.url] == null && !fetching.contains(o.url)) {
              fetching.add(o.url);
              _service.getFileSize(o.url).then((sz) {
                if (innerCtx.mounted) setSS(() => sizes[o.url] = sz);
              });
            }
          }
          return SafeArea(
            top: false,
            child: SingleChildScrollView(
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                Container(
                  width: 36, height: 4,
                  margin: const EdgeInsets.only(top: 10, bottom: 10),
                  decoration: BoxDecoration(
                      color: Colors.white24,
                      borderRadius: BorderRadius.circular(2)),
                ),
                const Padding(
                  padding: EdgeInsets.fromLTRB(16, 0, 16, 10),
                  child: Row(children: [
                    Icon(Icons.download_rounded, color: Colors.white, size: 20),
                    SizedBox(width: 8),
                    Text('Download Video',
                        style: TextStyle(
                            color: Colors.white,
                            fontSize: 15,
                            fontWeight: FontWeight.w700)),
                  ]),
                ),
                ...opts.map((o) {
                  final sz  = sizes[o.url];
                  final res = int.tryParse(o.res.replaceAll('p', '')) ?? 0;
                  final badge = res >= 1080 ? 'Full HD' : res >= 720 ? 'HD' : 'SD';
                  return ListTile(
                    leading: CircleAvatar(
                      radius: 18,
                      backgroundColor: AppTheme.primary.withOpacity(0.15),
                      child: Text(o.res,
                          style: TextStyle(
                              color: AppTheme.primary,
                              fontSize: 10,
                              fontWeight: FontWeight.w800)),
                    ),
                    title: Text('${o.res} · $badge',
                        style: const TextStyle(
                            color: Colors.white,
                            fontSize: 14,
                            fontWeight: FontWeight.w600)),
                    subtitle: Text(
                      sz == null ? 'Checking file size…' : 'Tap to download  ·  saves to Downloads',
                      style: const TextStyle(color: Colors.white38, fontSize: 11),
                    ),
                    trailing: sz == null
                        ? const SizedBox(
                            width: 14, height: 14,
                            child: CircularProgressIndicator(
                                strokeWidth: 1.5, color: Colors.white38))
                        : Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 10, vertical: 5),
                            decoration: BoxDecoration(
                                color: AppTheme.primary.withOpacity(0.15),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(
                                    color: AppTheme.primary.withOpacity(0.5))),
                            child: Text(sz,
                                style: TextStyle(
                                    color: AppTheme.primary,
                                    fontSize: 13,
                                    fontWeight: FontWeight.w800)),
                          ),
                    onTap: () {
                      Navigator.pop(sheetCtx);
                      manager.startDownload(
                        movieId: widget.video.pageUrl.isNotEmpty
                            ? widget.video.pageUrl
                            : widget.video.title.hashCode.toString(),
                        title: title,
                        quality: o.res,
                        url: o.url,
                        thumbnail: thumb,
                      );
                      _showAdultTopToast('"$title" (${o.res}) added to downloads…');
                    },
                  );
                }),
                const SizedBox(height: 16),
              ]),
            ),
          );
        },
      ),
    );
  }

  // ── Build ──────────────────────────────────────────────────────────────────
  @override
  Widget build(BuildContext context) {
    // Fullscreen: show ONLY the player, no info/related
    if (_isFullscreen) {
      return Scaffold(
        backgroundColor: Colors.black,
        body: _buildPlayerStack(fullscreen: true),
      );
    }

    return Scaffold(
      backgroundColor: Colors.black,
      body: SafeArea(
        child: Stack(children: [
        CustomScrollView(
          controller: _scrollCtrl,
          slivers: [
            SliverToBoxAdapter(child: _buildPlayerStack(fullscreen: false)),
            SliverToBoxAdapter(child: _buildInfo()),
            SliverToBoxAdapter(child: _buildRelatedHeader()),
            _relatedLoading
                ? const SliverToBoxAdapter(child: Center(child: Padding(
                    padding: EdgeInsets.all(24),
                    child: CircularProgressIndicator(color: Color(0xFFE50914)))))
                : SliverGrid(
                    delegate: SliverChildBuilderDelegate(
                      (_, i) {
                        if (i >= _related.length) {
                          // Loading skeleton at the end
                          return Container(
                            decoration: BoxDecoration(
                              color: Colors.black,
                              borderRadius: BorderRadius.circular(8)),
                          );
                        }
                        return _RelatedCard(video: _related[i], onTap: () {
                          Navigator.pushReplacement(context, MaterialPageRoute(
                              builder: (_) => AdultPlayerScreen(video: _related[i])));
                        });
                      },
                      childCount: _related.length + (_relatedLoadingMore ? 3 : 0),
                    ),
                    gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                      crossAxisCount: 3,
                      childAspectRatio: 0.65,
                      mainAxisSpacing: 8,
                      crossAxisSpacing: 8,
                    ),
                  ),
            if (_relatedLoadingMore)
              const SliverToBoxAdapter(
                child: Center(child: Padding(
                  padding: EdgeInsets.symmetric(vertical: 12),
                  child: CircularProgressIndicator(color: Color(0xFFE50914), strokeWidth: 2.5))),
              ),
            const SliverToBoxAdapter(child: SizedBox(height: 80)),
          ],
        ),
        // Scroll-to-top FAB — takes user back up to the video player
        Positioned(
          bottom: 72, right: 20,
          child: AnimatedOpacity(
            opacity: _showScrollTop ? 1.0 : 0.0,
            duration: const Duration(milliseconds: 300),
            child: IgnorePointer(
              ignoring: !_showScrollTop,
              child: GestureDetector(
                onTap: () => _scrollCtrl.animateTo(0,
                    duration: const Duration(milliseconds: 500),
                    curve: Curves.easeOutCubic),
                child: Container(
                  width: 44, height: 44,
                  decoration: BoxDecoration(
                    color: const Color(0xFFE50914), shape: BoxShape.circle,
                    boxShadow: [BoxShadow(
                      color: const Color(0xFFE50914).withOpacity(0.45),
                      blurRadius: 14, offset: const Offset(0, 4))],
                  ),
                  child: const Icon(Icons.keyboard_arrow_up_rounded,
                      color: Colors.white, size: 26),
                ),
              ),
            ),
          ),
        ),
      ]),
      ),
    );
  }

  // ── Player stack (portrait or fullscreen) ──────────────────────────────────
  Widget _buildPlayerStack({required bool fullscreen}) {
    final size = MediaQuery.of(context).size;
    final w = size.width;
    final h = fullscreen
        ? size.height        // fill entire screen in landscape
        : w * 9 / 16;        // proper 16:9 in portrait — no height cap

    return SizedBox(
      width: w,
      height: h,
      child: Stack(
        fit: StackFit.expand,
        clipBehavior: Clip.hardEdge,
        children: [
          // ── Video ──
          _buildVideo(),

          // ── Gesture layer ──
          if (!_isLocked)
            GestureDetector(
              behavior: HitTestBehavior.translucent,
              // Capture the tap position so onTap can decide if it hit centre
              onTapDown: (d) => _tapDownPos = d.localPosition,
              onTap: () {
                // Only toggle play/pause when the tap lands in the centre
                // 50 % zone (25–75 % of width, 25–75 % of height).
                final p = _tapDownPos;
                if (p != null &&
                    p.dx >= w * 0.25 && p.dx <= w * 0.75 &&
                    p.dy >= h * 0.25 && p.dy <= h * 0.75) {
                  _togglePlay();
                }
              },
              onDoubleTapDown: (d) {
                final x = d.localPosition.dx;
                if (x < w * 0.35) _seekBy(-10);
                else if (x > w * 0.65) _seekBy(10);
                else { _togglePlay(); _resetControls(); }
              },
              onDoubleTap: () {},
              onVerticalDragStart: (d) {
                _dragStartY = d.localPosition.dy;
                _dragType = d.localPosition.dx < w / 2 ? 'brightness' : 'volume';
                _dragStartVal = _dragType == 'brightness' ? _brightness : _volume;
                setState(() { _isDragging = true; _dragValue = _dragStartVal; });
                _controlsTimer?.cancel();
              },
              onVerticalDragUpdate: (d) {
                final delta = (_dragStartY - d.localPosition.dy) / h;
                if (_dragType == 'brightness') {
                  final nv = (_dragStartVal + delta * 1.5).clamp(0.0, 1.0);
                  setState(() => _dragValue = nv);
                  _brightness = nv;
                  ScreenBrightness.instance.setApplicationScreenBrightness(nv).catchError((_) {});
                } else {
                  final nv = (_dragStartVal + delta * 2.0).clamp(0.0, 2.0);
                  setState(() => _dragValue = nv);
                  _applyVolumeAndBoost(nv);
                }
              },
              onVerticalDragEnd: (_) {
                setState(() { _isDragging = false; _dragType = null; });
                _resetControls();
              },
              child: SizedBox(width: w, height: h),
            ),

          // ── Seek ripple overlays ──
          if (_seekSide == 'left')  _seekOverlay(false, w, h),
          if (_seekSide == 'right') _seekOverlay(true,  w, h),

          // ── Drag indicator ──
          if (_isDragging) _dragIndicator(),

          // ── Controls overlay ──
          ValueListenableBuilder<bool>(
            valueListenable: _ctrlsVis,
            builder: (_, vis, __) => AnimatedOpacity(
              opacity: (_isLocked || !vis) ? 0.0 : 1.0,
              duration: const Duration(milliseconds: 250),
              child: IgnorePointer(
                ignoring: !vis || _isLocked,
                child: _controls(w, h, fullscreen: fullscreen),
              ),
            ),
          ),

          // ── Tap-flash icon (appears on tap then fades away) ───────────────
          IgnorePointer(
            child: AnimatedOpacity(
              opacity: _showTapIcon ? 1.0 : 0.0,
              duration: const Duration(milliseconds: 250),
              child: Center(
                child: Container(
                  width: 72, height: 72,
                  decoration: BoxDecoration(
                    color: Colors.black54,
                    shape: BoxShape.circle,
                    border: Border.all(color: Colors.white24, width: 1.5),
                  ),
                  child: Icon(
                    _tapIconIsPlay
                        ? Icons.play_arrow_rounded
                        : Icons.pause_rounded,
                    color: Colors.white,
                    size: 42,
                  ),
                ),
              ),
            ),
          ),

          // ── Lock button — always visible ──
          if (_ctrlsVis.value || _isLocked)
            Positioned(
              right: 12, top: h / 2 - 22,
              child: GestureDetector(
                onTap: _toggleLock,
                child: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: const BoxDecoration(color: Colors.black54, shape: BoxShape.circle),
                  child: Icon(
                    _isLocked ? Icons.lock_rounded : Icons.lock_open_rounded,
                    color: _isLocked ? AppTheme.primary : Colors.white70,
                    size: 22,
                  ),
                ),
              ),
            ),

          // ── Initializing ──
          if (_isInitializing)
            const Center(child: CircularProgressIndicator(color: Color(0xFFE50914), strokeWidth: 3)),

          // ── Error ──
          if (_error != null && !_isInitializing)
            Center(child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                const Icon(Icons.error_outline_rounded, color: Color(0xFFE50914), size: 42),
                const SizedBox(height: 10),
                Text(_error!, style: const TextStyle(color: Colors.white70, fontSize: 13),
                    textAlign: TextAlign.center),
                const SizedBox(height: 14),
                ElevatedButton.icon(
                  onPressed: _loadDetails,
                  icon: const Icon(Icons.refresh_rounded),
                  label: const Text('Retry'),
                  style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary),
                ),
              ]),
            )),
        ],
      ),
    );
  }

  // ── Video widget ───────────────────────────────────────────────────────────
  Widget _buildVideo() {
    if (_vpc == null || !_vpc!.value.isInitialized) return const SizedBox.shrink();
    final vp = VideoPlayer(_vpc!);
    switch (_aspectMode) {
      case 1: return SizedBox.expand(child: FittedBox(fit: BoxFit.cover,
          child: SizedBox(width: _vpc!.value.size.width, height: _vpc!.value.size.height, child: vp)));
      case 2: return SizedBox.expand(child: FittedBox(fit: BoxFit.fill,
          child: SizedBox(width: _vpc!.value.size.width, height: _vpc!.value.size.height, child: vp)));
      default: return Center(child: AspectRatio(aspectRatio: _vpc!.value.aspectRatio, child: vp));
    }
  }

  // ── Seek ripple ────────────────────────────────────────────────────────────
  Widget _seekOverlay(bool right, double w, double h) {
    return Positioned(
      left: right ? w * 0.5 : 0, right: right ? 0 : w * 0.5,
      top: 0, bottom: 0,
      child: Container(
        decoration: BoxDecoration(color: Colors.black.withOpacity(0.32),
            borderRadius: BorderRadius.horizontal(
              left: right ? Radius.zero : const Radius.circular(0),
              right: right ? const Radius.circular(0) : Radius.zero)),
        child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
          Icon(right ? Icons.forward_10_rounded : Icons.replay_10_rounded,
              color: Colors.white, size: 44),
          const SizedBox(height: 6),
          Text('$_seekAcc s', style: const TextStyle(
              color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
        ]),
      ),
    );
  }

  // ── Drag indicator (brightness / volume) ──────────────────────────────────
  Widget _dragIndicator() {
    final isBright = _dragType == 'brightness';
    final isBoost  = !isBright && _dragValue > 1.0;
    const boostColor = Color(0xFFFF8C00);
    final icon = isBright
        ? (_dragValue > 0.6 ? Icons.brightness_high_rounded
            : _dragValue > 0.3 ? Icons.brightness_medium_rounded
            : Icons.brightness_low_rounded)
        : isBoost ? Icons.bolt_rounded
            : (_dragValue > 0.5 ? Icons.volume_up_rounded : Icons.volume_down_rounded);
    final normalFrac = isBright ? _dragValue : _dragValue.clamp(0.0, 1.0);
    final boostFrac  = isBoost ? (_dragValue - 1.0).clamp(0.0, 1.0) : 0.0;

    return Center(child: Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 18),
      decoration: BoxDecoration(
        color: Colors.black.withOpacity(0.78), borderRadius: BorderRadius.circular(18),
        border: isBoost ? Border.all(color: boostColor.withOpacity(0.5), width: 1.5) : null),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, color: isBoost ? boostColor : Colors.white, size: 34),
        const SizedBox(height: 8),
        Text(isBright ? 'Brightness' : isBoost ? 'BOOST' : 'Volume',
            style: TextStyle(color: isBoost ? boostColor : Colors.white60, fontSize: 12,
                fontWeight: isBoost ? FontWeight.w700 : FontWeight.normal)),
        const SizedBox(height: 10),
        SizedBox(width: 110, child: LinearProgressIndicator(
          value: normalFrac, backgroundColor: Colors.white24,
          valueColor: AlwaysStoppedAnimation(isBright ? Colors.amber : AppTheme.primary),
          minHeight: 5, borderRadius: BorderRadius.circular(3))),
        if (isBoost) ...[
          const SizedBox(height: 5),
          SizedBox(width: 110, child: LinearProgressIndicator(
            value: boostFrac, backgroundColor: Colors.white24,
            valueColor: const AlwaysStoppedAnimation(boostColor),
            minHeight: 5, borderRadius: BorderRadius.circular(3))),
        ],
        const SizedBox(height: 6),
        Text('${(_dragValue * 100).round()}%',
            style: TextStyle(color: isBoost ? boostColor : Colors.white,
                fontSize: 14, fontWeight: FontWeight.bold)),
      ]),
    ));
  }

  // ── Controls overlay ──────────────────────────────────────────────────────
  Widget _controls(double w, double h, {required bool fullscreen}) {
    final topPad    = fullscreen ? 28.0 : 8.0;
    final bottomPad = fullscreen ? 20.0 : 10.0;

    // Gradient is in a separate IgnorePointer layer so that taps on the
    // empty areas of the player fall through to the background GestureDetector
    // (which calls _togglePlay). Only the interactive widgets (seek bar,
    // chips) absorb taps — the blank gradient areas do not.
    return Stack(
      fit: StackFit.expand,
      children: [
        IgnorePointer(
          child: Container(
            decoration: const BoxDecoration(gradient: LinearGradient(
              begin: Alignment.topCenter, end: Alignment.bottomCenter,
              colors: [Color(0xCC000000), Colors.transparent, Color(0xCC000000)],
              stops: [0.0, 0.45, 1.0],
            )),
          ),
        ),
        Column(children: [
        // ── Top bar ──────────────────────────────────────────────────────────
        // Top bar — only shown in fullscreen; portrait has no top overlay
        // (the duplicate fullscreen icon that was here is removed — the
        //  bottom-right chip row already has the toggle)
        if (fullscreen)
          Padding(
            padding: EdgeInsets.fromLTRB(8, topPad, 8, 0),
            child: Row(children: [
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.picture_in_picture_alt_rounded,
                    color: Colors.white, size: 20),
                onPressed: _enterPip),
              IconButton(
                icon: const Icon(Icons.download_rounded,
                    color: Color(0xFFE50914), size: 22),
                onPressed: _showDownloadSheet),
            ]),
          ),

        // ── Centre: transparent tap area (tap handled by background gesture) ──
        const Expanded(child: SizedBox.expand()),

        // ── Bottom bar ────────────────────────────────────────────────────────
        Padding(
          padding: EdgeInsets.fromLTRB(12, 0, 12, bottomPad),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            // ── Seek bar ──
            ValueListenableBuilder<Duration>(
              valueListenable: _pos,
              builder: (_, position, __) => ValueListenableBuilder<Duration>(
                valueListenable: _dur,
                builder: (_, duration, __) {
                  final frac = duration.inMilliseconds > 0
                      ? (_isSeeking
                          ? _seekDragFrac
                          : (position.inMilliseconds / duration.inMilliseconds)
                              .clamp(0.0, 1.0))
                      : 0.0;
                  return Column(mainAxisSize: MainAxisSize.min, children: [
                    Row(children: [
                      Text(
                        _fmt(_isSeeking
                            ? Duration(milliseconds:
                                (_seekDragFrac * duration.inMilliseconds).round())
                            : position),
                        style: const TextStyle(color: Colors.white70, fontSize: 10)),
                      const Spacer(),
                      Text(_fmt(duration),
                          style: const TextStyle(color: Colors.white70, fontSize: 10)),
                    ]),
                    SliderTheme(
                      data: SliderThemeData(
                        trackHeight: 2.5,
                        thumbShape:
                            const RoundSliderThumbShape(enabledThumbRadius: 6),
                        activeTrackColor: AppTheme.primary,
                        inactiveTrackColor: Colors.white24,
                        thumbColor: Colors.white,
                        overlayColor: Colors.white12,
                      ),
                      child: Slider(
                        value: frac.toDouble(),
                        onChangeStart: (_) => setState(() => _isSeeking = true),
                        onChanged: (v) => setState(() {
                          _seekDragFrac = v;
                          _isSeeking = true;
                        }),
                        onChangeEnd: (v) {
                          _vpc?.seekTo(Duration(
                              milliseconds:
                                  (v * _dur.value.inMilliseconds).round()));
                          setState(() {
                            _isSeeking = false;
                            _seekDragFrac = 0;
                          });
                          _resetControls();
                        },
                      ),
                    ),
                  ]);
                },
              ),
            ),
            // ── Action chips + download + fullscreen toggle row ──
            Row(children: [
              // Speed
              _chip('${_speed}x', const Color(0xFF2A2A2A), _showSpeedSheet),
              const SizedBox(width: 6),
              // Aspect mode (Fit / Fill / Stretch)
              _chip(_aspectLabel, const Color(0xFF2A2A2A), _cycleAspect),
              const SizedBox(width: 6),
              // Quality
              _chip(_qualityLabel, AppTheme.primary, _showQualitySheet),
              const Spacer(),
              // Download — always visible in both portrait and fullscreen
              IconButton(
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
                icon: const Icon(Icons.download_rounded,
                    color: Color(0xFFE50914), size: 22),
                onPressed: _showDownloadSheet,
              ),
              // Fullscreen toggle
              IconButton(
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 36, minHeight: 36),
                icon: Icon(
                  fullscreen
                      ? Icons.fullscreen_exit_rounded
                      : Icons.fullscreen_rounded,
                  color: Colors.white,
                  size: 28,
                ),
                onPressed: fullscreen ? _exitFullscreen : _enterFullscreen,
              ),
            ]),
          ]),
        ),
        ]),   // Column
      ],      // Stack children
    );        // Stack
  }

  Widget _chip(String label, Color bg, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
        decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(5)),
        child: Text(label,
            style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.w600)),
      ),
    );
  }

  // ── Info + related headers ─────────────────────────────────────────────────
  Widget _buildInfo() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(12, 12, 12, 0),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(_details?.title ?? widget.video.title,
            style: const TextStyle(
                color: Colors.white, fontSize: 14, fontWeight: FontWeight.w700, height: 1.4)),
        if (widget.video.views.isNotEmpty) ...[
          const SizedBox(height: 4),
          Text(widget.video.views,
              style: const TextStyle(color: Colors.white38, fontSize: 12)),
        ],
        const SizedBox(height: 10),
        const Divider(color: Colors.white10, height: 1),
      ]),
    );
  }

  Widget _buildRelatedHeader() {
    return const Padding(
      padding: EdgeInsets.fromLTRB(12, 12, 12, 8),
      child: Text('Related Videos',
          style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w700)),
    );
  }
}

// ── Related video card ────────────────────────────────────────────────────────

class _RelatedCard extends StatelessWidget {
  final AdultVideo video;
  final VoidCallback onTap;
  const _RelatedCard({required this.video, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        decoration: BoxDecoration(
          color: Colors.black,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: Colors.white10)),
        clipBehavior: Clip.hardEdge,
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Expanded(child: Stack(fit: StackFit.expand, children: [
            AdultPreviewThumb(
              thumbnail: video.thumbnail,
              previewGif: video.previewGif,
            ),
            const Center(child: Icon(Icons.play_circle_fill_rounded,
                color: Colors.white38, size: 30)),
            if (video.duration.isNotEmpty)
              Positioned(bottom: 3, right: 4, child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 3, vertical: 1),
                decoration: BoxDecoration(color: Colors.black87, borderRadius: BorderRadius.circular(3)),
                child: Text(video.duration,
                    style: const TextStyle(color: Colors.white, fontSize: 8, fontWeight: FontWeight.w600)),
              )),
          ])),
          Padding(
            padding: const EdgeInsets.fromLTRB(5, 4, 5, 5),
            child: Text(video.title, maxLines: 2, overflow: TextOverflow.ellipsis,
                style: const TextStyle(
                    color: Colors.white, fontSize: 10, fontWeight: FontWeight.w500, height: 1.3)),
          ),
        ]),
      ),
    );
  }
}

// ── Animated top-toast widget (mirrors Movies-side _TopToast) ────────────────

class _AdultTopToast extends StatefulWidget {
  final String message;
  final VoidCallback onDone;
  const _AdultTopToast({required this.message, required this.onDone});
  @override
  State<_AdultTopToast> createState() => _AdultTopToastState();
}

class _AdultTopToastState extends State<_AdultTopToast> with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;
  late final Animation<double> _opacity;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 300));
    _opacity = CurvedAnimation(parent: _ctrl, curve: Curves.easeOut);
    _ctrl.forward();
    Future.delayed(const Duration(milliseconds: 2000), () async {
      if (mounted) {
        await _ctrl.reverse();
        widget.onDone();
      }
    });
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    final top = MediaQuery.of(context).padding.top + 14;
    return Positioned(
      top: top, left: 16, right: 16,
      child: FadeTransition(
        opacity: _opacity,
        child: Material(
          color: Colors.transparent,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 13),
            decoration: BoxDecoration(
              color: Colors.black,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: const Color(0xFFE50914).withOpacity(0.5)),
              boxShadow: const [BoxShadow(color: Colors.black54, blurRadius: 16, offset: Offset(0, 4))],
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                Container(
                  width: 34, height: 34,
                  decoration: BoxDecoration(
                    color: const Color(0xFFE50914),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: const Icon(Icons.arrow_circle_down_rounded, color: Colors.white, size: 20),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    widget.message,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: const TextStyle(color: Colors.white, fontSize: 13.5, fontWeight: FontWeight.w600),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
