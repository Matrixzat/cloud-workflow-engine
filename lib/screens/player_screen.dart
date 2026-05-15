import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:video_player/video_player.dart';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:screen_brightness/screen_brightness.dart';
import 'package:wakelock_plus/wakelock_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../api/models.dart';
import '../api/moviebox_client.dart';
import '../api/vod_client.dart';

import '../theme/app_theme.dart';
import '../utils/app_cache_manager.dart';
import '../utils/quality_utils.dart';
import '../widgets/cast_button.dart';
import 'detail_screen.dart';
import 'uganda_detail_screen.dart';
import 'uganda_view_all_screen.dart';

final _ugR = String.fromCharCodes([104,116,116,112,115,58,47,47,109,117,110,111,119,97,116,99,104,46,111,114,103,47]);
final _ugO = String.fromCharCodes([104,116,116,112,115,58,47,47,109,117,110,111,119,97,116,99,104,46,111,114,103]);
final _mbR = String.fromCharCodes([104,116,116,112,115,58,47,47,102,109,111,118,105,101,115,117,110,98,108,111,99,107,101,100,46,110,101,116,47]);
final _mbO = String.fromCharCodes([104,116,116,112,115,58,47,47,102,109,111,118,105,101,115,117,110,98,108,111,99,107,101,100,46,110,101,116]);
final _ugK = String.fromCharCodes([109,117,110,111,119,97,116,99,104]);

class PlayerScreen extends StatefulWidget {
  final Movie movie;
  final MovieSource source;
  final int? season;
  final int? episode;
  final String? preSelectedSubtitle;
  final List<MovieSource>? allSources;
  final List<SeasonInfo>? seasons;
  final List<Movie>? ugandaPlaylist;
  final int? ugandaIndex;
  final bool noRelated;

  const PlayerScreen({
    super.key,
    required this.movie,
    required this.source,
    this.season,
    this.episode,
    this.preSelectedSubtitle,
    this.allSources,
    this.seasons,
    this.ugandaPlaylist,
    this.ugandaIndex,
    this.noRelated = false,
  });

  @override
  State<PlayerScreen> createState() => _PlayerScreenState();
}

class _PlayerScreenState extends State<PlayerScreen> {
  static const _mediaCh = MethodChannel('com.adiza.moviezbox/media');

  // ── Video ──────────────────────────────────────────────────────────────────
  VideoPlayerController? _vpc;
  bool _isInitializing = true;
  String? _error;
  Timer? _positionTimer;
  Timer? _controlsTimer;
  Timer? _saveTimer;

  // ── ValueNotifiers (performance — avoids full-tree rebuilds) ─────────────
  final ValueNotifier<Duration> _pos = ValueNotifier(Duration.zero);
  final ValueNotifier<Duration> _dur = ValueNotifier(Duration.zero);
  final ValueNotifier<bool> _playing = ValueNotifier(false);
  final ValueNotifier<double> _bufferedFrac = ValueNotifier(0.0);
  final ValueNotifier<bool> _ctrlsVisible = ValueNotifier(true);
  final ValueNotifier<String> _subText = ValueNotifier('');

  // ── Player state ──────────────────────────────────────────────────────────
  bool _isFullscreen = false;
  bool _isLocked = false;
  bool _isPip = false;
  int _aspectMode = 0; // 0=contain  1=cover/crop  2=stretch
  double _speed = 1.0;
  double _volume = 1.0;
  double _brightness = 0.5;

  // ── Seek slider drag ──────────────────────────────────────────────────────
  bool _isSeeking = false;
  double _seekDragFrac = 0.0;

  // ── Double-tap seek animation ──────────────────────────────────────────────
  String? _seekSide; // 'left' | 'right'
  int _seekAcc = 0;
  Timer? _seekClearTimer;

  // ── Brightness / Volume swipe ─────────────────────────────────────────────
  bool _isDragging = false;
  String? _dragType; // 'brightness' | 'volume'
  double _dragValue = 0.0;
  double _dragStartY = 0.0;
  double _dragStartVal = 0.0;

  // ── Subtitles ──────────────────────────────────────────────────────────────
  List<SubtitleEntry> _subs = [];
  String? _activeLang;
  bool _showSubs = true;
  bool _loadingSubs = false;

  // ── Quality / Episode switching ───────────────────────────────────────────
  late MovieSource _currentSource;
  late int? _currentSeason;
  late int? _currentEpisode;
  List<MovieSource> _allSources = [];
  bool _loadingNextPrev = false;

  // ── Uganda playlist ───────────────────────────────────────────────────────
  late int _ugandaIndex;
  Movie? _ugandaCurrentMovie;

  // ── Related content (main app) ─────────────────────────────────────────────
  final MovieBoxClient _client = MovieBoxClient();
  final List<Movie> _related = [];
  bool _loadingMore = false;
  bool _hasMore = true;
  int _relatedPage = 1;
  int _kwIndex = 0;
  String? _activeKw;
  bool _loadScheduled = false;
  final ScrollController _scrollCtrl = ScrollController();
  final ValueNotifier<bool> _showFab = ValueNotifier(false);

  // ── Uganda: genre-based sections ──────────────────────────────────────────
  static const _ugGenreNames = <int, String>{
    1: 'Action', 2: 'Horror', 5: 'Series', 7: 'Adventure', 8: 'Love Story',
    9: 'Comedy', 12: 'Crime', 13: 'Family', 14: 'Sci-Fi', 15: 'Romance',
    16: 'Kung Fu', 17: 'Drama', 18: 'Sport', 19: 'Thriller', 20: 'Animation',
    21: 'Korean', 22: 'Filipino', 23: 'Indian', 24: 'Chinese',
  };
  List<({String title, List<Movie> movies, String pipeType, int pipeId})> _ugSections = [];
  bool _loadingUgSections = false;

  // ── Init ──────────────────────────────────────────────────────────────────
  @override
  void initState() {
    super.initState();
    _currentSource = widget.source;
    _currentSeason = widget.season;
    _currentEpisode = widget.episode;
    _allSources = widget.allSources ?? [widget.source];
    _ugandaIndex = widget.ugandaIndex ?? 0;
    SystemChrome.setPreferredOrientations([
      DeviceOrientation.portraitUp,
      DeviceOrientation.landscapeLeft,
      DeviceOrientation.landscapeRight,
    ]);
    WakelockPlus.enable();
    _initPlayer();
    _scrollCtrl.addListener(_onScroll);
    _mediaCh.setMethodCallHandler((call) async {
      if (!mounted) return;
      if (call.method == 'pipModeChanged') {
        setState(() => _isPip = call.arguments as bool? ?? false);
      } else if (call.method == 'volumeBoostChanged') {
        final gainMb = call.arguments as int? ?? 0;
        final newVol = 1.0 + gainMb / 2000.0;
        setState(() {
          _volume = newVol.clamp(0.0, 2.0);
          _dragType = 'volume';
          _dragValue = _volume;
          _isDragging = true;
        });
        _dragType = 'volume';
        Future.delayed(const Duration(milliseconds: 800), () {
          if (mounted) setState(() { _isDragging = false; _dragType = null; });
        });
      }
    });
    _mediaCh.invokeMethod('setPlayerActive', true).catchError((_) {});
    ScreenBrightness.instance.application.then((v) => _brightness = v).catchError((_) => 0.5);
    Future.delayed(const Duration(seconds: 2), () {
      if (!mounted) return;
      final pre = widget.preSelectedSubtitle;
      if (pre != null && _currentSource.subtitleUrls.containsKey(pre)) {
        _loadSubtitles(pre, _currentSource.subtitleUrls[pre]!);
      }
    });
    Future.delayed(const Duration(seconds: 1), () {
      if (!mounted) return;
      if (widget.noRelated) {
        _loadUgandaSections();
      } else {
        _loadRelated();
      }
    });
  }

  void _onScroll() {
    final show = _scrollCtrl.offset > 200;
    if (show != _showFab.value) _showFab.value = show;
    // Infinite scroll only for non-Uganda (Uganda uses static genre sections)
    if (!widget.noRelated &&
        !_loadScheduled &&
        _scrollCtrl.position.pixels >= _scrollCtrl.position.maxScrollExtent - 600) {
      _loadScheduled = true;
      Future.delayed(const Duration(milliseconds: 200), () {
        _loadScheduled = false;
        _loadRelated();
      });
    }
  }

  List<String> _buildKeywords() {
    final m = widget.movie;
    final words = <String>{};
    for (final g in m.genres) {
      final g2 = g.trim();
      if (g2.isNotEmpty) words.add(g2);
    }
    for (final w in m.title.split(' ')) {
      if (w.length > 3) words.add(w);
    }
    if (words.isEmpty) words.add(m.title.split(' ').first);
    return words.toList();
  }

  Future<void> _loadRelated() async {
    if (_loadingMore || !_hasMore) return;
    if (mounted) setState(() => _loadingMore = true);
    try {
      final m = widget.movie;
      if (widget.noRelated) {
        // ── Uganda Cinema Plus: search Bambilla by movie title ─────────────
        final kws = _buildKeywords();
        _activeKw ??= kws.first;
        final res = await VodClient().search(_activeKw!, page: _relatedPage);
        if (!mounted) return;
        if (res.isEmpty) {
          // Exhausted this keyword — try next
          _kwIndex++;
          if (_kwIndex < kws.length) {
            _activeKw = kws[_kwIndex];
            _relatedPage = 1;
            if (mounted) setState(() => _loadingMore = false);
            _loadRelated();
            return;
          }
          _hasMore = false;
        } else {
          setState(() {
            _related.addAll(res.where((r) => r.id != m.id));
            _relatedPage++;
          });
          if (res.length < 10) {
            _kwIndex++;
            if (_kwIndex < kws.length) {
              _activeKw = kws[_kwIndex];
              _relatedPage = 1;
            } else {
              _hasMore = false;
            }
          }
        }
      } else {
        // ── Main app: search MovieBox by genre / title keywords ────────────
        final kws = _buildKeywords();
        _activeKw ??= kws.first;
        final res = await _client.search(_activeKw!, page: _relatedPage, perPage: 20);
        if (!mounted) return;
        if (res.isEmpty || res.length < 4) {
          // Exhausted this keyword — try next
          _kwIndex++;
          if (_kwIndex < kws.length) {
            _activeKw = kws[_kwIndex];
            _relatedPage = 1;
            if (mounted) setState(() => _loadingMore = false);
            _loadRelated();
            return;
          }
          _hasMore = false;
        } else {
          setState(() {
            _related.addAll(res.where((r) => r.id != m.id));
            _relatedPage++;
          });
          // If page was thin, try next keyword next time
          if (res.length < 20) {
            _kwIndex++;
            if (_kwIndex < kws.length) {
              _activeKw = kws[_kwIndex];
              _relatedPage = 1;
            } else {
              _hasMore = false;
            }
          }
        }
      }
    } catch (_) {}
    if (mounted) setState(() => _loadingMore = false);
  }

  // ── Uganda: fetch genre-based sections for "More Like This" ───────────────
  Future<void> _loadUgandaSections() async {
    if (_loadingUgSections || !mounted) return;
    setState(() => _loadingUgSections = true);

    // Try to get the genre from the cached stream metadata
    int genreId = 0;
    try {
      final cached = await VodClient().getCachedStream(widget.movie.id);
      genreId = int.tryParse(cached?.categoryId ?? '') ?? 0;
    } catch (_) {}

    final seen = <String>{};
    final pipes = <({String title, String pt, int pid})>[];

    void addPipe(String title, String pt, int pid) {
      if (seen.add('$pt/$pid')) pipes.add((title: title, pt: pt, pid: pid));
    }

    // Genre-specific section first when genre is known
    if (genreId > 0 && _ugGenreNames.containsKey(genreId)) {
      addPipe('More ${_ugGenreNames[genreId]!}', 'g', genreId);
    }
    addPipe('Latest (2026)', 'p', 4);
    // Fill up to 6 total sections with popular genres (skip current genre)
    for (final gid in [17, 1, 2, 15, 14, 5, 20, 9, 19, 8]) {
      if (pipes.length >= 6) break;
      if (gid != genreId && _ugGenreNames.containsKey(gid)) {
        addPipe(_ugGenreNames[gid]!, 'g', gid);
      }
    }

    final results = await Future.wait(pipes.map((p) async {
      try {
        final r = await VodClient().getGrid(pipeType: p.pt, pipeId: p.pid);
        final movies = r.movies.where((m) => m.id != widget.movie.id).take(20).toList();
        if (movies.isEmpty) return null;
        return (title: p.title, movies: movies, pipeType: p.pt, pipeId: p.pid);
      } catch (_) {
        return null;
      }
    }));

    if (!mounted) return;
    setState(() {
      _ugSections = results
          .whereType<({String title, List<Movie> movies, String pipeType, int pipeId})>()
          .toList();
      _loadingUgSections = false;
    });
  }

  // ── Resume / position persistence ─────────────────────────────────────────
  String get _resumeKey {
    final prefix = widget.noRelated ? 'resume_ug_' : 'resume_';
    final base = '$prefix${widget.movie.id}';
    if (_currentSeason != null && _currentEpisode != null) {
      return '${base}_s${_currentSeason}e${_currentEpisode}';
    }
    return base;
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
        final m = widget.movie;
        final payload = jsonEncode({
          'pos': pos.inSeconds,
          'dur': dur.inSeconds,
          'title': m.title,
          'thumb': m.thumbnail ?? '',
          'id': m.id,
          'type': m.subjectType,
          'year': m.year ?? '',
          'rating': m.rating ?? '',
          'detailPath': m.detailPath ?? '',
          'genres': m.genres,
          'season': _currentSeason,
          'episode': _currentEpisode,
          'ts': DateTime.now().millisecondsSinceEpoch,
        });
        await prefs.setString(_resumeKey, payload);
      }
    } catch (_) {}
  }

  // ── Video init ─────────────────────────────────────────────────────────────
  Future<void> _initPlayer({MovieSource? src}) async {
    if (src != null) _currentSource = src;
    setState(() { _isInitializing = true; _error = null; });
    try {
      final cleanUrl = _currentSource.directUrl.replaceAll(' ', '%20');
      // Bunny CDN (b-cdn.net) blocks requests that include a Referer header —
      // send NO Referer/Origin for those URLs so the CDN serves the file.
      final isBunnyCdn = cleanUrl.contains('b-cdn.net');
      final Map<String, String> videoHeaders = {
        'User-Agent': 'Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
      };
      if (!isBunnyCdn) {
        // Uganda (bambilla) streams use bambilla.org referer.
        // Route each source through its own CDN-expected Referer — that is
        // what the video CDN whitelists. Sending the aoneroom API URL breaks playback.
        final isUganda = widget.ugandaPlaylist != null ||
            _currentSource.referer.contains(_ugK);
        final _referer = isUganda
            ? (_currentSource.referer.isNotEmpty ? _currentSource.referer : _ugR)
            : _mbR;
        final _origin = isUganda
            ? (Uri.tryParse(_currentSource.referer)?.origin ?? _ugO)
            : _mbO;
        videoHeaders['Referer'] = _referer;
        videoHeaders['Origin'] = _origin;
      }
      _vpc = VideoPlayerController.networkUrl(
        Uri.parse(cleanUrl),
        httpHeaders: videoHeaders,
      );
      await _vpc!.initialize();
      if (!mounted) { _vpc?.dispose(); return; }
      _dur.value = _vpc!.value.duration;
      _vpc!.setVolume(_volume.clamp(0.0, 1.0));
      _vpc!.setPlaybackSpeed(_speed);
      final savedSecs = await _loadSavedSeconds();
      if (!mounted) { _vpc?.dispose(); return; }
      if (savedSecs != null && savedSecs > 0) {
        final resumeAt = Duration(seconds: savedSecs);
        await _vpc!.seekTo(resumeAt);
        if (!mounted) { _vpc?.dispose(); return; }
        _pos.value = resumeAt;
      }
      _vpc!.play();
      _playing.value = true;
      _startTimers();
      _resetControls();
      setState(() => _isInitializing = false);
      if (savedSecs != null && mounted) {
        final mm = savedSecs ~/ 60;
        final ss = (savedSecs % 60).toString().padLeft(2, '0');
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Resumed from $mm:$ss'),
            duration: const Duration(seconds: 5),
            backgroundColor: const Color(0xFF1A1A2E),
            action: SnackBarAction(
              label: 'Restart',
              textColor: AppTheme.accent,
              onPressed: () {
                _vpc?.seekTo(Duration.zero);
                _pos.value = Duration.zero;
              },
            ),
          ),
        );
      }
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _isInitializing = false;
        _error = 'Failed to load video. Try a different quality.';
      });
    }
  }

  void _startTimers() {
    _positionTimer?.cancel();
    _positionTimer = Timer.periodic(const Duration(milliseconds: 500), (_) {
      if (_vpc == null || !_vpc!.value.isInitialized) return;
      final v = _vpc!.value;
      if (!_isSeeking) _pos.value = v.position;
      _playing.value = v.isPlaying;
      final bufs = v.buffered;
      if (bufs.isNotEmpty && v.duration.inMilliseconds > 0) {
        _bufferedFrac.value = (bufs.last.end.inMilliseconds / v.duration.inMilliseconds).clamp(0.0, 1.0);
      }
      if (_showSubs && _subs.isNotEmpty) {
        final pos = v.position;
        final entry = _subs.where((s) => pos >= s.start && pos <= s.end).firstOrNull;
        final t = entry?.text ?? '';
        if (t != _subText.value) _subText.value = t;
      } else if (_subText.value.isNotEmpty) {
        _subText.value = '';
      }
    });
    _saveTimer?.cancel();
    _saveTimer = Timer.periodic(const Duration(seconds: 5), (_) {
      _saveCurrentPosition();
    });
  }

  void _resetControls() {
    _controlsTimer?.cancel();
    if (!_ctrlsVisible.value) _ctrlsVisible.value = true;
    _controlsTimer = Timer(const Duration(seconds: 4), () {
      if (!_isSeeking && !_isDragging) _ctrlsVisible.value = false;
    });
  }

  void _toggleControls() {
    if (_isLocked) return;
    if (_ctrlsVisible.value) {
      _controlsTimer?.cancel();
      _ctrlsVisible.value = false;
    } else {
      _resetControls();
    }
  }

  // ── Seek ───────────────────────────────────────────────────────────────────
  void _seekBy(int secs) {
    if (_vpc == null) return;
    final cur = _vpc!.value.position;
    final tot = _vpc!.value.duration;
    var np = cur + Duration(seconds: secs);
    if (np < Duration.zero) np = Duration.zero;
    if (np > tot) np = tot;
    _vpc!.seekTo(np);
    _pos.value = np;
    setState(() {
      _seekSide = secs < 0 ? 'left' : 'right';
      _seekAcc += secs.abs();
    });
    _seekClearTimer?.cancel();
    _seekClearTimer = Timer(const Duration(milliseconds: 850), () {
      if (mounted) setState(() { _seekSide = null; _seekAcc = 0; });
    });
    _resetControls();
  }

  void _togglePlay() {
    if (_vpc == null) return;
    if (_vpc!.value.isPlaying) {
      _vpc!.pause();
      _playing.value = false;
    } else {
      _vpc!.play();
      _playing.value = true;
    }
    _resetControls();
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

  // ── Aspect mode ────────────────────────────────────────────────────────────
  void _cycleAspect() {
    setState(() => _aspectMode = (_aspectMode + 1) % 3);
    _resetControls();
  }

  String get _aspectLabel {
    switch (_aspectMode) {
      case 0: return 'Fit';
      case 1: return 'Fill';
      default: return 'Stretch';
    }
  }

  // ── Lock ───────────────────────────────────────────────────────────────────
  void _toggleLock() {
    setState(() => _isLocked = !_isLocked);
    if (!_isLocked) _resetControls();
  }

  // ── Volume + Boost ─────────────────────────────────────────────────────────
  // _volume range: 0.0 – 2.0 (> 1.0 = software boost via LoudnessEnhancer)
  void _applyVolumeAndBoost(double volume) {
    _volume = volume.clamp(0.0, 2.0);
    _vpc?.setVolume(_volume.clamp(0.0, 1.0));
    final gainMb = _volume > 1.0 ? ((_volume - 1.0) * 2000).round() : 0;
    _mediaCh.invokeMethod('setBoost', {'gain': gainMb}).catchError((_) {});
  }

  // ── PiP ────────────────────────────────────────────────────────────────────
  Future<void> _enterPip() async {
    try { await _mediaCh.invokeMethod<bool>('enterPip'); } catch (_) {}
  }

  // ── Speed picker ───────────────────────────────────────────────────────────
  void _showSpeedSheet() {
    _controlsTimer?.cancel();
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (_) {
        final speeds = [0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0];
        return DraggableScrollableSheet(
          initialChildSize: 0.45,
          minChildSize: 0.25,
          maxChildSize: 0.85,
          expand: false,
          builder: (_, ctrl) => Container(
            decoration: const BoxDecoration(
              color: Colors.black,
              borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
            ),
            child: ListView(
              controller: ctrl,
              padding: const EdgeInsets.fromLTRB(0, 0, 0, 24),
              children: [
                _sheetHandle(),
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 10),
                  child: Text('Playback Speed',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
                ),
                ...speeds.map((s) => ListTile(
                  leading: Icon(
                    _speed == s ? Icons.check_circle_rounded : Icons.radio_button_unchecked_rounded,
                    color: _speed == s ? AppTheme.primary : Colors.white38,
                    size: 20,
                  ),
                  title: Text(s == 1.0 ? 'Normal  (1×)' : '${s}×',
                      style: TextStyle(
                          color: _speed == s ? AppTheme.primary : Colors.white,
                          fontSize: 14,
                          fontWeight: _speed == s ? FontWeight.w600 : FontWeight.normal)),
                  onTap: () {
                    setState(() => _speed = s);
                    _vpc?.setPlaybackSpeed(s);
                    Navigator.pop(context);
                    _resetControls();
                  },
                )),
              ],
            ),
          ),
        );
      },
    ).whenComplete(_resetControls);
  }

  // ── Quality picker ─────────────────────────────────────────────────────────
  void _showQualitySheet() {
    _controlsTimer?.cancel();
    if (_allSources.length > 1) {
      _openQualityOptions(_allSources);
      return;
    }
    // Load all sources on demand
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (ctx) => _QualityLoadingSheet(
        client: _client,
        movie: widget.movie,
        season: _currentSeason ?? 0,
        episode: _currentEpisode ?? 0,
        currentUrl: _currentSource.directUrl,
        onSelect: (src) {
          Navigator.pop(ctx);
          _allSources = [src];
          _switchSource(src);
        },
      ),
    ).whenComplete(_resetControls);
  }

  void _openQualityOptions(List<MovieSource> sources) {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (_) => DraggableScrollableSheet(
        initialChildSize: sources.length > 4 ? 0.6 : 0.45,
        minChildSize: 0.25,
        maxChildSize: 0.85,
        expand: false,
        builder: (_, ctrl) => Container(
          decoration: const BoxDecoration(
            color: Colors.black,
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          child: ListView(
            controller: ctrl,
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
            children: [
              Center(child: Container(
                margin: const EdgeInsets.symmetric(vertical: 12),
                width: 40, height: 4,
                decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2)),
              )),
              const Padding(
                padding: EdgeInsets.only(bottom: 12),
                child: Text('Select Quality to Watch',
                    style: TextStyle(color: Colors.white, fontWeight: FontWeight.w700, fontSize: 17)),
              ),
              ...sources.map((s) {
                final isCurrent = s.directUrl == _currentSource.directUrl;
                return Container(
                  margin: const EdgeInsets.only(bottom: 10),
                  decoration: BoxDecoration(
                    color: Colors.black,
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(
                      color: isCurrent ? qualityColor(s.quality) : qualityColor(s.quality).withOpacity(0.28),
                      width: isCurrent ? 1.5 : 1,
                    ),
                  ),
                  child: InkWell(
                    borderRadius: BorderRadius.circular(14),
                    splashColor: qualityColor(s.quality).withOpacity(0.08),
                    onTap: () {
                      Navigator.pop(context);
                      _switchSource(s);
                      _resetControls();
                    },
                    child: Padding(
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
                      child: Row(
                        children: [
                          Container(
                            width: 50, height: 50,
                            decoration: BoxDecoration(
                              color: qualityColor(s.quality).withOpacity(isCurrent ? 0.2 : 0.12),
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(color: qualityColor(s.quality).withOpacity(0.4)),
                            ),
                            child: Icon(
                              qualityIcon(s.quality),
                              color: qualityColor(s.quality), size: 26,
                            ),
                          ),
                          const SizedBox(width: 14),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Row(children: [
                                  Text(s.quality,
                                      style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.w800)),
                                  const SizedBox(width: 8),
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                                    decoration: BoxDecoration(color: qualityColor(s.quality), borderRadius: BorderRadius.circular(5)),
                                    child: Text(qualityLabel(s.quality),
                                        style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.w700)),
                                  ),
                                  if (isCurrent) ...[
                                    const SizedBox(width: 8),
                                    Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                      decoration: BoxDecoration(color: Colors.white12, borderRadius: BorderRadius.circular(4)),
                                      child: const Text('Playing', style: TextStyle(color: Colors.white54, fontSize: 9, fontWeight: FontWeight.w600)),
                                    ),
                                  ],
                                ]),
                                if (s.size > 0) ...[
                                  const SizedBox(height: 3),
                                  Text('${(s.size / 1024 / 1024).toStringAsFixed(0)} MB',
                                      style: const TextStyle(color: Colors.white38, fontSize: 12)),
                                ],
                              ],
                            ),
                          ),
                          const Icon(Icons.chevron_right_rounded, color: Colors.white24, size: 22),
                        ],
                      ),
                    ),
                  ),
                );
              }),
            ],
          ),
        ),
      ),
    ).whenComplete(_resetControls);
  }

  Future<void> _switchSource(MovieSource newSrc) async {
    if (newSrc.directUrl == _currentSource.directUrl) return;
    final savedPos = _vpc?.value.position ?? Duration.zero;
    _vpc?.pause();
    _vpc?.dispose();
    _vpc = null;
    _subs = [];
    _subText.value = '';
    _activeLang = null;
    await _initPlayer(src: newSrc);
    if (savedPos.inSeconds > 5 && _vpc != null) {
      await _vpc!.seekTo(savedPos);
      _pos.value = savedPos;
    }
  }

  // ── Episode navigation ─────────────────────────────────────────────────────
  SeasonInfo? get _currentSeasonInfo {
    if (widget.seasons == null || _currentSeason == null) return null;
    try { return widget.seasons!.firstWhere((s) => s.season == _currentSeason); }
    catch (_) { return null; }
  }

  bool get _hasPrevEpisode {
    if (!widget.movie.isTvSeries || _currentEpisode == null) return false;
    if (_currentEpisode! > 1) return true;
    return widget.seasons != null && _currentSeason != null && _currentSeason! > 1;
  }

  bool get _hasNextEpisode {
    if (!widget.movie.isTvSeries || _currentEpisode == null) return false;
    final si = _currentSeasonInfo;
    if (si != null && _currentEpisode! < si.maxEpisode) return true;
    return widget.seasons != null && _currentSeason != null &&
        widget.seasons!.any((s) => s.season > _currentSeason!);
  }

  Future<void> _goNextEpisode() async {
    if (!_hasNextEpisode || _loadingNextPrev) return;
    int newSeason = _currentSeason!;
    int newEp = _currentEpisode! + 1;
    final si = _currentSeasonInfo;
    if (si != null && _currentEpisode! >= si.maxEpisode) {
      newSeason = _currentSeason! + 1;
      newEp = 1;
    }
    await _loadEpisode(newSeason, newEp);
  }

  Future<void> _goPrevEpisode() async {
    if (!_hasPrevEpisode || _loadingNextPrev) return;
    int newSeason = _currentSeason!;
    int newEp = _currentEpisode! - 1;
    if (newEp < 1) {
      newSeason = _currentSeason! - 1;
      final prevSi = widget.seasons!.cast<SeasonInfo?>().firstWhere(
          (s) => s?.season == newSeason, orElse: () => null);
      newEp = prevSi?.maxEpisode ?? 1;
    }
    await _loadEpisode(newSeason, newEp);
  }

  // ── Uganda prev / next ─────────────────────────────────────────────────────
  bool get _hasPrevUganda =>
      widget.ugandaPlaylist != null && _ugandaIndex > 0;

  bool get _hasNextUganda =>
      widget.ugandaPlaylist != null &&
      _ugandaIndex < (widget.ugandaPlaylist!.length - 1);

  Future<void> _goPrevUganda() async {
    if (!_hasPrevUganda || _loadingNextPrev) return;
    await _loadUgandaMovie(_ugandaIndex - 1);
  }

  Future<void> _goNextUganda() async {
    if (!_hasNextUganda || _loadingNextPrev) return;
    await _loadUgandaMovie(_ugandaIndex + 1);
  }

  Future<void> _loadUgandaMovie(int newIndex) async {
    setState(() => _loadingNextPrev = true);
    try {
      final movie = widget.ugandaPlaylist![newIndex];
      final stream = await VodClient().getStream(movie.id);
      if (!mounted) return;
      if (stream.url.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
              content: Text('No stream available'),
              backgroundColor: Color(0xFF1A1A2E)),
        );
        setState(() => _loadingNextPrev = false);
        return;
      }
      final newSource = MovieSource(
        id: movie.id,
        quality: stream.vj.isNotEmpty ? stream.vj : 'Uganda HD',
        directUrl: stream.url,
        referer: _ugR,
      );
      final newMovie = Movie(
        id: movie.id,
        title: stream.title.isNotEmpty ? stream.title : movie.title,
        thumbnail: stream.image.isNotEmpty ? stream.image : movie.thumbnail,
        summary: stream.vj.isNotEmpty ? 'By ${stream.vj}' : movie.summary,
        subjectType: 1,
      );
      _ugandaIndex = newIndex;
      _ugandaCurrentMovie = newMovie;
      _allSources = [newSource];
      _subs = [];
      _subText.value = '';
      _activeLang = null;
      _vpc?.pause();
      _vpc?.dispose();
      _vpc = null;
      setState(() => _loadingNextPrev = false);
      await _initPlayer(src: newSource);
    } catch (_) {
      if (mounted) setState(() => _loadingNextPrev = false);
    }
  }

  Future<void> _loadEpisode(int season, int episode) async {
    setState(() => _loadingNextPrev = true);
    try {
      final sources = await _client.getSources(widget.movie.id, season: season, episode: episode);
      if (!mounted) return;
      if (sources.isEmpty) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('No stream for S${season}E${episode}'),
              backgroundColor: const Color(0xFF1A1A2E)));
        setState(() => _loadingNextPrev = false);
        return;
      }
      _currentSeason = season;
      _currentEpisode = episode;
      _allSources = sources;
      _subs = [];
      _subText.value = '';
      _activeLang = null;
      _vpc?.pause();
      _vpc?.dispose();
      _vpc = null;
      setState(() => _loadingNextPrev = false);
      await _initPlayer(src: sources.first);
    } catch (_) {
      if (mounted) setState(() => _loadingNextPrev = false);
    }
  }

  // ── Subtitle picker ────────────────────────────────────────────────────────
  void _showSubSheet() {
    _controlsTimer?.cancel();
    final subs = _currentSource.subtitleUrls;
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
          borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
      builder: (_) => DraggableScrollableSheet(
        initialChildSize: subs.length > 6 ? 0.6 : 0.4,
        minChildSize: 0.25,
        maxChildSize: 0.85,
        expand: false,
        builder: (_, ctrl) => Container(
          decoration: const BoxDecoration(
            color: Colors.black,
            borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
          ),
          child: Column(
            children: [
              _sheetHandle(),
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 10),
                child: Text('Subtitles',
                    style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
              ),
              Expanded(
                child: ListView(
                  controller: ctrl,
                  padding: const EdgeInsets.only(bottom: 24),
                  children: [
                    ListTile(
                      leading: Icon(
                          !_showSubs ? Icons.check_circle_rounded : Icons.radio_button_unchecked_rounded,
                          color: !_showSubs ? AppTheme.primary : Colors.white38,
                          size: 20),
                      title: const Text('Off', style: TextStyle(color: Colors.white, fontSize: 14)),
                      onTap: () {
                        setState(() { _showSubs = false; _subText.value = ''; });
                        Navigator.pop(context);
                      },
                    ),
                    if (subs.isEmpty)
                      const Padding(
                          padding: EdgeInsets.all(16),
                          child: Text('No subtitles available',
                              style: TextStyle(color: Colors.white54, fontSize: 13))),
                    ...subs.entries.map((e) => ListTile(
                      leading: Icon(
                          _activeLang == e.key && _showSubs
                              ? Icons.check_circle_rounded
                              : Icons.subtitles_outlined,
                          color: _activeLang == e.key && _showSubs ? AppTheme.primary : Colors.white38,
                          size: 20),
                      title: Text(e.key, style: const TextStyle(color: Colors.white, fontSize: 14)),
                      onTap: () {
                        setState(() => _showSubs = true);
                        _loadSubtitles(e.key, e.value);
                        Navigator.pop(context);
                      },
                    )),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    ).whenComplete(_resetControls);
  }

  Widget _sheetHandle() => Container(
        margin: const EdgeInsets.symmetric(vertical: 12),
        width: 44, height: 4,
        decoration:
            BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2)));

  // ── Subtitles ──────────────────────────────────────────────────────────────
  Future<void> _loadSubtitles(String lang, String url) async {
    if (!mounted) return;
    setState(() { _loadingSubs = true; _activeLang = lang; });
    try {
      final content = await _client.fetchSubtitleContent(url);
      if (!mounted) return;
      final parsed = content != null ? _parseSubs(content) : <SubtitleEntry>[];
      setState(() { _subs = parsed; _loadingSubs = false; });
    } catch (_) {
      if (!mounted) return;
      setState(() { _subs = []; _loadingSubs = false; });
    }
  }

  List<SubtitleEntry> _parseSubs(String content) {
    final entries = <SubtitleEntry>[];
    final cleaned = content.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
    final isVtt = cleaned.trimLeft().startsWith('WEBVTT');
    final blocks = cleaned.trim().split(RegExp(r'\n\n+'));
    final tRx = isVtt
        ? RegExp(r'(\d{1,2}:\d{2}:\d{2}[.,]\d{3})\s*-->\s*(\d{1,2}:\d{2}:\d{2}[.,]\d{3})')
        : RegExp(r'(\d{2}:\d{2}:\d{2}[,]\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}[,]\d{3})');
    for (final block in blocks) {
      final lines = block.trim().split('\n');
      String? tLine;
      int tStart = 0;
      for (int i = 0; i < lines.length; i++) {
        if (tRx.hasMatch(lines[i])) { tLine = lines[i]; tStart = i + 1; break; }
      }
      if (tLine == null) continue;
      final match = tRx.firstMatch(tLine);
      if (match == null) continue;
      final text = lines.sublist(tStart).join('\n').replaceAll(RegExp(r'<[^>]+>'), '').trim();
      if (text.isNotEmpty) {
        entries.add(SubtitleEntry(
            start: _parseTime(match.group(1)!),
            end: _parseTime(match.group(2)!),
            text: text));
      }
    }
    return entries;
  }

  Duration _parseTime(String t) {
    final parts = t.replaceAll(',', '.').split(':');
    if (parts.length == 3) {
      final h = int.tryParse(parts[0]) ?? 0;
      final m = int.tryParse(parts[1]) ?? 0;
      final sp = parts[2].split('.');
      final s = int.tryParse(sp[0]) ?? 0;
      final ms = sp.length > 1 ? int.tryParse(sp[1].padRight(3, '0').substring(0, 3)) ?? 0 : 0;
      return Duration(hours: h, minutes: m, seconds: s, milliseconds: ms);
    }
    return Duration.zero;
  }

  String _fmt(Duration d) {
    final h = d.inHours;
    final m = d.inMinutes.remainder(60).toString().padLeft(2, '0');
    final s = d.inSeconds.remainder(60).toString().padLeft(2, '0');
    return h > 0 ? '$h:$m:$s' : '$m:$s';
  }

  String get _epLabel {
    if (_currentSeason != null && _currentEpisode != null) {
      return 'S${_currentSeason} E${_currentEpisode}  •  ${_currentSource.quality}';
    }
    return _currentSource.quality;
  }

  // ── Dispose ────────────────────────────────────────────────────────────────
  @override
  void dispose() {
    _saveTimer?.cancel();
    _saveCurrentPosition();
    _positionTimer?.cancel();
    _controlsTimer?.cancel();
    _seekClearTimer?.cancel();
    _scrollCtrl.dispose();
    _showFab.dispose();
    _pos.dispose();
    _dur.dispose();
    _playing.dispose();
    _bufferedFrac.dispose();
    _ctrlsVisible.dispose();
    _subText.dispose();
    _mediaCh.invokeMethod('setPlayerActive', false).catchError((_) {});
    _mediaCh.invokeMethod('setBoost', {'gain': 0}).catchError((_) {});
    _mediaCh.setMethodCallHandler(null);
    SystemChrome.setPreferredOrientations([DeviceOrientation.portraitUp]);
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
    WakelockPlus.disable();
    ScreenBrightness.instance.resetApplicationScreenBrightness().catchError((_) {});
    _vpc?.dispose();
    super.dispose();
  }

  // ══════════════════════════════════════════════════════════════════════════
  // PLAYER LAYER (portrait + fullscreen share this)
  // ══════════════════════════════════════════════════════════════════════════
  Widget _playerLayer(double w, double h) {
    // In PiP mode show only the video — no controls, no overlays
    if (_isPip) {
      return Container(
        color: Colors.black, width: w, height: h,
        child: _videoContent(),
      );
    }
    return Stack(
      children: [
        // ── Video ────────────────────────────────────────────────────────
        Container(color: Colors.black, width: w, height: h,
            child: _videoContent()),

        // ── Gestures ─────────────────────────────────────────────────────
        if (!_isLocked) _gestureLayer(w, h),

        // ── Seek ripple animation ─────────────────────────────────────────
        if (_seekSide == 'left')  _seekOverlay(false, w),
        if (_seekSide == 'right') _seekOverlay(true, w),

        // ── Brightness / Volume indicator ─────────────────────────────────
        if (_isDragging) _dragIndicator(),

        // ── Subtitle text ─────────────────────────────────────────────────
        _subtitleOverlay(),

        // ── Controls overlay ──────────────────────────────────────────────
        if (!_isLocked && !_isInitializing && _error == null)
          ValueListenableBuilder<bool>(
            valueListenable: _ctrlsVisible,
            builder: (_, v, __) => AnimatedOpacity(
              opacity: v ? 1.0 : 0.0,
              duration: const Duration(milliseconds: 220),
              child: IgnorePointer(
                ignoring: !v,
                child: _controlsOverlay(w, h),
              ),
            ),
          ),

        // ── Lock screen overlay ───────────────────────────────────────────
        if (_isLocked) _lockOverlay(w, h),
      ],
    );
  }

  // ── Video display (handles 3 aspect modes) ─────────────────────────────────
  Widget _videoContent() {
    if (_isInitializing) {
      return const Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          CircularProgressIndicator(color: AppTheme.primary),
          SizedBox(height: 12),
          Text('Loading video…', style: TextStyle(color: Colors.white70, fontSize: 13)),
        ]),
      );
    }
    if (_error != null) {
      return Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Icon(Icons.error_outline_rounded, color: AppTheme.primary, size: 44),
          const SizedBox(height: 10),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 24),
            child: Text(_error!,
                style: const TextStyle(color: Colors.white, fontSize: 13),
                textAlign: TextAlign.center),
          ),
          const SizedBox(height: 16),
          ElevatedButton.icon(
            onPressed: _initPlayer,
            icon: const Icon(Icons.refresh_rounded),
            label: const Text('Retry'),
            style: ElevatedButton.styleFrom(backgroundColor: AppTheme.primary),
          ),
        ]),
      );
    }
    if (_vpc == null || !_vpc!.value.isInitialized) return const SizedBox.shrink();
    final vp = VideoPlayer(_vpc!);
    switch (_aspectMode) {
      case 1: // Fill / crop
        return SizedBox.expand(child: FittedBox(
            fit: BoxFit.cover,
            child: SizedBox(
                width: _vpc!.value.size.width,
                height: _vpc!.value.size.height,
                child: vp)));
      case 2: // Stretch
        return SizedBox.expand(child: FittedBox(
            fit: BoxFit.fill,
            child: SizedBox(
                width: _vpc!.value.size.width,
                height: _vpc!.value.size.height,
                child: vp)));
      default: // Contain/Fit
        return Center(child: AspectRatio(
            aspectRatio: _vpc!.value.aspectRatio, child: vp));
    }
  }

  // ── Gesture layer ──────────────────────────────────────────────────────────
  Widget _gestureLayer(double w, double h) {
    return GestureDetector(
      behavior: HitTestBehavior.translucent,
      onTap: _toggleControls,
      onDoubleTapDown: (d) {
        final x = d.localPosition.dx;
        if (x < w * 0.35) {
          _seekBy(-10);
        } else if (x > w * 0.65) {
          _seekBy(10);
        } else {
          _togglePlay();
          _resetControls();
        }
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
          // Volume goes 0–200% (0.0–2.0); extra range = boost
          final nv = (_dragStartVal + delta * 2.0).clamp(0.0, 2.0);
          setState(() => _dragValue = nv);
          _applyVolumeAndBoost(nv);
        }
      },
      onVerticalDragEnd: (_) {
        setState(() => _isDragging = false);
        _dragType = null;
        _resetControls();
      },
      child: SizedBox(width: w, height: h),
    );
  }

  // ── Seek ripple overlay ────────────────────────────────────────────────────
  Widget _seekOverlay(bool right, double w) {
    return Positioned(
      left: right ? w * 0.5 : 0,
      right: right ? 0 : w * 0.5,
      top: 0, bottom: 0,
      child: Container(
        decoration: BoxDecoration(
          color: Colors.black.withOpacity(0.32),
          borderRadius: BorderRadius.horizontal(
            left: right ? Radius.zero : const Radius.circular(0),
            right: right ? const Radius.circular(0) : Radius.zero,
          ),
        ),
        child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
          Icon(
              right ? Icons.forward_10_rounded : Icons.replay_10_rounded,
              color: Colors.white, size: 44),
          const SizedBox(height: 6),
          Text('$_seekAcc s',
              style: const TextStyle(
                  color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
        ]),
      ),
    );
  }

  // ── Drag indicator (brightness/volume) ────────────────────────────────────
  Widget _dragIndicator() {
    final isBright = _dragType == 'brightness';
    final isBoost = !isBright && _dragValue > 1.0;
    const boostOrange = Color(0xFFFF8C00);

    final icon = isBright
        ? (_dragValue > 0.6
            ? Icons.brightness_high_rounded
            : _dragValue > 0.3
                ? Icons.brightness_medium_rounded
                : Icons.brightness_low_rounded)
        : isBoost
            ? Icons.bolt_rounded
            : (_dragValue > 0.5 ? Icons.volume_up_rounded : Icons.volume_down_rounded);

    // For volume: progress bar shows 0–100% normal, then a separate boost segment
    final normalFrac = isBright ? _dragValue : _dragValue.clamp(0.0, 1.0);
    final boostFrac = isBoost ? (_dragValue - 1.0).clamp(0.0, 1.0) : 0.0;

    return Center(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 18),
        decoration: BoxDecoration(
            color: Colors.black.withOpacity(0.78),
            borderRadius: BorderRadius.circular(18),
            border: isBoost
                ? Border.all(color: boostOrange.withOpacity(0.5), width: 1.5)
                : null),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(icon, color: isBoost ? boostOrange : Colors.white, size: 34),
          const SizedBox(height: 8),
          Text(
            isBright ? 'Brightness' : isBoost ? 'BOOST' : 'Volume',
            style: TextStyle(
                color: isBoost ? boostOrange : Colors.white60, fontSize: 12,
                fontWeight: isBoost ? FontWeight.w700 : FontWeight.normal),
          ),
          const SizedBox(height: 10),
          // Normal volume bar (0-100%)
          SizedBox(
            width: 110,
            child: LinearProgressIndicator(
              value: normalFrac,
              backgroundColor: Colors.white24,
              valueColor: AlwaysStoppedAnimation(
                  isBright ? Colors.amber : AppTheme.primary),
              minHeight: 5,
              borderRadius: BorderRadius.circular(3),
            ),
          ),
          // Boost bar (only shown when >100%)
          if (isBoost) ...[
            const SizedBox(height: 5),
            SizedBox(
              width: 110,
              child: LinearProgressIndicator(
                value: boostFrac,
                backgroundColor: Colors.white24,
                valueColor: const AlwaysStoppedAnimation(boostOrange),
                minHeight: 5,
                borderRadius: BorderRadius.circular(3),
              ),
            ),
          ],
          const SizedBox(height: 6),
          Text(
            '${(_dragValue * 100).round()}%',
            style: TextStyle(
                color: isBoost ? boostOrange : Colors.white,
                fontSize: 14,
                fontWeight: FontWeight.bold),
          ),
        ]),
      ),
    );
  }

  // ── Subtitle overlay ───────────────────────────────────────────────────────
  Widget _subtitleOverlay() {
    return ValueListenableBuilder<String>(
      valueListenable: _subText,
      builder: (_, text, __) {
        if (text.isEmpty) return const SizedBox.shrink();
        return Positioned(
          left: 16, right: 16, bottom: _isFullscreen ? 16 : 48,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
            decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.78),
                borderRadius: BorderRadius.circular(6)),
            child: Text(text,
              textAlign: TextAlign.center,
              style: const TextStyle(
                  color: Colors.white,
                  fontSize: 15,
                  height: 1.4,
                  shadows: [Shadow(blurRadius: 4, color: Colors.black)]),
            ),
          ),
        );
      },
    );
  }

  // ── Lock overlay ───────────────────────────────────────────────────────────
  Widget _lockOverlay(double w, double h) {
    return GestureDetector(
      onTap: () {},
      child: Container(
        width: w, height: h, color: Colors.transparent,
        alignment: Alignment.centerLeft,
        padding: const EdgeInsets.only(left: 14),
        child: GestureDetector(
          onTap: _toggleLock,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 14),
            decoration: BoxDecoration(
                color: Colors.black.withOpacity(0.6),
                borderRadius: BorderRadius.circular(36)),
            child: const Column(mainAxisSize: MainAxisSize.min, children: [
              Icon(Icons.lock_rounded, color: Colors.white, size: 24),
              SizedBox(height: 5),
              Text('Tap to\nunlock',
                  textAlign: TextAlign.center,
                  style: TextStyle(color: Colors.white70, fontSize: 10)),
            ]),
          ),
        ),
      ),
    );
  }

  // ── Controls overlay ───────────────────────────────────────────────────────
  Widget _controlsOverlay(double w, double h) {
    return GestureDetector(
      onTap: _toggleControls,
      child: Container(
        width: w, height: h,
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [
              Color(0xBB000000),
              Colors.transparent,
              Colors.transparent,
              Color(0xBB000000),
            ],
            stops: [0.0, 0.18, 0.72, 1.0],
          ),
        ),
        child: Stack(children: [
          Positioned(top: 0, left: 0, right: 0, child: _topBar()),
          Center(child: _centerControls()),
          Positioned(bottom: 0, left: 0, right: 0, child: _bottomBar()),
        ]),
      ),
    );
  }

  // ── Top bar ────────────────────────────────────────────────────────────────
  Widget _topBar() {
    return SafeArea(
      bottom: false,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(4, 4, 8, 0),
        child: Row(children: [
          IconButton(
            icon: const Icon(Icons.arrow_back_ios_rounded, color: Colors.white, size: 22),
            onPressed: _isFullscreen ? _exitFullscreen : () => Navigator.pop(context),
          ),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(widget.movie.title,
                  style: const TextStyle(
                      color: Colors.white, fontSize: 14, fontWeight: FontWeight.w700),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis),
              if (_epLabel.isNotEmpty)
                Text(_epLabel,
                    style: const TextStyle(color: Colors.white60, fontSize: 11)),
            ]),
          ),
          // Aspect ratio pill
          GestureDetector(
            onTap: _cycleAspect,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
              decoration: BoxDecoration(
                  color: Colors.white12,
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: Colors.white24)),
              child: Row(mainAxisSize: MainAxisSize.min, children: [
                const Icon(Icons.aspect_ratio_rounded, color: Colors.white70, size: 14),
                const SizedBox(width: 4),
                Text(_aspectLabel,
                    style: const TextStyle(
                        color: Colors.white, fontSize: 11, fontWeight: FontWeight.w600)),
              ]),
            ),
          ),
          const SizedBox(width: 4),
          // Cast
          CastIconButton(
            url: _currentSource.directUrl,
            title: widget.movie.title,
            size: 22,
          ),
          // PiP
          IconButton(
            icon: const Icon(Icons.picture_in_picture_alt_rounded,
                color: Colors.white, size: 22),
            tooltip: 'Picture in Picture',
            onPressed: _enterPip,
          ),
          // Lock
          IconButton(
            icon: const Icon(Icons.lock_open_rounded, color: Colors.white, size: 22),
            tooltip: 'Lock screen',
            onPressed: _toggleLock,
          ),
        ]),
      ),
    );
  }

  // ── Center controls (prev | -10 | play | +10 | next) ──────────────────────
  Widget _centerControls() {
    final isTv = widget.movie.isTvSeries && _currentSeason != null;
    final isUganda = widget.ugandaPlaylist != null;
    final showPrev = isTv ? _hasPrevEpisode : (isUganda ? _hasPrevUganda : false);
    final showNext = isTv ? _hasNextEpisode : (isUganda ? _hasNextUganda : false);
    final onPrev = isTv ? _goPrevEpisode : (isUganda ? _goPrevUganda : null);
    final onNext = isTv ? _goNextEpisode : (isUganda ? _goNextUganda : null);
    return Row(mainAxisAlignment: MainAxisAlignment.center, children: [
      if (isTv || isUganda) ...[
        _loadingNextPrev
            ? const SizedBox(width: 44, height: 44,
                child: Center(child: SizedBox(width: 22, height: 22,
                    child: CircularProgressIndicator(color: Colors.white54, strokeWidth: 2))))
            : _iconBtn(Icons.skip_previous_rounded, 30,
                showPrev ? onPrev : null),
        const SizedBox(width: 8),
      ],
      _iconBtn(Icons.replay_10_rounded, 38, () => _seekBy(-10)),
      const SizedBox(width: 20),
      ValueListenableBuilder<bool>(
        valueListenable: _playing,
        builder: (_, isPlaying, __) => GestureDetector(
          onTap: _togglePlay,
          child: Container(
            width: 66,
            height: 66,
            decoration: BoxDecoration(
              color: Colors.black45,
              shape: BoxShape.circle,
              border: Border.all(color: Colors.white38, width: 2),
            ),
            child: Icon(
                isPlaying ? Icons.pause_rounded : Icons.play_arrow_rounded,
                color: Colors.white,
                size: 42),
          ),
        ),
      ),
      const SizedBox(width: 20),
      _iconBtn(Icons.forward_10_rounded, 38, () => _seekBy(10)),
      if (isTv || isUganda) ...[
        const SizedBox(width: 8),
        _loadingNextPrev
            ? const SizedBox(width: 44, height: 44)
            : _iconBtn(Icons.skip_next_rounded, 30,
                showNext ? onNext : null),
      ],
    ]);
  }

  Widget _iconBtn(IconData icon, double size, VoidCallback? onTap) {
    final active = onTap != null;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(10),
        child: Icon(icon, color: active ? Colors.white : Colors.white24, size: size),
      ),
    );
  }

  // ── Clean seek bar ─────────────────────────────────────────────────────────
  Widget _cleanSeekBar(double prog, double buf, Duration total) {
    return LayoutBuilder(builder: (_, box) {
      final w = box.maxWidth;
      return GestureDetector(
        behavior: HitTestBehavior.opaque,
        onHorizontalDragStart: (d) {
          _isSeeking = true;
          _seekDragFrac = (d.localPosition.dx / w).clamp(0.0, 1.0);
          _controlsTimer?.cancel();
          _ctrlsVisible.value = true;
          setState(() {});
        },
        onHorizontalDragUpdate: (d) {
          setState(() => _seekDragFrac = (d.localPosition.dx / w).clamp(0.0, 1.0));
        },
        onHorizontalDragEnd: (_) {
          _isSeeking = false;
          final st = Duration(milliseconds: (_seekDragFrac * total.inMilliseconds).round());
          _vpc?.seekTo(st);
          _pos.value = st;
          _resetControls();
        },
        onTapDown: (d) {
          final frac = (d.localPosition.dx / w).clamp(0.0, 1.0);
          final st = Duration(milliseconds: (frac * total.inMilliseconds).round());
          _vpc?.seekTo(st);
          _pos.value = st;
          setState(() { _isSeeking = false; });
          _resetControls();
        },
        child: SizedBox(
          height: 28,
          child: Stack(alignment: Alignment.centerLeft, children: [
            // Background track
            Container(height: 3, decoration: BoxDecoration(color: Colors.white.withOpacity(0.15), borderRadius: BorderRadius.circular(2))),
            // Buffer track
            FractionallySizedBox(
              widthFactor: buf,
              child: Container(height: 3, decoration: BoxDecoration(color: Colors.white38, borderRadius: BorderRadius.circular(2))),
            ),
            // Progress track
            FractionallySizedBox(
              widthFactor: prog,
              child: Container(height: 3, decoration: BoxDecoration(color: AppTheme.primary, borderRadius: BorderRadius.circular(2))),
            ),
            // Thumb
            Positioned(
              left: (prog * w - 7).clamp(0.0, w - 14),
              child: Container(
                width: 14, height: 14,
                decoration: BoxDecoration(
                  color: AppTheme.primary,
                  shape: BoxShape.circle,
                  boxShadow: const [BoxShadow(color: Colors.black54, blurRadius: 4, spreadRadius: 1)],
                ),
              ),
            ),
          ]),
        ),
      );
    });
  }

  // ── Bottom bar ─────────────────────────────────────────────────────────────
  Widget _bottomBar() {
    return SafeArea(
      top: false,
      bottom: _isFullscreen,
      child: Padding(
        padding: const EdgeInsets.fromLTRB(6, 0, 6, 4),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          // Seek bar
          ValueListenableBuilder<Duration>(
            valueListenable: _pos,
            builder: (_, pos, __) {
              final total = _dur.value;
              final prog = total.inMilliseconds > 0
                  ? (_isSeeking ? _seekDragFrac : pos.inMilliseconds / total.inMilliseconds).clamp(0.0, 1.0)
                  : 0.0;
              return Column(mainAxisSize: MainAxisSize.min, children: [
                ValueListenableBuilder<double>(
                  valueListenable: _bufferedFrac,
                  builder: (_, buf, __) => _cleanSeekBar(prog, buf.clamp(0.0, 1.0), total),
                ),
                Padding(
                  padding: const EdgeInsets.fromLTRB(12, 2, 12, 0),
                  child: Row(children: [
                    Text(
                      _fmt(_isSeeking ? Duration(milliseconds: (_seekDragFrac * total.inMilliseconds).round()) : pos),
                      style: const TextStyle(color: Colors.white, fontSize: 12, fontWeight: FontWeight.w500),
                    ),
                    const Spacer(),
                    Text(_fmt(total), style: const TextStyle(color: Colors.white60, fontSize: 12)),
                  ]),
                ),
              ]);
            },
          ),

          // Action row
          Row(children: [
            // Mute toggle
            ValueListenableBuilder<bool>(
              valueListenable: _playing,
              builder: (_, __, ___) => IconButton(
                icon: Icon(
                    _volume == 0
                        ? Icons.volume_off_rounded
                        : _volume > 1.0
                            ? Icons.volume_up_rounded
                            : _volume < 0.5
                                ? Icons.volume_down_rounded
                                : Icons.volume_up_rounded,
                    color: _volume > 1.0 ? const Color(0xFFFF8C00) : Colors.white,
                    size: 22),
                onPressed: () {
                  final nv = _volume > 0 ? 0.0 : 1.0;
                  _applyVolumeAndBoost(nv);
                  setState(() {});
                  _resetControls();
                },
              ),
            ),
            const Spacer(),
            // Speed
            GestureDetector(
              onTap: _showSpeedSheet,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
                decoration: BoxDecoration(
                    color: Colors.white12,
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: Colors.white24)),
                child: Text('${_speed}×',
                    style: const TextStyle(
                        color: Colors.white,
                        fontSize: 12,
                        fontWeight: FontWeight.w600)),
              ),
            ),
            // Quality — hidden for Uganda Cinema (single MP4, no quality options)
            if (widget.ugandaPlaylist == null) ...[
              const SizedBox(width: 6),
              Builder(builder: (ctx) {
                final qc = qualityColor(_currentSource.quality);
                return GestureDetector(
                  onTap: _showQualitySheet,
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
                    decoration: BoxDecoration(
                        color: qc.withOpacity(0.12),
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(color: qc.withOpacity(0.4))),
                    child: Row(mainAxisSize: MainAxisSize.min, children: [
                      Icon(Icons.hd_rounded, color: qc, size: 14),
                      const SizedBox(width: 4),
                      Text(
                        _currentSource.quality.length > 6
                            ? _currentSource.quality.substring(0, 6)
                            : _currentSource.quality,
                        style: TextStyle(
                            color: qc,
                            fontSize: 11,
                            fontWeight: FontWeight.w700)),
                    ]),
                  ),
                );
              }),
            ],
            const SizedBox(width: 6),
            // Subtitles — hidden for Uganda Cinema (no subtitle tracks available)
            if (widget.ugandaPlaylist == null)
              Stack(children: [
                IconButton(
                  icon: Icon(
                      _showSubs && _subs.isNotEmpty
                          ? Icons.subtitles_rounded
                          : Icons.subtitles_outlined,
                      color: _showSubs && _subs.isNotEmpty
                          ? AppTheme.primary
                          : Colors.white,
                      size: 22),
                  onPressed: _showSubSheet,
                ),
                if (_loadingSubs)
                  const Positioned(
                      right: 8,
                      top: 8,
                      child: SizedBox(
                          width: 10,
                          height: 10,
                          child: CircularProgressIndicator(
                              strokeWidth: 2, color: AppTheme.primary))),
              ]),
            // Fullscreen
            IconButton(
              icon: Icon(
                  _isFullscreen
                      ? Icons.fullscreen_exit_rounded
                      : Icons.fullscreen_rounded,
                  color: Colors.white,
                  size: 26),
              onPressed: _isFullscreen ? _exitFullscreen : _enterFullscreen,
            ),
          ]),
        ]),
      ),
    );
  }

  // ══════════════════════════════════════════════════════════════════════════
  // BUILD
  // ══════════════════════════════════════════════════════════════════════════
  @override
  Widget build(BuildContext context) {
    if (_isFullscreen) {
      final sz = MediaQuery.of(context).size;
      return PopScope(
        onPopInvoked: (_) => _exitFullscreen(),
        child: Scaffold(
          backgroundColor: Colors.black,
          body: _playerLayer(sz.width, sz.height),
        ),
      );
    }

    return Scaffold(
      backgroundColor: Colors.black,
      floatingActionButton: ValueListenableBuilder<bool>(
        valueListenable: _showFab,
        builder: (_, show, __) => show
            ? FloatingActionButton.extended(
                onPressed: () => _scrollCtrl.animateTo(0,
                    duration: const Duration(milliseconds: 380),
                    curve: Curves.easeOut),
                backgroundColor: AppTheme.primary,
                icon: const Icon(Icons.play_circle_outline_rounded,
                    color: Colors.white),
                label: const Text('Back to Player',
                    style: TextStyle(
                        color: Colors.white,
                        fontWeight: FontWeight.w700,
                        fontSize: 13)),
              )
            : const SizedBox.shrink(),
      ),
      body: SafeArea(
        top: true,
        bottom: false,
        child: CustomScrollView(
          controller: _scrollCtrl,
          cacheExtent: 1500,
          slivers: [
            // ── Player ──────────────────────────────────────────────────
            const SliverToBoxAdapter(child: SizedBox(height: 10)),
            SliverToBoxAdapter(
              child: LayoutBuilder(builder: (_, c) {
                final h = c.maxWidth * 9 / 16;
                return SizedBox(height: h, child: _playerLayer(c.maxWidth, h));
              }),
            ),

            // ── Movie info ───────────────────────────────────────────────
            SliverToBoxAdapter(
              child: Container(
                color: const Color(0xFF000000),
                padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
                child: Row(children: [
                  Expanded(
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(widget.movie.title,
                              style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 14,
                                  fontWeight: FontWeight.w700),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis),
                          if (widget.movie.year != null)
                            Text(widget.movie.year!,
                                style: const TextStyle(
                                    color: AppTheme.textMuted, fontSize: 12)),
                        ]),
                  ),
                  if (widget.movie.rating != null)
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 8, vertical: 4),
                      decoration: BoxDecoration(
                          color: AppTheme.card,
                          borderRadius: BorderRadius.circular(6)),
                      child: Row(children: [
                        const Icon(Icons.star_rounded,
                            color: AppTheme.gold, size: 13),
                        const SizedBox(width: 4),
                        Text(widget.movie.rating!,
                            style: const TextStyle(
                                color: Colors.white,
                                fontSize: 12,
                                fontWeight: FontWeight.w600)),
                      ]),
                    ),
                ]),
              ),
            ),

            // ── More Like This header ─────────────────────────────
            SliverToBoxAdapter(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 20, 16, 12),
                child: Row(children: [
                  Container(
                      width: 4,
                      height: 20,
                      decoration: BoxDecoration(
                          color: AppTheme.primary,
                          borderRadius: BorderRadius.circular(2))),
                  const SizedBox(width: 10),
                  const Text('More Like This',
                      style: TextStyle(
                          color: AppTheme.textPrimary,
                          fontSize: 17,
                          fontWeight: FontWeight.w800)),
                  if (widget.noRelated && _loadingUgSections) ...[
                    const SizedBox(width: 10),
                    const SizedBox(
                      width: 13, height: 13,
                      child: CircularProgressIndicator(
                          color: AppTheme.primary, strokeWidth: 2),
                    ),
                  ],
                ]),
              ),
            ),

            // ── Uganda: horizontal genre sections ─────────────────
            if (widget.noRelated) ...[
              // Loading shimmer rows while fetching
              if (_loadingUgSections && _ugSections.isEmpty)
                SliverToBoxAdapter(
                  child: Column(
                    children: List.generate(3, (_) => Padding(
                      padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Container(
                            height: 13, width: 110,
                            decoration: BoxDecoration(
                              color: AppTheme.shimmerBase,
                              borderRadius: BorderRadius.circular(6),
                            ),
                          ),
                          const SizedBox(height: 10),
                          SizedBox(
                            height: 190,
                            child: ListView.builder(
                              scrollDirection: Axis.horizontal,
                              itemCount: 4,
                              itemBuilder: (_, __) => Container(
                                width: 110, height: 190,
                                margin: const EdgeInsets.only(right: 10),
                                decoration: BoxDecoration(
                                  color: AppTheme.shimmerBase,
                                  borderRadius: BorderRadius.circular(8),
                                ),
                              ),
                            ),
                          ),
                        ],
                      ),
                    )),
                  ),
                ),
              // Actual genre sections
              for (final sec in _ugSections)
                SliverToBoxAdapter(
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        // Section label + View All
                        Row(children: [
                          Text(
                            sec.title,
                            style: const TextStyle(
                              color: AppTheme.textSecondary,
                              fontSize: 13,
                              fontWeight: FontWeight.w700,
                              letterSpacing: 0.3,
                            ),
                          ),
                          const Spacer(),
                          GestureDetector(
                            onTap: () => Navigator.push(
                              context,
                              MaterialPageRoute(
                                builder: (_) => UgandaViewAllScreen(
                                  title: sec.title,
                                  pipeType: sec.pipeType,
                                  pipeId: sec.pipeId,
                                ),
                              ),
                            ),
                            child: const Text(
                              'View All',
                              style: TextStyle(
                                color: AppTheme.primary,
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                              ),
                            ),
                          ),
                        ]),
                        const SizedBox(height: 10),
                        // Horizontal movie row
                        SizedBox(
                          height: 190,
                          child: ListView.builder(
                            scrollDirection: Axis.horizontal,
                            physics: const BouncingScrollPhysics(),
                            itemCount: sec.movies.length,
                            itemBuilder: (_, i) {
                              final m = sec.movies[i];
                              return GestureDetector(
                                onTap: () {
                                  final streamFuture =
                                      VodClient().getStream(m.id);
                                  Navigator.pushReplacement(
                                    context,
                                    MaterialPageRoute(
                                      builder: (_) => UgandaDetailScreen(
                                        movie: m,
                                        streamFuture: streamFuture,
                                        ugandaPlaylist: sec.movies,
                                        ugandaIndex: i,
                                      ),
                                    ),
                                  );
                                },
                                child: Container(
                                  width: 110,
                                  margin: const EdgeInsets.only(right: 10),
                                  child: Column(
                                    crossAxisAlignment: CrossAxisAlignment.start,
                                    children: [
                                      Expanded(
                                        child: ClipRRect(
                                          borderRadius: BorderRadius.circular(8),
                                          child: m.thumbnail != null
                                              ? CachedNetworkImage(
                                                  imageUrl: m.thumbnail!,
                                                  width: 110,
                                                  fit: BoxFit.cover,
                                                  memCacheWidth: 330,
                                                  filterQuality: FilterQuality.high,
                                                  fadeInDuration: const Duration(milliseconds: 180),
                                                  placeholder: (_, __) => Container(color: AppTheme.shimmerBase),
                                                  errorWidget: (_, __, ___) => Container(
                                                    color: AppTheme.shimmerBase,
                                                    child: const Icon(Icons.movie_rounded,
                                                        color: AppTheme.textMuted, size: 22),
                                                  ),
                                                )
                                              : Container(
                                                  color: AppTheme.shimmerBase,
                                                  child: const Icon(Icons.movie_rounded,
                                                      color: AppTheme.textMuted, size: 22),
                                                ),
                                        ),
                                      ),
                                      const SizedBox(height: 5),
                                      Text(
                                        m.title,
                                        maxLines: 2,
                                        overflow: TextOverflow.ellipsis,
                                        style: const TextStyle(
                                          color: AppTheme.textPrimary,
                                          fontSize: 10,
                                          fontWeight: FontWeight.w600,
                                          height: 1.3,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              );
                            },
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              SliverToBoxAdapter(child: SizedBox(height: 80)),
            ],

            // ── Main app: 3-column related grid ──────────────────
            if (!widget.noRelated) ...[
              SliverPadding(
                padding: const EdgeInsets.symmetric(horizontal: 12),
                sliver: SliverGrid(
                  gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 3,
                    crossAxisSpacing: 8,
                    mainAxisSpacing: 8,
                    childAspectRatio: 0.56,
                  ),
                  delegate: SliverChildBuilderDelegate(
                    (context, i) {
                      final m = _related[i];
                      return GestureDetector(
                        onTap: () => Navigator.pushReplacement(context,
                            MaterialPageRoute(builder: (_) => DetailScreen(movie: m))),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Expanded(
                              child: ClipRRect(
                                borderRadius: BorderRadius.circular(8),
                                child: Stack(fit: StackFit.expand, children: [
                                  m.thumbnail != null
                                      ? CachedNetworkImage(
                                          imageUrl: m.thumbnail!,
                                          fit: BoxFit.cover,
                                          memCacheWidth: 400,
                                          memCacheHeight: 600,
                                          filterQuality: FilterQuality.high,
                                          fadeInDuration: const Duration(milliseconds: 180),
                                          cacheManager: AdizaCacheManager(),
                                          placeholder: (_, __) => Container(color: AppTheme.shimmerBase),
                                          errorWidget: (_, __, ___) => Container(
                                              color: AppTheme.shimmerBase,
                                              child: const Icon(Icons.movie_rounded,
                                                  color: AppTheme.textMuted, size: 22)))
                                      : Container(
                                          color: AppTheme.shimmerBase,
                                          child: const Icon(Icons.movie_rounded,
                                              color: AppTheme.textMuted, size: 22)),
                                  Positioned(
                                    top: 4, left: 4,
                                    child: Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                                      decoration: BoxDecoration(
                                          color: m.isTvSeries ? AppTheme.accent : AppTheme.primary,
                                          borderRadius: BorderRadius.circular(3)),
                                      child: Text(m.isTvSeries ? 'TV' : 'MV',
                                          style: const TextStyle(color: Colors.white, fontSize: 8, fontWeight: FontWeight.w800)),
                                    ),
                                  ),
                                ]),
                              ),
                            ),
                            const SizedBox(height: 5),
                            Text(m.title,
                                maxLines: 2,
                                overflow: TextOverflow.ellipsis,
                                style: const TextStyle(
                                    color: AppTheme.textPrimary,
                                    fontSize: 11,
                                    fontWeight: FontWeight.w600,
                                    height: 1.3)),
                            if (m.year != null)
                              Text(m.year!,
                                  style: const TextStyle(
                                      color: AppTheme.textMuted, fontSize: 10)),
                          ],
                        ),
                      );
                    },
                    childCount: _related.length,
                  ),
                ),
              ),
              SliverToBoxAdapter(
                child: _loadingMore
                    ? const Padding(
                        padding: EdgeInsets.symmetric(vertical: 24),
                        child: Center(
                            child: CircularProgressIndicator(
                                color: AppTheme.primary, strokeWidth: 2.5)))
                    : !_hasMore && _related.isNotEmpty
                        ? const Padding(
                            padding: EdgeInsets.symmetric(vertical: 24),
                            child: Center(
                                child: Text('No more content',
                                    style: TextStyle(
                                        color: AppTheme.textMuted, fontSize: 12))))
                        : const SizedBox(height: 80),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

// ── Quality loading sheet ─────────────────────────────────────────────────────
class _QualityLoadingSheet extends StatefulWidget {
  final MovieBoxClient client;
  final Movie movie;
  final int season;
  final int episode;
  final String currentUrl;
  final void Function(MovieSource) onSelect;
  const _QualityLoadingSheet({
    required this.client, required this.movie, required this.season,
    required this.episode, required this.currentUrl, required this.onSelect,
  });
  @override State<_QualityLoadingSheet> createState() => _QualityLoadingSheetState();
}

class _QualityLoadingSheetState extends State<_QualityLoadingSheet> {
  List<MovieSource>? _sources;
  String? _err;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final s = widget.season > 0
          ? await widget.client.getSources(widget.movie.id,
              season: widget.season, episode: widget.episode)
          : await widget.client.getSources(widget.movie.id);
      if (!mounted) return;
      setState(() => _sources = s);
    } catch (e) {
      if (mounted) setState(() => _err = 'Failed to load qualities');
    }
  }

  @override
  Widget build(BuildContext context) {
    final count = _sources?.length ?? 0;
    return DraggableScrollableSheet(
      initialChildSize: count > 4 ? 0.6 : 0.45,
      minChildSize: 0.25,
      maxChildSize: 0.85,
      expand: false,
      builder: (_, ctrl) => Container(
        decoration: const BoxDecoration(
            color: Colors.black,
            borderRadius: BorderRadius.vertical(top: Radius.circular(20))),
        child: ListView(
          controller: ctrl,
          padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
          children: [
            Center(child: Container(
              margin: const EdgeInsets.symmetric(vertical: 12),
              width: 40, height: 4,
              decoration: BoxDecoration(color: Colors.white24, borderRadius: BorderRadius.circular(2)),
            )),
            const Padding(
              padding: EdgeInsets.only(bottom: 12),
              child: Text('Select Quality to Watch',
                  style: TextStyle(color: Colors.white, fontWeight: FontWeight.w700, fontSize: 17)),
            ),
            if (_err != null)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 16),
                child: Row(children: [
                  const Icon(Icons.error_outline_rounded, color: AppTheme.primary, size: 20),
                  const SizedBox(width: 8),
                  Text(_err!, style: const TextStyle(color: Colors.white70, fontSize: 13)),
                ]),
              ),
            if (_err == null && _sources == null)
              const Padding(
                padding: EdgeInsets.symmetric(vertical: 28),
                child: Center(child: CircularProgressIndicator(color: AppTheme.primary, strokeWidth: 2.5)),
              ),
            if (_sources != null)
              ..._sources!.map((s) {
              final isCurrent = s.directUrl == widget.currentUrl;
              return Container(
                margin: const EdgeInsets.only(bottom: 10),
                decoration: BoxDecoration(
                  color: Colors.black,
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(
                    color: isCurrent ? AppTheme.primary : AppTheme.primary.withOpacity(0.28),
                    width: isCurrent ? 1.5 : 1,
                  ),
                ),
                child: InkWell(
                  borderRadius: BorderRadius.circular(14),
                  splashColor: AppTheme.primary.withOpacity(0.08),
                  onTap: () => widget.onSelect(s),
                  child: Padding(
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
                    child: Row(
                      children: [
                        Container(
                          width: 50, height: 50,
                          decoration: BoxDecoration(
                            color: AppTheme.primary.withOpacity(isCurrent ? 0.2 : 0.12),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: AppTheme.primary.withOpacity(0.4)),
                          ),
                          child: Icon(
                            isCurrent ? Icons.play_circle_filled_rounded : Icons.play_circle_rounded,
                            color: AppTheme.primary, size: 26,
                          ),
                        ),
                        const SizedBox(width: 14),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(children: [
                                Text(s.quality,
                                    style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.w800)),
                                const SizedBox(width: 8),
                                Container(
                                  padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                                  decoration: BoxDecoration(color: AppTheme.primary, borderRadius: BorderRadius.circular(5)),
                                  child: Text(qualityLabel(s.quality),
                                      style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.w700)),
                                ),
                                if (isCurrent) ...[
                                  const SizedBox(width: 8),
                                  Container(
                                    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                    decoration: BoxDecoration(color: Colors.white12, borderRadius: BorderRadius.circular(4)),
                                    child: const Text('Playing', style: TextStyle(color: Colors.white54, fontSize: 9, fontWeight: FontWeight.w600)),
                                  ),
                                ],
                              ]),
                              if (s.size > 0) ...[
                                const SizedBox(height: 3),
                                Text('${(s.size / 1024 / 1024).toStringAsFixed(0)} MB',
                                    style: const TextStyle(color: Colors.white38, fontSize: 12)),
                              ],
                            ],
                          ),
                        ),
                        const Icon(Icons.chevron_right_rounded, color: Colors.white24, size: 22),
                      ],
                    ),
                  ),
                ),
              );
            }),
          ],
        ),
      ),
    );
  }
}
