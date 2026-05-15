import 'dart:async';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:video_player/video_player.dart';
import 'package:webview_flutter/webview_flutter.dart';
import 'package:wakelock_plus/wakelock_plus.dart';
import '../services/football_service.dart';
import '../theme/app_theme.dart';

// ── Allowed domains inside the WebView (everything else is blocked) ────────────
const _kAllowed = [
  'embedsports.top',
  'streamed.pk',
  'streamed.su',
  'cdn-lab.shop',
];

bool _isAllowed(String url) {
  final u = url.toLowerCase();
  // Always allow m3u8 / ts / stream data
  if (u.contains('.m3u8') || u.contains('.ts') || u.contains('/hls/')) return true;
  return _kAllowed.any((d) => u.contains(d));
}

class FootballPlayerScreen extends StatefulWidget {
  final FootballMatch match;
  final List<FootballStream> streams;

  const FootballPlayerScreen({
    super.key,
    required this.match,
    required this.streams,
  });

  @override
  State<FootballPlayerScreen> createState() => _FootballPlayerScreenState();
}

class _FootballPlayerScreenState extends State<FootballPlayerScreen> {
  static const _mediaCh = MethodChannel('com.adiza.moviezbox/media');

  int     _streamIdx      = 0;
  String? _interceptedM3u8;

  // Native player state
  VideoPlayerController? _vpc;
  bool _vpcReady    = false;
  bool _showControls = true;
  Timer? _hideTimer;

  // PiP state
  bool _isPip = false;

  // WebView state
  late WebViewController _wvc;
  bool _showWebView    = false;   // stays false until fallback timeout fires
  bool _streamNotLive  = false;   // true when 232011 / no-source error detected
  Timer? _fallbackTimer;

  // Loading / status text shown while intercepting
  String _statusMsg = 'Connecting to stream…';
  Timer? _dotTimer;
  int    _dotCount  = 0;

  @override
  void initState() {
    super.initState();
    WakelockPlus.enable();
    SystemChrome.setPreferredOrientations([
      DeviceOrientation.landscapeLeft,
      DeviceOrientation.landscapeRight,
    ]);
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.immersiveSticky);
    _mediaCh.setMethodCallHandler((call) async {
      if (call.method == 'pipModeChanged') {
        if (mounted) setState(() => _isPip = call.arguments as bool? ?? false);
      }
    });
    _startDotAnimation();
    _initWebView();
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  FootballStream? get _currentStream =>
      widget.streams.isNotEmpty && _streamIdx < widget.streams.length
          ? widget.streams[_streamIdx]
          : null;

  void _startDotAnimation() {
    _dotTimer?.cancel();
    _dotTimer = Timer.periodic(const Duration(milliseconds: 500), (_) {
      if (!mounted) return;
      _dotCount = (_dotCount + 1) % 4;
      final dots = '.' * _dotCount;
      setState(() => _statusMsg = 'Connecting to stream$dots');
    });
  }

  // ── WebView init ───────────────────────────────────────────────────────────

  void _initWebView() {
    final stream = _currentStream;
    if (stream == null) return;

    _wvc = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setBackgroundColor(Colors.black)
      ..addJavaScriptChannel(
        'AdizaStream',
        onMessageReceived: (msg) {
          final url = msg.message.trim();
          if (url.contains('.m3u8') && _interceptedM3u8 == null && mounted) {
            _interceptedM3u8 = url;
            _fallbackTimer?.cancel();
            _dotTimer?.cancel();
            _tryNativePlayer(url);
          }
        },
      )
      ..addJavaScriptChannel(
        'AdizaError',
        onMessageReceived: (msg) {
          if (mounted && !_vpcReady) {
            _fallbackTimer?.cancel();
            _dotTimer?.cancel();
            setState(() => _streamNotLive = true);
          }
        },
      )
      ..setNavigationDelegate(NavigationDelegate(
        onNavigationRequest: (req) {
          // Block every URL that isn't from an allowed domain
          if (!_isAllowed(req.url)) {
            return NavigationDecision.prevent;
          }
          return NavigationDecision.navigate;
        },
        onPageStarted: (_) => _injectAll(),
        onPageFinished: (_) {
          _injectAll();
          // Give 18 seconds for m3u8 interception, then fall back to WebView
          _fallbackTimer?.cancel();
          _fallbackTimer = Timer(const Duration(seconds: 18), () {
            if (mounted && _interceptedM3u8 == null) {
              _dotTimer?.cancel();
              setState(() {
                _showWebView = true;
                _statusMsg   = 'Loading alternative stream…';
              });
            }
          });
        },
        onWebResourceError: (_) {},
      ))
      ..loadRequest(Uri.parse(stream.embedUrl));
  }

  // ── JavaScript injection ───────────────────────────────────────────────────

  void _injectAll() {
    // 1. Block all popups, alerts, redirects, window.open
    _wvc.runJavaScript(r'''
      (function() {
        window.open        = function() { return null; };
        window.alert       = function() {};
        window.confirm     = function() { return true; };
        window.prompt      = function() { return ''; };
        // Block location redirects
        try {
          Object.defineProperty(window, 'location', {
            set: function() {},
            configurable: true
          });
        } catch(_) {}
      })();
    ''');

    // 2. Intercept m3u8 from fetch / XHR / video.src
    _wvc.runJavaScript(r'''
      (function() {
        if (window.__adizaHooked) return;
        window.__adizaHooked = true;

        function _send(url) {
          if (!url || !url.toString().includes('.m3u8')) return;
          try { AdizaStream.postMessage(url.toString()); } catch(_) {}
        }

        // Intercept fetch
        const _fetch = window.fetch;
        window.fetch = function(...args) {
          _send(args[0] instanceof Request ? args[0].url : args[0]);
          return _fetch.apply(this, args);
        };

        // Intercept XHR
        const _open = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url) {
          _send(url);
          return _open.apply(this, arguments);
        };

        // Intercept <video src=...>
        const _srcDesc = Object.getOwnPropertyDescriptor(HTMLMediaElement.prototype, 'src');
        if (_srcDesc && _srcDesc.set) {
          Object.defineProperty(HTMLMediaElement.prototype, 'src', {
            set: function(val) { _send(val); _srcDesc.set.call(this, val); },
            get: _srcDesc.get,
            configurable: true,
          });
        }

        // Intercept setAttribute('src', ...)
        const _setAttr = Element.prototype.setAttribute;
        Element.prototype.setAttribute = function(name, val) {
          if (name === 'src') _send(val);
          return _setAttr.call(this, name, val);
        };

        // Poll existing video elements
        setInterval(function() {
          document.querySelectorAll('video').forEach(function(v) {
            if (v.src) _send(v.src);
            if (v.currentSrc) _send(v.currentSrc);
          });
        }, 1000);
      })();
    ''');

    // 3. Hide any site branding, logos, watermarks, domain text
    _wvc.runJavaScript(r'''
      (function() {
        if (window.__adizaBrandHidden) return;
        window.__adizaBrandHidden = true;
        var style = document.createElement('style');
        style.textContent = [
          'header, footer, nav, .navbar, .header, .footer { display:none !important; }',
          '.logo, .brand, .watermark, .site-logo, [class*="logo"], [class*="brand"] { display:none !important; }',
          '.ad, .ads, .advertisement, [class*="banner"], [id*="banner"], iframe[src*="bet"] { display:none !important; }',
          'a[href*="streamed"], a[href*="embedsports"], a[href*="strmd"] { pointer-events:none !important; opacity:0 !important; }',
          'body { background:#000 !important; }'
        ].join(' ');
        (document.head || document.documentElement).appendChild(style);
      })();
    ''');

    // 4. Detect video errors (e.g. 232011 = stream not live yet)
    _wvc.runJavaScript(r'''
      (function() {
        if (window.__adizaErrHooked) return;
        window.__adizaErrHooked = true;
        function _checkErr(v) {
          v.addEventListener('error', function() {
            try { AdizaError.postMessage('error'); } catch(_) {}
          });
          // Also detect empty source / stalled with no data
          v.addEventListener('stalled', function() {
            if (!v.src && !v.currentSrc) {
              try { AdizaError.postMessage('nosrc'); } catch(_) {}
            }
          });
        }
        document.querySelectorAll('video').forEach(_checkErr);
        // Watch for future video elements added dynamically
        new MutationObserver(function(muts) {
          muts.forEach(function(m) {
            m.addedNodes.forEach(function(n) {
              if (n.tagName === 'VIDEO') _checkErr(n);
              if (n.querySelectorAll) n.querySelectorAll('video').forEach(_checkErr);
            });
          });
        }).observe(document.body || document.documentElement, { childList: true, subtree: true });
      })();
    ''');
  }

  // ── Native player ──────────────────────────────────────────────────────────

  Future<void> _tryNativePlayer(String m3u8Url) async {
    if (mounted) setState(() => _statusMsg = 'Starting HD stream…');

    final ctrl = VideoPlayerController.networkUrl(
      Uri.parse(m3u8Url),
      httpHeaders: {
        'Referer':    'https://embedsports.top/',
        'Origin':     'https://embedsports.top',
        'User-Agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7)',
      },
    );
    try {
      await ctrl.initialize().timeout(const Duration(seconds: 12));
      if (!mounted) { ctrl.dispose(); return; }
      setState(() {
        _vpc       = ctrl;
        _vpcReady  = true;
        _showWebView = false;
      });
      ctrl.play();
      _scheduleHideControls();
    } catch (_) {
      ctrl.dispose();
      // Native failed → show WebView as last resort
      if (mounted) {
        _dotTimer?.cancel();
        setState(() {
          _showWebView = true;
          _statusMsg   = 'Loading alternative stream…';
        });
      }
    }
  }

  void _scheduleHideControls() {
    _hideTimer?.cancel();
    _hideTimer = Timer(const Duration(seconds: 5), () {
      if (mounted && (_vpc?.value.isPlaying ?? false)) {
        setState(() => _showControls = false);
      }
    });
  }

  void _toggleControls() {
    setState(() => _showControls = !_showControls);
    if (_showControls) _scheduleHideControls();
  }

  // ── Stream switching ───────────────────────────────────────────────────────

  void _switchStream(int idx) {
    if (idx == _streamIdx) return;
    _fallbackTimer?.cancel();
    _dotTimer?.cancel();
    _vpc?.dispose();
    setState(() {
      _streamIdx       = idx;
      _vpcReady        = false;
      _showWebView     = false;
      _streamNotLive   = false;
      _interceptedM3u8 = null;
      _statusMsg       = 'Connecting to stream…';
    });
    _startDotAnimation();
    _initWebView();
  }

  @override
  void dispose() {
    _mediaCh.setMethodCallHandler(null);
    _hideTimer?.cancel();
    _fallbackTimer?.cancel();
    _dotTimer?.cancel();
    _vpc?.dispose();
    WakelockPlus.disable();
    SystemChrome.setPreferredOrientations([DeviceOrientation.portraitUp]);
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
    super.dispose();
  }

  Future<void> _enterPip() async {
    try { await _mediaCh.invokeMethod<bool>('enterPip'); } catch (_) {}
  }

  // ── Build ──────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Stack(
        children: [

          // ── 1. Hidden WebView (always running in background for interception)
          Offstage(
            offstage: !_showWebView,
            child: WebViewWidget(controller: _wvc),
          ),

          // ── 2. Native player (shown when m3u8 extracted successfully) ──────
          if (_vpcReady && _vpc != null)
            GestureDetector(
              onTap: _toggleControls,
              child: Stack(
                alignment: Alignment.center,
                children: [
                  SizedBox.expand(
                    child: FittedBox(
                      fit: BoxFit.contain,
                      child: SizedBox(
                        width:  _vpc!.value.size.width,
                        height: _vpc!.value.size.height,
                        child:  VideoPlayer(_vpc!),
                      ),
                    ),
                  ),
                  if (_showControls)
                    _NativeControls(
                      controller: _vpc!,
                      onSeek: (d) => _vpc!.seekTo(_vpc!.value.position + d),
                      onInteract: _scheduleHideControls,
                    ),
                ],
              ),
            ),

          // ── 3. Loading screen (shown until m3u8 found OR fallback fires) ───
          if (!_vpcReady && !_showWebView && !_streamNotLive)
            _LoadingScreen(
              matchTitle:    widget.match.title,
              statusMsg:     _statusMsg,
              homeBadgeUrl:  widget.match.homeBadgeUrl,
              awayBadgeUrl:  widget.match.awayBadgeUrl,
            ),

          // ── 4. Stream not live yet overlay ───────────────────────────────
          if (_streamNotLive)
            Container(
              color: Colors.black,
              child: Center(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 32),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.schedule_rounded,
                          color: Color(0xFF00C853), size: 64),
                      const SizedBox(height: 20),
                      const Text('Stream Not Live Yet',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 22,
                          fontWeight: FontWeight.w800,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 10),
                      Text(widget.match.title,
                        style: const TextStyle(
                          color: Color(0xFF00C853),
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'This match hasn\'t started broadcasting yet.\nCheck back closer to kick-off.',
                        style: TextStyle(
                          color: Colors.white54,
                          fontSize: 13,
                          height: 1.5,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 28),
                      if (widget.streams.length > 1)
                        OutlinedButton.icon(
                          onPressed: () {
                            final next = (_streamIdx + 1) % widget.streams.length;
                            _switchStream(next);
                          },
                          icon: const Icon(Icons.swap_horiz_rounded,
                              color: Color(0xFF00C853)),
                          label: const Text('Try Another Stream',
                              style: TextStyle(color: Color(0xFF00C853))),
                          style: OutlinedButton.styleFrom(
                            side: const BorderSide(color: Color(0xFF00C853)),
                            padding: const EdgeInsets.symmetric(
                                horizontal: 24, vertical: 12),
                          ),
                        ),
                      const SizedBox(height: 12),
                      TextButton.icon(
                        onPressed: () => Navigator.pop(context),
                        icon: const Icon(Icons.arrow_back_rounded,
                            color: Colors.white54, size: 18),
                        label: const Text('Go Back',
                            style: TextStyle(color: Colors.white54)),
                      ),
                    ],
                  ),
                ),
              ),
            ),

          if (!_isPip) ...[

            // ── Stream switcher bar (top) ────────────────────────────────────
            if (widget.streams.length > 1)
              Positioned(
                top: 0, left: 0, right: 0,
                child: _StreamBar(
                  streams: widget.streams,
                  current: _streamIdx,
                  onSelect: _switchStream,
                ),
              ),

            // ── Back button ─────────────────────────────────────────────────
            Positioned(
              top: widget.streams.length > 1 ? 44 : 4,
              left: 4,
              child: SafeArea(
                child: IconButton(
                  icon: const Icon(Icons.arrow_back_rounded,
                      color: Colors.white, shadows: [Shadow(color: Colors.black, blurRadius: 6)]),
                  onPressed: () => Navigator.pop(context),
                ),
              ),
            ),

            // ── Match title (top right) ──────────────────────────────────────
            Positioned(
              top: widget.streams.length > 1 ? 44 : 4,
              right: 8,
              child: SafeArea(
                child: Padding(
                  padding: const EdgeInsets.only(top: 12),
                  child: Text(
                    widget.match.title,
                    style: const TextStyle(
                      color: Colors.white60,
                      fontSize: 11,
                      fontWeight: FontWeight.w600,
                      shadows: [Shadow(color: Colors.black, blurRadius: 6)],
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ),
            ),

            // ── PiP button (bottom-left) ────────────────────────────────────
            Positioned(
              bottom: 12,
              left: 12,
              child: SafeArea(
                child: Material(
                  color: Colors.transparent,
                  child: Tooltip(
                    message: 'Picture in Picture',
                    child: InkWell(
                      onTap: _enterPip,
                      borderRadius: BorderRadius.circular(8),
                      child: Container(
                        padding: const EdgeInsets.all(6),
                        decoration: BoxDecoration(
                          color: Colors.black45,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: const Icon(
                          Icons.picture_in_picture_alt_rounded,
                          color: Colors.white,
                          size: 20,
                          shadows: [Shadow(color: Colors.black, blurRadius: 6)],
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),

            // ── Native HD badge ──────────────────────────────────────────────
            if (_vpcReady)
              const Positioned(
                bottom: 10,
                right: 12,
                child: _NativeBadge(),
              ),

          ], // end !_isPip
        ],
      ),
    );
  }
}

// ── Loading screen ─────────────────────────────────────────────────────────────

class _LoadingScreen extends StatelessWidget {
  final String  matchTitle;
  final String  statusMsg;
  final String? homeBadgeUrl;
  final String? awayBadgeUrl;

  const _LoadingScreen({
    required this.matchTitle,
    required this.statusMsg,
    this.homeBadgeUrl,
    this.awayBadgeUrl,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      color: Colors.black,
      child: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Team logos side-by-side (or fallback icon)
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                _BadgeLogo(url: homeBadgeUrl),
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  child: Column(
                    children: [
                      const Text('vs',
                        style: TextStyle(
                          color: Colors.white54,
                          fontSize: 16,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 1,
                        )),
                      const SizedBox(height: 6),
                      SizedBox(
                        width: 22, height: 22,
                        child: CircularProgressIndicator(
                          color: AppTheme.primary.withOpacity(0.8),
                          strokeWidth: 2,
                        ),
                      ),
                    ],
                  ),
                ),
                _BadgeLogo(url: awayBadgeUrl),
              ],
            ),
            const SizedBox(height: 22),
            Text(
              matchTitle,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 16,
                fontWeight: FontWeight.w700,
              ),
              textAlign: TextAlign.center,
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 14),
            Text(
              statusMsg,
              style: const TextStyle(color: Colors.white54, fontSize: 13),
            ),
            const SizedBox(height: 5),
            const Text(
              'Optimizing stream quality for you…',
              style: TextStyle(color: Colors.white24, fontSize: 11),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Badge logo (loading screen) ────────────────────────────────────────────────

class _BadgeLogo extends StatelessWidget {
  final String? url;
  const _BadgeLogo({this.url});

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 78, height: 78,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF161616),
        shape: BoxShape.circle,
        border: Border.all(
          color: Colors.white.withOpacity(0.12), width: 1.5),
      ),
      child: ClipOval(
        child: url != null
            ? CachedNetworkImage(
                imageUrl: url!,
                fit: BoxFit.contain,
                placeholder: (_, __) => const Icon(
                  Icons.sports_soccer_rounded,
                  color: Color(0xFF444444), size: 28),
                errorWidget: (_, __, ___) => const Icon(
                  Icons.sports_soccer_rounded,
                  color: Color(0xFF444444), size: 28),
              )
            : const Icon(Icons.sports_soccer_rounded,
                color: Color(0xFF444444), size: 28),
      ),
    );
  }
}

// ── Native player controls ─────────────────────────────────────────────────────

class _NativeControls extends StatefulWidget {
  final VideoPlayerController controller;
  final ValueChanged<Duration> onSeek;
  final VoidCallback onInteract;
  const _NativeControls({
    required this.controller,
    required this.onSeek,
    required this.onInteract,
  });
  @override
  State<_NativeControls> createState() => _NativeControlsState();
}

class _NativeControlsState extends State<_NativeControls> {
  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_update);
  }

  void _update() { if (mounted) setState(() {}); }

  @override
  void dispose() {
    widget.controller.removeListener(_update);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final val    = widget.controller.value;
    final dur    = val.duration;
    final isLive = dur.inSeconds == 0;

    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: widget.onInteract,
      child: Container(
        decoration: const BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topCenter,
            end: Alignment.bottomCenter,
            colors: [Colors.black54, Colors.transparent, Colors.transparent, Colors.black87],
          ),
        ),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.end,
          children: [
            if (isLive)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: Colors.red.withOpacity(0.85),
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: const Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.circle, color: Colors.white, size: 8),
                      SizedBox(width: 5),
                      Text('LIVE', style: TextStyle(
                        color: Colors.white, fontSize: 11,
                        fontWeight: FontWeight.w800, letterSpacing: 1.2)),
                    ],
                  ),
                ),
              ),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                if (!isLive)
                  IconButton(
                    icon: const Icon(Icons.replay_10_rounded, color: Colors.white, size: 32),
                    onPressed: () {
                      widget.onInteract();
                      widget.onSeek(const Duration(seconds: -10));
                    },
                  ),
                if (!isLive) const SizedBox(width: 24),
                IconButton(
                  icon: Icon(
                    val.isPlaying ? Icons.pause_circle_filled_rounded
                                  : Icons.play_circle_filled_rounded,
                    color: Colors.white, size: 56,
                  ),
                  onPressed: () {
                    widget.onInteract();
                    if (val.isPlaying) {
                      widget.controller.pause();
                    } else {
                      widget.controller.play();
                    }
                  },
                ),
                if (!isLive) const SizedBox(width: 24),
                if (!isLive)
                  IconButton(
                    icon: const Icon(Icons.forward_10_rounded, color: Colors.white, size: 32),
                    onPressed: () {
                      widget.onInteract();
                      widget.onSeek(const Duration(seconds: 10));
                    },
                  ),
              ],
            ),
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 4, 16, 16),
              child: isLive
                  ? const SizedBox.shrink()
                  : VideoProgressIndicator(
                      widget.controller,
                      allowScrubbing: true,
                      colors: const VideoProgressColors(
                        playedColor:     AppTheme.primary,
                        bufferedColor:   Colors.white24,
                        backgroundColor: Colors.white12,
                      ),
                    ),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Stream switcher bar ────────────────────────────────────────────────────────

class _StreamBar extends StatelessWidget {
  final List<FootballStream> streams;
  final int current;
  final ValueChanged<int> onSelect;
  const _StreamBar({required this.streams, required this.current, required this.onSelect});

  @override
  Widget build(BuildContext context) {
    return Container(
      color: Colors.black87,
      height: 40,
      child: ListView.separated(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 6),
        itemCount: streams.length,
        separatorBuilder: (_, __) => const SizedBox(width: 6),
        itemBuilder: (_, i) {
          final s   = streams[i];
          final sel = i == current;
          return GestureDetector(
            onTap: () => onSelect(i),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 2),
              decoration: BoxDecoration(
                color: sel ? AppTheme.primary : Colors.white12,
                borderRadius: BorderRadius.circular(6),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (s.hd)
                    const Text('HD ',
                        style: TextStyle(color: Colors.white, fontSize: 9, fontWeight: FontWeight.w800)),
                  Text(
                    s.language.isNotEmpty ? '${s.language} ${i + 1}' : 'Stream ${i + 1}',
                    style: TextStyle(
                      color: sel ? Colors.white : Colors.white70,
                      fontSize: 11,
                      fontWeight: sel ? FontWeight.w700 : FontWeight.w500,
                    ),
                  ),
                  if (s.viewers > 0) ...[
                    const SizedBox(width: 4),
                    Text('· ${s.viewers}',
                        style: const TextStyle(color: Colors.white38, fontSize: 9)),
                  ],
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

// ── Native HD badge ────────────────────────────────────────────────────────────

class _NativeBadge extends StatelessWidget {
  const _NativeBadge();
  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
      decoration: BoxDecoration(
        color: Colors.green.withOpacity(0.85),
        borderRadius: BorderRadius.circular(5),
      ),
      child: const Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.hd_rounded, color: Colors.white, size: 12),
          SizedBox(width: 4),
          Text('Native HD', style: TextStyle(color: Colors.white, fontSize: 9, fontWeight: FontWeight.w700)),
        ],
      ),
    );
  }
}
