import 'dart:async';
import 'package:cached_network_image/cached_network_image.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:video_player/video_player.dart';
import 'package:wakelock_plus/wakelock_plus.dart';
import '../services/iptv_service.dart';
import '../theme/app_theme.dart';

class IptvPlayerScreen extends StatefulWidget {
  final IptvChannel channel;
  final List<IptvChannel> playlist;
  final int initialIndex;

  const IptvPlayerScreen({
    super.key,
    required this.channel,
    required this.playlist,
    required this.initialIndex,
  });

  @override
  State<IptvPlayerScreen> createState() => _IptvPlayerScreenState();
}

class _IptvPlayerScreenState extends State<IptvPlayerScreen> {
  static const _mediaCh = MethodChannel('com.adiza.moviezbox/media');

  late int _idx;
  VideoPlayerController? _vpc;
  bool _ready    = false;
  bool _error    = false;
  bool _controls = true;
  Timer? _hideTimer;
  bool _isPip    = false;

  IptvChannel get _current => widget.playlist[_idx];

  @override
  void initState() {
    super.initState();
    _idx = widget.initialIndex;
    WakelockPlus.enable().catchError((_) {});
    _mediaCh.invokeMethod('setPlayerActive', true).catchError((_) {});
    SystemChrome.setPreferredOrientations([
      DeviceOrientation.landscapeLeft,
      DeviceOrientation.landscapeRight,
    ]);
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.immersiveSticky);
    _loadChannel();
  }

  Future<void> _loadChannel() async {
    setState(() { _ready = false; _error = false; });
    await _vpc?.dispose();
    _vpc = null;

    try {
      final ctrl = VideoPlayerController.networkUrl(
        Uri.parse(_current.streamUrl),
        httpHeaders: const {'User-Agent': 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36'},
        videoPlayerOptions: VideoPlayerOptions(mixWithOthers: false),
      );
      await ctrl.initialize().timeout(const Duration(seconds: 20));
      if (!mounted) { ctrl.dispose(); return; }
      setState(() { _vpc = ctrl; _ready = true; _error = false; });
      _vpc!.play();
      _scheduleHide();
    } catch (_) {
      if (mounted) setState(() { _error = true; _ready = false; });
    }
  }

  void _scheduleHide() {
    _hideTimer?.cancel();
    _hideTimer = Timer(const Duration(seconds: 4), () {
      if (mounted) setState(() => _controls = false);
    });
  }

  void _toggleControls() {
    setState(() => _controls = !_controls);
    if (_controls) _scheduleHide();
  }

  void _skipTo(int idx) {
    if (idx < 0 || idx >= widget.playlist.length) return;
    setState(() => _idx = idx);
    _loadChannel();
  }

  @override
  void dispose() {
    _hideTimer?.cancel();
    _vpc?.dispose();
    WakelockPlus.disable().catchError((_) {});
    _mediaCh.invokeMethod('setPlayerActive', false).catchError((_) {});
    SystemChrome.setPreferredOrientations([DeviceOrientation.portraitUp]);
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: GestureDetector(
        onTap: _toggleControls,
        child: Stack(
          children: [
            // ── Video ──────────────────────────────────────────────────
            Center(
              child: _ready && _vpc != null
                  ? AspectRatio(
                      aspectRatio: _vpc!.value.aspectRatio,
                      child: VideoPlayer(_vpc!),
                    )
                  : _error
                      ? _ErrorView(onRetry: _loadChannel, onSkip: () => _skipTo(_idx + 1))
                      : const _LoadingView(),
            ),

            // ── Controls overlay ───────────────────────────────────────
            AnimatedOpacity(
              opacity: _controls ? 1.0 : 0.0,
              duration: const Duration(milliseconds: 250),
              child: IgnorePointer(
                ignoring: !_controls,
                child: Container(
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      begin: Alignment.topCenter,
                      end: Alignment.bottomCenter,
                      colors: [
                        Colors.black.withOpacity(0.7),
                        Colors.transparent,
                        Colors.transparent,
                        Colors.black.withOpacity(0.8),
                      ],
                      stops: const [0, 0.3, 0.7, 1],
                    ),
                  ),
                  child: Column(
                    children: [
                      // Top bar
                      SafeArea(
                        child: Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                          child: Row(
                            children: [
                              IconButton(
                                icon: const Icon(Icons.arrow_back_rounded, color: Colors.white),
                                onPressed: () => Navigator.pop(context),
                              ),
                              const SizedBox(width: 8),
                              if (_current.logo.isNotEmpty)
                                ClipRRect(
                                  borderRadius: BorderRadius.circular(4),
                                  child: CachedNetworkImage(
                                    imageUrl: _current.logo,
                                    width: 36, height: 36,
                                    fit: BoxFit.contain,
                                    errorWidget: (_, __, ___) => const Icon(Icons.tv_rounded, color: Colors.white, size: 28),
                                  ),
                                ),
                              const SizedBox(width: 10),
                              Expanded(
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Text(
                                      _current.name,
                                      style: const TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.w700),
                                      overflow: TextOverflow.ellipsis,
                                    ),
                                    Row(children: [
                                      Container(
                                        padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                                        decoration: BoxDecoration(
                                          color: Colors.red,
                                          borderRadius: BorderRadius.circular(3),
                                        ),
                                        child: const Text('LIVE', style: TextStyle(color: Colors.white, fontSize: 8, fontWeight: FontWeight.w900)),
                                      ),
                                      if (_current.quality.isNotEmpty) ...[
                                        const SizedBox(width: 6),
                                        Text(_current.quality, style: const TextStyle(color: Colors.white70, fontSize: 10)),
                                      ],
                                    ]),
                                  ],
                                ),
                              ),
                              if (!_isPip)
                                IconButton(
                                  icon: const Icon(Icons.picture_in_picture_alt_rounded, color: Colors.white),
                                  onPressed: () async {
                                    setState(() => _isPip = true);
                                    await _mediaCh.invokeMethod('enterPip').catchError((_) {});
                                  },
                                ),
                            ],
                          ),
                        ),
                      ),

                      const Spacer(),

                      // Bottom: prev / play / next
                      Padding(
                        padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            _CtrlBtn(
                              icon: Icons.skip_previous_rounded,
                              enabled: _idx > 0,
                              onTap: () => _skipTo(_idx - 1),
                            ),
                            const SizedBox(width: 20),
                            _CtrlBtn(
                              icon: _ready && (_vpc?.value.isPlaying ?? false)
                                  ? Icons.pause_rounded
                                  : Icons.play_arrow_rounded,
                              size: 52,
                              onTap: () {
                                if (_vpc == null) return;
                                if (_vpc!.value.isPlaying) {
                                  _vpc!.pause();
                                } else {
                                  _vpc!.play();
                                }
                                setState(() {});
                                _scheduleHide();
                              },
                            ),
                            const SizedBox(width: 20),
                            _CtrlBtn(
                              icon: Icons.skip_next_rounded,
                              enabled: _idx < widget.playlist.length - 1,
                              onTap: () => _skipTo(_idx + 1),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _CtrlBtn extends StatelessWidget {
  final IconData icon;
  final double size;
  final bool enabled;
  final VoidCallback onTap;

  const _CtrlBtn({
    required this.icon,
    required this.onTap,
    this.size = 36,
    this.enabled = true,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: enabled ? onTap : null,
      child: Icon(icon, color: enabled ? Colors.white : Colors.white30, size: size),
    );
  }
}

class _LoadingView extends StatelessWidget {
  const _LoadingView();
  @override
  Widget build(BuildContext context) => Column(
    mainAxisSize: MainAxisSize.min,
    children: [
      const CircularProgressIndicator(color: AppTheme.primary, strokeWidth: 2.5),
      const SizedBox(height: 16),
      Text('Connecting to channel…',
          style: TextStyle(color: Colors.white.withOpacity(0.7), fontSize: 13)),
    ],
  );
}

class _ErrorView extends StatelessWidget {
  final VoidCallback onRetry;
  final VoidCallback onSkip;
  const _ErrorView({required this.onRetry, required this.onSkip});

  @override
  Widget build(BuildContext context) => Column(
    mainAxisSize: MainAxisSize.min,
    children: [
      const Icon(Icons.signal_wifi_bad_rounded, color: Colors.white54, size: 52),
      const SizedBox(height: 12),
      const Text('Channel unavailable', style: TextStyle(color: Colors.white, fontSize: 15, fontWeight: FontWeight.w700)),
      const SizedBox(height: 4),
      const Text('Stream may be offline or geo-blocked',
          style: TextStyle(color: Colors.white54, fontSize: 12)),
      const SizedBox(height: 20),
      Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          TextButton(
            onPressed: onRetry,
            child: const Text('Retry', style: TextStyle(color: AppTheme.primary)),
          ),
          const SizedBox(width: 16),
          TextButton(
            onPressed: onSkip,
            child: const Text('Next Channel', style: TextStyle(color: Colors.white70)),
          ),
        ],
      ),
    ],
  );
}
