import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:video_player/video_player.dart';
import '../theme/app_theme.dart';

class LocalVideoPlayerScreen extends StatefulWidget {
  final String filePath;
  final String title;

  const LocalVideoPlayerScreen({
    super.key,
    required this.filePath,
    required this.title,
  });

  @override
  State<LocalVideoPlayerScreen> createState() => _LocalVideoPlayerScreenState();
}

class _LocalVideoPlayerScreenState extends State<LocalVideoPlayerScreen> {
  late VideoPlayerController _controller;
  bool _initialized = false;
  bool _hasError = false;
  String _errorMsg = '';
  bool _showControls = true;
  Timer? _hideTimer;
  bool _isFullscreen = false; // ignore: unused_field

  @override
  void initState() {
    super.initState();
    SystemChrome.setPreferredOrientations([
      DeviceOrientation.portraitUp,
      DeviceOrientation.landscapeLeft,
      DeviceOrientation.landscapeRight,
    ]);
    _initPlayer();
  }

  Future<void> _initPlayer() async {
    final file = File(widget.filePath);
    if (!await file.exists()) {
      setState(() {
        _hasError = true;
        _errorMsg = 'File not found on device.\nPath: ${widget.filePath}';
      });
      return;
    }
    try {
      _controller = VideoPlayerController.file(file);
      await _controller.initialize();
      _controller.addListener(_onPlayerUpdate);
      await _controller.play();
      if (mounted) setState(() => _initialized = true);
      _scheduleHideControls();
    } catch (e) {
      if (mounted) {
        setState(() {
          _hasError = true;
          _errorMsg = 'Cannot play this file: $e';
        });
      }
    }
  }

  void _onPlayerUpdate() {
    if (mounted) setState(() {});
  }

  void _scheduleHideControls() {
    _hideTimer?.cancel();
    _hideTimer = Timer(const Duration(seconds: 3), () {
      if (mounted && _controller.value.isPlaying) {
        setState(() => _showControls = false);
      }
    });
  }

  void _toggleControls() {
    setState(() => _showControls = !_showControls);
    if (_showControls) _scheduleHideControls();
  }

  void _togglePlayPause() {
    if (_controller.value.isPlaying) {
      _controller.pause();
      setState(() => _showControls = true);
      _hideTimer?.cancel();
    } else {
      _controller.play();
      _scheduleHideControls();
    }
  }

  void _seek(Duration delta) {
    final pos = _controller.value.position + delta;
    final dur = _controller.value.duration;
    _controller.seekTo(pos.isNegative ? Duration.zero : (pos > dur ? dur : pos));
  }

  String _formatDuration(Duration d) {
    final h = d.inHours;
    final m = d.inMinutes.remainder(60).toString().padLeft(2, '0');
    final s = d.inSeconds.remainder(60).toString().padLeft(2, '0');
    return h > 0 ? '$h:$m:$s' : '$m:$s';
  }

  @override
  void dispose() {
    _hideTimer?.cancel();
    if (_initialized) {
      _controller.removeListener(_onPlayerUpdate);
      _controller.dispose();
    }
    SystemChrome.setPreferredOrientations([DeviceOrientation.portraitUp]);
    SystemChrome.setEnabledSystemUIMode(SystemUiMode.edgeToEdge);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: SafeArea(
        child: _hasError ? _buildError() : _buildPlayer(),
      ),
    );
  }

  Widget _buildError() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline_rounded, color: Colors.red, size: 56),
            const SizedBox(height: 16),
            Text(_errorMsg,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.white70, fontSize: 14)),
            const SizedBox(height: 24),
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Go Back', style: TextStyle(color: AppTheme.primary)),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPlayer() {
    if (!_initialized) {
      return const Center(child: CircularProgressIndicator(color: AppTheme.primary));
    }

    final size = _controller.value.size;
    final aspectRatio = size.width > 0 && size.height > 0
        ? size.width / size.height
        : 16 / 9;
    final pos  = _controller.value.position;
    final dur  = _controller.value.duration;
    final pct  = dur.inMilliseconds > 0 ? pos.inMilliseconds / dur.inMilliseconds : 0.0;

    return GestureDetector(
      onTap: _toggleControls,
      behavior: HitTestBehavior.opaque,
      child: Stack(
        children: [
          // Video
          Center(
            child: AspectRatio(
              aspectRatio: aspectRatio,
              child: VideoPlayer(_controller),
            ),
          ),

          // Overlay controls
          AnimatedOpacity(
            opacity: _showControls ? 1.0 : 0.0,
            duration: const Duration(milliseconds: 250),
            child: IgnorePointer(
              ignoring: !_showControls,
              child: Container(
                decoration: const BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topCenter,
                    end: Alignment.bottomCenter,
                    colors: [Color(0xAA000000), Colors.transparent, Colors.transparent, Color(0xCC000000)],
                    stops: [0.0, 0.25, 0.7, 1.0],
                  ),
                ),
                child: Column(
                  children: [
                    // Top bar
                    Padding(
                      padding: const EdgeInsets.fromLTRB(8, 8, 8, 0),
                      child: Row(
                        children: [
                          IconButton(
                            icon: const Icon(Icons.arrow_back_ios_new_rounded, color: Colors.white),
                            onPressed: () => Navigator.pop(context),
                          ),
                          Expanded(
                            child: Text(
                              widget.title,
                              style: const TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.w600),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                        ],
                      ),
                    ),

                    const Spacer(),

                    // Centre seek + play buttons
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        _SeekButton(
                          icon: Icons.replay_10_rounded,
                          onTap: () => _seek(const Duration(seconds: -10)),
                        ),
                        const SizedBox(width: 24),
                        GestureDetector(
                          onTap: _togglePlayPause,
                          child: Container(
                            width: 60, height: 60,
                            decoration: BoxDecoration(
                              color: AppTheme.primary.withOpacity(0.85),
                              shape: BoxShape.circle,
                            ),
                            child: Icon(
                              _controller.value.isPlaying
                                  ? Icons.pause_rounded
                                  : Icons.play_arrow_rounded,
                              color: Colors.white,
                              size: 36,
                            ),
                          ),
                        ),
                        const SizedBox(width: 24),
                        _SeekButton(
                          icon: Icons.forward_10_rounded,
                          onTap: () => _seek(const Duration(seconds: 10)),
                        ),
                      ],
                    ),

                    const Spacer(),

                    // Bottom progress bar + time
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                      child: Column(
                        children: [
                          SliderTheme(
                            data: SliderThemeData(
                              trackHeight: 3,
                              thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
                              overlayShape: const RoundSliderOverlayShape(overlayRadius: 12),
                              activeTrackColor: AppTheme.primary,
                              inactiveTrackColor: Colors.white24,
                              thumbColor: AppTheme.primary,
                              overlayColor: AppTheme.primary.withOpacity(0.2),
                            ),
                            child: Slider(
                              value: pct.clamp(0.0, 1.0),
                              onChanged: (v) {
                                _controller.seekTo(dur * v);
                                _scheduleHideControls();
                              },
                            ),
                          ),
                          Row(
                            mainAxisAlignment: MainAxisAlignment.spaceBetween,
                            children: [
                              Text(_formatDuration(pos),
                                  style: const TextStyle(color: Colors.white70, fontSize: 11)),
                              Text(_formatDuration(dur),
                                  style: const TextStyle(color: Colors.white70, fontSize: 11)),
                            ],
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
    );
  }
}

class _SeekButton extends StatelessWidget {
  final IconData icon;
  final VoidCallback onTap;
  const _SeekButton({required this.icon, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(10),
        decoration: BoxDecoration(
          color: Colors.black38,
          shape: BoxShape.circle,
          border: Border.all(color: Colors.white24),
        ),
        child: Icon(icon, color: Colors.white, size: 28),
      ),
    );
  }
}
