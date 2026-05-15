import 'dart:async';
import 'dart:io';
import 'dart:math' as math;

import 'package:dio/dio.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path_provider/path_provider.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Force-update watchdog
// ─────────────────────────────────────────────────────────────────────────────
class _ForceUpdateGuard with WidgetsBindingObserver {
  final NavigatorState navigator;
  final Map<String, dynamic> updateData;
  bool _active = true;
  bool _pushing = false;
  bool Function()? isMounted;

  _ForceUpdateGuard({required this.navigator, required this.updateData}) {
    WidgetsBinding.instance.addObserver(this);
  }

  void deactivate() {
    _active = false;
    isMounted = null;
    WidgetsBinding.instance.removeObserver(this);
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (!_active || _pushing) return;
    if (state == AppLifecycleState.resumed) {
      final showing = isMounted?.call() ?? false;
      if (!showing) {
        _pushing = true;
        navigator
            .push(PageRouteBuilder(
              opaque: true,
              barrierDismissible: false,
              pageBuilder: (_, __, ___) => UpdateScreen(
                apkUrl:      updateData['apkUrl']      as String,
                versionName: updateData['versionName'] as String,
                changelog:   updateData['changelog']   as String? ?? '',
                updateSize:  updateData['updateSize']  as String? ?? '',
                versionCode: updateData['versionCode'] as int? ?? 0,
                force: true,
              ),
              transitionsBuilder: (_, anim, __, child) =>
                  FadeTransition(opacity: anim, child: child),
            ))
            .then((_) => _pushing = false);
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// UpdateScreen
// ─────────────────────────────────────────────────────────────────────────────
class UpdateScreen extends StatefulWidget {
  final String apkUrl;
  final String versionName;
  final String changelog;
  final String updateSize;
  final int    versionCode;
  final bool   force;

  const UpdateScreen({
    super.key,
    required this.apkUrl,
    required this.versionName,
    required this.changelog,
    required this.updateSize,
    this.versionCode = 0,
    this.force = false,
  });

  @override
  State<UpdateScreen> createState() => _UpdateScreenState();
}

class _UpdateScreenState extends State<UpdateScreen>
    with TickerProviderStateMixin, WidgetsBindingObserver {

  static const _channel = MethodChannel('com.adiza.moviezbox/media');
  static _ForceUpdateGuard? _guard;

  // ── Animation controllers ────────────────────────────────────────────────
  late AnimationController _pulseCtrl;
  late AnimationController _glowCtrl;
  late AnimationController _ringCtrl;
  late AnimationController _contentCtrl;
  late AnimationController _successCtrl;

  late Animation<double> _pulse;
  late Animation<double> _glow;
  late Animation<double> _ring1;
  late Animation<double> _ring2;
  late Animation<double> _contentFade;
  late Animation<Offset>  _contentSlide;
  late Animation<double> _successScale;
  late Animation<double> _successFade;

  // ── Particles ────────────────────────────────────────────────────────────
  final List<_Particle> _particles = List.generate(
    18,
    (i) => _Particle(
      x:     math.Random().nextDouble(),
      y:     math.Random().nextDouble(),
      size:  math.Random().nextDouble() * 2 + 0.5,
      speed: math.Random().nextDouble() * 0.25 + 0.08,
      phase: math.Random().nextDouble() * math.pi * 2,
    ),
  );

  // ── Download state ───────────────────────────────────────────────────────
  bool   _downloading       = false;
  double _downloadProgress  = 0.0;
  double _downloadedMB      = 0.0;
  double _totalMB           = 0.0;
  String _downloadStatus    = '';
  CancelToken? _cancelToken;

  // ── Complete state ───────────────────────────────────────────────────────
  bool   _downloadComplete   = false;
  String _savedFilePath      = '';
  String _pendingContentUri  = '';
  String _pendingFileUri     = '';

  // ── Install state ────────────────────────────────────────────────────────
  bool _awaitingPermission = false;
  bool _awaitingUninstall  = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _initAnimations();
    _contentCtrl.forward();
    if (widget.force) _activateGuard();
  }

  void _initAnimations() {
    _pulseCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 2200))
      ..repeat(reverse: true);
    _glowCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1800))
      ..repeat(reverse: true);
    _ringCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 3200))
      ..repeat();
    _contentCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 800));
    _successCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 600));

    _pulse = Tween<double>(begin: 0.93, end: 1.08).animate(
        CurvedAnimation(parent: _pulseCtrl, curve: Curves.easeInOut));
    _glow = Tween<double>(begin: 0.4, end: 1.0).animate(
        CurvedAnimation(parent: _glowCtrl, curve: Curves.easeInOut));
    _ring1 = Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(parent: _ringCtrl, curve: Curves.linear));
    _ring2 = Tween<double>(begin: 0.3, end: 1.3).animate(
        CurvedAnimation(parent: _ringCtrl, curve: Curves.linear));
    _contentFade = Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(parent: _contentCtrl,
            curve: const Interval(0.0, 0.7, curve: Curves.easeOut)));
    _contentSlide =
        Tween<Offset>(begin: const Offset(0, 0.06), end: Offset.zero).animate(
            CurvedAnimation(parent: _contentCtrl, curve: Curves.easeOut));
    _successScale = Tween<double>(begin: 0.7, end: 1.0).animate(
        CurvedAnimation(parent: _successCtrl, curve: Curves.elasticOut));
    _successFade = Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(parent: _successCtrl,
            curve: const Interval(0.0, 0.4, curve: Curves.easeOut)));
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state != AppLifecycleState.resumed) return;
    if (_awaitingPermission || _awaitingUninstall) {
      _retryInstall();
      return;
    }
    if (_downloadComplete) _recheckVersion();
  }

  Future<void> _recheckVersion() async {
    try {
      final info    = await PackageInfo.fromPlatform();
      final current = int.tryParse(info.buildNumber) ?? 0;
      if (widget.versionCode > 0 && current >= widget.versionCode) {
        if (!mounted) return;
        deactivateGuard();
        Navigator.of(context).pop();
      }
    } catch (_) {}
  }

  void _activateGuard() {
    _channel.invokeMethod<void>('setForceUpdate', {'enabled': true}).catchError((_) {});
    if (_guard == null) {
      _guard = _ForceUpdateGuard(
        navigator: Navigator.of(context),
        updateData: {
          'apkUrl':      widget.apkUrl,
          'versionName': widget.versionName,
          'changelog':   widget.changelog,
          'updateSize':  widget.updateSize,
          'versionCode': widget.versionCode,
        },
      );
    }
    _guard!.isMounted = () => mounted;
  }

  static void deactivateGuard() {
    _guard?.deactivate();
    _guard = null;
    _channel.invokeMethod<void>('setForceUpdate', {'enabled': false}).catchError((_) {});
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    if (widget.force) _guard?.isMounted = null;
    _pulseCtrl.dispose();
    _glowCtrl.dispose();
    _ringCtrl.dispose();
    _contentCtrl.dispose();
    _successCtrl.dispose();
    super.dispose();
  }

  // ── Downloads path ────────────────────────────────────────────────────────
  Future<String> _getDownloadsPath() async {
    try {
      final dir = await getExternalStorageDirectory();
      if (dir != null) {
        final base = dir.path.split('/Android').first;
        return '$base/Download';
      }
    } catch (_) {}
    return '/storage/emulated/0/Download';
  }

  // ── Download ──────────────────────────────────────────────────────────────
  Future<void> _startDownload() async {
    if (_downloading) return;
    final rawUrl = widget.apkUrl
        .replaceFirst('www.dropbox.com', 'dl.dropboxusercontent.com')
        .replaceAll(RegExp(r'[?&]dl=\d'), '');

    if (!mounted) return;
    setState(() {
      _downloading       = true;
      _downloadComplete  = false;
      _awaitingPermission = false;
      _awaitingUninstall  = false;
      _downloadProgress  = 0.0;
      _downloadStatus    = 'Preparing download…';
    });

    try {
      final downloadsDir = await _getDownloadsPath();
      await Directory(downloadsDir).create(recursive: true);
      final savePath = '$downloadsDir/AdizaMoviezBox_update.apk';

      final old = File(savePath);
      if (await old.exists()) await old.delete();

      _cancelToken = CancelToken();
      final dio = Dio();

      await dio.download(
        rawUrl,
        savePath,
        cancelToken: _cancelToken,
        onReceiveProgress: (received, total) {
          if (!mounted) return;
          final dlMB  = received / 1048576.0;
          final totMB = total > 0 ? total / 1048576.0 : 0.0;
          final pct   = total > 0 ? (received / total).clamp(0.0, 1.0) : 0.0;
          final label = totMB > 0
              ? 'Downloading ${dlMB.toStringAsFixed(1)} / ${totMB.toStringAsFixed(1)} MB'
              : 'Downloading ${dlMB.toStringAsFixed(1)} MB…';
          setState(() {
            _downloadProgress = pct;
            _downloadedMB     = dlMB;
            _totalMB          = totMB;
            _downloadStatus   = label;
          });
        },
        options: Options(receiveTimeout: const Duration(minutes: 15)),
      );

      if (!mounted) return;

      final fileUri = 'file://$savePath';
      String contentUri = fileUri;
      try {
        contentUri = await _channel.invokeMethod<String>(
              'getContentUri', {'filePath': savePath}) ??
            fileUri;
      } catch (_) {}

      setState(() {
        _downloading       = false;
        _downloadComplete  = true;
        _savedFilePath     = savePath;
        _pendingContentUri = contentUri;
        _pendingFileUri    = fileUri;
        _downloadStatus    = '';
      });

      await _runInstall(contentUri, fileUri);
    } on DioException catch (e) {
      if (e.type == DioExceptionType.cancel) return;
      if (!mounted) return;
      setState(() {
        _downloading    = false;
        _downloadStatus = 'Download failed. Tap to retry.';
      });
    } catch (_) {
      if (!mounted) return;
      setState(() {
        _downloading    = false;
        _downloadStatus = 'Download failed. Tap to retry.';
      });
    }
  }

  Future<void> _retryInstall() async {
    if (_pendingFileUri.isEmpty) return;
    String freshUri = _pendingContentUri;
    try {
      final rawPath = _pendingFileUri.replaceFirst('file://', '');
      freshUri = await _channel.invokeMethod<String>(
            'getContentUri', {'filePath': rawPath}) ??
          _pendingContentUri;
    } catch (_) {}
    await _runInstall(freshUri, _pendingFileUri);
  }

  Future<void> _runInstall(String contentUri, String fileUri) async {
    try {
      final raw = await _channel.invokeMethod<Object>(
        'installUpdate',
        {'contentUri': contentUri, 'fileUri': fileUri},
      );
      final res = (raw as Map?)?.cast<String, dynamic>() ?? {};
      if (!mounted) return;
      final needsPerm   = res['needsPermission']   as bool? ?? false;
      final sigConflict = res['signatureConflict'] as bool? ?? false;
      final conflictPkg = res['conflictingPackage'] as String? ?? '';
      if (needsPerm) {
        setState(() { _awaitingPermission = true; _awaitingUninstall = false; });
      } else if (sigConflict) {
        setState(() {
          _awaitingUninstall  = true;
          _awaitingPermission = false;
          _downloadStatus = 'Please uninstall the existing version, then return here.';
        });
        try {
          await _channel.invokeMethod('triggerUninstall', {'packageName': conflictPkg});
        } catch (_) {}
      } else {
        setState(() { _awaitingPermission = true; _awaitingUninstall = false; });
      }
    } catch (_) {
      if (!mounted) return;
      setState(() { _downloadStatus = 'Install error. Tap to retry.'; });
    }
  }

  void _cancelDownload() {
    _cancelToken?.cancel();
    if (!mounted) return;
    setState(() {
      _downloading      = false;
      _downloadProgress = 0.0;
      _downloadStatus   = '';
    });
  }

  void _dismiss() {
    if (!widget.force) {
      deactivateGuard();
      Navigator.of(context).pop();
    }
  }

  // ── Build ─────────────────────────────────────────────────────────────────
  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    return PopScope(
      canPop: !widget.force,
      child: AnnotatedRegion<SystemUiOverlayStyle>(
        value: const SystemUiOverlayStyle(
          statusBarColor:            Colors.transparent,
          statusBarIconBrightness:   Brightness.light,
          systemNavigationBarColor:  Colors.black,
        ),
        child: Scaffold(
          backgroundColor: Colors.black,
          body: Stack(
            children: [
              // ── Animated background ──────────────────────────────────────
              _AnimatedBackground(
                particles: _particles,
                glowAnim:  _glow,
                ring1Anim: _ring1,
                ring2Anim: _ring2,
                size:      size,
              ),

              // ── Content ──────────────────────────────────────────────────
              SafeArea(
                child: FadeTransition(
                  opacity: _contentFade,
                  child: SlideTransition(
                    position: _contentSlide,
                    child: _buildBody(size),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildBody(Size size) {
    if (_downloading)                           return _buildDownloadingView(size);
    if (_downloadComplete)                      return _buildCompleteView(size);
    if (_awaitingPermission || _awaitingUninstall) return _buildInstallWaitView(size);
    return _buildInfoView(size);
  }

  // ── 1. Info view ──────────────────────────────────────────────────────────
  Widget _buildInfoView(Size size) {
    final hasChangelog = widget.changelog.isNotEmpty;
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: size.height - 80),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 28),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const SizedBox(height: 12),

              // ── Glowing animated icon ──
              _GlowingUpdateIcon(
                pulseAnim: _pulse,
                glowAnim:  _glow,
              ),
              const SizedBox(height: 22),

              // ── Badge ──
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
                decoration: BoxDecoration(
                  color: const Color(0xFFC90000).withOpacity(0.12),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                      color: const Color(0xFFC90000).withOpacity(0.35), width: 1),
                ),
                child: Text(
                  'UPDATE AVAILABLE',
                  style: GoogleFonts.poppins(
                    color: const Color(0xFFFF4444),
                    fontSize: 10,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 2.0,
                  ),
                ),
              ),
              const SizedBox(height: 12),

              // ── Version ──
              Text(
                'v${widget.versionName}',
                style: GoogleFonts.poppins(
                  color: Colors.white,
                  fontSize: 32,
                  fontWeight: FontWeight.w900,
                  letterSpacing: -0.5,
                ),
              ),
              Text(
                'Adiza Moviez Box',
                style: GoogleFonts.poppins(
                  color: Colors.white.withOpacity(0.4),
                  fontSize: 13,
                ),
              ),
              if (widget.updateSize.isNotEmpty) ...[
                const SizedBox(height: 6),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                  decoration: BoxDecoration(
                    color: Colors.white.withOpacity(0.06),
                    borderRadius: BorderRadius.circular(20),
                  ),
                  child: Text(
                    widget.updateSize,
                    style: GoogleFonts.poppins(
                      color: Colors.white54, fontSize: 12),
                  ),
                ),
              ],

              const SizedBox(height: 24),

              // ── Changelog ──
              if (hasChangelog) ...[
                Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    "WHAT'S NEW",
                    style: GoogleFonts.poppins(
                      color: Colors.white38,
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.5,
                    ),
                  ),
                ),
                const SizedBox(height: 8),
                Container(
                  width: double.infinity,
                  constraints: const BoxConstraints(maxHeight: 160),
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.white.withOpacity(0.04),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(
                        color: const Color(0xFFC90000).withOpacity(0.18), width: 1),
                  ),
                  child: SingleChildScrollView(
                    physics: const BouncingScrollPhysics(),
                    child: Text(
                      widget.changelog,
                      style: GoogleFonts.poppins(
                        color: Colors.white70,
                        fontSize: 13,
                        height: 1.7,
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 24),
              ],

              // ── Force warning ──
              if (widget.force) ...[
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  decoration: BoxDecoration(
                    color: const Color(0xFF1A0000),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                        color: const Color(0xFF3A0000), width: 1),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.warning_amber_rounded,
                          color: Color(0xFFFF4444), size: 18),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          'This update is required to continue using the app.',
                          style: GoogleFonts.poppins(
                            color: const Color(0xFFFF7777),
                            fontSize: 12,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 16),
              ],

              // ── Download button ──
              SizedBox(
                width: double.infinity,
                height: 54,
                child: ElevatedButton(
                  onPressed: widget.apkUrl.isEmpty ? null : _startDownload,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFC90000),
                    disabledBackgroundColor: Colors.white12,
                    elevation: 0,
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(16)),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.download_rounded,
                          color: Colors.white, size: 22),
                      const SizedBox(width: 10),
                      Text(
                        'Download Update',
                        style: GoogleFonts.poppins(
                          color: Colors.white,
                          fontSize: 15,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              if (!widget.force) ...[
                const SizedBox(height: 10),
                TextButton(
                  onPressed: _dismiss,
                  child: Text(
                    'Later',
                    style: GoogleFonts.poppins(
                      color: Colors.white24,
                      fontSize: 13,
                    ),
                  ),
                ),
              ],

              const SizedBox(height: 20),
              _buildFooter(),
            ],
          ),
        ),
      ),
    );
  }

  // ── 2. Downloading view ───────────────────────────────────────────────────
  Widget _buildDownloadingView(Size size) {
    final pct    = (_downloadProgress * 100).toStringAsFixed(0);
    final hasPct = _downloadProgress > 0;

    return SizedBox(
      width: size.width,
      height: size.height,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(
              'Adiza Moviez Box',
              style: GoogleFonts.poppins(
                color: const Color(0xFFC90000),
                fontSize: 18,
                fontWeight: FontWeight.w800,
                letterSpacing: 0.5,
              ),
            ),
            const SizedBox(height: 44),

            // Glowing circular progress
            AnimatedBuilder(
              animation: _glowCtrl,
              builder: (_, __) => Stack(
                alignment: Alignment.center,
                children: [
                  // Outer glow ring
                  Container(
                    width: 120,
                    height: 120,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      boxShadow: [
                        BoxShadow(
                          color: const Color(0xFFC90000)
                              .withOpacity(0.3 * _glow.value),
                          blurRadius: 40,
                          spreadRadius: 8,
                        ),
                      ],
                    ),
                  ),
                  SizedBox(
                    width: 100,
                    height: 100,
                    child: CircularProgressIndicator(
                      value: hasPct ? _downloadProgress : null,
                      color: const Color(0xFFC90000),
                      backgroundColor: Colors.white10,
                      strokeWidth: 5,
                    ),
                  ),
                  Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        hasPct ? '$pct%' : '…',
                        style: GoogleFonts.poppins(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.w800,
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),

            const SizedBox(height: 32),

            Text(
              _downloadStatus,
              textAlign: TextAlign.center,
              style: GoogleFonts.poppins(
                color: Colors.white60,
                fontSize: 13,
                height: 1.5,
              ),
            ),
            const SizedBox(height: 16),

            // Linear progress bar
            ClipRRect(
              borderRadius: BorderRadius.circular(6),
              child: LinearProgressIndicator(
                value: hasPct ? _downloadProgress : null,
                minHeight: 5,
                backgroundColor: Colors.white10,
                valueColor:
                    const AlwaysStoppedAnimation(Color(0xFFC90000)),
              ),
            ),

            const SizedBox(height: 24),

            // Saving hint
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.folder_outlined,
                    color: Color(0xFF555566), size: 14),
                const SizedBox(width: 6),
                Text(
                  'Saving to Downloads folder',
                  style: GoogleFonts.poppins(
                      color: Colors.white24, fontSize: 12),
                ),
              ],
            ),

            const SizedBox(height: 32),

            TextButton(
              onPressed: _cancelDownload,
              child: Text(
                'Cancel',
                style: GoogleFonts.poppins(
                    color: Colors.white24, fontSize: 13),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── 3. Download complete view ─────────────────────────────────────────────
  Widget _buildCompleteView(Size size) {
    return SizedBox(
      width: size.width,
      height: size.height,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 28),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            // Glowing green circle
            AnimatedBuilder(
              animation: _glowCtrl,
              builder: (_, __) => Container(
                width: 100,
                height: 100,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: const Color(0xFF00AA44).withOpacity(0.10),
                  border: Border.all(
                      color: const Color(0xFF00CC55).withOpacity(0.45),
                      width: 2),
                  boxShadow: [
                    BoxShadow(
                      color: const Color(0xFF00CC55)
                          .withOpacity(0.3 * _glow.value),
                      blurRadius: 40,
                      spreadRadius: 6,
                    ),
                  ],
                ),
                child: const Icon(Icons.install_mobile_rounded,
                    color: Color(0xFF00CC55), size: 48),
              ),
            ),
            const SizedBox(height: 24),

            Text(
              'Installing Update…',
              style: GoogleFonts.poppins(
                color: Colors.white,
                fontSize: 22,
                fontWeight: FontWeight.w800,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Accept the installer prompt to finish\nupdating to v${widget.versionName}.',
              textAlign: TextAlign.center,
              style: GoogleFonts.poppins(
                color: Colors.white54,
                fontSize: 13,
                height: 1.6,
              ),
            ),
            const SizedBox(height: 28),

            // File path card
            Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
              decoration: BoxDecoration(
                color: Colors.white.withOpacity(0.04),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(
                    color: const Color(0xFF00CC55).withOpacity(0.2), width: 1),
              ),
              child: Row(
                children: [
                  const Icon(Icons.folder_rounded,
                      color: Color(0xFF4A90D9), size: 18),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      _savedFilePath,
                      style: GoogleFonts.poppins(
                        color: Colors.white54,
                        fontSize: 11,
                        height: 1.4,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 28),

            SizedBox(
              width: double.infinity,
              height: 54,
              child: ElevatedButton(
                onPressed: () => _runInstall(_pendingContentUri, _pendingFileUri),
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF0D5C2A),
                  elevation: 0,
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16)),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const Icon(Icons.refresh_rounded,
                        color: Colors.white, size: 20),
                    const SizedBox(width: 10),
                    Text(
                      'Show Installer Again',
                      style: GoogleFonts.poppins(
                        color: Colors.white,
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
              ),
            ),

            if (!widget.force) ...[
              const SizedBox(height: 10),
              TextButton(
                onPressed: _dismiss,
                child: Text('Install Later',
                    style: GoogleFonts.poppins(
                        color: Colors.white24, fontSize: 13)),
              ),
            ],
          ],
        ),
      ),
    );
  }

  // ── 4. Awaiting permission / uninstall view ───────────────────────────────
  Widget _buildInstallWaitView(Size size) {
    final isConflict = _awaitingUninstall;
    final color      = isConflict ? const Color(0xFFFF9800) : const Color(0xFF4A90D9);
    final icon       = isConflict
        ? Icons.warning_amber_rounded
        : Icons.install_mobile_rounded;

    return SizedBox(
      width: size.width,
      height: size.height,
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            AnimatedBuilder(
              animation: _glowCtrl,
              builder: (_, __) => Container(
                width: 90,
                height: 90,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: color.withOpacity(0.08),
                  border: Border.all(color: color.withOpacity(0.4), width: 2),
                  boxShadow: [
                    BoxShadow(
                      color: color.withOpacity(0.3 * _glow.value),
                      blurRadius: 36, spreadRadius: 4,
                    ),
                  ],
                ),
                child: Icon(icon, color: color, size: 42),
              ),
            ),
            const SizedBox(height: 28),

            Text(
              isConflict ? 'Signature Conflict' : 'Permission Required',
              style: GoogleFonts.poppins(
                color: Colors.white,
                fontSize: 22,
                fontWeight: FontWeight.w800,
              ),
            ),
            const SizedBox(height: 12),

            Text(
              isConflict
                  ? 'Please uninstall the existing version,\nthen return here to finish installing.'
                  : 'Allow the permission in the system dialog,\nthen return to this screen.',
              textAlign: TextAlign.center,
              style: GoogleFonts.poppins(
                color: Colors.white54,
                fontSize: 13,
                height: 1.6,
              ),
            ),

            if (_downloadStatus.isNotEmpty) ...[
              const SizedBox(height: 16),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  color: const Color(0xFF1A0000),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: const Color(0xFF3A0000), width: 1),
                ),
                child: Text(
                  _downloadStatus,
                  textAlign: TextAlign.center,
                  style: GoogleFonts.poppins(
                    color: const Color(0xFFFF7777),
                    fontSize: 12, height: 1.5,
                  ),
                ),
              ),
            ],

            const SizedBox(height: 36),

            SizedBox(
              width: double.infinity,
              height: 54,
              child: ElevatedButton(
                onPressed: _retryInstall,
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFFC90000),
                  elevation: 0,
                  shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(16)),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const Icon(Icons.refresh_rounded,
                        color: Colors.white, size: 22),
                    const SizedBox(width: 10),
                    Text(
                      'Try Again',
                      style: GoogleFonts.poppins(
                        color: Colors.white,
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFooter() {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        _FooterDot(),
        const SizedBox(width: 8),
        Text(
          'Adiza Moviez Box  •  Update',
          style: GoogleFonts.poppins(
            color: Colors.white.withOpacity(0.12),
            fontSize: 11,
            letterSpacing: 0.5,
          ),
        ),
        const SizedBox(width: 8),
        _FooterDot(),
      ],
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Glowing update icon with pulse rings (mirrors activation screen)
// ─────────────────────────────────────────────────────────────────────────────
class _GlowingUpdateIcon extends StatelessWidget {
  final Animation<double> pulseAnim;
  final Animation<double> glowAnim;

  const _GlowingUpdateIcon({required this.pulseAnim, required this.glowAnim});

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([pulseAnim, glowAnim]),
      builder: (_, __) => SizedBox(
        width: 130,
        height: 130,
        child: Stack(alignment: Alignment.center, children: [
          // Outer glow
          Container(
            width: 130,
            height: 130,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFFC90000).withOpacity(0.35 * glowAnim.value),
                  blurRadius: 55,
                  spreadRadius: 12,
                ),
              ],
            ),
          ),
          // Pulse ring 1
          Transform.scale(
            scale: pulseAnim.value,
            child: Container(
              width: 108,
              height: 108,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: const Color(0xFFC90000).withOpacity(0.22),
                  width: 1.5,
                ),
              ),
            ),
          ),
          // Pulse ring 2
          Transform.scale(
            scale: 2.0 - pulseAnim.value,
            child: Container(
              width: 88,
              height: 88,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: const Color(0xFFC90000).withOpacity(0.12),
                  width: 1,
                ),
              ),
            ),
          ),
          // Icon container
          Container(
            width: 76,
            height: 76,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: RadialGradient(colors: [
                const Color(0xFFC90000).withOpacity(0.22),
                Colors.black.withOpacity(0.85),
              ]),
              border: Border.all(
                  color: const Color(0xFFC90000).withOpacity(0.5), width: 1.5),
            ),
            child: const Icon(Icons.system_update_rounded,
                color: Color(0xFFFF4444), size: 36),
          ),
        ]),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Animated background — particles + rotating gradient rings (same as activation)
// ─────────────────────────────────────────────────────────────────────────────
class _AnimatedBackground extends StatelessWidget {
  final List<_Particle> particles;
  final Animation<double> glowAnim;
  final Animation<double> ring1Anim;
  final Animation<double> ring2Anim;
  final Size size;

  const _AnimatedBackground({
    required this.particles,
    required this.glowAnim,
    required this.ring1Anim,
    required this.ring2Anim,
    required this.size,
  });

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([glowAnim, ring1Anim]),
      builder: (_, __) => CustomPaint(
        size: size,
        painter: _BgPainter(
          particles: particles,
          glow:    glowAnim.value,
          ring1:   ring1Anim.value,
          ring2:   ring2Anim.value,
          ts:      DateTime.now().millisecondsSinceEpoch / 1000.0,
        ),
      ),
    );
  }
}

class _BgPainter extends CustomPainter {
  final List<_Particle> particles;
  final double glow, ring1, ring2, ts;

  _BgPainter({
    required this.particles,
    required this.glow,
    required this.ring1,
    required this.ring2,
    required this.ts,
  });

  @override
  void paint(Canvas canvas, Size size) {
    // Base gradient
    canvas.drawRect(
      Offset.zero & size,
      Paint()
        ..shader = const RadialGradient(
          center: Alignment(0, -0.3),
          radius: 1.2,
          colors: [Color(0xFF1A0000), Color(0xFF0A0008), Colors.black],
        ).createShader(Offset.zero & size),
    );

    // Rotating glow rings
    final cx = size.width / 2;
    final cy = size.height * 0.38;
    final ringPaint = Paint()
      ..style     = PaintingStyle.stroke
      ..strokeWidth = 1.0;

    for (final (f, op) in [(ring1, 0.07), (ring2, 0.05)]) {
      ringPaint.color =
          const Color(0xFFC90000).withOpacity(op * glow);
      canvas.drawCircle(
          Offset(cx, cy), size.width * 0.55 + f * 20, ringPaint);
    }

    // Particles
    final ptPaint = Paint()..style = PaintingStyle.fill;
    for (final p in particles) {
      final dy   = math.sin(ts * p.speed + p.phase) * 0.015;
      final px   = p.x * size.width;
      final py   = (p.y + dy) * size.height;
      ptPaint.color =
          const Color(0xFFCC0000).withOpacity(0.3 * glow * p.size / 2.5);
      canvas.drawCircle(Offset(px, py), p.size, ptPaint);
    }
  }

  @override
  bool shouldRepaint(_BgPainter old) => true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Footer dot
// ─────────────────────────────────────────────────────────────────────────────
class _FooterDot extends StatelessWidget {
  @override
  Widget build(BuildContext context) => Container(
        width: 4,
        height: 4,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: Colors.white.withOpacity(0.12),
        ),
      );
}

// ─────────────────────────────────────────────────────────────────────────────
// Particle data
// ─────────────────────────────────────────────────────────────────────────────
class _Particle {
  final double x, y, size, speed, phase;
  const _Particle({
    required this.x,
    required this.y,
    required this.size,
    required this.speed,
    required this.phase,
  });
}
