import 'dart:async';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/license_service.dart';
import '../services/tamper_service.dart';
import '../theme/app_theme.dart';
import 'home_screen.dart';
import 'uganda_home_screen.dart';
import 'tamper_screen.dart';
import 'expiry_screen.dart';

class LicenseGateScreen extends StatefulWidget {
  const LicenseGateScreen({super.key});

  @override
  State<LicenseGateScreen> createState() => _LicenseGateScreenState();
}

class _LicenseGateScreenState extends State<LicenseGateScreen>
    with TickerProviderStateMixin {
  // ── Animation controllers ────────────────────────────────────────────────
  late AnimationController _pulseCtrl;
  late AnimationController _ringCtrl;
  late AnimationController _contentCtrl;
  late AnimationController _glowCtrl;
  late AnimationController _dotCtrl;
  late AnimationController _successCtrl;
  late AnimationController _rainbowCtrl;

  late Animation<double> _pulse;
  late Animation<double> _ring1;
  late Animation<double> _ring2;
  late Animation<double> _contentFade;
  late Animation<Offset> _contentSlide;
  late Animation<double> _glow;
  late Animation<double> _successScale;
  late Animation<double> _successFade;

  // ── State ────────────────────────────────────────────────────────────────
  String _deviceId = '';
  String _activationCode = '';
  String _statusText = 'Waiting for activation…';
  LicenseStatus _status = LicenseStatus.inactive;
  bool _codeLoaded = false;
  bool _codeCopied = false;
  bool _cmdCopied = false;
  Timer? _pollTimer;
  SharedPreferences? _prefs;

  // ── Particle positions ───────────────────────────────────────────────────
  final List<_Particle> _particles = List.generate(
    18,
    (i) => _Particle(
      x: math.Random().nextDouble(),
      y: math.Random().nextDouble(),
      size: math.Random().nextDouble() * 2 + 0.5,
      speed: math.Random().nextDouble() * 0.3 + 0.1,
      phase: math.Random().nextDouble() * math.pi * 2,
    ),
  );

  @override
  void initState() {
    super.initState();
    _initAnimations();
    _initLicense();
  }

  void _initAnimations() {
    _pulseCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 2200))
      ..repeat(reverse: true);
    _ringCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 3000))
      ..repeat();
    _contentCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 900));
    _glowCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1800))
      ..repeat(reverse: true);
    _dotCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 800))
      ..repeat(reverse: true);
    _successCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 600));
    _rainbowCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 2800))
      ..repeat();

    _pulse = Tween<double>(begin: 0.92, end: 1.08).animate(
        CurvedAnimation(parent: _pulseCtrl, curve: Curves.easeInOut));
    _ring1 = Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(parent: _ringCtrl, curve: Curves.linear));
    _ring2 = Tween<double>(begin: 0.3, end: 1.3).animate(
        CurvedAnimation(parent: _ringCtrl, curve: Curves.linear));
    _glow = Tween<double>(begin: 0.4, end: 1.0).animate(
        CurvedAnimation(parent: _glowCtrl, curve: Curves.easeInOut));
    _contentFade = Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(
            parent: _contentCtrl,
            curve: const Interval(0.0, 0.7, curve: Curves.easeOut)));
    _contentSlide =
        Tween<Offset>(begin: const Offset(0, 0.06), end: Offset.zero).animate(
            CurvedAnimation(parent: _contentCtrl, curve: Curves.easeOut));
    _successScale = Tween<double>(begin: 0.7, end: 1.0).animate(
        CurvedAnimation(parent: _successCtrl, curve: Curves.elasticOut));
    _successFade = Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(
            parent: _successCtrl,
            curve: const Interval(0.0, 0.4, curve: Curves.easeOut)));
  }

  // True while doing the initial check — screen stays fully invisible
  bool _isChecking = true;

  Future<void> _initLicense() async {
    _prefs = await SharedPreferences.getInstance();
    _deviceId = await LicenseService.getDeviceId();

    // Live check (splash already ruled out the cache fast-path)
    final liveResult = await LicenseService.checkActive(_deviceId);
    if (!mounted) return;

    if (liveResult.isActive) {
      _goHome();
      return;
    }

    if (liveResult.isExpired) {
      _goExpiry(liveResult.expiry);
      return;
    }

    // Not active — reveal the gate (zero flicker: nothing was visible until now)
    setState(() => _isChecking = false);
    _contentCtrl.forward();
    _loadCode();
    _startPolling();
  }

  void _goExpiry(String? expiry) {
    if (!mounted) return;
    Navigator.of(context).pushReplacement(PageRouteBuilder(
      pageBuilder: (_, __, ___) =>
          ExpiryScreen(deviceId: _deviceId, expiry: expiry),
      transitionsBuilder: (_, a, __, c) => FadeTransition(opacity: a, child: c),
      transitionDuration: const Duration(milliseconds: 400),
    ));
  }

  Future<void> _loadCode() async {
    final code = await LicenseService.fetchActivationCode(_deviceId);
    if (!mounted) return;
    setState(() {
      _activationCode = code;
      _codeLoaded = true;
    });
  }

  int _pollCount = 0;

  void _startPolling() {
    _pollTimer = Timer.periodic(const Duration(seconds: 2), (_) async {
      if (!mounted) return;

      // Tamper re-check every 10 polls (~30 s) while gate is open
      _pollCount++;
      if (_pollCount % 10 == 0) {
        final tamper = await TamperService.check();
        if (!mounted) return;
        if (tamper.tampered) {
          _pollTimer?.cancel();
          Navigator.of(context).pushReplacement(PageRouteBuilder(
            pageBuilder: (_, __, ___) => TamperScreen(
              serverTime: tamper.serverTime!,
              deviceTime: tamper.deviceTime!,
              onCleared: () => Navigator.of(context).pushReplacement(
                PageRouteBuilder(
                  pageBuilder: (_, __, ___) => const LicenseGateScreen(),
                  transitionsBuilder: (_, a, __, c) =>
                      FadeTransition(opacity: a, child: c),
                  transitionDuration: const Duration(milliseconds: 400),
                ),
              ),
            ),
            transitionsBuilder: (_, a, __, c) =>
                FadeTransition(opacity: a, child: c),
            transitionDuration: const Duration(milliseconds: 350),
          ));
          return;
        }
      }

      final result = await LicenseService.checkActive(_deviceId);
      if (!mounted) return;
      setState(() => _status = result.status);
      if (result.isActive) {
        _pollTimer?.cancel();
        _onActivated();
      } else if (result.isExpired) {
        _pollTimer?.cancel();
        _goExpiry(result.expiry);
      } else if (result.status == LicenseStatus.leftGroup) {
        setState(() => _statusText = 'Rejoining required — tap button below');
      } else {
        setState(() => _statusText = 'Waiting for activation…');
      }
    });
  }

  void _onActivated() {
    _successCtrl.forward();
    setState(() => _statusText = 'Activated! Opening app…');
    Future.delayed(const Duration(milliseconds: 1400), _goHome);
  }

  void _goHome() {
    if (!mounted) return;
    final lastSection = _prefs?.getString('last_section') ?? 'home';
    final defaultScreen = _prefs?.getString('default_screen') ?? 'main';

    final Widget dest = defaultScreen == 'uganda'
        ? UgandaHomeScreen(
            isRoot: true,
            onSwitchToMain: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const HomeScreen()),
            ),
          )
        : HomeScreen(
            restoreAdult: lastSection == 'adult',
            restoreFootball: lastSection == 'football',
          );

    Navigator.of(context).pushReplacement(PageRouteBuilder(
      pageBuilder: (_, __, ___) => dest,
      transitionsBuilder: (_, anim, __, child) =>
          FadeTransition(opacity: anim, child: child),
      transitionDuration: const Duration(milliseconds: 500),
    ));
  }

  void _copyCode() {
    if (!_codeLoaded || _activationCode.isEmpty) return;
    Clipboard.setData(ClipboardData(text: _activationCode));
    HapticFeedback.lightImpact();
    setState(() => _codeCopied = true);
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) setState(() => _codeCopied = false);
    });
  }

  void _copyCommand() {
    if (!_codeLoaded || _activationCode.isEmpty) return;
    final cmd = '/${LicenseService.tgCommand} $_activationCode';
    Clipboard.setData(ClipboardData(text: cmd));
    HapticFeedback.lightImpact();
    setState(() => _cmdCopied = true);
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) setState(() => _cmdCopied = false);
    });
  }

  Future<void> _openGroup() async {
    final uri = Uri.parse(LicenseService.groupLink);
    await launchUrl(uri, mode: LaunchMode.externalApplication);
  }

  @override
  void dispose() {
    _pulseCtrl.dispose();
    _ringCtrl.dispose();
    _contentCtrl.dispose();
    _glowCtrl.dispose();
    _dotCtrl.dispose();
    _successCtrl.dispose();
    _rainbowCtrl.dispose();
    _pollTimer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    // Show a full-screen branded loading spinner while the initial check runs
    if (_isChecking) {
      return const PopScope(
        canPop: false,
        child: _CheckingOverlay(),
      );
    }

    final size = MediaQuery.of(context).size;
    final isActivated = _status == LicenseStatus.active;

    return PopScope(
      canPop: false, // back button cannot dismiss the gate
      child: Scaffold(
        backgroundColor: Colors.black,
        body: Stack(
          children: [
            // ── Animated background ────────────────────────────────────────
            _AnimatedBackground(
                particles: _particles,
                glowAnim: _glow,
                ringAnim1: _ring1,
                ringAnim2: _ring2,
                size: size),

            // ── Main content ───────────────────────────────────────────────
            SafeArea(
              child: FadeTransition(
                opacity: _contentFade,
                child: SlideTransition(
                  position: _contentSlide,
                  child: isActivated
                      ? _buildSuccessOverlay()
                      : _buildGateContent(size),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildGateContent(Size size) {
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: size.height - 80),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 24),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const SizedBox(height: 16),
              _buildIcon(),
              const SizedBox(height: 20),
              _buildHeader(),
              const SizedBox(height: 28),
              _buildStep1(),
              const SizedBox(height: 12),
              _buildStep2(),
              const SizedBox(height: 20),
              _buildStatus(),
              const SizedBox(height: 16),
              _buildGroupButton(),
              const SizedBox(height: 24),
              _buildFooter(),
            ],
          ),
        ),
      ),
    );
  }

  // ── Shield icon with pulse rings ──────────────────────────────────────────
  Widget _buildIcon() {
    return AnimatedBuilder(
      animation: Listenable.merge([_pulseCtrl, _glowCtrl]),
      builder: (_, __) => SizedBox(
        width: 120,
        height: 120,
        child: Stack(alignment: Alignment.center, children: [
          // Outer glow
          Container(
            width: 120,
            height: 120,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: AppTheme.primary.withOpacity(0.35 * _glow.value),
                  blurRadius: 50,
                  spreadRadius: 10,
                ),
              ],
            ),
          ),
          // Pulsing ring 1
          Transform.scale(
            scale: _pulse.value,
            child: Container(
              width: 100,
              height: 100,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: AppTheme.primary.withOpacity(0.25),
                  width: 1.5,
                ),
              ),
            ),
          ),
          // Pulsing ring 2
          Transform.scale(
            scale: 2.0 - _pulse.value,
            child: Container(
              width: 80,
              height: 80,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                border: Border.all(
                  color: AppTheme.primary.withOpacity(0.15),
                  width: 1,
                ),
              ),
            ),
          ),
          // Icon box
          Container(
            width: 72,
            height: 72,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: RadialGradient(colors: [
                AppTheme.primary.withOpacity(0.18),
                Colors.black.withOpacity(0.85),
              ]),
              border: Border.all(
                  color: AppTheme.primary.withOpacity(0.5), width: 1.5),
            ),
            child: const Icon(Icons.shield_outlined,
                color: AppTheme.primary, size: 34),
          ),
        ]),
      ),
    );
  }

  // ── Header text ───────────────────────────────────────────────────────────
  Widget _buildHeader() {
    return Column(
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
          decoration: BoxDecoration(
            color: AppTheme.primary.withOpacity(0.12),
            borderRadius: BorderRadius.circular(20),
            border:
                Border.all(color: AppTheme.primary.withOpacity(0.3), width: 1),
          ),
          child: Text(
            'REVERSAL X MODS',
            style: GoogleFonts.poppins(
              color: AppTheme.primary,
              fontSize: 10,
              fontWeight: FontWeight.w700,
              letterSpacing: 2.0,
            ),
          ),
        ),
        const SizedBox(height: 12),
        Text(
          'Activate VIP Access',
          style: GoogleFonts.poppins(
            color: Colors.white,
            fontSize: 24,
            fontWeight: FontWeight.w800,
            letterSpacing: -0.3,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'Copy your code, join the group & send it.\nYour app unlocks automatically.',
          textAlign: TextAlign.center,
          style: GoogleFonts.poppins(
            color: Colors.white54,
            fontSize: 13,
            height: 1.5,
          ),
        ),
      ],
    );
  }

  // ── Step 1: activation code ───────────────────────────────────────────────
  Widget _buildStep1() {
    return _StepCard(
      step: '1',
      label: 'Your Activation Code',
      hint: 'Tap to copy',
      value: _codeLoaded ? _activationCode : 'Generating…',
      copied: _codeCopied,
      loading: !_codeLoaded,
      onTap: _copyCode,
    );
  }

  // ── Step 2: Telegram command ──────────────────────────────────────────────
  Widget _buildStep2() {
    final cmd = _codeLoaded
        ? '/${LicenseService.tgCommand} $_activationCode'
        : 'Loading…';
    return _StepCard(
      step: '2',
      label: 'Send this in the Telegram Group',
      hint: 'Tap to copy & paste',
      value: cmd,
      copied: _cmdCopied,
      loading: !_codeLoaded,
      onTap: _copyCommand,
      isCommand: true,
    );
  }

  // ── Status badge ──────────────────────────────────────────────────────────
  Widget _buildStatus() {
    final isLeft = _status == LicenseStatus.leftGroup;
    final isExpired = _status == LicenseStatus.expired;
    final isWaiting = !isLeft && !isExpired;
    return AnimatedBuilder(
      animation: Listenable.merge([_dotCtrl, _rainbowCtrl]),
      builder: (_, __) {
        final Color color;
        if (isLeft || isExpired) {
          color = Colors.orange;
        } else {
          // Rainbow cycle through hue
          color = HSVColor.fromAHSV(1.0, _rainbowCtrl.value * 360, 0.85, 1.0).toColor();
        }
        return Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          decoration: BoxDecoration(
            color: color.withOpacity(isWaiting ? 0.10 : 0.07),
            borderRadius: BorderRadius.circular(30),
            border: Border.all(color: color.withOpacity(0.35), width: 1),
            boxShadow: isWaiting
                ? [BoxShadow(color: color.withOpacity(0.18), blurRadius: 10, spreadRadius: 1)]
                : [],
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: 7,
                height: 7,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: color.withOpacity(0.6 + 0.4 * _dotCtrl.value),
                ),
              ),
              const SizedBox(width: 8),
              Text(
                _statusText,
                style: GoogleFonts.poppins(
                    color: color, fontSize: 12, fontWeight: FontWeight.w600),
              ),
            ],
          ),
        );
      },
    );
  }

  // ── Join group button ─────────────────────────────────────────────────────
  Widget _buildGroupButton() {
    return SizedBox(
      width: double.infinity,
      height: 52,
      child: ElevatedButton(
        onPressed: _openGroup,
        style: ElevatedButton.styleFrom(
          backgroundColor: AppTheme.primary,
          foregroundColor: Colors.white,
          elevation: 0,
          shadowColor: AppTheme.primary.withOpacity(0.6),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(14),
          ),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            const Icon(Icons.telegram, size: 20),
            const SizedBox(width: 10),
            Text(
              'Join Telegram Group',
              style: GoogleFonts.poppins(
                  fontWeight: FontWeight.w700, fontSize: 15),
            ),
            const SizedBox(width: 6),
            const Icon(Icons.chevron_right_rounded, size: 20),
          ],
        ),
      ),
    );
  }

  // ── Footer ────────────────────────────────────────────────────────────────
  Widget _buildFooter() {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        _FooterDot(),
        const SizedBox(width: 8),
        Text(
          'ReversalX  •  VIP Access',
          style: GoogleFonts.poppins(
              color: Colors.white.withOpacity(0.15), fontSize: 11, letterSpacing: 0.5),
        ),
        const SizedBox(width: 8),
        _FooterDot(),
      ],
    );
  }

  // ── Success overlay (when activated) ─────────────────────────────────────
  Widget _buildSuccessOverlay() {
    return AnimatedBuilder(
      animation: _successCtrl,
      builder: (_, __) => FadeTransition(
        opacity: _successFade,
        child: ScaleTransition(
          scale: _successScale,
          child: Center(
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  width: 90,
                  height: 90,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: Colors.green.withOpacity(0.12),
                    border:
                        Border.all(color: Colors.green.withOpacity(0.5), width: 2),
                    boxShadow: [
                      BoxShadow(
                          color: Colors.green.withOpacity(0.3),
                          blurRadius: 40,
                          spreadRadius: 8)
                    ],
                  ),
                  child: const Icon(Icons.check_rounded,
                      color: Colors.green, size: 48),
                ),
                const SizedBox(height: 20),
                Text('Activated!',
                    style: GoogleFonts.poppins(
                        color: Colors.white,
                        fontSize: 28,
                        fontWeight: FontWeight.w800)),
                const SizedBox(height: 8),
                Text('Opening app…',
                    style: GoogleFonts.poppins(
                        color: Colors.white38, fontSize: 14)),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// ── Animated background ───────────────────────────────────────────────────────
class _AnimatedBackground extends StatelessWidget {
  final List<_Particle> particles;
  final Animation<double> glowAnim;
  final Animation<double> ringAnim1;
  final Animation<double> ringAnim2;
  final Size size;

  const _AnimatedBackground({
    required this.particles,
    required this.glowAnim,
    required this.ringAnim1,
    required this.ringAnim2,
    required this.size,
  });

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([glowAnim, ringAnim1]),
      builder: (_, __) => CustomPaint(
        size: size,
        painter: _BackgroundPainter(
          particles: particles,
          glow: glowAnim.value,
          ring1: ringAnim1.value,
          ring2: ringAnim2.value,
        ),
      ),
    );
  }
}

class _BackgroundPainter extends CustomPainter {
  final List<_Particle> particles;
  final double glow;
  final double ring1;
  final double ring2;

  _BackgroundPainter(
      {required this.particles,
      required this.glow,
      required this.ring1,
      required this.ring2});

  @override
  void paint(Canvas canvas, Size size) {
    // Base black
    canvas.drawRect(Rect.fromLTWH(0, 0, size.width, size.height),
        Paint()..color = Colors.black);

    final center = Offset(size.width * 0.5, size.height * 0.28);

    // Red radial glow
    final glowPaint = Paint()
      ..shader = RadialGradient(
        colors: [
          const Color(0xFFE50914).withOpacity(0.22 * glow),
          const Color(0xFFE50914).withOpacity(0.06 * glow),
          Colors.transparent,
        ],
        stops: const [0.0, 0.4, 1.0],
      ).createShader(Rect.fromCircle(center: center, radius: size.width * 0.7));
    canvas.drawCircle(center, size.width * 0.7, glowPaint);

    // Expanding rings
    _drawRing(canvas, center, size.width * 0.38 * ring1,
        const Color(0xFFE50914).withOpacity(0.12 * (1 - ring1)));
    _drawRing(canvas, center, size.width * 0.55 * (ring2 % 1.0),
        const Color(0xFFE50914).withOpacity(0.07 * (1 - (ring2 % 1.0))));

    // Floating particles
    final pPaint = Paint()..style = PaintingStyle.fill;
    final t = DateTime.now().millisecondsSinceEpoch / 1000.0;
    for (final p in particles) {
      final dy = (math.sin(t * p.speed + p.phase) * 0.015);
      pPaint.color = const Color(0xFFE50914)
          .withOpacity(0.35 * math.sin(t * p.speed + p.phase).abs());
      canvas.drawCircle(
        Offset(p.x * size.width, (p.y + dy) * size.height),
        p.size,
        pPaint,
      );
    }

    // Subtle grid lines
    final gridPaint = Paint()
      ..color = Colors.white.withOpacity(0.025)
      ..strokeWidth = 0.5;
    const step = 36.0;
    for (double x = 0; x < size.width; x += step) {
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), gridPaint);
    }
    for (double y = 0; y < size.height; y += step) {
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }
  }

  void _drawRing(Canvas canvas, Offset center, double radius, Color color) {
    if (radius <= 0) return;
    canvas.drawCircle(
      center,
      radius,
      Paint()
        ..style = PaintingStyle.stroke
        ..color = color
        ..strokeWidth = 1.0,
    );
  }

  @override
  bool shouldRepaint(_BackgroundPainter old) => true;
}

// ── Step card ─────────────────────────────────────────────────────────────────
class _StepCard extends StatelessWidget {
  final String step;
  final String label;
  final String hint;
  final String value;
  final bool copied;
  final bool loading;
  final bool isCommand;
  final VoidCallback onTap;

  const _StepCard({
    required this.step,
    required this.label,
    required this.hint,
    required this.value,
    required this.copied,
    required this.loading,
    required this.onTap,
    this.isCommand = false,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: copied
              ? Colors.green.withOpacity(0.08)
              : AppTheme.primary.withOpacity(0.06),
          borderRadius: BorderRadius.circular(16),
          border: Border.all(
            color: copied
                ? Colors.green.withOpacity(0.5)
                : AppTheme.primary.withOpacity(0.3),
            width: 1.2,
          ),
          boxShadow: [
            BoxShadow(
              color: copied
                  ? Colors.green.withOpacity(0.08)
                  : AppTheme.primary.withOpacity(0.06),
              blurRadius: 16,
              spreadRadius: 2,
            ),
          ],
        ),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Step number circle
            Container(
              width: 26,
              height: 26,
              margin: const EdgeInsets.only(top: 2),
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: AppTheme.primary.withOpacity(0.15),
                border: Border.all(
                    color: AppTheme.primary.withOpacity(0.4), width: 1),
              ),
              child: Center(
                child: Text(step,
                    style: GoogleFonts.poppins(
                        color: AppTheme.primary,
                        fontSize: 11,
                        fontWeight: FontWeight.w800)),
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      Text(label,
                          style: GoogleFonts.poppins(
                              color: Colors.white54,
                              fontSize: 11,
                              fontWeight: FontWeight.w500)),
                      const Spacer(),
                      if (copied)
                        Text(
                          '✓ Copied',
                          style: GoogleFonts.poppins(
                            color: Colors.green,
                            fontSize: 10,
                            fontWeight: FontWeight.w600,
                          ),
                        ),
                    ],
                  ),
                  const SizedBox(height: 6),
                  AnimatedSwitcher(
                    duration: const Duration(milliseconds: 300),
                    child: loading
                        ? _LoadingShimmer(key: const ValueKey('loading'))
                        : Text(
                            value,
                            key: ValueKey(value),
                            style: GoogleFonts.robotoMono(
                              color: copied ? Colors.green : Colors.white,
                              fontSize: isCommand ? 11 : 13,
                              fontWeight: FontWeight.w600,
                              letterSpacing: 0.3,
                            ),
                          ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            Icon(
              copied ? Icons.check_circle_rounded : Icons.copy_rounded,
              color: copied ? Colors.green : Colors.white24,
              size: 18,
            ),
          ],
        ),
      ),
    );
  }
}

// ── Loading shimmer ────────────────────────────────────────────────────────────
class _LoadingShimmer extends StatefulWidget {
  const _LoadingShimmer({super.key});

  @override
  State<_LoadingShimmer> createState() => _LoadingShimmerState();
}

class _LoadingShimmerState extends State<_LoadingShimmer>
    with SingleTickerProviderStateMixin {
  late AnimationController _ctrl;
  late Animation<double> _anim;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1000))
      ..repeat(reverse: true);
    _anim = Tween<double>(begin: 0.2, end: 0.6).animate(_ctrl);
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _anim,
      builder: (_, __) => Container(
        height: 14,
        width: 160,
        decoration: BoxDecoration(
          color: Colors.white.withOpacity(_anim.value),
          borderRadius: BorderRadius.circular(6),
        ),
      ),
    );
  }
}

// ── Footer dot ────────────────────────────────────────────────────────────────
class _FooterDot extends StatefulWidget {
  @override
  State<_FooterDot> createState() => _FooterDotState();
}

class _FooterDotState extends State<_FooterDot>
    with SingleTickerProviderStateMixin {
  late AnimationController _c;

  @override
  void initState() {
    super.initState();
    _c = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1200))
      ..repeat(reverse: true);
  }

  @override
  void dispose() {
    _c.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _c,
      builder: (_, __) => Container(
        width: 4,
        height: 4,
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: AppTheme.primary.withOpacity(0.3 + 0.4 * _c.value),
        ),
      ),
    );
  }
}

// ── Full-screen loading overlay shown while the license check runs ─────────────
class _CheckingOverlay extends StatefulWidget {
  const _CheckingOverlay();

  @override
  State<_CheckingOverlay> createState() => _CheckingOverlayState();
}

class _CheckingOverlayState extends State<_CheckingOverlay>
    with SingleTickerProviderStateMixin {
  late final AnimationController _spinCtrl;
  late final Animation<double> _glow;

  @override
  void initState() {
    super.initState();
    _spinCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1600))
      ..repeat(reverse: true);
    _glow = Tween<double>(begin: 0.3, end: 1.0).animate(
        CurvedAnimation(parent: _spinCtrl, curve: Curves.easeInOut));
  }

  @override
  void dispose() {
    _spinCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      body: Center(
        child: AnimatedBuilder(
          animation: _spinCtrl,
          builder: (_, __) => Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Glowing spinner
              SizedBox(
                width: 80,
                height: 80,
                child: Stack(alignment: Alignment.center, children: [
                  // Glow ring behind spinner
                  Container(
                    width: 80,
                    height: 80,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      boxShadow: [
                        BoxShadow(
                          color: AppTheme.primary.withOpacity(0.4 * _glow.value),
                          blurRadius: 36,
                          spreadRadius: 8,
                        ),
                      ],
                    ),
                  ),
                  // Spinner
                  SizedBox(
                    width: 56,
                    height: 56,
                    child: CircularProgressIndicator(
                      strokeWidth: 3,
                      valueColor: AlwaysStoppedAnimation<Color>(
                        AppTheme.primary.withOpacity(0.8 + 0.2 * _glow.value),
                      ),
                      backgroundColor: AppTheme.primary.withOpacity(0.12),
                    ),
                  ),
                  // Shield icon in center
                  Icon(Icons.shield_outlined,
                      color: AppTheme.primary.withOpacity(0.7 + 0.3 * _glow.value),
                      size: 22),
                ]),
              ),
              const SizedBox(height: 24),
              Text(
                'Verifying…',
                style: GoogleFonts.poppins(
                  color: Colors.white38,
                  fontSize: 14,
                  fontWeight: FontWeight.w500,
                  letterSpacing: 0.5,
                ),
              ),
              const SizedBox(height: 6),
              Text(
                'REVERSAL X MODS',
                style: GoogleFonts.poppins(
                  color: AppTheme.primary.withOpacity(0.4),
                  fontSize: 9,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 2.5,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ── Particle data ─────────────────────────────────────────────────────────────
class _Particle {
  final double x, y, size, speed, phase;
  const _Particle(
      {required this.x,
      required this.y,
      required this.size,
      required this.speed,
      required this.phase});
}
