import 'dart:async';
import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import '../services/tamper_service.dart';

class TamperScreen extends StatefulWidget {
  final DateTime serverTime;
  final DateTime deviceTime;
  final VoidCallback onCleared;

  const TamperScreen({
    super.key,
    required this.serverTime,
    required this.deviceTime,
    required this.onCleared,
  });

  @override
  State<TamperScreen> createState() => _TamperScreenState();
}

class _TamperScreenState extends State<TamperScreen>
    with TickerProviderStateMixin {
  static const _settingsChannel =
      MethodChannel('com.adiza.moviezbox/system');

  // ── Animation controllers ────────────────────────────────────────────────
  late AnimationController _shakeCtrl;
  late AnimationController _pulseCtrl;
  late AnimationController _glowCtrl;
  late AnimationController _contentCtrl;
  late AnimationController _dotCtrl;

  late Animation<double> _shake;
  late Animation<double> _pulse;
  late Animation<double> _glow;
  late Animation<double> _contentFade;
  late Animation<Offset> _contentSlide;

  bool _checking = false;
  String _checkMsg = '';

  // Particles for background
  final List<_TamperParticle> _particles = List.generate(
    22,
    (i) => _TamperParticle(
      x: math.Random().nextDouble(),
      y: math.Random().nextDouble(),
      size: math.Random().nextDouble() * 2.5 + 0.5,
      speed: math.Random().nextDouble() * 0.4 + 0.1,
      phase: math.Random().nextDouble() * math.pi * 2,
    ),
  );

  @override
  void initState() {
    super.initState();
    _initAnimations();
    HapticFeedback.heavyImpact();
  }

  void _initAnimations() {
    _shakeCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 500))
      ..repeat(reverse: true);
    _pulseCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1800))
      ..repeat(reverse: true);
    _glowCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 2200))
      ..repeat(reverse: true);
    _contentCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 700));
    _dotCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 700))
      ..repeat(reverse: true);

    _shake = Tween<double>(begin: -3.0, end: 3.0).animate(
        CurvedAnimation(parent: _shakeCtrl, curve: Curves.easeInOut));
    _pulse = Tween<double>(begin: 0.90, end: 1.10).animate(
        CurvedAnimation(parent: _pulseCtrl, curve: Curves.easeInOut));
    _glow = Tween<double>(begin: 0.5, end: 1.0).animate(
        CurvedAnimation(parent: _glowCtrl, curve: Curves.easeInOut));
    _contentFade = Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(
            parent: _contentCtrl,
            curve: const Interval(0.0, 0.65, curve: Curves.easeOut)));
    _contentSlide =
        Tween<Offset>(begin: const Offset(0, 0.08), end: Offset.zero)
            .animate(CurvedAnimation(
                parent: _contentCtrl, curve: Curves.easeOut));

    _contentCtrl.forward();
  }

  @override
  void dispose() {
    _shakeCtrl.dispose();
    _pulseCtrl.dispose();
    _glowCtrl.dispose();
    _contentCtrl.dispose();
    _dotCtrl.dispose();
    super.dispose();
  }

  // ── Open Android date & time settings ────────────────────────────────────
  Future<void> _openDateSettings() async {
    try {
      await _settingsChannel.invokeMethod('openDateSettings');
    } catch (_) {}
  }

  // ── Re-check after user fixes time ───────────────────────────────────────
  Future<void> _recheck() async {
    if (_checking) return;
    setState(() {
      _checking = true;
      _checkMsg = 'Checking…';
    });
    final result = await TamperService.check();
    if (!mounted) return;
    if (!result.tampered) {
      widget.onCleared();
    } else {
      setState(() {
        _checking = false;
        _checkMsg = 'Still incorrect — please set to Automatic';
      });
      HapticFeedback.heavyImpact();
      Future.delayed(const Duration(seconds: 3), () {
        if (mounted) setState(() => _checkMsg = '');
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    return PopScope(
      canPop: false, // block back button
      child: Scaffold(
        backgroundColor: Colors.black,
        body: Stack(
          children: [
            // ── Animated red background ──────────────────────────────────
            AnimatedBuilder(
              animation: Listenable.merge([_glowCtrl, _pulseCtrl]),
              builder: (_, __) => CustomPaint(
                size: size,
                painter: _TamperBgPainter(
                    particles: _particles,
                    glow: _glow.value,
                    pulse: _pulse.value),
              ),
            ),

            // ── Content ──────────────────────────────────────────────────
            SafeArea(
              child: FadeTransition(
                opacity: _contentFade,
                child: SlideTransition(
                  position: _contentSlide,
                  child: _buildContent(size),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildContent(Size size) {
    final fmt = DateFormat('dd MMM yyyy  HH:mm:ss');
    return SingleChildScrollView(
      physics: const BouncingScrollPhysics(),
      child: ConstrainedBox(
        constraints: BoxConstraints(minHeight: size.height - 60),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 28),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const SizedBox(height: 12),

              // ── Shaking warning icon ─────────────────────────────────
              AnimatedBuilder(
                animation: Listenable.merge([_shakeCtrl, _pulseCtrl, _glowCtrl]),
                builder: (_, __) => Transform.translate(
                  offset: Offset(_shake.value, 0),
                  child: SizedBox(
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
                              color: const Color(0xFFFF2255)
                                  .withOpacity(0.45 * _glow.value),
                              blurRadius: 60,
                              spreadRadius: 12,
                            ),
                          ],
                        ),
                      ),
                      // Pulsing ring 1
                      Transform.scale(
                        scale: _pulse.value,
                        child: Container(
                          width: 110,
                          height: 110,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            border: Border.all(
                              color:
                                  const Color(0xFFFF2255).withOpacity(0.28),
                              width: 1.5,
                            ),
                          ),
                        ),
                      ),
                      // Pulsing ring 2
                      Transform.scale(
                        scale: 2.1 - _pulse.value,
                        child: Container(
                          width: 85,
                          height: 85,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            border: Border.all(
                              color:
                                  const Color(0xFFFF2255).withOpacity(0.15),
                              width: 1,
                            ),
                          ),
                        ),
                      ),
                      // Icon box
                      Container(
                        width: 78,
                        height: 78,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          gradient: RadialGradient(colors: [
                            const Color(0xFFFF2255).withOpacity(0.20),
                            Colors.black.withOpacity(0.85),
                          ]),
                          border: Border.all(
                            color: const Color(0xFFFF2255).withOpacity(0.55),
                            width: 1.8,
                          ),
                        ),
                        child: const Icon(
                          Icons.access_time_filled_rounded,
                          color: Color(0xFFFF2255),
                          size: 36,
                        ),
                      ),
                    ]),
                  ),
                ),
              ),

              const SizedBox(height: 22),

              // ── Security alert badge ─────────────────────────────────
              Container(
                padding:
                    const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
                decoration: BoxDecoration(
                  color: const Color(0xFFFF2255).withOpacity(0.12),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                      color: const Color(0xFFFF2255).withOpacity(0.35),
                      width: 1),
                ),
                child: Text(
                  'SECURITY ALERT',
                  style: GoogleFonts.poppins(
                    color: const Color(0xFFFF2255),
                    fontSize: 10,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 2.5,
                  ),
                ),
              ),

              const SizedBox(height: 14),

              // ── Title ────────────────────────────────────────────────
              Text(
                'Tampered Date & Time',
                textAlign: TextAlign.center,
                style: GoogleFonts.poppins(
                  color: Colors.white,
                  fontSize: 26,
                  fontWeight: FontWeight.w800,
                  letterSpacing: -0.3,
                ),
              ),

              const SizedBox(height: 10),

              Text(
                'Your device clock has been rolled back.\nSet your date and time to Automatic to continue.',
                textAlign: TextAlign.center,
                style: GoogleFonts.poppins(
                  color: Colors.white54,
                  fontSize: 13.5,
                  height: 1.55,
                ),
              ),

              const SizedBox(height: 24),

              // ── Time comparison cards ─────────────────────────────────
              _TimeCard(
                label: 'Server Time',
                time: fmt.format(widget.serverTime),
                color: Colors.green,
                icon: Icons.cloud_done_rounded,
              ),
              const SizedBox(height: 10),
              _TimeCard(
                label: 'Your Device Time',
                time: fmt.format(widget.deviceTime),
                color: const Color(0xFFFF2255),
                icon: Icons.warning_rounded,
              ),

              const SizedBox(height: 20),

              // ── Status dot ───────────────────────────────────────────
              AnimatedBuilder(
                animation: _dotCtrl,
                builder: (_, __) => Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 14, vertical: 8),
                  decoration: BoxDecoration(
                    color: const Color(0xFFFF2255).withOpacity(0.07),
                    borderRadius: BorderRadius.circular(30),
                    border: Border.all(
                        color: const Color(0xFFFF2255).withOpacity(0.25),
                        width: 1),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 7,
                        height: 7,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: const Color(0xFFFF2255).withOpacity(
                              0.5 + 0.5 * _dotCtrl.value),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        'Clock Manipulation Detected',
                        style: GoogleFonts.poppins(
                          color: const Color(0xFFFF2255),
                          fontSize: 12,
                          fontWeight: FontWeight.w500,
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              const SizedBox(height: 20),

              // ── Fix button ───────────────────────────────────────────
              SizedBox(
                width: double.infinity,
                height: 54,
                child: ElevatedButton(
                  onPressed: _openDateSettings,
                  style: ElevatedButton.styleFrom(
                    backgroundColor: const Color(0xFFFF2255),
                    foregroundColor: Colors.white,
                    elevation: 0,
                    shadowColor:
                        const Color(0xFFFF2255).withOpacity(0.5),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(14),
                    ),
                  ),
                  child: Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      const Icon(Icons.settings_rounded, size: 20),
                      const SizedBox(width: 10),
                      Text(
                        'Fix Date & Time',
                        style: GoogleFonts.poppins(
                          fontWeight: FontWeight.w700,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(width: 6),
                      const Icon(Icons.chevron_right_rounded, size: 20),
                    ],
                  ),
                ),
              ),

              const SizedBox(height: 12),

              // ── Re-check button ──────────────────────────────────────
              SizedBox(
                width: double.infinity,
                height: 48,
                child: OutlinedButton(
                  onPressed: _checking ? null : _recheck,
                  style: OutlinedButton.styleFrom(
                    foregroundColor: Colors.white60,
                    side: const BorderSide(color: Colors.white12, width: 1),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(14)),
                  ),
                  child: _checking
                      ? Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            const SizedBox(
                              width: 16,
                              height: 16,
                              child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  color: Colors.white38),
                            ),
                            const SizedBox(width: 10),
                            Text('Checking…',
                                style: GoogleFonts.poppins(fontSize: 14)),
                          ],
                        )
                      : Text(
                          _checkMsg.isNotEmpty ? _checkMsg : 'I Fixed It — Check Again',
                          style: GoogleFonts.poppins(
                              fontSize: 14, fontWeight: FontWeight.w500),
                        ),
                ),
              ),

              const SizedBox(height: 20),

              // ── Footer ───────────────────────────────────────────────
              Text(
                'ReversalX  •  Time Security',
                style: GoogleFonts.poppins(
                    color: Colors.white12, fontSize: 11, letterSpacing: 0.5),
              ),
              const SizedBox(height: 8),
            ],
          ),
        ),
      ),
    );
  }
}

// ── Time comparison card ──────────────────────────────────────────────────────
class _TimeCard extends StatelessWidget {
  final String label;
  final String time;
  final Color color;
  final IconData icon;

  const _TimeCard({
    required this.label,
    required this.time,
    required this.color,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: color.withOpacity(0.06),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: color.withOpacity(0.25), width: 1.2),
      ),
      child: Row(
        children: [
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: color.withOpacity(0.12),
            ),
            child: Icon(icon, color: color, size: 18),
          ),
          const SizedBox(width: 12),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(label,
                  style: GoogleFonts.poppins(
                      color: Colors.white38,
                      fontSize: 11,
                      fontWeight: FontWeight.w500)),
              const SizedBox(height: 2),
              Text(time,
                  style: GoogleFonts.robotoMono(
                      color: Colors.white,
                      fontSize: 13,
                      fontWeight: FontWeight.w600)),
            ],
          ),
        ],
      ),
    );
  }
}

// ── Background painter ────────────────────────────────────────────────────────
class _TamperBgPainter extends CustomPainter {
  final List<_TamperParticle> particles;
  final double glow;
  final double pulse;

  _TamperBgPainter(
      {required this.particles, required this.glow, required this.pulse});

  @override
  void paint(Canvas canvas, Size size) {
    canvas.drawRect(Rect.fromLTWH(0, 0, size.width, size.height),
        Paint()..color = Colors.black);

    final center = Offset(size.width * 0.5, size.height * 0.3);

    // Deep red glow
    canvas.drawCircle(
      center,
      size.width * 0.75,
      Paint()
        ..shader = RadialGradient(colors: [
          const Color(0xFFFF2255).withOpacity(0.20 * glow),
          const Color(0xFFFF2255).withOpacity(0.05 * glow),
          Colors.transparent,
        ]).createShader(
            Rect.fromCircle(center: center, radius: size.width * 0.75)),
    );

    // Expanding pulse ring
    canvas.drawCircle(
      center,
      size.width * 0.42 * pulse,
      Paint()
        ..style = PaintingStyle.stroke
        ..color = const Color(0xFFFF2255).withOpacity(0.10 * (2 - pulse))
        ..strokeWidth = 1.2,
    );

    // Floating particles
    final t = DateTime.now().millisecondsSinceEpoch / 1000.0;
    final pPaint = Paint()..style = PaintingStyle.fill;
    for (final p in particles) {
      final dy = math.sin(t * p.speed + p.phase) * 0.015;
      pPaint.color = const Color(0xFFFF2255)
          .withOpacity(0.3 * math.sin(t * p.speed + p.phase).abs());
      canvas.drawCircle(
          Offset(p.x * size.width, (p.y + dy) * size.height), p.size, pPaint);
    }

    // Grid
    final gridPaint = Paint()
      ..color = Colors.white.withOpacity(0.02)
      ..strokeWidth = 0.5;
    for (double x = 0; x < size.width; x += 36) {
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), gridPaint);
    }
    for (double y = 0; y < size.height; y += 36) {
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }
  }

  @override
  bool shouldRepaint(_TamperBgPainter old) => true;
}

class _TamperParticle {
  final double x, y, size, speed, phase;
  const _TamperParticle(
      {required this.x,
      required this.y,
      required this.size,
      required this.speed,
      required this.phase});
}
