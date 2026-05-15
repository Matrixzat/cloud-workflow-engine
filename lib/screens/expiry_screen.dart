import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/license_service.dart';
import 'license_gate_screen.dart';

class ExpiryScreen extends StatefulWidget {
  final String deviceId;
  final String? expiry;

  const ExpiryScreen({super.key, required this.deviceId, this.expiry});

  @override
  State<ExpiryScreen> createState() => _ExpiryScreenState();
}

class _ExpiryScreenState extends State<ExpiryScreen>
    with TickerProviderStateMixin {
  late final AnimationController _pulseCtrl;
  late final AnimationController _shakeCtrl;
  late final AnimationController _fadeCtrl;
  late final Animation<double> _pulse;
  late final Animation<double> _shake;
  late final Animation<double> _fade;

  bool _copied = false;
  bool _checking = false;

  @override
  void initState() {
    super.initState();

    _pulseCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1400))
      ..repeat(reverse: true);
    _pulse = Tween<double>(begin: 0.92, end: 1.08).animate(
        CurvedAnimation(parent: _pulseCtrl, curve: Curves.easeInOut));

    _shakeCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 500));
    _shake = TweenSequence<double>([
      TweenSequenceItem(tween: Tween(begin: 0, end: -10), weight: 1),
      TweenSequenceItem(tween: Tween(begin: -10, end: 10), weight: 2),
      TweenSequenceItem(tween: Tween(begin: 10, end: -8), weight: 2),
      TweenSequenceItem(tween: Tween(begin: -8, end: 8), weight: 2),
      TweenSequenceItem(tween: Tween(begin: 8, end: 0), weight: 1),
    ]).animate(CurvedAnimation(parent: _shakeCtrl, curve: Curves.easeInOut));

    _fadeCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 600))
      ..forward();
    _fade = CurvedAnimation(parent: _fadeCtrl, curve: Curves.easeOut);

    // Auto-shake icon on load after a short pause
    Future.delayed(const Duration(milliseconds: 700), () {
      if (mounted) _shakeCtrl.forward();
    });
  }

  @override
  void dispose() {
    _pulseCtrl.dispose();
    _shakeCtrl.dispose();
    _fadeCtrl.dispose();
    super.dispose();
  }

  String _formatExpiry(String? raw) {
    if (raw == null || raw.isEmpty || raw == '2080' || raw == '2099-12-31') {
      return 'Unknown';
    }
    try {
      final dt = DateTime.parse(raw).toLocal();
      final months = [
        'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
        'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
      ];
      return '${months[dt.month - 1]} ${dt.day}, ${dt.year}  '
          '${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')}';
    } catch (_) {
      return raw;
    }
  }

  Future<void> _copyDeviceId() async {
    await Clipboard.setData(ClipboardData(text: widget.deviceId));
    if (!mounted) return;
    setState(() => _copied = true);
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) setState(() => _copied = false);
    });
  }

  Future<void> _openTelegram() async {
    final uri = Uri.parse(LicenseService.groupLink);
    if (await canLaunchUrl(uri)) await launchUrl(uri, mode: LaunchMode.externalApplication);
  }

  Future<void> _retryCheck() async {
    if (_checking) return;
    setState(() => _checking = true);
    final result = await LicenseService.checkActive(widget.deviceId);
    if (!mounted) return;
    if (result.isActive) {
      if (!mounted) return;
      // LicenseGateScreen will confirm active and route home immediately
      Navigator.of(context).pushReplacement(PageRouteBuilder(
        pageBuilder: (_, __, ___) => const LicenseGateScreen(),
        transitionsBuilder: (_, a, __, c) => FadeTransition(opacity: a, child: c),
        transitionDuration: const Duration(milliseconds: 400),
      ));
    } else {
      setState(() => _checking = false);
      _shakeCtrl
        ..reset()
        ..forward();
    }
  }

  @override
  Widget build(BuildContext context) {
    final size = MediaQuery.of(context).size;
    final expiryStr = _formatExpiry(widget.expiry);
    final shortId = widget.deviceId.length > 20
        ? '${widget.deviceId.substring(0, 10)}…${widget.deviceId.substring(widget.deviceId.length - 6)}'
        : widget.deviceId;

    return PopScope(
      canPop: false,
      child: Scaffold(
        backgroundColor: Colors.black,
        body: FadeTransition(
          opacity: _fade,
          child: Stack(
            children: [
              // Background gradient
              Positioned.fill(
                child: DecoratedBox(
                  decoration: const BoxDecoration(
                    gradient: RadialGradient(
                      center: Alignment(0, -0.3),
                      radius: 1.2,
                      colors: [Color(0xFF1a0000), Colors.black],
                    ),
                  ),
                ),
              ),

              // Red glow top
              Positioned(
                top: -60,
                left: size.width * 0.15,
                right: size.width * 0.15,
                child: AnimatedBuilder(
                  animation: _pulse,
                  builder: (_, __) => Transform.scale(
                    scale: _pulse.value,
                    child: Container(
                      height: 200,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        boxShadow: [
                          BoxShadow(
                            color: const Color(0xFFff2200).withOpacity(0.25),
                            blurRadius: 100,
                            spreadRadius: 40,
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),

              // Main content
              SafeArea(
                child: SingleChildScrollView(
                  physics: const BouncingScrollPhysics(),
                  child: ConstrainedBox(
                    constraints: BoxConstraints(minHeight: size.height - 80),
                    child: Padding(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 24, vertical: 32),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.center,
                        children: [
                          const SizedBox(height: 24),

                          // Hourglass icon — shaking
                          AnimatedBuilder(
                            animation: _shake,
                            builder: (_, child) => Transform.translate(
                              offset: Offset(_shake.value, 0),
                              child: child,
                            ),
                            child: AnimatedBuilder(
                              animation: _pulse,
                              builder: (_, child) => Transform.scale(
                                scale: _pulse.value,
                                child: child,
                              ),
                              child: Container(
                                width: 100,
                                height: 100,
                                decoration: BoxDecoration(
                                  shape: BoxShape.circle,
                                  gradient: const RadialGradient(colors: [
                                    Color(0xFF3a0000),
                                    Color(0xFF1a0000),
                                  ]),
                                  border: Border.all(
                                      color: const Color(0xFFff3300)
                                          .withOpacity(0.7),
                                      width: 2),
                                  boxShadow: [
                                    BoxShadow(
                                      color: const Color(0xFFff2200)
                                          .withOpacity(0.5),
                                      blurRadius: 30,
                                      spreadRadius: 4,
                                    ),
                                  ],
                                ),
                                child: const Icon(
                                  Icons.hourglass_disabled_rounded,
                                  color: Color(0xFFff4422),
                                  size: 52,
                                ),
                              ),
                            ),
                          ),

                          const SizedBox(height: 28),

                          // Title
                          const Text(
                            'SUBSCRIPTION EXPIRED',
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: Color(0xFFff4422),
                              fontSize: 22,
                              fontWeight: FontWeight.w900,
                              letterSpacing: 1.8,
                            ),
                          ),
                          const SizedBox(height: 10),
                          const Text(
                            'Your VIP access has ended. Contact admin to renew.',
                            textAlign: TextAlign.center,
                            style: TextStyle(
                              color: Color(0xFFaaaaaa),
                              fontSize: 14,
                              height: 1.5,
                            ),
                          ),

                          const SizedBox(height: 32),

                          // Expiry date card
                          _InfoCard(
                            icon: Icons.calendar_today_rounded,
                            label: 'Expired On',
                            value: expiryStr,
                            valueColor: const Color(0xFFff6644),
                          ),

                          const SizedBox(height: 14),

                          // Device ID card
                          _InfoCard(
                            icon: Icons.smartphone_rounded,
                            label: 'Your Device ID',
                            value: shortId,
                            valueColor: Colors.white70,
                            trailing: GestureDetector(
                              onTap: _copyDeviceId,
                              child: AnimatedSwitcher(
                                duration: const Duration(milliseconds: 250),
                                child: _copied
                                    ? const Icon(Icons.check_circle_rounded,
                                        color: Color(0xFF44dd88), size: 20,
                                        key: ValueKey('ok'))
                                    : const Icon(Icons.copy_rounded,
                                        color: Color(0xFF888888), size: 20,
                                        key: ValueKey('copy')),
                              ),
                            ),
                          ),

                          const SizedBox(height: 10),

                          // Copy full ID chip
                          GestureDetector(
                            onTap: _copyDeviceId,
                            child: Container(
                              width: double.infinity,
                              padding: const EdgeInsets.symmetric(
                                  horizontal: 16, vertical: 12),
                              decoration: BoxDecoration(
                                color: const Color(0xFF111111),
                                borderRadius: BorderRadius.circular(10),
                                border: Border.all(
                                    color: const Color(0xFF333333), width: 1),
                              ),
                              child: Row(
                                children: [
                                  const Icon(Icons.copy_all_rounded,
                                      color: Color(0xFF666666), size: 16),
                                  const SizedBox(width: 10),
                                  Expanded(
                                    child: Text(
                                      widget.deviceId,
                                      style: const TextStyle(
                                        color: Color(0xFF888888),
                                        fontSize: 11,
                                        fontFamily: 'monospace',
                                        letterSpacing: 0.5,
                                      ),
                                    ),
                                  ),
                                  Text(
                                    _copied ? 'Copied!' : 'Tap to copy',
                                    style: TextStyle(
                                      color: _copied
                                          ? const Color(0xFF44dd88)
                                          : const Color(0xFF555555),
                                      fontSize: 11,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),

                          const SizedBox(height: 10),

                          Container(
                            padding: const EdgeInsets.all(14),
                            decoration: BoxDecoration(
                              color: const Color(0xFF0d1a0d),
                              borderRadius: BorderRadius.circular(12),
                              border: Border.all(
                                  color: const Color(0xFF1a4a1a), width: 1),
                            ),
                            child: Row(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: const [
                                Icon(Icons.info_outline_rounded,
                                    color: Color(0xFF44aa44),
                                    size: 18),
                                SizedBox(width: 10),
                                Expanded(
                                  child: Text(
                                    'Copy your Device ID above and send it to admin via Telegram to renew your subscription.',
                                    style: TextStyle(
                                      color: Color(0xFF88bb88),
                                      fontSize: 12.5,
                                      height: 1.5,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),

                          const SizedBox(height: 32),

                          // Contact Admin button
                          SizedBox(
                            width: double.infinity,
                            height: 52,
                            child: ElevatedButton.icon(
                              onPressed: _openTelegram,
                              icon: const Icon(Icons.telegram_rounded,
                                  color: Colors.white, size: 22),
                              label: const Text(
                                'Contact Admin on Telegram',
                                style: TextStyle(
                                  color: Colors.white,
                                  fontSize: 15,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: const Color(0xFF0088cc),
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(14),
                                ),
                                elevation: 6,
                              ),
                            ),
                          ),

                          const SizedBox(height: 14),

                          // Retry check button
                          SizedBox(
                            width: double.infinity,
                            height: 48,
                            child: OutlinedButton.icon(
                              onPressed: _checking ? null : _retryCheck,
                              icon: _checking
                                  ? const SizedBox(
                                      width: 16,
                                      height: 16,
                                      child: CircularProgressIndicator(
                                        strokeWidth: 2,
                                        color: Color(0xFF888888),
                                      ),
                                    )
                                  : const Icon(Icons.refresh_rounded,
                                      color: Color(0xFF888888), size: 20),
                              label: Text(
                                _checking ? 'Checking…' : 'Check Again',
                                style: const TextStyle(
                                  color: Color(0xFF888888),
                                  fontSize: 14,
                                ),
                              ),
                              style: OutlinedButton.styleFrom(
                                side: const BorderSide(
                                    color: Color(0xFF333333), width: 1),
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(14),
                                ),
                              ),
                            ),
                          ),

                          const SizedBox(height: 32),

                          // Footer
                          Text(
                            'ReversalX  •  VIP Access',
                            style: TextStyle(
                              color: Colors.white.withOpacity(0.10),
                              fontSize: 11,
                              letterSpacing: 0.5,
                            ),
                          ),
                          const SizedBox(height: 12),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _InfoCard extends StatelessWidget {
  final IconData icon;
  final String label;
  final String value;
  final Color valueColor;
  final Widget? trailing;

  const _InfoCard({
    required this.icon,
    required this.label,
    required this.value,
    required this.valueColor,
    this.trailing,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: const Color(0xFF0f0f0f),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0xFF2a2a2a), width: 1),
      ),
      child: Row(
        children: [
          Icon(icon, color: const Color(0xFF555555), size: 18),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label,
                    style: const TextStyle(
                        color: Color(0xFF555555), fontSize: 11)),
                const SizedBox(height: 3),
                Text(value,
                    style: TextStyle(
                        color: valueColor,
                        fontSize: 14,
                        fontWeight: FontWeight.w600)),
              ],
            ),
          ),
          if (trailing != null) trailing!,
        ],
      ),
    );
  }
}
