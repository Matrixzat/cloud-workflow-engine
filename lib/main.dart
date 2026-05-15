import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'theme/app_theme.dart';
import 'providers/app_provider.dart';
import 'services/download_manager.dart';
import 'services/update_service.dart';
import 'services/tamper_service.dart';
import 'services/license_service.dart';
import 'screens/license_gate_screen.dart';
import 'screens/expiry_screen.dart';
import 'screens/tamper_screen.dart';
import 'screens/home_screen.dart';
import 'screens/uganda_home_screen.dart';
import 'restart_widget.dart';

/// Global navigator key — lets background tasks push routes after the splash
/// has already handed off to the home screen.
final appNavKey = GlobalKey<NavigatorState>();

const _memoryChannel = MethodChannel('com.adiza.moviezbox/memory');

void _clearImageCache() {
  PaintingBinding.instance.imageCache.clear();
  PaintingBinding.instance.imageCache.clearLiveImages();
}

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await UpdateService.init();
  PaintingBinding.instance.imageCache.maximumSizeBytes = 15 * 1024 * 1024;
  PaintingBinding.instance.imageCache.maximumSize = 200;
  _memoryChannel.setMethodCallHandler((call) async {
    if (call.method == 'onTrimMemory') _clearImageCache();
  });
  SystemChrome.setPreferredOrientations(
      [DeviceOrientation.portraitUp, DeviceOrientation.portraitDown]);
  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor: Colors.transparent,
    statusBarIconBrightness: Brightness.light,
    systemNavigationBarColor: AppTheme.surface,
    systemNavigationBarIconBrightness: Brightness.light,
  ));
  runApp(
    RestartWidget(
      child: MultiProvider(
        providers: [
          ChangeNotifierProvider(create: (_) => AppProvider()),
          ChangeNotifierProvider(create: (_) => DownloadManager()),
        ],
        child: const MatrixMoviezApp(),
      ),
    ),
  );
}

class MatrixMoviezApp extends StatelessWidget {
  const MatrixMoviezApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      navigatorKey: appNavKey,
      title: 'Adiza Moviez Box',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.theme,
      home: const SplashScreen(),
    );
  }
}

// ── Splash Screen ─────────────────────────────────────────────────────────────
class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen>
    with TickerProviderStateMixin {
  late AnimationController _iconCtrl;
  late AnimationController _textCtrl;
  late AnimationController _glowCtrl;

  late Animation<double> _iconScale;
  late Animation<double> _iconOpacity;
  late Animation<double> _glowAnim;

  // "Adiza Moviez Box" broken into styled segments
  static const List<_Segment> _segments = [
    _Segment('Adiza ', false),
    _Segment('Moviez', true),
    _Segment(' Box', false),
  ];

  // Flat list of (char, isPrimary) for letter animation
  static final List<(String, bool)> _letters = [
    for (final seg in _segments)
      for (int i = 0; i < seg.text.length; i++) (seg.text[i], seg.isPrimary),
  ];

  List<Animation<double>> _letterAnims = [];

  // ── Pre-fetched nav result (runs in parallel with animations) ────────────
  _SplashNavResult? _navResult;
  bool _navReady = false;

  @override
  void initState() {
    super.initState();

    _iconCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 900));
    _textCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1400));
    _glowCtrl = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 1600))
      ..repeat(reverse: true);

    _iconScale = Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(parent: _iconCtrl, curve: Curves.elasticOut));
    _iconOpacity = Tween<double>(begin: 0.0, end: 1.0).animate(
        CurvedAnimation(
            parent: _iconCtrl, curve: const Interval(0.0, 0.4)));
    _glowAnim = Tween<double>(begin: 0.3, end: 1.0).animate(
        CurvedAnimation(parent: _glowCtrl, curve: Curves.easeInOut));

    // Staggered letter animations — each letter slides up + fades in
    final n = _letters.length;
    _letterAnims = List.generate(n, (i) {
      final start = (i / n) * 0.75;
      final end = (start + 0.35).clamp(0.0, 1.0);
      return Tween<double>(begin: 0.0, end: 1.0).animate(
          CurvedAnimation(
              parent: _textCtrl,
              curve: Interval(start, end, curve: Curves.easeOut)));
    });

    // ── Start security checks immediately, in parallel with animations ───
    // By the time the 4-second timer fires the results are usually ready.
    _prefetchNav();
    _startAnimations();
  }

  // Runs all checks in the background while the splash plays.
  Future<void> _prefetchNav() async {
    try {
      final tamper = await TamperService.check();
      if (tamper.tampered) {
        _navResult = _SplashNavResult.tamper(tamper);
        _navReady = true;
        return;
      }
      final prefs    = await SharedPreferences.getInstance();
      final deviceId = await LicenseService.getDeviceId();
      final cacheHit = await LicenseService.hasCachedActive(deviceId);
      if (cacheHit) {
        // Cache says VIP — let user in immediately, no network wait.
        // Verify silently in the background; redirect if expired / revoked.
        _navResult = _SplashNavResult.home(prefs);
        _navReady  = true;
        _backgroundVerify(deviceId);
        return;
      }
      // No valid cache → must do live check (first-time / unactivated user).
      final live = await LicenseService.checkActive(deviceId);
      if (live.isActive) {
        _navResult = _SplashNavResult.home(prefs);
      } else {
        _navResult = _SplashNavResult.gate();
      }
    } catch (_) {
      _navResult = _SplashNavResult.gate();
    }
    _navReady = true;
  }

  /// Runs after the user is already inside the app (cache-fast-path).
  /// Redirects immediately if the server says they're expired or revoked.
  /// On network failure or ambiguous result the cache is left intact.
  static Future<void> _backgroundVerify(String deviceId) async {
    try {
      final live = await LicenseService.checkActive(deviceId);
      if (live.isActive) return; // still good — cache already refreshed inside checkActive

      // Only revoke on clear server-side signals, not on timeout/network errors
      if (live.status == LicenseStatus.inactive) return; // ambiguous — keep cache

      // Definite expiry or group-leave signal — invalidate cache
      await LicenseService.invalidateCache();

      final nav = appNavKey.currentState;
      if (nav == null) return;

      if (live.isExpired) {
        nav.pushAndRemoveUntil(
          PageRouteBuilder(
            pageBuilder: (_, __, ___) =>
                ExpiryScreen(deviceId: deviceId, expiry: live.expiry),
            transitionsBuilder: (_, anim, __, child) =>
                FadeTransition(opacity: anim, child: child),
            transitionDuration: const Duration(milliseconds: 400),
          ),
          (_) => false,
        );
      } else {
        // inactive or left group → gate
        nav.pushAndRemoveUntil(
          PageRouteBuilder(
            pageBuilder: (_, __, ___) => const LicenseGateScreen(),
            transitionsBuilder: (_, anim, __, child) =>
                FadeTransition(opacity: anim, child: child),
            transitionDuration: const Duration(milliseconds: 400),
          ),
          (_) => false,
        );
      }
    } catch (_) {
      // Network error — keep user in, try again next open
    }
  }

  void _startAnimations() {
    Future.delayed(const Duration(milliseconds: 200),
        () { if (mounted) _iconCtrl.forward(); });
    Future.delayed(const Duration(milliseconds: 800),
        () { if (mounted) _textCtrl.forward(); });
    // Fire navigation after animations finish; the check runs in parallel.
    Future.delayed(const Duration(milliseconds: 3000), _navigateHome);
  }

  Future<void> _navigateHome() async {
    if (!mounted) return;

    // Wait for check to finish — polls every 100 ms, up to 7 s total.
    if (!_navReady) {
      for (var i = 0; i < 70 && !_navReady; i++) {
        await Future.delayed(const Duration(milliseconds: 100));
      }
    }

    final result = _navResult ?? _SplashNavResult.gate();

    if (result.isTamper) {
      Navigator.of(context).pushReplacement(PageRouteBuilder(
        pageBuilder: (_, __, ___) => TamperScreen(
          serverTime: result.tamperResult!.serverTime!,
          deviceTime: result.tamperResult!.deviceTime!,
          onCleared: () {
            Navigator.of(context).pushReplacement(PageRouteBuilder(
              pageBuilder: (_, __, ___) => const LicenseGateScreen(),
              transitionsBuilder: (_, anim, __, child) =>
                  FadeTransition(opacity: anim, child: child),
              transitionDuration: const Duration(milliseconds: 400),
            ));
          },
        ),
        transitionsBuilder: (_, anim, __, child) =>
            FadeTransition(opacity: anim, child: child),
        transitionDuration: const Duration(milliseconds: 350),
      ));
      return;
    }

    if (result.isHome && result.prefs != null) {
      _goHomeDirectly(result.prefs!);
      return;
    }

    Navigator.of(context).pushReplacement(PageRouteBuilder(
      pageBuilder: (_, __, ___) => const LicenseGateScreen(),
      transitionsBuilder: (_, anim, __, child) =>
          FadeTransition(opacity: anim, child: child),
      transitionDuration: const Duration(milliseconds: 400),
    ));
  }

  void _goHomeDirectly(SharedPreferences prefs) {
    final lastSection   = prefs.getString('last_section')   ?? 'home';
    final defaultScreen = prefs.getString('default_screen') ?? 'main';
    final Widget dest = defaultScreen == 'uganda'
        ? UgandaHomeScreen(
            isRoot: true,
            onSwitchToMain: () => Navigator.of(context).push(
              MaterialPageRoute(builder: (_) => const HomeScreen()),
            ),
          )
        : HomeScreen(
            restoreAdult:    lastSection == 'adult',
            restoreFootball: lastSection == 'football',
          );
    Navigator.of(context).pushReplacement(PageRouteBuilder(
      pageBuilder: (_, __, ___) => dest,
      transitionsBuilder: (_, anim, __, child) =>
          FadeTransition(opacity: anim, child: child),
      transitionDuration: const Duration(milliseconds: 500),
    ));

    Future.delayed(const Duration(seconds: 3), () {
      final ctx = appNavKey.currentContext;
      if (ctx != null) UpdateService.checkAndPrompt(ctx);
    });
  }

  @override
  void dispose() {
    _iconCtrl.dispose();
    _textCtrl.dispose();
    _glowCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF06060F),
      body: Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // ── App icon ──────────────────────────────────────────────────
            AnimatedBuilder(
              animation: Listenable.merge([_iconCtrl, _glowCtrl]),
              builder: (_, __) => Opacity(
                opacity: _iconOpacity.value,
                child: Transform.scale(
                  scale: _iconScale.value,
                  child: Stack(alignment: Alignment.center, children: [
                    // Red glow ring behind logo
                    Container(
                      width: 160,
                      height: 160,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        boxShadow: [
                          BoxShadow(
                            color: AppTheme.primary
                                .withOpacity(0.55 * _glowAnim.value),
                            blurRadius: 60,
                            spreadRadius: 12,
                          ),
                        ],
                      ),
                    ),
                    // AMB circular logo
                    ClipOval(
                      child: Image.asset(
                        'assets/amb_logo.png',
                        width: 140,
                        height: 140,
                        fit: BoxFit.cover,
                        filterQuality: FilterQuality.high,
                        isAntiAlias: true,
                      ),
                    ),
                  ]),
                ),
              ),
            ),
            const SizedBox(height: 28),
            // ── Letter-by-letter title ─────────────────────────────────────
            AnimatedBuilder(
              animation: _textCtrl,
              builder: (_, __) => Row(
                mainAxisSize: MainAxisSize.min,
                children: List.generate(_letters.length, (i) {
                  final (char, isPrimary) = _letters[i];
                  final v = _letterAnims[i].value;
                  return Opacity(
                    opacity: v,
                    child: Transform.translate(
                      offset: Offset(0, 18 * (1 - v)),
                      child: Text(
                        char,
                        style: TextStyle(
                          color: isPrimary ? AppTheme.primary : Colors.white,
                          fontSize: 23,
                          fontWeight: FontWeight.w900,
                          letterSpacing: 0.3,
                        ),
                      ),
                    ),
                  );
                }),
              ),
            ),
            const SizedBox(height: 8),
            // ── Subtitle ───────────────────────────────────────────────────
            AnimatedBuilder(
              animation: _textCtrl,
              builder: (_, __) {
                final v = (_textCtrl.value - 0.7).clamp(0.0, 0.3) / 0.3;
                return Opacity(
                  opacity: v,
                  child: const Text(
                    'Stream • Download • Enjoy',
                    style: TextStyle(
                        color: Colors.white38,
                        fontSize: 12,
                        letterSpacing: 1.5,
                        fontWeight: FontWeight.w400),
                  ),
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}

class _Segment {
  final String text;
  final bool isPrimary;
  const _Segment(this.text, this.isPrimary);
}

// ── Splash nav result ──────────────────────────────────────────────────────────
enum _SplashNavType { home, gate, tamper }

class _SplashNavResult {
  final _SplashNavType type;
  final SharedPreferences? prefs;
  final TamperResult? tamperResult;

  const _SplashNavResult._({required this.type, this.prefs, this.tamperResult});

  factory _SplashNavResult.home(SharedPreferences p) =>
      _SplashNavResult._(type: _SplashNavType.home, prefs: p);
  factory _SplashNavResult.gate() =>
      _SplashNavResult._(type: _SplashNavType.gate);
  factory _SplashNavResult.tamper(TamperResult t) =>
      _SplashNavResult._(type: _SplashNavType.tamper, tamperResult: t);

  bool get isHome   => type == _SplashNavType.home;
  bool get isTamper => type == _SplashNavType.tamper;
}
