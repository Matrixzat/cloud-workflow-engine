import 'package:flutter/material.dart';
import '../services/cast_service.dart';
import '../theme/app_theme.dart';

// ── Public helper — call this from any screen ──────────────────────────────
void showCastSheet(BuildContext context, String url, String title) {
  showModalBottomSheet(
    context: context,
    isScrollControlled: true,
    useRootNavigator: true,
    backgroundColor: Colors.transparent,
    builder: (_) => _CastSheet(url: url, title: title),
  );
}

// ── Small icon button (use in appbar, player top bar, etc.) ───────────────
class CastIconButton extends StatelessWidget {
  final String url;
  final String title;
  final Color? iconColor;
  final double size;

  const CastIconButton({
    super.key,
    required this.url,
    required this.title,
    this.iconColor,
    this.size = 22,
  });

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: CastService(),
      builder: (_, __) {
        final cs = CastService();
        final active = cs.isCasting;
        return IconButton(
          icon: Icon(
            active ? Icons.cast_connected_rounded : Icons.cast_rounded,
            color: active ? Colors.greenAccent : (iconColor ?? Colors.white),
            size: size,
          ),
          tooltip: active ? 'Casting to ${cs.activeDevice?.name}' : 'Cast to device',
          onPressed: () => showCastSheet(context, url, title),
        );
      },
    );
  }
}

// ── Compact tap-target (use inside episode tiles / cards) ─────────────────
class CastTileButton extends StatelessWidget {
  final String url;
  final String title;

  const CastTileButton({super.key, required this.url, required this.title});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () => showCastSheet(context, url, title),
      child: const Icon(Icons.cast_rounded, color: AppTheme.textMuted, size: 20),
    );
  }
}

// ── The bottom sheet ───────────────────────────────────────────────────────
class _CastSheet extends StatefulWidget {
  final String url;
  final String title;
  const _CastSheet({required this.url, required this.title});

  @override
  State<_CastSheet> createState() => _CastSheetState();
}

class _CastSheetState extends State<_CastSheet>
    with SingleTickerProviderStateMixin {
  final CastService _cs = CastService();
  late AnimationController _barCtrl;
  String? _connecting;
  bool _castSuccess = false;
  String? _castError;

  @override
  void initState() {
    super.initState();
    _barCtrl = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat();
    _cs.addListener(_onServiceChange);
    _cs.discover();
  }

  @override
  void dispose() {
    _barCtrl.dispose();
    _cs.removeListener(_onServiceChange);
    _cs.stopDiscovery();
    super.dispose();
  }

  void _onServiceChange() {
    if (mounted) setState(() {});
  }

  Future<void> _castTo(CastDevice device) async {
    setState(() { _connecting = device.id; _castError = null; });
    final ok = await _cs.castTo(device, widget.url, widget.title);
    if (!mounted) return;
    if (ok) {
      setState(() { _castSuccess = true; _connecting = null; });
      await Future.delayed(const Duration(seconds: 1));
      if (mounted) Navigator.pop(context);
    } else {
      setState(() {
        _castError = 'Could not connect to ${device.name}. Make sure you\'re on the same Wi-Fi.';
        _connecting = null;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final devices = _cs.devices;
    final isSearching = _cs.isDiscovering;

    return Container(
      decoration: const BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      padding: EdgeInsets.only(
        bottom: MediaQuery.of(context).viewInsets.bottom + 24,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Handle
          Center(
            child: Container(
              margin: const EdgeInsets.only(top: 12, bottom: 4),
              width: 40, height: 4,
              decoration: BoxDecoration(
                color: Colors.black12,
                borderRadius: BorderRadius.circular(2),
              ),
            ),
          ),

          // Header
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 12, 20, 4),
            child: Row(
              children: [
                const Icon(Icons.cast_rounded, color: Colors.black87, size: 22),
                const SizedBox(width: 10),
                const Text(
                  'Cast to',
                  style: TextStyle(
                    color: Colors.black87,
                    fontSize: 18,
                    fontWeight: FontWeight.w700,
                  ),
                ),
                const Spacer(),
                if (_cs.isCasting)
                  GestureDetector(
                    onTap: () { _cs.stopCasting(); Navigator.pop(context); },
                    child: Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                      decoration: BoxDecoration(
                        color: Colors.red.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(20),
                        border: Border.all(color: Colors.red.withOpacity(0.3)),
                      ),
                      child: const Text(
                        'Stop',
                        style: TextStyle(color: Colors.red, fontSize: 13, fontWeight: FontWeight.w600),
                      ),
                    ),
                  ),
              ],
            ),
          ),

          // Animated progress bar + status text
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 8, 20, 0),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  _castSuccess
                      ? 'Connected — playing on ${_cs.activeDevice?.name}'
                      : _connecting != null
                          ? 'Connecting…'
                          : isSearching
                              ? 'Looking for devices…'
                              : devices.isEmpty
                                  ? 'No devices found. Make sure your TV or Chromecast is on the same Wi-Fi.'
                                  : 'Select a device',
                  style: TextStyle(
                    color: _castSuccess ? Colors.green.shade700 : Colors.black54,
                    fontSize: 13,
                  ),
                ),
                const SizedBox(height: 8),
                if (isSearching || _connecting != null)
                  AnimatedBuilder(
                    animation: _barCtrl,
                    builder: (_, __) {
                      return ClipRRect(
                        borderRadius: BorderRadius.circular(2),
                        child: LinearProgressIndicator(
                          value: null,
                          backgroundColor: Colors.black.withOpacity(0.08),
                          valueColor: AlwaysStoppedAnimation(
                            Colors.green.shade400,
                          ),
                          minHeight: 3,
                        ),
                      );
                    },
                  )
                else
                  Container(
                    height: 3,
                    decoration: BoxDecoration(
                      color: Colors.black.withOpacity(0.08),
                      borderRadius: BorderRadius.circular(2),
                    ),
                  ),
              ],
            ),
          ),

          // Error
          if (_castError != null)
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 12, 20, 0),
              child: Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.red.withOpacity(0.07),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: Colors.red.withOpacity(0.2)),
                ),
                child: Text(
                  _castError!,
                  style: const TextStyle(color: Colors.red, fontSize: 12),
                ),
              ),
            ),

          // Device list
          if (devices.isNotEmpty) ...[
            const SizedBox(height: 12),
            ListView.separated(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: devices.length,
              separatorBuilder: (_, __) => const Divider(height: 1, indent: 20),
              itemBuilder: (_, i) {
                final d = devices[i];
                final isConnecting = _connecting == d.id;
                final isConnected = _cs.activeDevice?.id == d.id && _cs.isCasting;
                return ListTile(
                  leading: Container(
                    width: 40, height: 40,
                    decoration: BoxDecoration(
                      color: isConnected
                          ? Colors.green.withOpacity(0.12)
                          : Colors.black.withOpacity(0.06),
                      shape: BoxShape.circle,
                    ),
                    child: Icon(
                      d.type == CastDeviceType.chromecast
                          ? Icons.cast_rounded
                          : Icons.tv_rounded,
                      color: isConnected ? Colors.green : Colors.black54,
                      size: 20,
                    ),
                  ),
                  title: Text(
                    d.name,
                    style: const TextStyle(
                      color: Colors.black87,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  subtitle: Text(
                    isConnected ? 'Now casting' : d.typeLabel,
                    style: TextStyle(
                      color: isConnected ? Colors.green : Colors.black38,
                      fontSize: 11,
                    ),
                  ),
                  trailing: isConnecting
                      ? const SizedBox(
                          width: 20, height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2, color: Colors.black54),
                        )
                      : isConnected
                          ? const Icon(Icons.check_circle_rounded, color: Colors.green, size: 22)
                          : const Icon(Icons.chevron_right_rounded, color: Colors.black26, size: 22),
                  onTap: (isConnecting || isConnected) ? null : () => _castTo(d),
                );
              },
            ),
          ],

          const SizedBox(height: 8),
        ],
      ),
    );
  }
}
