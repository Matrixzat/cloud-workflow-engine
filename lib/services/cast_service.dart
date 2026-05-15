import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

enum CastDeviceType { dlna, chromecast, unknown }

class CastDevice {
  final String id;
  final String name;
  final String host;
  final int port;
  final CastDeviceType type;
  final String? controlUrl;

  const CastDevice({
    required this.id,
    required this.name,
    required this.host,
    required this.port,
    required this.type,
    this.controlUrl,
  });

  String get typeLabel {
    switch (type) {
      case CastDeviceType.chromecast:
        return 'Chromecast';
      case CastDeviceType.dlna:
        return 'Smart TV / DLNA';
      case CastDeviceType.unknown:
        return 'Cast Device';
    }
  }
}

enum CastState { idle, discovering, casting }

class CastService extends ChangeNotifier {
  static final CastService _instance = CastService._internal();
  factory CastService() => _instance;
  CastService._internal();

  CastState _state = CastState.idle;
  final List<CastDevice> _devices = [];
  CastDevice? _activeDevice;

  CastState get state => _state;
  List<CastDevice> get devices => List.unmodifiable(_devices);
  CastDevice? get activeDevice => _activeDevice;
  bool get isCasting => _state == CastState.casting;
  bool get isDiscovering => _state == CastState.discovering;

  RawDatagramSocket? _socket;
  Timer? _stopTimer;
  final Set<String> _seenLocations = {};

  final Dio _dio = Dio(BaseOptions(
    connectTimeout: const Duration(seconds: 3),
    receiveTimeout: const Duration(seconds: 3),
    sendTimeout: const Duration(seconds: 3),
  ));

  // ── Discovery ──────────────────────────────────────────────────────────────
  Future<void> discover() async {
    _devices.clear();
    _seenLocations.clear();
    _state = CastState.discovering;
    notifyListeners();

    try {
      _socket?.close();
      _socket = await RawDatagramSocket.bind(
        InternetAddress.anyIPv4,
        0,
        reuseAddress: true,
        reusePort: false,
      );
      _socket!.broadcastEnabled = true;

      _socket!.listen((event) {
        if (event == RawSocketEvent.read) {
          final dg = _socket!.receive();
          if (dg != null) {
            _handleSsdpPacket(
                utf8.decode(dg.data, allowMalformed: true));
          }
        }
      }, onError: (_) {});

      for (final st in [
        'urn:schemas-upnp-org:device:MediaRenderer:1',
        'urn:dial-multiscreen-org:service:dial:1',
        'ssdp:all',
      ]) {
        _sendMSearch(st);
        await Future.delayed(const Duration(milliseconds: 80));
      }

      _stopTimer?.cancel();
      _stopTimer = Timer(const Duration(seconds: 6), _finishDiscovery);
    } catch (_) {
      _state = CastState.idle;
      notifyListeners();
    }
  }

  void _sendMSearch(String st) {
    final msg =
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 3\r\n'
        'ST: $st\r\n'
        '\r\n';
    try {
      _socket?.send(
          utf8.encode(msg), InternetAddress('239.255.255.250'), 1900);
    } catch (_) {}
  }

  void _handleSsdpPacket(String data) {
    if (!data.startsWith('HTTP/1.1 200')) return;
    final locMatch =
        RegExp(r'LOCATION:\s*(\S+)', caseSensitive: false).firstMatch(data);
    final location = locMatch?.group(1)?.trim();
    if (location == null || _seenLocations.contains(location)) return;
    _seenLocations.add(location);
    _fetchDeviceDescription(location);
  }

  Future<void> _fetchDeviceDescription(String location) async {
    try {
      final uri = Uri.parse(location);
      final resp = await _dio.get<String>(location,
          options: Options(responseType: ResponseType.plain));
      final body = resp.data ?? '';

      final name =
          RegExp(r'<friendlyName>([^<]+)</friendlyName>', caseSensitive: false)
                  .firstMatch(body)
                  ?.group(1)
                  ?.trim() ??
              uri.host;

      CastDeviceType type = CastDeviceType.unknown;
      String? controlUrl;

      if (body.contains('dial-multiscreen') ||
          body.toLowerCase().contains('chromecast') ||
          body.toLowerCase().contains('google')) {
        type = CastDeviceType.chromecast;
      }

      final avMatch = RegExp(
        r'<serviceType>[^<]*AVTransport[^<]*</serviceType>.*?<controlURL>([^<]+)</controlURL>',
        dotAll: true,
        caseSensitive: false,
      ).firstMatch(body);

      if (avMatch != null) {
        final raw = avMatch.group(1)!.trim();
        controlUrl = raw.startsWith('http')
            ? raw
            : '${uri.scheme}://${uri.host}:${uri.port}$raw';
        if (type == CastDeviceType.unknown) type = CastDeviceType.dlna;
      }

      if (type == CastDeviceType.unknown) return;

      final device = CastDevice(
        id: location,
        name: name,
        host: uri.host,
        port: uri.port,
        type: type,
        controlUrl: controlUrl,
      );

      if (!_devices.any((d) => d.id == device.id)) {
        _devices.add(device);
        notifyListeners();
      }
    } catch (_) {}
  }

  void _finishDiscovery() {
    _socket?.close();
    _socket = null;
    if (_state == CastState.discovering) {
      _state = CastState.idle;
      notifyListeners();
    }
  }

  void stopDiscovery() {
    _stopTimer?.cancel();
    _finishDiscovery();
  }

  // ── Cast to device ──────────────────────────────────────────────────────────
  Future<bool> castTo(CastDevice device, String url, String title) async {
    try {
      bool ok = false;
      if (device.type == CastDeviceType.chromecast) {
        ok = await _dialLaunch(device, url);
      } else if (device.type == CastDeviceType.dlna) {
        ok = await _dlnaPlay(device, url, title);
      }
      if (ok) {
        _activeDevice = device;
        _state = CastState.casting;
        notifyListeners();
      }
      return ok;
    } catch (_) {
      return false;
    }
  }

  Future<bool> _dialLaunch(CastDevice device, String url) async {
    final dialUrl =
        'http://${device.host}:${device.port}/apps/CC1AD845';
    try {
      final r = await _dio.post<String>(
        dialUrl,
        data: 'v=${Uri.encodeComponent(url)}',
        options: Options(
          contentType: 'text/plain',
          responseType: ResponseType.plain,
          validateStatus: (s) => s != null && s < 500,
        ),
      );
      return (r.statusCode ?? 0) < 400;
    } catch (_) {
      return false;
    }
  }

  Future<bool> _dlnaPlay(
      CastDevice device, String url, String title) async {
    final ctrl = device.controlUrl;
    if (ctrl == null) return false;

    final safeUrl = url.replaceAll('&', '&amp;');
    final safeTitle =
        title.replaceAll('&', 'and').replaceAll('<', '').replaceAll('>', '');

    final setBody = '''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
      <InstanceID>0</InstanceID>
      <CurrentURI>$safeUrl</CurrentURI>
      <CurrentURIMetaData>&lt;DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/"
xmlns:dc="http://purl.org/dc/elements/1.1/"
xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/"&gt;
&lt;item id="0" parentID="-1" restricted="1"&gt;
&lt;dc:title&gt;$safeTitle&lt;/dc:title&gt;
&lt;upnp:class&gt;object.item.videoItem&lt;/upnp:class&gt;
&lt;res&gt;$safeUrl&lt;/res&gt;
&lt;/item&gt;&lt;/DIDL-Lite&gt;</CurrentURIMetaData>
    </u:SetAVTransportURI>
  </s:Body>
</s:Envelope>''';

    try {
      final r1 = await _dio.post<String>(ctrl,
          data: setBody,
          options: Options(
            headers: {
              'Content-Type': 'text/xml; charset="utf-8"',
              'SOAPAction':
                  '"urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI"',
            },
            validateStatus: (s) => s != null && s < 500,
          ));
      if ((r1.statusCode ?? 0) >= 300) return false;

      const playBody = '''<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
            s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
      <InstanceID>0</InstanceID>
      <Speed>1</Speed>
    </u:Play>
  </s:Body>
</s:Envelope>''';

      final r2 = await _dio.post<String>(ctrl,
          data: playBody,
          options: Options(
            headers: {
              'Content-Type': 'text/xml; charset="utf-8"',
              'SOAPAction':
                  '"urn:schemas-upnp-org:service:AVTransport:1#Play"',
            },
            validateStatus: (s) => s != null && s < 500,
          ));
      return (r2.statusCode ?? 0) < 300;
    } catch (_) {
      return false;
    }
  }

  Future<void> stopCasting() async {
    _activeDevice = null;
    _state = CastState.idle;
    notifyListeners();
  }
}
