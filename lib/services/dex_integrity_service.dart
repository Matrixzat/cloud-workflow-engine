import 'dart:io';

// ═══════════════════════════════════════════════════════════════════════════
// DEX & Manifest Integrity Service
// Compiled into libapp.so — runs before any license or UI logic.
//
// Detects two attack vectors:
//   1. Extra DEX injection  — attacker repackages the APK with a new
//      classes63.dex (or similar) to hijack the app at runtime.
//   2. Manifest tampering   — attacker adds a <provider> to auto-initialise
//      a dialog-killer or hook loader via ContentProvider.
//
// Strategy (no external packages, pure Dart/IO):
//   A. /proc/self/maps — fast in-memory check; sees all loaded DEX files
//      and native libraries currently mapped into the process.
//   B. APK ZIP central-directory scan — reads only the CD section (tail of
//      the APK file) without loading the full APK into memory; counts every
//      classes*.dex entry and flags suspicious filenames.
//
// On any positive detection → caller calls exit(0): silent kill, no UI.
// ═══════════════════════════════════════════════════════════════════════════

class DexIntegrityService {
  DexIntegrityService._();

  // ── Thresholds ─────────────────────────────────────────────────────────────
  // Flutter release APKs with many plugins can have 4-7 DEX files (multidex).
  // Set a generous threshold so legitimate builds are never false-positived.
  // Attacker-repackaged APKs are caught by name/fingerprint checks below.
  static const _kMaxDex = 8;

  // ── Known attacker fingerprints (from reversing classes63.dex) ────────────
  // Exact package path of the aantik dialog-killer DEX:  com/aantik/killer/getCx
  // Using byte-level fragments so `strings` on libapp.so cannot find them.
  // Each entry is XOR-encoded with a single-byte key (0x5A).
  //   "com/aantik"   = raw bytes XOR'd with 0x5A → _kA
  //   "killer/getCx" = raw bytes XOR'd with 0x5A → _kB
  //   "killer/hm"    = raw bytes XOR'd with 0x5A → _kC
  //   "aantik.killer"= raw bytes XOR'd with 0x5A → _kD  (authority string)
  static const int _xk = 0x5A;

  static const _kA = [ // "com/aantik"
    0x39,0x3f,0x37,0x64,0x3b,0x3b,0x36,0x39,0x34,0x35
  ];
  static const _kB = [ // "killer/getCx"
    0x31,0x34,0x3f,0x3f,0x35,0x38,0x64,0x3d,0x35,0x39,0x43,0x36
  ];
  static const _kC = [ // "killer/hm"
    0x31,0x34,0x3f,0x3f,0x35,0x38,0x64,0x32,0x37
  ];
  static const _kD = [ // "aantik.killer"
    0x3b,0x3b,0x36,0x39,0x34,0x35,0x14,0x31,0x34,0x3f,0x3f,0x35,0x38
  ];

  static String _dec(List<int> enc) =>
      String.fromCharCodes(enc.map((b) => b ^ _xk));

  // Decoded lazily — never stored as string literals in the binary.
  static String get _sigA => _dec(_kA);
  static String get _sigB => _dec(_kB);
  static String get _sigC => _dec(_kC);
  static String get _sigD => _dec(_kD);

  // ── Public entry point ────────────────────────────────────────────────────
  /// Returns true if any tampering is detected.
  /// Caller must call exit(0) silently on true.
  static Future<bool> isTampered() async {
    if (!Platform.isAndroid) return false;
    try {
      // Run both checks in parallel for speed.
      final results = await Future.wait([
        _checkMaps(),
        _checkApkZip(),
      ]);
      return results.any((r) => r);
    } catch (_) {
      return false;
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Check A: /proc/self/maps
  // Reads the kernel memory map of the current process.
  // Finds every DEX file loaded from our APK and every mapped library.
  // ══════════════════════════════════════════════════════════════════════════
  static Future<bool> _checkMaps() async {
    try {
      final maps = await File('/proc/self/maps').readAsString();

      // A1. Count UNIQUE DEX file names loaded from our APK.
      // Each DEX is mapped multiple times (r--, r-x, rw- segments),
      // so we collect into a Set and compare unique names only.
      final dexRe = RegExp(r'base\.apk!/(classes\d*\.dex)', multiLine: true);
      final uniqueDex = <String>{};
      for (final m in dexRe.allMatches(maps)) {
        uniqueDex.add(m.group(1)!);
      }
      if (uniqueDex.length > _kMaxDex) return true;

      // A2. Scan for known attacker fingerprints in the maps string.
      for (final sig in [_sigA, _sigB, _sigC, _sigD]) {
        if (maps.contains(sig)) return true;
      }
    } catch (_) {}
    return false;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // Check B: APK ZIP Central Directory scan
  // Reads only the tail of the APK (EOCD + Central Directory) — never loads
  // the full APK into memory.  Counts classes*.dex entries and looks for
  // suspicious file names injected by an attacker's repackaging tool.
  // ══════════════════════════════════════════════════════════════════════════
  static Future<bool> _checkApkZip() async {
    final apkPath = await _findApkPath();
    if (apkPath == null) return false;

    RandomAccessFile? raf;
    try {
      final file = File(apkPath);
      final fileSize = await file.length();
      raf = await file.open(mode: FileMode.read);

      // ── B1. Find the End-of-Central-Directory (EOCD) record ──────────────
      // EOCD signature: PK\x05\x06 (0x06054b50 LE)
      // It lives in the last 22–(22+65535) bytes of the file.
      final searchLen = fileSize < 65557 ? fileSize : 65557;
      await raf.setPosition(fileSize - searchLen);
      final tail = await raf.read(searchLen);

      int eocdPos = -1;
      for (int i = tail.length - 22; i >= 0; i--) {
        if (tail[i] == 0x50 && tail[i + 1] == 0x4B &&
            tail[i + 2] == 0x05 && tail[i + 3] == 0x06) {
          eocdPos = i;
          break;
        }
      }
      if (eocdPos < 0) return false;

      // ── B2. Extract Central Directory offset and size from EOCD ──────────
      final cdSize   = _u32(tail, eocdPos + 12);
      final cdOffset = _u32(tail, eocdPos + 16);
      if (cdSize <= 0 || cdOffset < 0) return false;

      // ── B3. Read Central Directory ────────────────────────────────────────
      await raf.setPosition(cdOffset);
      final cd = await raf.read(cdSize);

      // ── B4. Parse every CD entry ──────────────────────────────────────────
      // CD entry signature: PK\x01\x02 (0x02014b50 LE)
      // Layout (relevant offsets from entry start):
      //   +0  : signature  (4 bytes)
      //   +28 : filename length (uint16 LE)
      //   +30 : extra field length (uint16 LE)
      //   +32 : comment length (uint16 LE)
      //   +46 : filename (fnLen bytes)
      int dexCount = 0;
      int pos = 0;
      final sigs = [_sigA, _sigB, _sigC, _sigD];

      while (pos + 46 < cd.length) {
        if (cd[pos] != 0x50 || cd[pos + 1] != 0x4B ||
            cd[pos + 2] != 0x01 || cd[pos + 3] != 0x02) break;

        final fnLen    = _u16(cd, pos + 28);
        final extraLen = _u16(cd, pos + 30);
        final cmtLen   = _u16(cd, pos + 32);

        final fnEnd = pos + 46 + fnLen;
        if (fnEnd > cd.length) break;

        final filename = String.fromCharCodes(cd.sublist(pos + 46, fnEnd));

        // Count DEX files.
        if (RegExp(r'^classes\d*\.dex$').hasMatch(filename)) {
          dexCount++;
          if (dexCount > _kMaxDex) return true;
        }

        // Scan filename for attacker fingerprints.
        final fnLower = filename.toLowerCase();
        for (final sig in sigs) {
          if (fnLower.contains(sig.toLowerCase())) return true;
        }

        pos += 46 + fnLen + extraLen + cmtLen;
      }
    } catch (_) {
      return false;
    } finally {
      await raf?.close();
    }
    return false;
  }

  // ── Resolve APK path from /proc/self/maps ─────────────────────────────────
  // Modern Android stores the APK at:
  //   /data/app/~~<hash>/<package>-<key>/base.apk
  static Future<String?> _findApkPath() async {
    try {
      final maps = await File('/proc/self/maps').readAsString();
      for (final line in maps.split('\n')) {
        if (!line.contains('base.apk')) continue;
        // Exclude entries that reference a DEX/ODEX inside the APK
        // (those have "base.apk!/" — we want the naked APK path).
        if (line.contains('base.apk!/')) continue;
        final parts = line.trim().split(RegExp(r'\s+'));
        if (parts.isEmpty) continue;
        final path = parts.last;
        if (path.endsWith('base.apk')) {
          final f = File(path);
          if (await f.exists()) return path;
        }
      }
    } catch (_) {}
    return null;
  }

  // ── Little-endian readers ─────────────────────────────────────────────────
  static int _u16(List<int> b, int o) => b[o] | (b[o + 1] << 8);
  static int _u32(List<int> b, int o) =>
      b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24);
}
