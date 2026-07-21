package com.dex2c.mega.engine;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;
import android.os.Environment;
import com.dex2c.mega.ui.SettingsFragment;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;
import java.util.regex.*;
import java.util.zip.*;

public class ApkProtector {

    public interface ProgressCallback {
        void onProgress(int percent, String message);
    }


    private final Context context;
    private ProgressCallback callback;

    public ApkProtector(Context context) {
        this.context = context;
    }

    public void setProgressCallback(ProgressCallback cb) { this.callback = cb; }

    private void report(int pct, String msg) {
        if (callback != null) callback.onProgress(pct, msg);
    }

    public String protect(Uri inputUri, String filterText, boolean signOutput) throws Exception {
        // Clear all leftover dex2c_mega_* dirs from previous runs before starting fresh
        File baseCache = context.getCacheDir();
        File[] stale = baseCache.listFiles(f -> f.isDirectory() && f.getName().startsWith("dex2c_mega_"));
        if (stale != null) {
            for (File old : stale) deleteDir(old);
        }

        File cacheDir = new File(baseCache, "dex2c_mega_" + System.currentTimeMillis());
        cacheDir.mkdirs();
        try {
            report(5, "Copying APK…");
            File inputApk = copyToCache(inputUri, cacheDir);
            return protectApk(inputApk, filterText, signOutput, cacheDir);
        } finally {
            deleteDir(cacheDir);
        }
    }

    private String protectApk(File inputApk, String filterText,
                               boolean signOutput, File cacheDir) throws Exception {

        String libName = getLibraryName();
        List<String> targetAbis = getTargetAbis();

        // ── 1. Init compiler (auto-extracts from bundled asset on first run) ──
        report(8, "Initialising compiler…");
        NdkBuilder ndk = new NdkBuilder(context);
        boolean compilerReady = ndk.setup(new NdkBuilder.BuildCallback() {
            public void onProgress(String m) { report(10, m); }
            public void onLog(String l) {}
        });
        if (!compilerReady) {
            throw new Exception("Compiler initialisation failed — cannot protect APK.");
        }

        // ── 3. Validate class list ────────────────────────────────
        report(20, "Checking class list…");
        if (filterText == null || filterText.trim().isEmpty())
            throw new Exception("No classes selected to protect.");
        long classCount = filterText.lines().filter(l -> !l.isBlank()).count();
        report(25, classCount + " class(es) selected for protection");

        // ── 4. Extract DEX files (needed for bytecode patching later) ────────
        report(30, "Extracting DEX…");
        File dexDir = new File(cacheDir, "dex");
        dexDir.mkdirs();
        List<File> dexFiles = extractDexFiles(inputApk, dexDir);
        if (dexFiles.isEmpty()) throw new Exception("No DEX files found in APK.");

        // ── 5. Transpile APK → C++ via codehasan/dex2c (filter_bridge.py) ────
        // filter_bridge.py loads ALL DEX files from the APK in one androguard
        // Analysis pass, applies codehasan's MethodFilter (subclassed with global
        // multi-DEX R8 shadow-class taint check), and compiles each eligible method.
        report(35, "Transpiling " + classCount + " class(es) to C++…");
        File cSourceDir = new File(cacheDir, "c_src");
        cSourceDir.mkdirs();

        DexTranspiler transpiler = new DexTranspiler(context);
        DexTranspiler.TranspileResult transpileResult = transpiler.transpile(
                inputApk.getAbsolutePath(), filterText, cSourceDir,
                msg -> report(40, msg));

        int transpiled = transpileResult != null ? transpileResult.successCount() : 0;

        if (transpileResult != null) {
            for (String e : transpileResult.errors) report(42, "  " + e);
        }

        // Surface the Python debug log if present
        File debugLog = new File(cSourceDir, "dex_bridge_debug.log");
        if (debugLog.exists()) {
            try {
                List<String> logLines = new ArrayList<>();
                try (BufferedReader br = new BufferedReader(new FileReader(debugLog))) {
                    String line;
                    while ((line = br.readLine()) != null) logLines.add(line);
                }
                int start = Math.max(0, logLines.size() - 20);
                for (int i = start; i < logLines.size(); i++) {
                    report(43, "LOG> " + logLines.get(i));
                }
            } catch (Exception ignored) {}
        }

        if (transpiled == 0) {
            String errs = transpileResult != null
                    ? String.join(" | ", transpileResult.errors.subList(
                            0, Math.min(5, transpileResult.errors.size())))
                    : "unknown";
            throw new Exception("Transpiler produced no output. " + errs);
        }
        report(50, "Transpiled " + transpiled + " method(s) → C++");

        // ── 5b. guard layer ──────────────────────────────────────────────────
        // guard ships as libcipher.so (OLLVM prebuilt) in the app's jniLibs.
        // NdkBuilder.getGuardSoFromNativeLibs() finds it and links it into the
        // target .so via --whole-archive.  No source, no key, no decrypt.

        // ── 5c. LVM_STR — AES-256-CBC string encryption before NDK compile ──────
        // Scans every generated .cpp file for ALL 7 naked string categories
        // (NewStringUTF, D2C_RESOLVE_METHOD/FIELD/CLASS, D2C_CHECK_CAST) and
        // replaces each with a LVM_STR(N,...) call backed by lvm_str_dec() in
        // libcipher.so.  Same KHI/KLO/IHI/ILO split-key format as lvm_method_exec.
        // guard.cpp (which uses reveal_ns()) is skipped automatically.
        try {
            int lsdCount = encryptSensitiveStrings(cSourceDir);
            if (lsdCount > 0)
                report(53, "LVM_STR: AES-256-CBC encrypted " + lsdCount + " string(s) across all classes");
            else
                report(53, "LVM_STR: no encryptable strings found in generated C++");
        } catch (Exception lsdEx) {
            // Non-fatal — log and continue; better plain strings than a build failure
            report(53, "LVM_STR: skipped (" + lsdEx.getMessage() + ")");
        }

        // ── 6. Compile C++ → .so ─────────────────────────────────
        report(55, "Compiling native library…");
        File soFile = new File(cacheDir, "lib" + libName + ".so");

        // Write a build trace log to /sdcard/Dex2c/ for debugging
        File traceLog = new File(Environment.getExternalStorageDirectory(), "Dex2c Mega/build_trace.log");
        traceLog.getParentFile().mkdirs();
        final PrintWriter traceWriter;
        PrintWriter _tw = null;
        try { _tw = new PrintWriter(new FileWriter(traceLog, false)); } catch (Exception ignored) {}
        traceWriter = _tw;

        NdkBuilder.BuildResult buildResult = ndk.compile(cSourceDir, soFile,
                new NdkBuilder.BuildCallback() {
                    public void onProgress(String m) {
                        report(60, m);
                        android.util.Log.i("NdkBuilder", m);
                        if (traceWriter != null) { traceWriter.println("[PROGRESS] " + m); traceWriter.flush(); }
                    }
                    public void onLog(String l) {
                        report(61, l);
                        android.util.Log.d("Clang", l);
                        if (traceWriter != null) { traceWriter.println(l); traceWriter.flush(); }
                    }
                });
        if (traceWriter != null) traceWriter.close();

        if (!buildResult.success || buildResult.soFile == null) {
            android.util.Log.e("ApkProtector", "Compile FAILED:\n" + buildResult.error);
            throw new Exception("Compilation failed:\n" + buildResult.error
                    + "\n(full log → /sdcard/Dex2c Mega/build_trace.log)");
        }
        report(65, "Native library compiled (" + (soFile.length() / 1024) + " KB)");

        // ── 7. Strip bytecode from DEX via vova7878/DexFile ──────────
        report(70, "Stripping bytecode…");
        Set<String> compiledKeys = transpileResult.compiled.keySet();
        int stripped = Tier1DexPatcher.patchAll(dexDir, compiledKeys, libName,
                msg -> report(71, msg));
        report(78, "Stripped " + stripped + " method(s) — bytecode gone");

        // ── 7b. Early-load injection — REMOVED ───────────────────────────────
        // injectEarlyLoad() was injecting System.loadLibrary + Guard.check into
        // Application.attachBaseContext().  This caused SIGABRT on pairIP-protected
        // apps: patchAll() already made attachBaseContext ACC_NATIVE; injectEarlyLoad
        // then overwrote it with bytecode, so JNI_OnLoad's RegisterNatives for that
        // method failed with NoSuchMethodError.
        //
        // Bootstrap is not needed:
        //   • Every compiled class already has System.loadLibrary in its <clinit>.
        //     The JVM guarantees <clinit> completes before any method on that class
        //     can run, so JNI_OnLoad + RegisterNatives for ALL compiled classes fires
        //     before any compiled method is ever called — on every app, every device.
        //   • Anti-dialog-killer / killer-provider detection is handled by
        //     fonts_apply_metrics(env), injected by NdkBuilder.patchJniOnload() into
        //     JNI_OnLoad.  fonts_apply_metrics uses ActivityThread.currentApplication()
        //     with a 30ms retry thread — no Context argument, no attachBaseContext.
        //   • fonts_init() (__attribute__((constructor))) covers manifest-hash, DEX
        //     count, anti-debug and VCore detection before any Java code runs.
        report(80, "Bootstrap via per-class <clinit> — attachBaseContext untouched ✓");

        // ── 8. Repack APK ─────────────────────────────────────────
        report(82, "Rebuilding APK…");
        File libsDir = new File(cacheDir, "libs");
        placeTier1Libs(soFile, libsDir, targetAbis);

        File assetsDir = new File(cacheDir, "assets_inject");
        assetsDir.mkdirs();

        // ── 8b. Manifest-hash + dex-count integrity stamps ────────────────
        // Must run AFTER patchAll() so dexDir contains the final DEX set, and
        // AFTER assetsDir is created so stamp files land there for ApkRebuilder.
        // If the user disabled the check in Settings, sentinel stamps (hash=0,
        // count=0) are written instead — guard.cpp recognises (0,0) and skips.
        boolean manifestDexEnabled = context.getSharedPreferences(
                SettingsFragment.PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(SettingsFragment.KEY_MANIFEST_DEX_CHECK, true);
        if (manifestDexEnabled) {
            report(81, "Stamping integrity check…");
            writeIntegrityStamps(inputApk, dexDir, assetsDir);
        } else {
            report(81, "Manifest & Dex check disabled — writing sentinel stamps…");
            writeDisabledStamps(assetsDir);
        }

        // ── 8c. Native SO self-integrity stamp ───────────────────────────────
        // FNV-1a64 hash of the compiled .so → AES-256-CBC encrypted →
        // assets/font_glyph.dat.  guard.cpp crashes at every lvm_method_exec
        // pulse AND at ELF constructor time if this file is missing or the .so
        // has been patched.  MUST be stamped after soFile is finalised.
        report(82, "Stamping native SO integrity…");
        writeNativeSoHash(soFile, assetsDir);

        File outputApk = buildOutputPath(signOutput);
        ApkRebuilder.rebuild(inputApk, outputApk, dexDir, libsDir, assetsDir,
                msg -> report(85, msg));

        if (signOutput) {
            report(93, "Signing APK…");
            File signed = new File(outputApk.getParent(),
                    outputApk.getName().replace("_unsigned", ""));
            ApkSigner.sign(context, outputApk, signed);
            outputApk.delete();
            outputApk = signed;
        }

        report(100, "Done! → " + outputApk.getName());
        return outputApk.getAbsolutePath();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private File buildOutputPath(boolean signOutput) {
        File dir = new File(Environment.getExternalStorageDirectory(), "Dex2c Mega");
        dir.mkdirs();
        String ts = String.valueOf(System.currentTimeMillis());
        return new File(dir, "protected_" + ts + (signOutput ? "_unsigned.apk" : ".apk"));
    }

    private List<File> extractDexFiles(File apk, File outDir) throws IOException {
        List<File> result = new ArrayList<>();
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(apk))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (name.matches("classes\\d*\\.dex")) {
                    File out = new File(outDir, name);
                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = zis.read(buf)) != -1) fos.write(buf, 0, n);
                    }
                    result.add(out);
                }
            }
        }
        return result;
    }

    private void placeTier1Libs(File soFile, File libsDir, List<String> targetAbis) throws IOException {
        for (String abi : targetAbis) {
            File abiDir = new File(libsDir, abi);
            abiDir.mkdirs();
            copyFile(soFile, new File(abiDir, soFile.getName()));
        }
    }

    /** Reads the configured library name from Settings, falling back to the default. */
    private String getLibraryName() {
        SharedPreferences prefs = context.getSharedPreferences(
                SettingsFragment.PREFS_NAME, Context.MODE_PRIVATE);
        String name = prefs.getString(SettingsFragment.KEY_LIBRARY_NAME,
                SettingsFragment.DEFAULT_LIBRARY_NAME);
        if (name == null || name.trim().isEmpty() || !name.matches("[A-Za-z0-9_-]+")) {
            return SettingsFragment.DEFAULT_LIBRARY_NAME;
        }
        return name;
    }

    /** Reads the configured target ABIs from Settings, falling back to arm64-v8a + armeabi-v7a. */
    private List<String> getTargetAbis() {
        SharedPreferences prefs = context.getSharedPreferences(
                SettingsFragment.PREFS_NAME, Context.MODE_PRIVATE);
        List<String> abis = new ArrayList<>();
        if (prefs.getBoolean(SettingsFragment.KEY_ABI_ARM64, true))   abis.add("arm64-v8a");
        if (prefs.getBoolean(SettingsFragment.KEY_ABI_ARMEABI, true)) abis.add("armeabi-v7a");
        if (prefs.getBoolean(SettingsFragment.KEY_ABI_X86_64, false)) abis.add("x86_64");
        if (prefs.getBoolean(SettingsFragment.KEY_ABI_X86, false))    abis.add("x86");
        if (abis.isEmpty()) abis.add("arm64-v8a");
        return abis;
    }

    // ── Integrity stamp helpers ────────────────────────────────────────────

    /**
     * Stamps the protected APK with two AES-256-CBC encrypted asset files:
     *   assets/font_metrics.dat — FNV-1a64 hash of AndroidManifest.xml
     *   assets/font_index.dat   — count of classes*.dex files in dexDir
     *
     * guard.cpp's detect_metrics_tamper() verifies both on every launch and
     * crashes on any mismatch. This catches ANY tamper that changes the
     * manifest (e.g. declaring a new provider) or adds/removes a DEX file
     * (e.g. injecting a dialog-killer DEX), without needing hardcoded names.
     *
     * Called AFTER patchAll() so dexDir contains the final DEX set (including
     * the fonts/Metrics guard DEX merged in by patchAll).
     * Called AFTER assetsDir is created so the stamp files land in assetsDir
     * and get merged into the output APK by ApkRebuilder.rebuild().
     */
    private void writeIntegrityStamps(File inputApk, File dexDir, File assetsDir) throws Exception {
        byte[] manifestBytes = readZipEntry(inputApk, "AndroidManifest.xml");
        if (manifestBytes == null || manifestBytes.length == 0) {
            throw new Exception("AndroidManifest.xml not found in input APK — cannot stamp integrity check.");
        }
        long hash = fnv1a64(manifestBytes);

        File[] dexFiles = dexDir.listFiles((d, n) -> n.matches("classes(\\d*)\\.dex"));
        int dexCount = dexFiles != null ? dexFiles.length : 0;
        if (dexCount == 0) {
            throw new Exception("No DEX files found to stamp — refusing to ship without an integrity check.");
        }

        byte[] hashBytes  = new byte[8];
        byte[] countBytes = new byte[4];
        for (int i = 0; i < 8; i++) hashBytes[i]  = (byte) ((hash    >>> (8 * i)) & 0xFF);
        for (int i = 0; i < 4; i++) countBytes[i] = (byte) ((dexCount >>> (8 * i)) & 0xFF);

        byte[] key = buildGuardKey();
        byte[] iv  = buildGuardIv();
        try {
            writeEncrypted(new File(assetsDir, "font_metrics.dat"), hashBytes, key, iv);
            writeEncrypted(new File(assetsDir, "font_index.dat"),   countBytes, key, iv);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(iv,  (byte) 0);
        }
        android.util.Log.i("ApkProtector",
            "Integrity stamps written — manifest hash=0x" + Long.toHexString(hash)
            + " dexCount=" + dexCount);
    }

    /**
     * Writes sentinel stamp files (hash=0, count=0) when the user disables
     * the Manifest & Dex integrity check in Settings.
     *
     * guard.cpp's detect_metrics_tamper() detects (expected_hash==0 &&
     * expected_count==0) after decryption and returns 0 (clean) immediately,
     * so the protected APK runs without any manifest/dex verification.
     *
     * The stamp files must still be present in the APK (guard.cpp crashes if
     * they are missing) — only their payload is zeroed, not the files themselves.
     */
    private void writeDisabledStamps(File assetsDir) throws Exception {
        byte[] hashBytes  = new byte[8];   // all zeros → expected_hash  == 0
        byte[] countBytes = new byte[4];   // all zeros → expected_count == 0
        byte[] key = buildGuardKey();
        byte[] iv  = buildGuardIv();
        try {
            writeEncrypted(new File(assetsDir, "font_metrics.dat"), hashBytes, key, iv);
            writeEncrypted(new File(assetsDir, "font_index.dat"),   countBytes, key, iv);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(iv,  (byte) 0);
        }
        android.util.Log.i("ApkProtector", "Sentinel stamps written (manifest/dex check DISABLED)");
    }

    /**
     * Computes FNV-1a64 of the compiled user .so and writes the result
     * AES-256-CBC encrypted to assets/font_glyph.dat.
     *
     * guard.cpp's detect_so_tamper() reads this file at:
     *   • fonts_init() — ELF __attribute__((constructor)), before any Java
     *   • Every 4096 lvm_method_exec opcode dispatches (VM pulse)
     *   • The forked background watchdog child (every 5 s)
     *
     * Behaviour:
     *   • Missing font_glyph.dat  → immediate crash_now()
     *   • Hash mismatch            → immediate crash_now()
     *   • Sentinel (hash == 0)     → check skipped (used when SO integrity disabled)
     */
    private void writeNativeSoHash(File soFile, File assetsDir) throws Exception {
        // Read the entire compiled .so
        byte[] soBytes;
        try (java.io.FileInputStream fis = new java.io.FileInputStream(soFile);
             java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream()) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = fis.read(buf)) != -1) baos.write(buf, 0, n);
            soBytes = baos.toByteArray();
        }

        long hash = fnv1a64(soBytes);

        // Pack as little-endian 8 bytes — same layout guard.cpp uses with memcpy
        byte[] hashBytes = new byte[8];
        for (int i = 0; i < 8; i++) hashBytes[i] = (byte) ((hash >>> (8 * i)) & 0xFF);

        byte[] key = buildGuardKey();
        byte[] iv  = buildGuardIv();
        try {
            writeEncrypted(new File(assetsDir, "font_glyph.dat"), hashBytes, key, iv);
        } finally {
            java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(iv,  (byte) 0);
        }
        android.util.Log.i("ApkProtector",
            "SO integrity stamp: hash=0x" + Long.toHexString(hash)
            + " size=" + soBytes.length + " bytes");
    }

    /**
     * FNV-1a 64-bit hash. MUST match guard.cpp's fnv1a64() bit-for-bit
     * (same algorithm, same little-endian byte layout when serialised).
     */
    private static long fnv1a64(byte[] data) {
        long h = 0xcbf29ce484222325L; // 14695981039346656037 unsigned as 64-bit bit pattern
        for (byte b : data) {
            h ^= (b & 0xFFL);
            h *= 0x100000001b3L;  // 1099511628211
        }
        return h;
    }

    /** Reads a named entry from a ZIP/APK file into a byte array. */
    private static byte[] readZipEntry(File zipFile, String entryName) throws java.io.IOException {
        try (java.util.zip.ZipFile zf = new java.util.zip.ZipFile(zipFile)) {
            java.util.zip.ZipEntry e = zf.getEntry(entryName);
            if (e == null) return null;
            try (java.io.InputStream in = zf.getInputStream(e)) {
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) baos.write(buf, 0, n);
                return baos.toByteArray();
            }
        }
    }

    /**
     * Reconstructs the AES-256 key guard.cpp derives via build_key256()
     * (KEY_HI/KEY_LO/K2_HI/K2_LO XOR split). MUST stay in sync with guard.cpp.
     */
    private static byte[] buildGuardKey() {
        int[] keyHi = {0xA1,0x2B,0x1C,0xF4,0x83,0x65,0xC0,0x31,0x57,0xD4,0xE9,0x28,0x15,0x8A,0x44,0x60};
        int[] keyLo = {0x72,0x61,0x67,0x65,0x46,0x4B,0x4F,0x51,0x43,0x6C,0x4A,0x74,0x6C,0x6C,0x69,0x6F};
        int[] k2Hi  = {0xA2,0x76,0xFC,0x0B,0xD9,0x14,0x83,0xEE,0x6B,0xCA,0x39,0x42,0xF1,0xDE,0xB0,0x79};
        int[] k2Lo  = {0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};
        byte[] key = new byte[32];
        for (int i = 0; i < 16; i++) key[i]      = (byte) (keyHi[i] ^ keyLo[i]);
        for (int i = 0; i < 16; i++) key[16 + i] = (byte) (k2Hi[i]  ^ k2Lo[i]);
        return key;
    }

    /**
     * Reconstructs the AES IV guard.cpp derives via build_iv()
     * (IV_HI/IV_LO XOR split). MUST stay in sync with guard.cpp.
     */
    private static byte[] buildGuardIv() {
        int[] ivHi = {0x27,0xE5,0x58,0x1D,0xD0,0x83,0xF7,0x64,0xA3,0x35,0xC1,0x78,0x82,0x13,0x6A,0x2E};
        int[] ivLo = {0x69,0x69,0x69,0x67,0x65,0x71,0x61,0x69,0x6B,0x66,0x66,0x63,0x66,0x73,0x43,0x5B};
        byte[] iv = new byte[16];
        for (int i = 0; i < 16; i++) iv[i] = (byte) (ivHi[i] ^ ivLo[i]);
        return iv;
    }

    /** AES-256-CBC encrypts {@code plain} (PKCS5 padded) and writes ciphertext to {@code dest}. */
    private static void writeEncrypted(File dest, byte[] plain, byte[] key, byte[] iv) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, "AES"),
                new javax.crypto.spec.IvParameterSpec(iv));
        byte[] enc = cipher.doFinal(plain);
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(enc);
        }
    }

    /** Count classes*.dex entries in an APK zip. Legacy helper kept for reference. */
    @SuppressWarnings("unused")
    private int countDexFilesInApk(File apk) {
        int count = 0;
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(apk))) {
            ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.getName().matches("classes(\\d*)\\.dex")) count++;
                zis.closeEntry();
            }
        } catch (IOException ignored) {}
        return count;
    }

    private File copyToCache(Uri uri, File dir) throws IOException {
        File dest = new File(dir, "input.apk");
        try (InputStream in = context.getContentResolver().openInputStream(uri);
             OutputStream out = new BufferedOutputStream(new FileOutputStream(dest), 1 << 16)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
        return dest;
    }

    private void copyFile(File src, File dst) throws IOException {
        try (InputStream in  = new BufferedInputStream(new FileInputStream(src), 1 << 16);
             OutputStream out = new BufferedOutputStream(new FileOutputStream(dst), 1 << 16)) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
    }

    private void deleteDir(File dir) {
        if (dir == null || !dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) for (File f : files) {
            if (f.isDirectory()) deleteDir(f); else f.delete();
        }
        dir.delete();
    }


    // ── LVM_STR: AES-256-CBC split-key string encryption ──────────────────────
    //
    // Replaces GSTR (3-pattern single-byte-XOR) with full AES-256-CBC covering
    // every naked string category that dex2c emits in generated .cpp files:
    //
    //   1. env->NewStringUTF("ANY STRING")            ALL const-string opcodes
    //   2. D2C_RESOLVE_METHOD(c,m,"CLS","MTH","SIG")  all 3 string args
    //   3. D2C_RESOLVE_STATIC_METHOD(...)             all 3 string args
    //   4. D2C_RESOLVE_FIELD(c,f,"CLS","FLD","TYPE")  all 3 string args
    //   5. D2C_RESOLVE_STATIC_FIELD(...)              all 3 string args
    //   6. D2C_RESOLVE_CLASS(clz,"CLS")               class name
    //   7. D2C_CHECK_CAST(v, clz, "CLS")              cast target class
    //
    // Encryption format: IDENTICAL to vm_encryptor.VmEncryptor:
    //   KHI[32] ^ KLO[32] = AES-256 key
    //   IHI[16] ^ ILO[16] = CBC IV
    //   XOR checksum over unpadded plaintext bytes
    //
    // Decryption: lvm_str_dec() exported from libcipher.so (guard.cpp),
    // called via template<int N> lvm_str_slot_() for safe in-place use
    // as a const char* expression in any argument position.
    // -------------------------------------------------------------------------

    // Injected at the top of every modified .cpp file.
    private static final String LVM_STR_HEADER =
        "// LVM_STR runtime (injected by ApkProtector)\n" +
        "// AES-256-CBC split-key, identical format to lvm_method_exec in guard.cpp.\n" +
        "// Decryption via lvm_str_dec() exported from libcipher.so (--whole-archive).\n" +
        "#ifndef LVM_STR_H_\n" +
        "#define LVM_STR_H_\n" +
        "#include <stdint.h>\n" +
        "#include <stdbool.h>\n" +
        "extern \"C\" void lvm_str_dec(\n" +
        "    const volatile uint8_t*, const volatile uint8_t*,\n" +
        "    const volatile uint8_t*, const volatile uint8_t*,\n" +
        "    const volatile uint8_t*, int, uint8_t, char*, int);\n" +
        "template<int _N>\n" +
        "static __attribute__((noinline)) const char* lvm_str_slot_(\n" +
        "        const volatile uint8_t*k0, const volatile uint8_t*k1,\n" +
        "        const volatile uint8_t*i0, const volatile uint8_t*i1,\n" +
        "        const volatile uint8_t*e,  int el, uint8_t cs) {\n" +
        "    static char b[512]; static bool ok = false;\n" +
        "    if (!ok) { lvm_str_dec(k0,k1,i0,i1,e,el,cs,b,511); ok = true; }\n" +
        "    return b;\n" +
        "}\n" +
        "#define LVM_STR(N,k0,k1,i0,i1,e,el,cs) \\\n" +
        "    lvm_str_slot_<N>((k0),(k1),(i0),(i1),(e),(el),(uint8_t)(cs))\n" +
        "#endif // LVM_STR_H_\n\n";

    // ── AES-256-CBC encrypt one string, random KHI/KLO/IHI/ILO split keys ──
    // Returns: {khi[32], klo[32], ihi[16], ilo[16], enc[], {cs}}
    private static byte[][] lsdEncrypt(String plain, SecureRandom rng) throws Exception {
        byte[] khi = new byte[32]; rng.nextBytes(khi);
        byte[] klo = new byte[32]; rng.nextBytes(klo);
        byte[] ihi = new byte[16]; rng.nextBytes(ihi);
        byte[] ilo = new byte[16]; rng.nextBytes(ilo);

        byte[] key = new byte[32], iv = new byte[16];
        for (int i = 0; i < 32; i++) key[i] = (byte)(khi[i] ^ klo[i]);
        for (int i = 0; i < 16; i++) iv[i]  = (byte)(ihi[i] ^ ilo[i]);

        byte[] pb = plain.getBytes(StandardCharsets.UTF_8);
        byte cs = 0;
        for (byte b : pb) cs ^= b;

        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
            new javax.crypto.spec.SecretKeySpec(key, "AES"),
            new javax.crypto.spec.IvParameterSpec(iv));
        byte[] enc = cipher.doFinal(pb);
        return new byte[][] { khi, klo, ihi, ilo, enc, new byte[]{ cs } };
    }

    // Format bytes as C `static volatile const uint8_t name[] = {...};`
    private static String lsdCArr(String name, byte[] data) {
        StringBuilder sb = new StringBuilder("static volatile const uint8_t ");
        sb.append(name).append("[] = {");
        for (int i = 0; i < data.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(String.format("0x%02x", data[i] & 0xFF));
        }
        return sb.append("};\n").toString();
    }

    // Encrypt one plain string, emit declarations, return the LVM_STR(N,...) call.
    private static String lsdMakeCall(String plain, int id,
                                      SecureRandom rng, List<String> decls) throws Exception {
        byte[][] p = lsdEncrypt(plain, rng);
        String x = "_gs" + id;
        decls.add(lsdCArr(x + "_KHI", p[0]));
        decls.add(lsdCArr(x + "_KLO", p[1]));
        decls.add(lsdCArr(x + "_IHI", p[2]));
        decls.add(lsdCArr(x + "_ILO", p[3]));
        decls.add(lsdCArr(x + "_ENC", p[4]));
        decls.add(String.format("#define %s_LEN %d\n", x, p[4].length));
        decls.add(String.format("#define %s_CS  0x%02xu\n", x, p[5][0] & 0xFF));
        return String.format("LVM_STR(%d,%s_KHI,%s_KLO,%s_IHI,%s_ILO,%s_ENC,%s_LEN,%s_CS)",
            id, x, x, x, x, x, x, x);
    }

    int encryptSensitiveStrings(File cSourceDir) {
        // Patterns — multi-arg (D2C_RESOLVE_*) first, single-arg / NewStringUTF last.
        // All patterns use non-greedy matching inside strings to avoid cross-line bleed.

        // 3-arg: D2C_RESOLVE_METHOD / STATIC_METHOD
        //   g1=macro  g2=clz  g3=mid  g4=cls_str  g5=mth_str  g6=sig_str
        final Pattern P_METHOD = Pattern.compile(
            "(D2C_RESOLVE_(?:STATIC_)?METHOD)\\s*\\(\\s*(\\w+)\\s*,\\s*(\\w+)\\s*," +
            "\\s*\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\"\\s*\\)\\s*;");

        // 3-arg: D2C_RESOLVE_FIELD / STATIC_FIELD
        //   g1=macro  g2=clz  g3=fld  g4=cls_str  g5=fld_str  g6=type_str
        final Pattern P_FIELD = Pattern.compile(
            "(D2C_RESOLVE_(?:STATIC_)?FIELD)\\s*\\(\\s*(\\w+)\\s*,\\s*(\\w+)\\s*," +
            "\\s*\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\"\\s*\\)\\s*;");

        // 1-arg: D2C_RESOLVE_CLASS
        //   g1=macro  g2=clz  g3=cls_str
        final Pattern P_CLASS = Pattern.compile(
            "(D2C_RESOLVE_CLASS)\\s*\\(\\s*(\\w+)\\s*,\\s*\"([^\"]+)\"\\s*\\)\\s*;");

        // 1-arg: D2C_CHECK_CAST  (3rd arg is the class name)
        //   g1=macro  g2=first_two_args_no_closing_paren  g3=cls_str
        final Pattern P_CAST = Pattern.compile(
            "(D2C_CHECK_CAST)\\s*\\(([^)]+?),\\s*\"([^\"]+)\"\\s*\\)\\s*;");

        // 1-arg: env->NewStringUTF — ALL literals >= 4 chars
        //   g1=prefix  g2=str  g3=suffix
        final Pattern P_NEWSTR = Pattern.compile(
            "(env->NewStringUTF\\s*\\()\"([^\"\\\\\\r\\n]{4,})\"(\\s*\\))");

        SecureRandom rng = new SecureRandom();
        int totalEncrypted = 0;

        File[] cppFiles = cSourceDir.listFiles(f ->
            f.isFile() && f.getName().endsWith(".cpp") && !f.getName().equals("guard.cpp"));
        if (cppFiles == null || cppFiles.length == 0) return 0;

        for (File cpp : cppFiles) {
            try {
                StringBuilder src = new StringBuilder();
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(new FileInputStream(cpp), StandardCharsets.UTF_8))) {
                    String ln;
                    while ((ln = br.readLine()) != null) src.append(ln).append('\n');
                }
                String source = src.toString();

                // Natural-order map so floorEntry/higherEntry work correctly for overlap
                // detection. We iterate descendingMap() at apply-time for back-to-front.
                TreeMap<Integer, String[]> reps = new TreeMap<>();

                // noOverlap: true if [s,e) doesn't intersect any already-registered range.
                java.util.function.BiPredicate<Integer,Integer> noOverlap = (s, e) -> {
                    // Check the existing entry whose start <= s; if its end > s it overlaps.
                    Map.Entry<Integer,String[]> lo = reps.floorEntry(s);
                    if (lo != null && Integer.parseInt(lo.getValue()[0]) > s) return false;
                    // Check the first existing entry whose start > s; if it starts < e it overlaps.
                    Map.Entry<Integer,String[]> hi = reps.higherEntry(s);
                    if (hi != null && hi.getKey() < e) return false;
                    return true;
                };

                List<String> decls = new ArrayList<>();
                int counter = 0;
                Matcher m;

                // ── 3-arg D2C_RESOLVE_METHOD / STATIC_METHOD ────────────────
                m = P_METHOD.matcher(source);
                while (m.find()) {
                    if (!noOverlap.test(m.start(), m.end())) continue;
                    String c0 = lsdMakeCall(m.group(4), counter,   rng, decls);
                    String c1 = lsdMakeCall(m.group(5), counter+1, rng, decls);
                    String c2 = lsdMakeCall(m.group(6), counter+2, rng, decls);
                    String rep = m.group(1)+"("+m.group(2)+","+m.group(3)+","+c0+","+c1+","+c2+");";
                    reps.put(m.start(), new String[]{ String.valueOf(m.end()), rep });
                    counter += 3;
                }

                // ── 3-arg D2C_RESOLVE_FIELD / STATIC_FIELD ──────────────────
                m = P_FIELD.matcher(source);
                while (m.find()) {
                    if (!noOverlap.test(m.start(), m.end())) continue;
                    String c0 = lsdMakeCall(m.group(4), counter,   rng, decls);
                    String c1 = lsdMakeCall(m.group(5), counter+1, rng, decls);
                    String c2 = lsdMakeCall(m.group(6), counter+2, rng, decls);
                    String rep = m.group(1)+"("+m.group(2)+","+m.group(3)+","+c0+","+c1+","+c2+");";
                    reps.put(m.start(), new String[]{ String.valueOf(m.end()), rep });
                    counter += 3;
                }

                // ── 1-arg D2C_RESOLVE_CLASS ──────────────────────────────────
                m = P_CLASS.matcher(source);
                while (m.find()) {
                    if (!noOverlap.test(m.start(), m.end())) continue;
                    String c0 = lsdMakeCall(m.group(3), counter, rng, decls);
                    String rep = m.group(1)+"("+m.group(2)+","+c0+");";
                    reps.put(m.start(), new String[]{ String.valueOf(m.end()), rep });
                    counter++;
                }

                // ── 1-arg D2C_CHECK_CAST ─────────────────────────────────────
                m = P_CAST.matcher(source);
                while (m.find()) {
                    if (!noOverlap.test(m.start(), m.end())) continue;
                    String c0 = lsdMakeCall(m.group(3), counter, rng, decls);
                    String rep = m.group(1)+"("+m.group(2)+","+c0+");";
                    reps.put(m.start(), new String[]{ String.valueOf(m.end()), rep });
                    counter++;
                }

                // ── NewStringUTF — ALL literals >= 4 chars ───────────────────
                m = P_NEWSTR.matcher(source);
                while (m.find()) {
                    // The quoted string occupies [m.start(2)-1 .. m.end(2)+1)
                    int qs = m.start(2) - 1;
                    int qe = m.end(2)   + 1;
                    if (!noOverlap.test(qs, qe)) continue;
                    String c0 = lsdMakeCall(m.group(2), counter, rng, decls);
                    reps.put(qs, new String[]{ String.valueOf(qe), c0 });
                    counter++;
                }

                if (counter == 0) continue;

                // Apply replacements back-to-front (descendingMap = largest key first)
                StringBuilder patched = new StringBuilder(source);
                for (Map.Entry<Integer, String[]> entry : reps.descendingMap().entrySet()) {
                    int s = entry.getKey();
                    int e = Integer.parseInt(entry.getValue()[0]);
                    patched.replace(s, e, entry.getValue()[1]);
                }

                String header = LVM_STR_HEADER
                    + "// LVM_STR string blobs (" + counter + " strings)\n"
                    + String.join("", decls)
                    + "// end LVM_STR blobs\n\n";

                try (OutputStreamWriter ow = new OutputStreamWriter(
                        new FileOutputStream(cpp), StandardCharsets.UTF_8)) {
                    ow.write(header + patched.toString());
                }

                totalEncrypted += counter;
                android.util.Log.i("ApkProtector",
                    "LVM_STR: encrypted " + counter + " string(s) in " + cpp.getName());

            } catch (Exception e) {
                android.util.Log.w("ApkProtector",
                    "LVM_STR: skipped " + cpp.getName() + ": " + e.getMessage());
            }
        }
        return totalEncrypted;
    }
}
