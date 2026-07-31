package com.dex2c.mega.engine;

import android.util.Log;

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.dex2c.mega.engine.vmp.Dex2c;
import com.dex2c.mega.engine.vmp.GlobalDexConfig;
import com.dex2c.mega.engine.vmp.converter.ClassAnalyzer;
import com.dex2c.mega.engine.vmp.converter.instructionrewriter.RandomInstructionRewriter;
import com.dex2c.mega.engine.vmp.filters.BasicKeepConfig;
import com.dex2c.mega.engine.vmp.filters.ClassAndMethodFilter;
import com.dex2c.mega.engine.vmp.filters.SimpleConvertConfig;
import com.dex2c.mega.engine.vmp.filters.SimpleRules;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * DexTranspiler — routes APK methods to either:
 *
 *   MODE_DEX2C  — codehasan/dex2c Python transpiler (existing path, unchanged)
 *   MODE_VMP    — maoabc/nmmp VMP interpreter (Dalvik → custom opcodes + C VM)
 *   MODE_HYBRID — VMP for selected classes, dex2c for everything else
 *
 * The routing decision is made per-protect-run via the {@code mode} parameter.
 * Both paths write their C output files to {@code outputDir}; NdkBuilder
 * picks them all up in a single compilation pass.
 */
public class DexTranspiler {

    private static final String TAG = "DexTranspiler";

    // ── Modes ────────────────────────────────────────────────────────────────
    public static final int MODE_DEX2C  = 0;  // existing Python bridge only
    public static final int MODE_VMP    = 1;  // NMMP VMP interpreter only
    public static final int MODE_HYBRID = 2;  // VMP for vmpFilter classes, dex2c for rest

    // ── Callback / result types ──────────────────────────────────────────────
    public interface TranspileCallback {
        void onProgress(String message);
    }

    public static class TranspileResult {
        public final Map<String, String> compiled  = new LinkedHashMap<>();
        public final List<String>        errors    = new ArrayList<>();
        public       GlobalDexConfig     vmpConfig = null;   // non-null when VMP ran
        public int successCount() { return compiled.size(); }
    }

    private final android.content.Context context;

    public DexTranspiler(android.content.Context context) {
        this.context = context.getApplicationContext();
    }

    // ── Public entry points ──────────────────────────────────────────────────

    /**
     * Transpile with explicit mode selection.
     *
     * @param apkPath    path to the input APK
     * @param filterText classes to protect — one class name per line for dex2c,
     *                   or NMMP SimpleRules format for VMP
     *                   ("class com.foo.Bar { *; }")
     * @param outputDir  directory to write generated C / C++ files into
     * @param mode       MODE_DEX2C | MODE_VMP | MODE_HYBRID
     * @param cb         progress callback (nullable)
     */
    public TranspileResult transpile(String apkPath, String filterText,
                                     File outputDir, int mode,
                                     TranspileCallback cb) {
        switch (mode) {
            case MODE_VMP:    return transpileVmp(apkPath, filterText, outputDir, cb);
            case MODE_HYBRID: return transpileHybrid(apkPath, filterText, outputDir, cb);
            default:          return transpileDex2c(apkPath, filterText, outputDir, cb);
        }
    }

    /**
     * Legacy overload — defaults to MODE_DEX2C (backwards-compatible).
     */
    public TranspileResult transpile(String apkPath, String filterText,
                                     File outputDir, TranspileCallback cb) {
        return transpileDex2c(apkPath, filterText, outputDir, cb);
    }

    // ── Path 1: existing Python dex2c (unchanged) ────────────────────────────

    private TranspileResult transpileDex2c(String apkPath, String filterText,
                                           File outputDir, TranspileCallback cb) {
        Log.i(TAG, "transpile(DEX2C) apk=" + apkPath);
        Dex2cPythonBridge bridge = new Dex2cPythonBridge(context);
        if (!bridge.isAvailable()) {
            TranspileResult r = new TranspileResult();
            r.errors.add("Python runtime not available — check storage and try again.");
            return r;
        }
        return bridge.transpile(apkPath, filterText, outputDir, cb);
    }

    // ── Path 2: NMMP VMP interpreter ─────────────────────────────────────────

    /**
     * VMP path — converts selected Dalvik methods to randomised custom opcodes
     * interpreted at runtime by the nmmvm C engine (InterpC-portable.cpp).
     *
     * filterText uses NMMP SimpleRules format, e.g.:
     *   class com.foo.LicenseChecker { *; }
     *   class com.foo.CryptoUtil { *; }
     *
     * If filterText is plain class names (one per line, no "class" keyword),
     * we auto-wrap them into SimpleRules format.
     */
    private TranspileResult transpileVmp(String apkPath, String filterText,
                                         File outputDir, TranspileCallback cb) {
        Log.i(TAG, "transpile(VMP) apk=" + apkPath);
        TranspileResult result = new TranspileResult();
        try {
            progress(cb, "VMP: extracting DEX files from APK…");
            List<File> dexFiles = extractDexFiles(apkPath, outputDir);
            if (dexFiles.isEmpty()) {
                result.errors.add("VMP: no DEX files found in " + apkPath);
                return result;
            }
            progress(cb, "VMP: parsing class hierarchy…");
            ClassAnalyzer classAnalyzer = buildClassAnalyzer(dexFiles);

            progress(cb, "VMP: building filter rules…");
            ClassAndMethodFilter filter = buildFilter(filterText, classAnalyzer);

            // Random opcode map — different every protect run
            RandomInstructionRewriter rewriter = new RandomInstructionRewriter();

            progress(cb, "VMP: converting methods → custom opcodes + C stubs…");
            File vmpOutDir = new File(outputDir, "vmp");
            if (!vmpOutDir.exists()) vmpOutDir.mkdirs();

            GlobalDexConfig vmpConfig = Dex2c.handleAllDex(
                    dexFiles, filter, rewriter, classAnalyzer, vmpOutDir);

            result.vmpConfig = vmpConfig;

            // Register ALL generated C files so NdkBuilder compiles every one:
            //   classes_native_functions.c  — method bodies as vmCode[] structs
            //   classes_resolver.c          — RegisterNatives table
            //   jni_init.c                  — JNI_OnLoad that calls each *_setup()
            // We glob the whole vmpOutDir rather than hardcoding names so multi-DEX
            // APKs (classes.dex + classes2.dex → two native_functions files) all land.
            File[] cFiles = vmpOutDir.listFiles(f -> f.getName().endsWith(".c"));
            if (cFiles != null) {
                for (File cf : cFiles) {
                    // Also copy each .c file one level up into outputDir (= cSourceDir)
                    // so NdkBuilder's single-directory compile pass picks them up.
                    File dest = new File(outputDir, cf.getName());
                    Files.copy(cf.toPath(), dest.toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                    result.compiled.put("vmp_" + cf.getName(), dest.getAbsolutePath());
                    Log.d(TAG, "VMP C file registered: " + cf.getName());
                }
            }

            // Also copy any generated .h files (e.g. classes_resolver.h) so that
            // native_functions.c can #include them via the file's own directory.
            File[] hFiles = vmpOutDir.listFiles(f -> f.getName().endsWith(".h"));
            if (hFiles != null) {
                for (File hf : hFiles) {
                    File dest = new File(outputDir, hf.getName());
                    Files.copy(hf.toPath(), dest.toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                    Log.d(TAG, "VMP header copied: " + hf.getName());
                }
            }

            progress(cb, "VMP: done — " + result.compiled.size() + " C file(s) registered.");
        } catch (Exception e) {
            Log.e(TAG, "VMP transpile failed", e);
            result.errors.add("VMP error: " + e.getMessage());
        }
        return result;
    }

    // ── Path 3: HYBRID (VMP selected classes + dex2c the rest) ──────────────

    private TranspileResult transpileHybrid(String apkPath, String filterText,
                                            File outputDir, TranspileCallback cb) {
        Log.i(TAG, "transpile(HYBRID) apk=" + apkPath);

        // Split filterText: lines starting with "vmp:" → VMP, rest → dex2c
        StringBuilder vmpFilter   = new StringBuilder();
        StringBuilder dex2cFilter = new StringBuilder();
        for (String line : filterText.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.startsWith("vmp:")) {
                vmpFilter.append(trimmed.substring(4).trim()).append("\n");
            } else if (!trimmed.isEmpty()) {
                dex2cFilter.append(trimmed).append("\n");
            }
        }

        TranspileResult combined = new TranspileResult();

        // Run VMP leg
        if (vmpFilter.length() > 0) {
            progress(cb, "HYBRID: running VMP leg…");
            TranspileResult vmpResult = transpileVmp(
                    apkPath, vmpFilter.toString(), outputDir, cb);
            combined.compiled.putAll(vmpResult.compiled);
            combined.errors.addAll(vmpResult.errors);
            combined.vmpConfig = vmpResult.vmpConfig;
        }

        // Run dex2c leg
        if (dex2cFilter.length() > 0) {
            progress(cb, "HYBRID: running dex2c leg…");
            TranspileResult d2cResult = transpileDex2c(
                    apkPath, dex2cFilter.toString(), outputDir, cb);
            combined.compiled.putAll(d2cResult.compiled);
            combined.errors.addAll(d2cResult.errors);
        }

        return combined;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Extract all classes*.dex files from the APK into a temp dir and return
     * their File handles in order (classes.dex, classes2.dex, …).
     */
    private List<File> extractDexFiles(String apkPath, File baseDir) throws IOException {
        File dexDir = new File(baseDir, "extracted_dex");
        if (!dexDir.exists()) dexDir.mkdirs();

        List<File> dexFiles = new ArrayList<>();
        byte[] buf = new byte[65536];

        try (ZipInputStream zis = new ZipInputStream(
                new BufferedInputStream(new FileInputStream(apkPath)))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (name.matches("classes\\d*\\.dex")) {
                    File out = new File(dexDir, name);
                    try (FileOutputStream fos = new FileOutputStream(out)) {
                        int n;
                        while ((n = zis.read(buf)) != -1) fos.write(buf, 0, n);
                    }
                    dexFiles.add(out);
                    Log.d(TAG, "Extracted " + name + " (" + out.length() + " bytes)");
                }
            }
        }
        // Sort: classes.dex < classes2.dex < classes3.dex …
        dexFiles.sort((a, b) -> {
            int na = dexIndex(a.getName());
            int nb = dexIndex(b.getName());
            return Integer.compare(na, nb);
        });
        return dexFiles;
    }

    private static int dexIndex(String name) {
        // "classes.dex" → 1, "classes2.dex" → 2, etc.
        String num = name.replace("classes", "").replace(".dex", "");
        return num.isEmpty() ? 1 : Integer.parseInt(num);
    }

    /**
     * Build a ClassAnalyzer that understands the full class hierarchy across
     * all DEX files in the APK (needed for virtual method dispatch resolution).
     */
    private ClassAnalyzer buildClassAnalyzer(List<File> dexFiles) throws IOException {
        ClassAnalyzer analyzer = new ClassAnalyzer();
        for (File f : dexFiles) {
            DexBackedDexFile dexFile = DexBackedDexFile.fromInputStream(
                    null,
                    new BufferedInputStream(new FileInputStream(f)));
            analyzer.loadDexFile(dexFile);
        }
        return analyzer;
    }

    /**
     * Build a ClassAndMethodFilter from the user-supplied filter text.
     *
     * Supports two formats:
     *   1. NMMP SimpleRules ("class com.foo.Bar { *; }")
     *   2. Plain class names, one per line ("com.foo.Bar") — auto-converted
     *      to SimpleRules format so existing dex2c filter files work directly.
     */
    private ClassAndMethodFilter buildFilter(String filterText,
                                             ClassAnalyzer classAnalyzer) throws IOException {
        // Auto-convert plain class names → SimpleRules format
        String rulesText = filterText;
        if (!filterText.contains("class ")) {
            StringBuilder sb = new StringBuilder();
            for (String line : filterText.split("\\r?\\n")) {
                String cls = line.trim();
                if (!cls.isEmpty()) {
                    sb.append("class ").append(cls).append(" { *; }\n");
                }
            }
            rulesText = sb.toString();
        }

        SimpleRules rules = new SimpleRules();
        rules.parse(new StringReader(rulesText));

        // BasicKeepConfig skips constructors + static-initializers
        // (ART verifier cannot handle VMP'd <init> / <clinit>)
        BasicKeepConfig keepConfig = new BasicKeepConfig();

        return new SimpleConvertConfig(keepConfig, rules);
    }

    private static void progress(TranspileCallback cb, String msg) {
        Log.i(TAG, msg);
        if (cb != null) cb.onProgress(msg);
    }
}
