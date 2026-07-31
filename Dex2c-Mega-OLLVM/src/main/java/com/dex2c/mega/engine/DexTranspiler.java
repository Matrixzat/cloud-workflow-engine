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
import java.util.regex.Pattern;
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

            // Generate a per-run DexOpcodes.h that matches the randomized bytecode opcode map.
            // Without this, the static vmp_headers/DexOpcodes.h (standard Dalvik ordering) is
            // used during compilation but the bytecode was written with a shuffled opcode map →
            // every instruction dispatches to the wrong handler in vmInterpret → SIGSEGV.
            // This replicates NMMP's CmakeUtils.writeOpcodeHeaderFile() logic.
            progress(cb, "VMP: generating per-run DexOpcodes.h…");
            try {
                File dexOpcodesH = new File(vmpOutDir, "DexOpcodes.h");
                generateDexOpcodesHeader(rewriter, dexOpcodesH);
                Log.i(TAG, "Per-run DexOpcodes.h written → " + dexOpcodesH.getAbsolutePath());
            } catch (Exception e) {
                Log.e(TAG, "generateDexOpcodesHeader failed", e);
                result.errors.add("VMP: DexOpcodes.h generation failed: " + e.getMessage());
                return result;
            }

            // Register ALL generated C files so NdkBuilder compiles every one:
            //   classes_native_functions.c  — method bodies as vmCode[] structs
            //   classes_resolver.c          — RegisterNatives table
            //   jni_init.c                  — JNI_OnLoad that calls each *_setup()
            // We glob the whole vmpOutDir rather than hardcoding names so multi-DEX
            // APKs (classes.dex + classes2.dex → two native_functions files) all land.
            // Glob all generated source files (.c and .cpp — jni_init is now .cpp)
            // and headers (.h) from vmpOutDir into outputDir (= cSourceDir).
            File[] srcFiles = vmpOutDir.listFiles(f -> {
                String n = f.getName();
                return n.endsWith(".c") || n.endsWith(".cpp") || n.endsWith(".h");
            });
            if (srcFiles != null) {
                for (File sf : srcFiles) {
                    File dest = new File(outputDir, sf.getName());
                    Files.copy(sf.toPath(), dest.toPath(),
                            StandardCopyOption.REPLACE_EXISTING);
                    if (sf.getName().endsWith(".h")) {
                        Log.d(TAG, "VMP header copied: " + sf.getName());
                    } else {
                        result.compiled.put("vmp_" + sf.getName(), dest.getAbsolutePath());
                        Log.d(TAG, "VMP source registered: " + sf.getName());
                    }
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
     * Supports:
     *   1. NMMP SimpleRules format  : "class com.foo.Bar { *; }"
     *   2. Dot-notation class name  : "com.example.MyClass"
     *   3. Smali whole-class        : "Lcom/example/MyClass;"
     *   4. Smali method entry       : "Lcom/example/MyClass;->foo()V"
     *
     * For (4), the specific method name is preserved in the SimpleRule so only
     * that method gets VMP'd — not the entire class.
     * Multiple method entries for the same class are merged into one rule block.
     */
    private ClassAndMethodFilter buildFilter(String filterText,
                                             ClassAnalyzer classAnalyzer) throws IOException {
        String rulesText = filterText;
        if (!filterText.contains("class ")) {
            // Collect whole-class entries and per-method entries independently.
            // Nothing supersedes — both manual tree and class-paste are fully honoured.
            // If the same class appears as whole AND with specific methods, SimpleRules
            // stores both MethodRules under the same ClassRule key; { *; } then matches
            // any method so all methods get VMP'd — correct behaviour.
            java.util.LinkedHashSet<String> classEntries = new java.util.LinkedHashSet<>();
            java.util.LinkedHashMap<String, java.util.LinkedHashSet<String>> methodEntries =
                    new java.util.LinkedHashMap<>();

            for (String line : filterText.split("\\r?\\n")) {
                String entry = line.trim();
                if (entry.isEmpty() || entry.startsWith("#")) continue;

                if (entry.contains("->")) {
                    // Method-level: "Lcom/example/MyClass;->foo()V"
                    int arrow = entry.indexOf("->");
                    String smaliClass = entry.substring(0, arrow);
                    String rest       = entry.substring(arrow + 2);
                    int paren = rest.indexOf('(');
                    String methodName = paren > 0 ? rest.substring(0, paren) : rest;
                    if ("<init>".equals(methodName) || "<clinit>".equals(methodName)) continue;

                    // Normalise all class identifier formats → dot notation for SimpleRules:
                    //   "Lcom/foo/Bar;"  (smali full)     → "com.foo.Bar"
                    //   "com/foo/Bar;"   (MethodNode.fullPattern prefix, no L) → "com.foo.Bar"
                    //   "com/foo/Bar"    (slash, no semi)  → "com.foo.Bar"
                    //   "com.foo.Bar"    (already dot)     → "com.foo.Bar"
                    String dotClass;
                    if (smaliClass.startsWith("L") && smaliClass.endsWith(";")) {
                        dotClass = smaliClass.substring(1, smaliClass.length() - 1).replace('/', '.');
                    } else if (smaliClass.endsWith(";")) {
                        dotClass = smaliClass.substring(0, smaliClass.length() - 1).replace('/', '.');
                    } else {
                        dotClass = smaliClass.replace('/', '.');
                    }
                    if (!dotClass.isEmpty()) {
                        methodEntries.computeIfAbsent(dotClass,
                                k -> new java.util.LinkedHashSet<>()).add(methodName);
                    }
                } else {
                    // Whole-class entry — normalise smali → dot
                    String cls = entry;
                    if (cls.startsWith("L") && cls.endsWith(";")) {
                        cls = cls.substring(1, cls.length() - 1).replace('/', '.');
                    }
                    if (!cls.isEmpty()) classEntries.add(cls);
                }
            }

            // Build SimpleRules text — whole-class first, then per-method
            StringBuilder sb = new StringBuilder();
            for (String cls : classEntries) {
                sb.append("class ").append(cls).append(" { *; }\n");
            }
            for (java.util.Map.Entry<String, java.util.LinkedHashSet<String>> e
                    : methodEntries.entrySet()) {
                sb.append("class ").append(e.getKey()).append(" {\n");
                for (String m : e.getValue()) sb.append("    ").append(m).append(";\n");
                sb.append("}\n");
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

    /**
     * Generate a per-run DexOpcodes.h by reading the static template from assets and
     * patching the enum body + goto-table body with the current rewriter's opcode map.
     *
     * This replicates NMMP's CmakeUtils.writeOpcodeHeaderFile() which NMMP runs at
     * protection time before passing source files to cmake/ndk-build. Without this step
     * the VM runtime is compiled with the standard (identity) opcode ordering but the
     * protected bytecode uses the randomized ordering → every opcode dispatches to the
     * wrong handler in vmInterpret → deterministic SIGSEGV.
     *
     * Note on double-backslash in generateConfig() output: the gotoTableWriter receives
     * lines ending with "\\\n" (two chars: backslash + newline). When those lines are
     * used as a String.replaceAll() replacement string, each "\\" becomes a literal
     * single "\" in the output — which is exactly the C macro line-continuation syntax.
     */
    private void generateDexOpcodesHeader(
            com.dex2c.mega.engine.vmp.converter.instructionrewriter.InstructionRewriter rewriter,
            File dest) throws IOException {
        // Read the static DexOpcodes.h template from assets
        String template;
        try (InputStream is = context.getAssets().open("vmp_headers/DexOpcodes.h");
             java.util.Scanner sc = new java.util.Scanner(is, "UTF-8").useDelimiter("\\A")) {
            template = sc.hasNext() ? sc.next() : "";
        }

        // Generate randomized enum body and goto-table body
        StringWriter enumW = new StringWriter();
        StringWriter gotoW = new StringWriter();
        rewriter.generateConfig(enumW, gotoW);

        // Replace enum body:  "enum Opcode { … };" → new enum with shuffled values
        Pattern enumPat = Pattern.compile(
                "enum Opcode \\{.*?\\};",
                Pattern.MULTILINE | Pattern.DOTALL);
        String result = enumPat.matcher(template)
                .replaceAll(String.format("enum Opcode {\n%s};", enumW));

        // Replace goto-table body:  "_name[kNumPackedOpcodes] = { … };" → new table
        Pattern gotoPat = Pattern.compile(
                "_name\\[kNumPackedOpcodes\\] = \\{.*?\\};",
                Pattern.MULTILINE | Pattern.DOTALL);
        result = gotoPat.matcher(result)
                .replaceAll(String.format(
                        "_name[kNumPackedOpcodes] = {        \\\\\n%s};", gotoW));

        try (FileWriter fw = new FileWriter(dest)) {
            fw.write(result);
        }
    }

    private static void progress(TranspileCallback cb, String msg) {
        Log.i(TAG, msg);
        if (cb != null) cb.onProgress(msg);
    }
}
