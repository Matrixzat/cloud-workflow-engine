package com.dex2c.mega.engine;

import android.util.Log;
import java.io.*;
import java.util.*;

/**
 * DexTranspiler — APK → C++ via codehasan/dex2c Python transpiler (filter_bridge.py).
 *
 * Delegates entirely to Dex2cPythonBridge which:
 *   1. Extracts bundled assets/dex2c_python/ to filesDir (once, cached)
 *   2. Runs: python3 filter_bridge.py --apk <apk> --filter <filter.txt> --outdir <dir>
 *   3. Returns .cpp files for NdkBuilder to compile with on-device clang++
 *
 * filter_bridge.py uses codehasan's MethodFilter + Dex2C verbatim, with a
 * global multi-DEX R8 shadow-class taint check layered on top via subclassing.
 */
public class DexTranspiler {

    private static final String TAG = "DexTranspiler";

    public interface TranspileCallback {
        void onProgress(String message);
    }

    public static class TranspileResult {
        public final Map<String, String> compiled = new LinkedHashMap<>();
        public final List<String> errors = new ArrayList<>();
        public int successCount() { return compiled.size(); }
    }

    private final android.content.Context context;

    public DexTranspiler(android.content.Context context) {
        this.context = context.getApplicationContext();
    }

    /**
     * Transpile an APK to C++ source files using codehasan/dex2c.
     *
     * @param apkPath    path to the input APK (all DEX files loaded by Python)
     * @param filterText class names to protect, one per line (e.g. "com.foo.Bar")
     * @param outputDir  directory to write .cpp files into
     * @param cb         progress callback (nullable)
     */
    public TranspileResult transpile(String apkPath, String filterText,
                                     File outputDir, TranspileCallback cb) {
        Log.i(TAG, "transpile() apk=" + apkPath);

        Dex2cPythonBridge bridge = new Dex2cPythonBridge(context);

        if (!bridge.isAvailable()) {
            TranspileResult r = new TranspileResult();
            r.errors.add("Python runtime not available. The bundled Python 3 could not be extracted — check storage space and try again.");
            return r;
        }

        return bridge.transpile(apkPath, filterText, outputDir, cb);
    }
}
