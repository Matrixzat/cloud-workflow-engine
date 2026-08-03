package com.ultra.dex2cvmp.engine.packer;

import android.content.Context;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * DEX Packer — wraps a dex2c/VMP-processed APK with the com.secure.dex stub loader.
 *
 * Flow:
 *  1. Extract classes*.dex + AndroidManifest.xml from input APK.
 *  2. Parse manifest → capture real Application class, patch android:name → ProxyApplication.
 *  3. Encrypt all DEX shards and bundle them into a single phantom.vmp payload.
 *     Bundle format: [4-byte shard count][count × 4-byte shard sizes][encrypted bytes…]
 *  4. Write assets/phantom/app.cfg (real app class name, UTF-8).
 *  5. Load pre-built stub.dex from our own app assets.
 *  6. Repack: stub.dex + patched manifest + phantom payload + rest of original APK.
 */
public class DexPacker {

    /** Must match com.secure.dex.data.Const.PROTECT_KEY in the stub loader. */
    public static final String PROTECT_KEY = "U1tr4D3x2CVMP!!!";

    /** Asset sub-dir name in the output APK. Must match Const.DP_LIB. */
    public static final String ASSET_DIR = "phantom";

    /** Single-file bundle name. Must match Const.BUNDLE_FILE. */
    public static final String BUNDLE_FILE = "phantom.vmp";

    /** Fully-qualified stub Application class injected into the manifest. */
    public static final String PROXY_APP  = "com.ultra.dex2cvmp.ProxyApplication";

    /** Asset name used to pass real app class to stub at runtime. */
    public static final String REAL_APP_ASSET = "app.cfg";

    private final Context context;

    public DexPacker(Context context) {
        this.context = context;
    }

    /**
     * Pack {@code inputApk} into {@code outputApk} using the stub loader.
     *
     * @param inputApk   Dex2c/VMP-processed APK (will not be modified).
     * @param outputApk  Destination for the packed APK (unsigned; sign separately).
     * @param workDir    Scratch directory for extracted + encrypted files.
     */
    public void pack(File inputApk, File outputApk, File workDir) throws Exception {
        // ── 1. Extract manifest + DEX files from input APK ───────────────────
        File extractDir = new File(workDir, "extracted");
        FastZip.extract(inputApk, extractDir);

        // ── 2. Parse + patch manifest ─────────────────────────────────────────
        File manifestFile = new File(extractDir, "AndroidManifest.xml");
        byte[] manifestBytes = readFile(manifestFile);

        byte[] patchedManifest = ManifestPatcher.parseManifest(manifestBytes, PROXY_APP);
        // ManifestPatcher.customApplicationName now holds the original app class (or "")

        String realAppClass = ManifestPatcher.customApplication
                ? ManifestPatcher.customApplicationName
                : "android.app.Application";

        // Expand ".<name>" short-form to fully qualified using package name
        if (realAppClass.startsWith(".") && !ManifestPatcher.packageName.isEmpty()) {
            realAppClass = ManifestPatcher.packageName + realAppClass;
        }

        // ── 3. Encrypt all DEX shards and bundle into one phantom.vmp ────────
        File shardsDir = new File(workDir, "shards");
        shardsDir.mkdirs();

        // Collect encrypted bytes for every shard
        List<byte[]> shards = new ArrayList<>();
        File classesDex = new File(extractDir, "classes.dex");
        if (classesDex.exists()) shards.add(encryptDexToBytes(classesDex));
        for (int i = 2; ; i++) {
            File dex = new File(extractDir, "classes" + i + ".dex");
            if (!dex.exists()) break;
            shards.add(encryptDexToBytes(dex));
        }

        // Write bundle: [4-byte count][count × 4-byte shard size][shard bytes…]
        File bundleFile = new File(shardsDir, BUNDLE_FILE);
        try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(bundleFile))) {
            dos.writeInt(shards.size());
            for (byte[] shard : shards) dos.writeInt(shard.length);
            for (byte[] shard : shards) dos.write(shard);
        }

        // ── 4. Write app.cfg (real app class name) ────────────────────────────
        File realAppFile = new File(shardsDir, REAL_APP_ASSET);
        try (FileOutputStream fos = new FileOutputStream(realAppFile)) {
            fos.write(realAppClass.getBytes("UTF-8"));
        }

        // ── 5. Load pre-built stub DEX from our assets ────────────────────────
        byte[] stubDex = readAsset("stub.dex");

        // ── 6. Repack ─────────────────────────────────────────────────────────
        FastZip.repack(inputApk, outputApk, stubDex, shardsDir, ASSET_DIR, patchedManifest);
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    private byte[] encryptDexToBytes(File input) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (InputStream in = new FileInputStream(input)) {
            DexCrypto.encrypt(PROTECT_KEY, in, baos);
        }
        return baos.toByteArray();
    }

    private byte[] readFile(File f) throws IOException {
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] data = new byte[(int) f.length()];
            fis.read(data);
            return data;
        }
    }

    private byte[] readAsset(String name) throws IOException {
        try (InputStream is = context.getAssets().open(name)) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192]; int n;
            while ((n = is.read(buf)) > 0) baos.write(buf, 0, n);
            return baos.toByteArray();
        }
    }
}
