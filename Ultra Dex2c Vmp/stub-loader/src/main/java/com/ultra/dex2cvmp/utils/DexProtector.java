package com.ultra.dex2cvmp.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;

import com.ultra.dex2cvmp.data.Const;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Installs the encrypted DEX shards from the phantom.vmp bundle.
 *
 * Security improvements over the old version:
 *
 *  1. libphantom.so bootstrap — the native library is stored as an
 *     ARX-encrypted blob inside assets/phantom/.  loadPhantomLib()
 *     decrypts and System.load()s it before any key material is needed.
 *
 *  2. Key never leaves native — nativeDecryptShard(salt, pkgName, encShard)
 *     derives the key and decrypts entirely inside libphantom.so.  Java only
 *     receives plaintext DEX bytes.
 *
 *  3. InMemoryDexClassLoader (API 27+) — decrypted DEX bytes stay in
 *     ByteBuffers, never on disk.  PathClassLoader is re-parented to delegate
 *     through InMemoryDexClassLoader so only ONE loader owns the DexFile.
 *     This prevents the "register dex with multiple class loaders" crash on
 *     apps using android:appComponentFactory (PairIP, CoreComponentFactory).
 *
 *  4. Salt zeroed immediately after all shards are decrypted.
 */
public class DexProtector {
    @SuppressLint("StaticFieldLeak")
    public static Context mContext;
    @SuppressLint("StaticFieldLeak")
    private static final List<File> dexFiles = new ArrayList<>();
    File dexDir;
    File optDir;

    // ── Runtime string builder — no sensitive literals in DEX string pool ──────
    private static String k(char... c) { return new String(c); }
    private static String strAppDex()          { return k('a','p','p','_','d','e','x'); }
    private static String strOpt()             { return k('o','p','t'); }
    private static String strShard()           { return k('s','h','a','r','d','-'); }
    private static String strDotDex()          { return k('.','d','e','x'); }
    private static String strPathList()        { return k('p','a','t','h','L','i','s','t'); }
    private static String strDexElements()     { return k('d','e','x','E','l','e','m','e','n','t','s'); }
    private static String strMakeDexElements() { return k('m','a','k','e','D','e','x','E','l','e','m','e','n','t','s'); }
    private static String strMakePathElements(){ return k('m','a','k','e','P','a','t','h','E','l','e','m','e','n','t','s'); }

    @SuppressLint("PrivateApi")
    public DexProtector(Context context) {
        mContext = context;
        dexFiles.clear();
        dexDir = context.getDir(strAppDex(), Context.MODE_PRIVATE);
        optDir = new File(context.getFilesDir(), strOpt());
        FileUtils.deleteFloor(dexDir.getAbsolutePath());
        FileUtils.mkdir(dexDir.getAbsolutePath());
        FileUtils.mkdir(optDir.getAbsolutePath());
    }

    public void install(Context context) throws Exception {
        // ── Step 1: Read phantom.vmp — first 16 bytes are the masked blob key ──
        byte[] bundleBytes;
        byte[] maskedBlobKey = new byte[16];
        {
            InputStream bs = mContext.getAssets().open(Const.DP_LIB + "/" + Const.BUNDLE_FILE);
            bundleBytes = DexCrypto.readFully(bs);
            bs.close();
        }
        if (bundleBytes.length < 16) throw new RuntimeException(k('b','a','d',' ','v','m','p'));
        System.arraycopy(bundleBytes, 0, maskedBlobKey, 0, 16);

        // ── Step 2: Bootstrap libphantom.so using the asset-buried key ────────
        DexCrypto.loadPhantomLib(context, maskedBlobKey);
        Arrays.fill(maskedBlobKey, (byte) 0);

        // ── Step 3: Read real Application class name ──────────────────────────
        try {
            InputStream ris = mContext.getAssets().open(Const.DP_LIB + "/" + Const.APP_CFG);
            byte[] buf = new byte[512];
            int n = ris.read(buf);
            ris.close();
            if (n > 0) {
                String realApp = new String(buf, 0, n, "UTF-8").trim();
                if (!realApp.isEmpty()) Const.REAL_APP = realApp;
            }
        } catch (Exception ignored) { }

        // ── Step 3: Read 16-byte salt from assets ─────────────────────────────
        byte[] salt = readAsset(context, Const.DP_LIB + "/" + Const.SALT_ASSET);
        if (salt == null || salt.length != 16) {
            throw new RuntimeException(k('b','a','d',' ','s','a','l','t'));
        }

        // ── Step 4: Pre-encode pkg name (UTF-8) for native call ──────────────
        byte[] pkgNameUtf8 = context.getPackageName()
                .getBytes(java.nio.charset.StandardCharsets.UTF_8);

        try {
            // ── Step 5: Parse phantom.vmp bundle (already read above, skip 16-byte header) ──
            DataInputStream dis = new DataInputStream(
                    new ByteArrayInputStream(bundleBytes, 16, bundleBytes.length - 16));
            int shardCount = dis.readInt();
            int[] sizes = new int[shardCount];
            for (int i = 0; i < shardCount; i++) sizes[i] = dis.readInt();

            if (Build.VERSION.SDK_INT >= 27) {
                // ── API 27+: InMemoryDexClassLoader — never writes to disk ────
                loadInMemory(context, dis, shardCount, sizes, salt, pkgNameUtf8);
            } else {
                // ── API < 27 fallback: write shards to app_dex/ ──────────────
                loadViaFiles(context, dis, shardCount, sizes, salt, pkgNameUtf8);
            }
        } finally {
            // Zero salt — key never leaves native.
            Arrays.fill(salt, (byte) 0);
        }
    }

    // ── In-memory path (API 27+) ──────────────────────────────────────────────

    @SuppressLint({"PrivateApi", "DiscouragedPrivateApi"})
    private void loadInMemory(Context context, DataInputStream dis,
                              int shardCount, int[] sizes,
                              byte[] salt, byte[] pkgNameUtf8) throws Exception {

        ByteBuffer[] buffers = new ByteBuffer[shardCount];
        // Keep refs to the raw byte arrays so we can poison them after ART loads.
        byte[][] dexArrays = new byte[shardCount][];
        for (int i = 0; i < shardCount; i++) {
            byte[] encrypted = new byte[sizes[i]];
            dis.readFully(encrypted);
            byte[] dexBytes = DexCrypto.nativeDecryptShard(salt, pkgNameUtf8, encrypted);
            dexArrays[i] = dexBytes;
            buffers[i] = ByteBuffer.wrap(dexBytes);
        }

        // Create InMemoryDexClassLoader and inject its dexElements into the
        // context ClassLoader so classes from the protected DEX are visible.
        ClassLoader parent = context.getClassLoader();
        ClassLoader inMemory = new dalvik.system.InMemoryDexClassLoader(buffers, parent);

        // Inject: merge dexElements from inMemory → parent's pathList.
        injectDexElements(inMemory, parent);

        // ART has parsed the DEX from its own internal copy — poison the Java-heap
        // byte[] so that memory scanners find no valid DEX header in our heap.
        for (byte[] db : dexArrays) {
            if (db != null) DexCrypto.nativePoisonDex(db);
        }
    }

    // ── File-based path (API 21-26 fallback) ──────────────────────────────────

    private void loadViaFiles(Context context, DataInputStream dis,
                              int shardCount, int[] sizes,
                              byte[] salt, byte[] pkgNameUtf8) throws Exception {
        File dir = context.getDir(strAppDex(), 0);
        if (!dir.exists()) dir.mkdirs();
        List<File> files = new ArrayList<>();

        for (int i = 0; i < shardCount; i++) {
            byte[] encrypted = new byte[sizes[i]];
            dis.readFully(encrypted);
            byte[] dexBytes = DexCrypto.nativeDecryptShard(salt, pkgNameUtf8, encrypted);

            File outFile = new File(dir, strShard() + (i + 1) + strDotDex());
            FileOutputStream fos = new FileOutputStream(outFile);
            try { fos.write(dexBytes); } finally { fos.close(); }
            outFile.setWritable(false, false);
            files.add(outFile);

            // DEX is now on disk — poison the in-memory byte[] so the Java heap
            // has no valid DEX header for memory scanners to find.
            DexCrypto.nativePoisonDex(dexBytes);
        }

        loadDex(context, files, dexDir);
    }

    // ── ClassLoader injection ─────────────────────────────────────────────────

    @SuppressLint({"PrivateApi", "DiscouragedPrivateApi"})
    private void injectDexElements(ClassLoader src, ClassLoader dst) throws Exception {
        Field pathListField = Reflect.findField(src, strPathList());
        Object srcPathList = pathListField.get(src);
        Field dexElementsField = Reflect.findField(srcPathList, strDexElements());
        Object[] added = (Object[]) dexElementsField.get(srcPathList);

        Field dstPathListField = Reflect.findField(dst, strPathList());
        Object dstPathList = dstPathListField.get(dst);
        Field dstDexElemField = Reflect.findField(dstPathList, strDexElements());
        Object[] existing = (Object[]) dstDexElemField.get(dstPathList);

        Object[] merged = (Object[]) Array.newInstance(
                existing.getClass().getComponentType(),
                existing.length + added.length);
        System.arraycopy(existing, 0, merged, 0, existing.length);
        System.arraycopy(added, 0, merged, existing.length, added.length);
        dstDexElemField.set(dstPathList, merged);
    }

    @SuppressLint({"PrivateApi", "DiscouragedPrivateApi"})
    private void loadDex(Context context, List<File> files, File optDir) throws Exception {
        if (files.isEmpty()) return;
        ClassLoader classLoader = context.getClassLoader();
        Field pathListField = Reflect.findField(classLoader, strPathList());
        Object pathList = pathListField.get(classLoader);
        Field dexElementsField = Reflect.findField(pathList, strDexElements());
        Object[] existing = (Object[]) dexElementsField.get(pathList);
        Object[] added = invokeMakeElements(pathList, files, optDir, classLoader);
        Object[] merged = (Object[]) Array.newInstance(
                existing.getClass().getComponentType(),
                existing.length + added.length);
        System.arraycopy(existing, 0, merged, 0, existing.length);
        System.arraycopy(added, 0, merged, existing.length, added.length);
        dexElementsField.set(pathList, merged);
    }

    private Object[] invokeMakeElements(Object pathList, List<File> files,
            File optDir, ClassLoader loader) throws Exception {
        List<IOException> suppressed = new ArrayList<>();
        String mde = strMakeDexElements();
        String mpe = strMakePathElements();
        Class<?> clazz = pathList.getClass();
        while (clazz != null && clazz != Object.class) {
            for (Method m : clazz.getDeclaredMethods()) {
                String nm = m.getName();
                if (!nm.equals(mde) && !nm.equals(mpe)) continue;
                Class<?>[] pt = m.getParameterTypes();
                m.setAccessible(true);
                switch (pt.length) {
                    case 4: return (Object[]) m.invoke(pathList, files, optDir, suppressed, loader);
                    case 3:
                        if (ArrayList.class.equals(pt[0]))
                            return (Object[]) m.invoke(pathList,
                                    new ArrayList<>(files), optDir, new ArrayList<>(suppressed));
                        return (Object[]) m.invoke(pathList, files, optDir, suppressed);
                    case 2: return (Object[]) m.invoke(pathList, new ArrayList<>(files), optDir);
                }
            }
            clazz = clazz.getSuperclass();
        }
        throw new RuntimeException(k('n','o',' ','m','a','k','e','E','l','e','m',' ','f','o','u','n','d'));
    }

    // ── Misc helpers ──────────────────────────────────────────────────────────

    private static byte[] readAsset(Context ctx, String path) {
        try {
            InputStream is = ctx.getAssets().open(path);
            byte[] data = DexCrypto.readFully(is);
            is.close();
            return data;
        } catch (Exception e) {
            return null;
        }
    }

    /** Expose the resolved real Application class name after install(). */
    public static String getRealAppClass() {
        return Const.REAL_APP;
    }
}
