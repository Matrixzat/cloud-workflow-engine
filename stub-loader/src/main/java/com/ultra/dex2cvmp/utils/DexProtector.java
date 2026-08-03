package com.ultra.dex2cvmp.utils;

import android.annotation.SuppressLint;
import android.content.Context;

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
import java.util.ArrayList;
import java.util.List;

public class DexProtector {
    @SuppressLint("StaticFieldLeak")
    public static Context mContext;
    @SuppressLint("StaticFieldLeak")
    private static List<File> dexFiles = new ArrayList<>();
    File dexDir;
    File optDir;

    // ── Runtime string builder — no sensitive literals in DEX string pool ──────
    // NOTE: to move to native later, replace k() with a JNI call to guard.cpp.
    private static String k(char... c) { return new String(c); }

    // Sensitive strings built at runtime so they never appear in the string pool:
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
        dexFiles = new ArrayList<>();
        dexDir = context.getDir(strAppDex(), Context.MODE_PRIVATE);
        optDir = new File(context.getFilesDir(), strOpt());

        FileUtils.deleteFloor(dexDir.getAbsolutePath());
        FileUtils.mkdir(dexDir.getAbsolutePath());
        FileUtils.mkdir(optDir.getAbsolutePath());
    }

    public void install(Context context) throws Exception {
        // ── Read real Application class name from phantom/app.cfg ────────────
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

        // ── Read + decrypt phantom.vmp bundle ─────────────────────────────────
        // Bundle format: [4-byte count N][N × 4-byte shard sizes][shard bytes…]
        InputStream bundleStream = mContext.getAssets().open(Const.DP_LIB + "/" + Const.BUNDLE_FILE);
        byte[] bundleBytes = readFully(bundleStream);
        bundleStream.close();

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bundleBytes));
        int shardCount = dis.readInt();
        int[] sizes    = new int[shardCount];
        for (int i = 0; i < shardCount; i++) sizes[i] = dis.readInt();

        File dexDir = context.getDir(strAppDex(), 0);
        if (!dexDir.exists()) dexDir.mkdirs();

        for (int i = 0; i < shardCount; i++) {
            byte[] encrypted = new byte[sizes[i]];
            dis.readFully(encrypted);

            // Decrypt shard → write as shard-N.dex (must end in .dex for ART)
            File outFile = new File(dexDir, strShard() + (i + 1) + strDotDex());
            DexCrypto.decDex(new ByteArrayInputStream(encrypted), outFile);
            // Android 16 (API 36) rejects loading world-writable DEX files with SecurityException.
            // Remove write permission immediately after writing so ART / makeDexElements accepts it.
            outFile.setWritable(false, false);
            dexFiles.add(outFile);
        }

        loadDex(context, dexFiles, dexDir);
        // DEX files intentionally NOT deleted — ART reads them lazily.
    }

    private static byte[] readFully(InputStream is) throws IOException {
        byte[] buf = new byte[8192];
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int n;
        while ((n = is.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }

    @SuppressLint({"PrivateApi", "DiscouragedPrivateApi"})
    private void loadDex(Context context, List<File> dexFiles, File optDir) throws Exception {
        if (dexFiles.isEmpty()) return;

        ClassLoader classLoader = context.getClassLoader();

        Field pathListField = Reflect.findField(classLoader, strPathList());
        Object pathList = pathListField.get(classLoader);

        Field dexElementsField = Reflect.findField(pathList, strDexElements());
        Object[] existing = (Object[]) dexElementsField.get(pathList);

        Object[] added = invokeMakeElements(pathList, dexFiles, optDir, classLoader);

        Object[] merged = (Object[]) Array.newInstance(
                existing.getClass().getComponentType(),
                existing.length + added.length);
        System.arraycopy(existing, 0, merged, 0, existing.length);
        System.arraycopy(added,    0, merged, existing.length, added.length);

        dexElementsField.set(pathList, merged);
    }

    private Object[] invokeMakeElements(Object pathList, List<File> files,
            File optDir, ClassLoader loader) throws Exception {

        List<IOException> suppressed = new ArrayList<>();
        String mde  = strMakeDexElements();
        String mpe  = strMakePathElements();

        Class<?> clazz = pathList.getClass();
        while (clazz != null && clazz != Object.class) {
            for (Method m : clazz.getDeclaredMethods()) {
                String nm = m.getName();
                if (!nm.equals(mde) && !nm.equals(mpe)) continue;

                Class<?>[] pt = m.getParameterTypes();
                m.setAccessible(true);

                switch (pt.length) {
                    case 4:
                        return (Object[]) m.invoke(pathList, files, optDir, suppressed, loader);
                    case 3:
                        if (ArrayList.class.equals(pt[0])) {
                            return (Object[]) m.invoke(pathList,
                                    new ArrayList<>(files), optDir, new ArrayList<>(suppressed));
                        }
                        return (Object[]) m.invoke(pathList, files, optDir, suppressed);
                    case 2:
                        return (Object[]) m.invoke(pathList, new ArrayList<>(files), optDir);
                    default:
                        break;
                }
            }
            clazz = clazz.getSuperclass();
        }

        throw new RuntimeException(k('n','o',' ','m','a','k','e','E','l','e','m',' ','f','o','u','n','d'));
    }

    /** Expose the resolved real Application class name after install(). */
    public static String getRealAppClass() {
        return Const.REAL_APP;
    }
}
