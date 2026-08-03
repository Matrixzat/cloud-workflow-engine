package com.ultra.dex2cvmp.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Build;

import com.ultra.dex2cvmp.data.Const;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.InflaterInputStream;
import java.util.zip.InflaterOutputStream;

/**
 * Runtime DEX decryption + libphantom bootstrap for the stub loader.
 *
 * Key changes vs. the old version:
 *  • Const.getProtectKey() / static PROTECT_KEY are gone.
 *  • The 16-byte session key is obtained by calling the native method
 *    nativeGetKey(salt, certHash, pkgName) exported by libphantom.so.
 *  • libphantom.so is stored inside the APK as an ARX-encrypted blob
 *    (assets/phantom/libphantom_arm64.blob or libphantom_arm.blob).
 *    loadPhantomLib(Context) decrypts it, writes it to code_cache/, and
 *    calls System.load() — all of this MUST complete before nativeGetKey
 *    is invoked.
 *  • decrypt / decryptToBytes accept a byte[] key so no key material ever
 *    lives as a Java String.
 *
 * ── Call order ────────────────────────────────────────────────────────────────
 *   DexCrypto.loadPhantomLib(ctx);                  // extract + load .so
 *   byte[] key = DexCrypto.nativeGetKey(salt, certHash, pkgName);
 *   // … pass key to DexProtector for in-memory DEX decryption …
 *   Arrays.fill(key, (byte) 0);                     // zero after use
 * ─────────────────────────────────────────────────────────────────────────────
 */
public class DexCrypto {

    // ── Native entry-point ────────────────────────────────────────────────────

    /**
     * Derive the 16-byte DEX session key inside libphantom.so.
     *
     * The native side runs the same ARX KDF as PhantomKey.deriveKey() on the
     * host.  If {@code certHash} does not match the cert that was present at
     * pack time the derived key will be wrong and decryption will silently
     * produce garbage — no error string is exposed.
     *
     * MUST be called only after {@link #loadPhantomLib(Context)}.
     *
     * @param salt        16-byte raw salt from assets/phantom/ph_salt.
     * @param pkgNameUtf8 Package name pre-encoded as standard UTF-8 bytes by the
     *                    caller (context.getPackageName().getBytes(UTF_8)).
     * @return 16-byte key (caller MUST zero with Arrays.fill after use).
     */
    public static native byte[] nativeGetKey(byte[] salt, byte[] pkgNameUtf8);

    // ── Blob bootstrap ────────────────────────────────────────────────────────

    /**
     * Hardcoded blob-decryption key — built char-by-char so the value never
     * appears verbatim in the DEX string pool.
     * This key is ONLY used to decrypt the libphantom.so blob; it does NOT
     * protect any user data.  It is separate from, and weaker than, the per-APK
     * key derived by nativeGetKey().
     */
    private static byte[] blobKey() {
        // "Ph4nt0mBl0bK3y!" (16 bytes) — change when regenerating blobs.
        char[] c = new char[]{
            'P','h','4','n','t','0','m','B','l','0','b','K','3','y','!','!'
        };
        byte[] k = new byte[c.length];
        for (int i = 0; i < c.length; i++) k[i] = (byte) c[i];
        return k;
    }

    /**
     * Extract the ABI-appropriate libphantom blob from assets, decrypt it with
     * the hardcoded blob key, write it to {@code getCodeCacheDir()/libphantom.so},
     * and call {@code System.load()}.
     *
     * Idempotent — if the file already exists it is reused (the blob only changes
     * when a new libphantom build is shipped).
     */
    @SuppressLint("UnsafeDynamicallyLoadedCode")
    public static void loadPhantomLib(Context ctx) throws Exception {
        File soFile = new File(ctx.getCodeCacheDir(), "libphantom.so");

        if (!soFile.exists()) {
            String blobName = pickBlobName();
            String assetPath = Const.DP_LIB + "/" + blobName;

            InputStream bis = ctx.getAssets().open(assetPath);
            byte[] blob = readFully(bis);
            closeQuiet(bis);

            byte[] soBytes = decryptBlob(blob);

            File parent = soFile.getParentFile();
            if (parent != null && !parent.exists()) parent.mkdirs();

            FileOutputStream fos = new FileOutputStream(soFile);
            try {
                fos.write(soBytes);
            } finally {
                closeQuiet(fos);
            }

            // Remove write permission so ART is happy.
            soFile.setWritable(false, false);
        }

        System.load(soFile.getAbsolutePath());
    }

    // ── Decryption helpers called by DexProtector ─────────────────────────────

    /**
     * Decrypt {@code encrypted} bytes (a single DEX shard) into a fresh byte[].
     *
     * @param key       16-byte key from nativeGetKey().
     * @param encrypted Encrypted shard bytes from the phantom.vmp bundle.
     * @return Plaintext DEX bytes.
     */
    public static byte[] decryptToBytes(byte[] key, byte[] encrypted) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(encrypted.length);
        decrypt(key,
                new java.io.ByteArrayInputStream(encrypted),
                baos);
        return baos.toByteArray();
    }

    /** Streaming decrypt — used when writing a shard to disk (API < 26 fallback). */
    public static void decrypt(byte[] key, InputStream input, OutputStream output) throws Exception {
        InflaterInputStream  is = new InflaterInputStream(input);
        InflaterOutputStream os = new InflaterOutputStream(output);
        exfr(key, is, os);
        os.close();
        is.close();
    }

    // ── Private implementation ────────────────────────────────────────────────

    /** Decrypt a raw blob byte[] using the hardcoded blob key. */
    private static byte[] decryptBlob(byte[] blob) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream(blob.length);
        decrypt(blobKey(), new java.io.ByteArrayInputStream(blob), out);
        return out.toByteArray();
    }

    /** Pick the right blob asset name for the current device ABI. */
    private static String pickBlobName() {
        String[] abis = (Build.VERSION.SDK_INT >= 21)
                ? Build.SUPPORTED_ABIS
                : new String[]{ Build.CPU_ABI, Build.CPU_ABI2 };
        for (String abi : abis) {
            if (abi != null && abi.startsWith("arm64")) return Const.PHANTOM_BLOB_ARM64;
        }
        return Const.PHANTOM_BLOB_ARM;
    }

    /** ARX stream cipher — key is 16 raw bytes (little-endian → 4 × int). */
    private static void exfr(byte[] key, InputStream in, OutputStream out) throws Exception {
        if (key == null || key.length < 16) throw new IllegalArgumentException("key must be 16 bytes");

        int[] iArr = new int[4];
        for (int i = 0; i < 4; i++) {
            int b = i * 4;
            iArr[i] = (key[b]     & 0xFF)
                    | ((key[b+1] & 0xFF) << 8)
                    | ((key[b+2] & 0xFF) << 16)
                    | ((key[b+3] & 0xFF) << 24);
        }
        int[] iArr2 = new int[]{ iArr[0] ^ iArr[2], iArr[1] ^ iArr[3] };
        iArr = FxIjsF(iArr);

        byte[] buf = new byte[8192];
        int pos = 0;
        while (true) {
            int read = in.read(buf);
            if (read < 0) return;
            int end = pos + read;
            int i5 = 0;
            while (pos < end) {
                int i6 = pos % 8;
                if (i6 == 0) nDnv(iArr, iArr2);
                buf[i5] = (byte) (((byte) (iArr2[i6 / 4] >> ((pos % 4) * 8))) ^ buf[i5]);
                pos++;
                i5++;
            }
            out.write(buf, 0, read);
        }
    }

    private static int[] FxIjsF(int[] iArr) {
        int[] r = new int[27];
        int i = iArr[0];
        r[0] = i;
        int[] t = new int[]{ iArr[1], iArr[2], iArr[3] };
        for (int i2 = 0; i2 < 26; i2++) {
            t[i2 % 3] = (((t[i2 % 3] >>> 8) | (t[i2 % 3] << 24)) + i) ^ i2;
            i = ((i << 3) | (i >>> 29)) ^ t[i2 % 3];
            r[i2 + 1] = i;
        }
        return r;
    }

    private static void nDnv(int[] iArr, int[] iArr2) {
        int i = iArr2[0], i2 = iArr2[1];
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[0];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[1];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[2];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[3];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[4];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[5];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[6];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[7];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[8];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[9];  i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[10]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[11]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[12]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[13]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[14]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[15]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[16]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[17]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[18]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[19]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[20]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[21]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[22]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[23]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[24]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[25]; i=((i<<3)|(i>>>29))^i2;
        i2 = (((i2>>>8)|(i2<<24))+i)^iArr[26];
        iArr2[0] = ((i<<3)|(i>>>29))^i2;
        iArr2[1] = i2;
    }

    // ── tiny helpers ──────────────────────────────────────────────────────────

    static byte[] readFully(InputStream is) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n;
        while ((n = is.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }

    private static void closeQuiet(Closeable c) {
        if (c == null) return;
        try { c.close(); } catch (IOException ignored) {}
    }
}
