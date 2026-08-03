package com.ultra.dex2cvmp.data;

/**
 * Runtime constants for the DEX loader stub.
 *
 * DP_LIB / LUA_MPH / PROTECT_KEY are fixed at compile time and must match
 * the values used by DexPacker on the protection side.
 *
 * REAL_APP is the only value that varies per protected APK; DexPacker writes
 * it to assets/dp-real-app (UTF-8, no trailing newline) and DexProtector.install()
 * reads it before realApplication() is called.
 */
public class Const {
    /** Asset sub-directory holding the phantom payload. */
    public static final String DP_LIB = "phantom";

    /** Single-file bundle containing all encrypted DEX shards. */
    public static final String BUNDLE_FILE = "phantom.vmp";

    /** Asset holding the real Application class name. */
    public static final String APP_CFG = "app.cfg";

    /**
     * 16-char cipher key built at runtime from individual chars so the complete
     * key string never appears in the DEX string pool.
     * Must match DexPacker.PROTECT_KEY = "U1tr4D3x2CVMP!!!".
     */
    public static String getProtectKey() {
        char[] k = new char[16];
        k[0]  = 'U'; k[1]  = '1'; k[2]  = 't'; k[3]  = 'r';
        k[4]  = '4'; k[5]  = 'D'; k[6]  = '3'; k[7]  = 'x';
        k[8]  = '2'; k[9]  = 'C'; k[10] = 'V'; k[11] = 'M';
        k[12] = 'P'; k[13] = '!'; k[14] = '!'; k[15] = '!';
        return new String(k);
    }

    /**
     * Real Application class name — default is the base Application.
     * DexProtector.install() overwrites this from assets/phantom/app.cfg
     * before realApplication() is invoked.
     */
    public static String REAL_APP = "android.app.Application";
}
