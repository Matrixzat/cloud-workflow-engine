package com.secure.dex.data;

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

    // Cipher key is embedded in the native library only (guard.cpp §9 SL_PKEY).
    // Keeping it here as a Java constant would expose it to bytecode analysis.

    /**
     * Real Application class name — default is the base Application.
     * DexProtector.install() overwrites this from assets/phantom/app.cfg
     * before realApplication() is invoked.
     */
    public static String REAL_APP = "android.app.Application";
}
