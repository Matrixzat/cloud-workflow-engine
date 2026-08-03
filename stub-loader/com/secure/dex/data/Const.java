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
    /**
     * Real Application class name — default is the base Application.
     * guard.cpp §9 overwrites this via JNI (SetStaticObjectField) after
     * reading assets/phantom/app.cfg, before realApplication() is invoked.
     * All other asset paths are handled natively with XOR-encrypted strings.
     */
    public static String REAL_APP = "android.app.Application";
}
