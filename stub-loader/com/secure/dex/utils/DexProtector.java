package com.secure.dex.utils;

import android.content.Context;

/**
 * Stub shell — all logic lives in guard.cpp (stub_install_impl).
 * ProxyApplication loads the native library then calls install().
 */
public class DexProtector {
    public static native void install(Context context);
}
