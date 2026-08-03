package com.ultra.dex2cvmp;

import android.app.Application;
import android.app.Instrumentation;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.util.ArrayMap;

import com.secure.dex.data.Const;
import com.secure.dex.utils.DexProtector;
import com.secure.dex.utils.Reflect;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;

public class ProxyApplication extends Application {

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);

        // Read the native library name written by DexPacker into phantom/lib.cfg,
        // load it (triggers JNI_OnLoad → stub_register_natives), then decrypt+inject.
        // Read lib name — only catch IO errors; let loadLibrary failures propagate
        // so UnsatisfiedLinkError surfaces clearly instead of being swallowed.
        String libName = null;
        try {
            InputStream in = base.getAssets().open("phantom/lib.cfg");
            byte[] buf = new byte[256];
            int n = in.read(buf);
            in.close();
            if (n > 0) libName = new String(buf, 0, n, "UTF-8").trim();
        } catch (java.io.IOException ignored) { }
        if (libName != null) System.loadLibrary(libName);

        DexProtector.install(base);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        Application app = realApplication();
        if (app != null) {
            app.onCreate();
        }
    }

    private Application realApplication() {
        Object currentActivityThread = Reflect.invokeMethod(
                "android.app.ActivityThread", null, "currentActivityThread",
                new Object[]{}, null);
        Object mBoundApplication = Reflect.getFieldValue(
                "android.app.ActivityThread", currentActivityThread,
                "mBoundApplication");
        Object loadedApkInfo = Reflect.getFieldValue(
                "android.app.ActivityThread$AppBindData",
                mBoundApplication, "info");
        Reflect.setFieldValue("android.app.LoadedApk", loadedApkInfo, "mApplication", null);
        Object oldApplication = Reflect.getFieldValue(
                "android.app.ActivityThread", currentActivityThread,
                "mInitialApplication");
        ArrayList<Application> mAllApplications = (ArrayList<Application>) Reflect
                .getFieldValue("android.app.ActivityThread",
                        currentActivityThread, "mAllApplications");
        if (mAllApplications != null) mAllApplications.remove(oldApplication);

        ApplicationInfo loadedApk = (ApplicationInfo) Reflect
                .getFieldValue("android.app.LoadedApk", loadedApkInfo, "mApplicationInfo");
        ApplicationInfo appBindData = (ApplicationInfo) Reflect
                .getFieldValue("android.app.ActivityThread$AppBindData",
                        mBoundApplication, "appInfo");

        if (loadedApk  != null) loadedApk.className  = Const.REAL_APP;
        if (appBindData != null) appBindData.className = Const.REAL_APP;

        Application app = (Application) Reflect.invokeMethod(
                "android.app.LoadedApk", loadedApkInfo, "makeApplication",
                new Object[]{false, null},
                boolean.class, Instrumentation.class);

        Reflect.setFieldValue("android.app.ActivityThread",
                currentActivityThread, "mInitialApplication", app);

        ArrayMap<?, ?> mProviderMap = (ArrayMap<?, ?>) Reflect.getFieldOjbect(
                "android.app.ActivityThread", currentActivityThread, "mProviderMap");
        if (mProviderMap != null) {
            Iterator<?> it = mProviderMap.values().iterator();
            while (it.hasNext()) {
                Object rec = it.next();
                Object localProvider = Reflect.getFieldOjbect(
                        "android.app.ActivityThread$ProviderClientRecord",
                        rec, "mLocalProvider");
                if (localProvider != null)
                    Reflect.setFieldOjbect("android.content.ContentProvider",
                            "mContext", localProvider, app);
            }
        }
        return app;
    }
}
