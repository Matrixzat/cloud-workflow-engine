package fonts;

import android.content.Context;

/**
 * Stub class — exists solely so guard.cpp can RegisterNatives against it
 * at JNI_OnLoad time.  The real implementation is _fonts_measure_impl in
 * guard.cpp; this Java shell carries the native declaration so the JVM
 * accepts the binding without throwing NoSuchMethodError.
 */
public class Metrics {
    public native void measure(Context context);
}
