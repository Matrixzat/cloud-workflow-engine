-keep class io.flutter.** { *; }
-keep class io.flutter.plugins.** { *; }
-dontwarn io.flutter.embedding.**
-keep class com.matrixdev.adizamoviez.** { *; }

-dontwarn com.google.android.play.**
-dontwarn com.google.android.play.core.**
-dontwarn com.google.android.play.core.splitcompat.**
-dontwarn com.google.android.play.core.splitinstall.**
-dontwarn com.google.android.play.core.tasks.**
-keep class com.google.android.play.core.splitcompat.SplitCompatApplication { *; }
-keep public class * extends java.lang.Exception

-keepattributes *Annotation*

# Strip source info from stack traces
-renamesourcefileattribute S
-keepattributes SourceFile,LineNumberTable

# R8 full-mode aggressive optimisation
-optimizationpasses 7
-allowaccessmodification
-mergeinterfacesaggressively
-overloadaggressively
-repackageclasses ''
-flattenpackagehierarchy ''

-dontskipnonpubliclibraryclassmembers

# Strip all logging from release builds
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(...);
    public static int i(...);
    public static int w(...);
    public static int d(...);
    public static int e(...);
    public static int wtf(...);
}

# OkHttp / OkIO — keep just enough for runtime
-keep class okhttp3.** { *; }
-keep interface okhttp3.** { *; }
-dontwarn okhttp3.**
-dontwarn okio.**

-keep class com.google.gson.** { *; }
-dontwarn com.google.gson.**

-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}

-dontwarn javax.annotation.**
-dontwarn kotlin.**
-dontwarn kotlinx.**

-keep class androidx.work.** { *; }

# background_downloader — WorkManager-based native download engine
-keep class com.bbflight.background_downloader.** { *; }
-dontwarn com.bbflight.background_downloader.**

# Suppress R8 full-mode missing-class warnings for optional dependencies
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
-dontwarn javax.naming.**
-dontwarn java.lang.instrument.**
