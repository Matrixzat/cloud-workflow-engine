package com.dex2c.mega.engine.vmp;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

public class GlobalDexConfig {

    private final ArrayList<DexConfig> configs = new ArrayList<>();

    private final File outputDir;

    public GlobalDexConfig(File outputDir) {
        this.outputDir = outputDir;
    }

    public File getInitCodeFile() {
        return new File(outputDir, "jni_init.cpp");
    }

    public void addDexConfig(DexConfig config) {
        configs.add(config);
    }

    public List<DexConfig> getConfigs() {
        return configs;
    }

    public void generateJniInitCode() throws IOException {
        try (
                final FileWriter writer = new FileWriter(getInitCodeFile());
        ) {
            generateJniInitCode(writer);
        }
    }

    private void generateJniInitCode(Writer writer) throws IOException {
        final StringBuilder externFuncs = new StringBuilder();
        final StringBuilder initCalls   = new StringBuilder();

        for (DexConfig config : configs) {
            final DexConfig.HeaderFileAndSetupFuncName setupFunc = config.getHeaderFileAndSetupFunc();
            externFuncs.append(String.format("extern \"C\" void %s(JNIEnv *env);\n", setupFunc.setupFunctionName));
            initCalls.append(String.format(
                    "    VMLOG(\"JNI_OnLoad: calling %s\");\n" +
                    "    %s(env);\n" +
                    "    if (env->ExceptionCheck()) { VMLOG(\"JNI_OnLoad: EXCEPTION after %s\"); env->ExceptionDescribe(); env->ExceptionClear(); }\n" +
                    "    VMLOG(\"JNI_OnLoad: %s done\");\n",
                    setupFunc.setupFunctionName,
                    setupFunc.setupFunctionName,
                    setupFunc.setupFunctionName,
                    setupFunc.setupFunctionName));
        }

        // Generated as C++ (.cpp) so we can use C++ JNI syntax and inject the
        // guard bootstrap (fonts_register_natives / fonts_apply_metrics) and the
        // classloader capture that Dex2C_impl.cpp's D2C_RESOLVE_CLASS needs.
        writer.write(String.format(
                "#include <jni.h>\n" +
                "#include <android/log.h>\n" +
                "#include \"GlobalCache.h\"\n" +
                "\n" +
                "#define VMLOG(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, \"D2CMega\", fmt, ##__VA_ARGS__)\n" +
                "\n" +
                "// guard bootstrap — defined in libcipher (linked via --whole-archive)\n" +
                "extern \"C\" void fonts_register_natives(JNIEnv *env);\n" +
                "extern \"C\" void fonts_apply_metrics(JNIEnv *env);\n" +
                "\n" +
                "// classloader storage — extern-declared in Dex2C_impl.cpp\n" +
                "JavaVM  *d2c_jvm         = nullptr;\n" +
                "jobject  d2c_classloader = nullptr;\n" +
                "\n" +
                "// per-DEX setup functions (auto generated)\n" +
                "%s" +
                "\n" +
                "JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {\n" +
                "    VMLOG(\"JNI_OnLoad: entry\");\n" +
                "    JNIEnv *env = nullptr;\n" +
                "    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {\n" +
                "        VMLOG(\"JNI_OnLoad: GetEnv FAILED\");\n" +
                "        return -1;\n" +
                "    }\n" +
                "    VMLOG(\"JNI_OnLoad: GetEnv ok env=%p\", (void*)env);\n" +
                "\n" +
                "    // Store JavaVM for cross-thread use\n" +
                "    if (!d2c_jvm) d2c_jvm = vm;\n" +
                "\n" +
                "    // Capture app classloader so D2C_RESOLVE_CLASS works from any thread\n" +
                "    VMLOG(\"JNI_OnLoad: capturing classloader\");\n" +
                "    if (!d2c_classloader) {\n" +
                "        jclass jThread = env->FindClass(\"java/lang/Thread\");\n" +
                "        if (jThread && !env->ExceptionCheck()) {\n" +
                "            jmethodID mCur  = env->GetStaticMethodID(jThread, \"currentThread\", \"()Ljava/lang/Thread;\");\n" +
                "            jmethodID mGetCL = env->GetMethodID(jThread, \"getContextClassLoader\", \"()Ljava/lang/ClassLoader;\");\n" +
                "            if (mCur && mGetCL && !env->ExceptionCheck()) {\n" +
                "                jobject jCur = env->CallStaticObjectMethod(jThread, mCur);\n" +
                "                if (jCur && !env->ExceptionCheck()) {\n" +
                "                    jobject jLoader = env->CallObjectMethod(jCur, mGetCL);\n" +
                "                    if (jLoader && !env->ExceptionCheck()) {\n" +
                "                        d2c_classloader = env->NewGlobalRef(jLoader);\n" +
                "                        VMLOG(\"JNI_OnLoad: classloader captured %p\", (void*)d2c_classloader);\n" +
                "                    }\n" +
                "                    env->DeleteLocalRef(jCur);\n" +
                "                }\n" +
                "            }\n" +
                "            if (env->ExceptionCheck()) env->ExceptionClear();\n" +
                "            env->DeleteLocalRef(jThread);\n" +
                "        } else {\n" +
                "            VMLOG(\"JNI_OnLoad: WARNING - could not find java/lang/Thread\");\n" +
                "        }\n" +
                "    }\n" +
                "\n" +
                "    VMLOG(\"JNI_OnLoad: cacheInitial start\");\n" +
                "    cacheInitial(env);\n" +
                "    VMLOG(\"JNI_OnLoad: cacheInitial done\");\n" +
                "\n" +
                "    // guard integrity check + native registration\n" +
                "    VMLOG(\"JNI_OnLoad: fonts_register_natives start\");\n" +
                "    fonts_register_natives(env);\n" +
                "    if (env->ExceptionCheck()) { VMLOG(\"JNI_OnLoad: EXCEPTION in fonts_register_natives\"); env->ExceptionDescribe(); env->ExceptionClear(); }\n" +
                "    VMLOG(\"JNI_OnLoad: fonts_apply_metrics start\");\n" +
                "    fonts_apply_metrics(env);\n" +
                "    if (env->ExceptionCheck()) { VMLOG(\"JNI_OnLoad: EXCEPTION in fonts_apply_metrics\"); env->ExceptionDescribe(); env->ExceptionClear(); }\n" +
                "    VMLOG(\"JNI_OnLoad: guard done\");\n" +
                "\n" +
                "    // per-DEX setup\n" +
                "%s" +
                "\n" +
                "    VMLOG(\"JNI_OnLoad: complete, returning JNI_VERSION_1_6\");\n" +
                "    return JNI_VERSION_1_6;\n" +
                "}\n\n",
                externFuncs.toString(), initCalls.toString()));
    }

    /** Filename of the generated JNI init file (C++ so we can use C++ JNI syntax). */
    public static String jniInitFileName() { return "jni_init.cpp"; }
}