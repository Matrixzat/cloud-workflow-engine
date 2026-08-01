package com.ultra.dex2cvmp.engine.vmp;

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.util.MethodUtil;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import com.android.tools.smali.dexlib2.writer.pool.DexPool;
import com.v7878.dex.DexIO;
import com.v7878.dex.DexVersion;
import com.v7878.dex.WriteOptions;
import com.v7878.dex.immutable.Dex;
import java.nio.file.Files;
import com.google.common.collect.HashMultimap;
import com.ultra.dex2cvmp.engine.vmp.converter.ClassAnalyzer;
import com.ultra.dex2cvmp.engine.vmp.converter.JniCodeGenerator;
import com.ultra.dex2cvmp.engine.vmp.converter.instructionrewriter.InstructionRewriter;
import com.ultra.dex2cvmp.engine.vmp.converter.structs.MethodConverter;
import com.ultra.dex2cvmp.engine.vmp.converter.structs.MyClassDef;
import com.ultra.dex2cvmp.engine.vmp.converter.structs.RegisterNativesCallerClassDef;
import com.ultra.dex2cvmp.engine.vmp.filters.ClassAndMethodFilter;
import com.ultra.dex2cvmp.engine.vmp.util.Pair;

import javax.annotation.Nonnull;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class Dex2c {

    public static final String LANDROID_APP_APPLICATION = "Landroid/app/Application;";

    // Same pattern as Tier1DexPatcher — lock every written DEX to version 035.
    // dexlib2's DexPool can silently mis-encode wide types, try-catch tables,
    // and annotations; passing the output through vova7878/DexIO corrects it.
    private static final WriteOptions WRITE_OPTIONS_035 =
            WriteOptions.defaultOptions().withDexVersion(DexVersion.DEX035);

    /**
     * Write a dexlib2 DexPool to {@code file} and then re-encode it through
     * vova7878/DexFile with WriteOptions locked to DEX 035.  This fixes
     * wide-type register miscounts, try-catch mis-encodings, annotation bugs,
     * and string-pool issues that dexlib2's own writer occasionally produces.
     */
    public static void writeDexPool035(DexPool pool, File file) throws IOException {
        pool.writeTo(new FileDataStore(file));
        byte[] raw = Files.readAllBytes(file.toPath());
        Dex fixed = DexIO.read(raw);
        Files.write(file.toPath(), DexIO.write(WRITE_OPTIONS_035, fixed));
    }

    private Dex2c() {
    }

    /**
     * Holds the method lists computed for one class during the parallel phase
     * of splitDex().  The serial phase then calls internClass() in original
     * DEX order — which is required for deterministic pool ordering.
     */
    private static final class ClassBuildResult {
        final ClassDef classDef;
        final boolean accepted;
        // non-null only when accepted == true
        final List<Method> shellDirect;
        final List<Method> shellVirtual;
        final List<Method> implDirect;
        final List<Method> implVirtual;
        // one entry per converted method (pair.first); added to shellMethods multimap
        final List<List<? extends Method>> shellMethodEntries;

        /** Rejected — pass the class through to shellDexPool unchanged. */
        ClassBuildResult(ClassDef cd) {
            classDef = cd; accepted = false;
            shellDirect = shellVirtual = implDirect = implVirtual = null;
            shellMethodEntries = null;
        }

        /** Accepted — carries the fully-computed method lists. */
        ClassBuildResult(ClassDef cd,
                         List<Method> sd, List<Method> sv,
                         List<Method> id, List<Method> iv,
                         List<List<? extends Method>> sme) {
            classDef = cd; accepted = true;
            shellDirect = sd; shellVirtual = sv;
            implDirect = id; implVirtual = iv;
            shellMethodEntries = sme;
        }
    }

    /**
     * 处理多个dex文件
     *
     * @param dexFiles dex文件列表
     * @param outDir   生成c文件等输出目录
     * @return 输出结果配置
     * @throws IOException
     */
    public static GlobalDexConfig handleAllDex(@Nonnull List<File> dexFiles,
                                               @Nonnull ClassAndMethodFilter filter,
                                               @Nonnull InstructionRewriter instructionRewriter,
                                               @Nonnull ClassAnalyzer classAnalyzer,
                                               @Nonnull File outDir) throws IOException {
        if (!outDir.exists()) outDir.mkdirs();
        final GlobalDexConfig globalConfig = new GlobalDexConfig(outDir);

        // ── Parallel DEX processing ───────────────────────────────────────────
        // Each DEX file writes to its own output files (shell/impl DEX, C files).
        // ClassAnalyzer is read-only after construction → safe for concurrent reads.
        int threads = Math.max(1, Math.min(dexFiles.size(),
                Runtime.getRuntime().availableProcessors()));
        ExecutorService exec = Executors.newFixedThreadPool(threads);
        List<Future<DexConfig>> futures = new ArrayList<>(dexFiles.size());

        for (File file : dexFiles) {
            futures.add(exec.submit(() -> {
                DexConfig cfg = handleDex(file, filter, classAnalyzer,
                        instructionRewriter, outDir);
                cfg.setShellMethods(null);
                return cfg;
            }));
        }
        exec.shutdown();

        // Collect in original order (preserves classes.dex / classes2.dex ordering)
        for (Future<DexConfig> future : futures) {
            try {
                globalConfig.addDexConfig(future.get());
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof IOException) throw (IOException) cause;
                throw new IOException("DEX processing failed", cause);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("DEX processing interrupted", e);
            }
        }
        globalConfig.generateJniInitCode();
        return globalConfig;
    }

    /**
     * 处理单个dex文件
     */
    public static DexConfig handleDex(@Nonnull File dexFile,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull InstructionRewriter instructionRewriter,
                                      @Nonnull File outDir) throws IOException {
        return handleDex(new BufferedInputStream(new FileInputStream(dexFile)),
                dexFile.getName(),
                filter,
                classAnalyzer,
                instructionRewriter,
                outDir);
    }

    public static DexConfig handleModuleDex(@Nonnull File dexFile,
                                            @Nonnull ClassAndMethodFilter filter,
                                            @Nonnull ClassAnalyzer classAnalyzer,
                                            @Nonnull InstructionRewriter instructionRewriter,
                                            @Nonnull File outDir) throws IOException {
        final GlobalDexConfig globalDexConfig = new GlobalDexConfig(outDir);
        final DexConfig dexConfig = handleDex(dexFile, filter, classAnalyzer, instructionRewriter, outDir);
        globalDexConfig.addDexConfig(dexConfig);

        globalDexConfig.generateJniInitCode();
        return dexConfig;
    }

    /**
     * 处理单个dex流
     */
    public static DexConfig handleDex(@Nonnull InputStream dex,
                                      @Nonnull String dexFileName,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull InstructionRewriter instructionRewriter,
                                      @Nonnull File outDir) throws IOException {
        if (!outDir.exists()) outDir.mkdirs();
        DexConfig config = splitDex(dex, dexFileName, filter, classAnalyzer, outDir);


        final DexBackedDexFile nativeImplDexFile = DexBackedDexFile.fromInputStream(null,
                new BufferedInputStream(new FileInputStream(config.getImplDexFile())));

        //根据符号dex生成c代码
        try (FileWriter nativeCodeWriter = new FileWriter(config.getNativeFunctionsFile());
             FileWriter resolverWriter = new FileWriter(config.getResolverFile());
        ) {
            JniCodeGenerator codeGenerator = new JniCodeGenerator(nativeImplDexFile,
                    classAnalyzer,
                    instructionRewriter);

            codeGenerator.generate(
                    config,
                    resolverWriter,
                    nativeCodeWriter
            );
            config.setResult(codeGenerator);
        }

        return config;
    }

    //分割dex产生两个dex,一个为壳dex,一个为实现dex,壳dex将会打包进apk,实现dex会被转换为c代码
    @Nonnull
    private static DexConfig splitDex(@Nonnull InputStream dex,
                                      @Nonnull String dexFileName,
                                      @Nonnull ClassAndMethodFilter filter,
                                      @Nonnull ClassAnalyzer classAnalyzer,
                                      @Nonnull File outDir) throws IOException {
        DexBackedDexFile originDexFile = DexBackedDexFile.fromInputStream(
                null,
                dex);

        //把方法变为本地方法,用它替换掉原本的dex
        DexPool shellDexPool = new DexPool(originDexFile.getOpcodes());
        DexPool nativeImplDexPool = new DexPool(originDexFile.getOpcodes());

        final MethodConverter methodConverter = new MethodConverter(classAnalyzer);
        HashMultimap<String, List<? extends Method>> shellMethods = HashMultimap.create();

        // ── Parallel class processing ─────────────────────────────────────────
        // Phase 1 (parallel): method conversion is pure computation — it reads
        //   read-only dexlib2 objects and ClassAnalyzer (read-only after init).
        // Phase 2 (serial):   DexPool.internClass() is not thread-safe; intern
        //   in the same order as the original DEX to guarantee deterministic output.
        List<ClassDef> classes = new ArrayList<>(originDexFile.getClasses());
        int threads = Math.max(1, Math.min(classes.size(),
                Runtime.getRuntime().availableProcessors()));
        ExecutorService exec = Executors.newFixedThreadPool(threads);
        List<Future<ClassBuildResult>> futures = new ArrayList<>(classes.size());

        for (final ClassDef classDef : classes) {
            futures.add(exec.submit(() -> {
                if (!filter.acceptClass(classDef)) {
                    return new ClassBuildResult(classDef);
                }
                ArrayList<Method> shellDirect = new ArrayList<>();
                ArrayList<Method> shellVirtual = new ArrayList<>();
                ArrayList<Method> implDirect  = new ArrayList<>();
                ArrayList<Method> implVirtual = new ArrayList<>();
                ArrayList<List<? extends Method>> shellEntries = new ArrayList<>();

                for (Method method : classDef.getMethods()) {
                    if (filter.acceptMethod(method)) {
                        final Pair<List<? extends Method>, Method> pair =
                                methodConverter.convert(method);
                        addMethods(shellDirect, shellVirtual, pair.first);
                        shellEntries.add(pair.first);
                        addMethod(implDirect, implVirtual, pair.second);
                    } else {
                        addMethod(shellDirect, shellVirtual, method);
                    }
                }
                return new ClassBuildResult(classDef,
                        shellDirect, shellVirtual, implDirect, implVirtual, shellEntries);
            }));
        }
        exec.shutdown();

        // Phase 2 — serial intern (preserves original DEX class ordering)
        for (Future<ClassBuildResult> future : futures) {
            final ClassBuildResult r;
            try {
                r = future.get();
            } catch (ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof IOException) throw (IOException) cause;
                throw new IOException("Class conversion failed", cause);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Class conversion interrupted", e);
            }
            if (r.accepted) {
                shellDexPool.internClass(
                        new MyClassDef(r.classDef, r.shellDirect, r.shellVirtual));
                nativeImplDexPool.internClass(
                        new MyClassDef(r.classDef, r.implDirect, r.implVirtual));
                for (List<? extends Method> entry : r.shellMethodEntries) {
                    shellMethods.put(r.classDef.getType(), entry);
                }
            } else {
                shellDexPool.internClass(r.classDef);
            }
        }
        DexConfig config = new DexConfig(outDir, dexFileName);

        config.setShellMethods(shellMethods);

        //写入需要运行的dex (re-encoded to DEX 035 via vova7878)
        writeDexPool035(shellDexPool, config.getShellDexFile());
        //写入符号dex (re-encoded to DEX 035 via vova7878)
        writeDexPool035(nativeImplDexPool, config.getImplDexFile());
        return config;
    }

    private static void addMethods(List<Method> directMethods,
                                   List<Method> virtualMethods,
                                   List<? extends Method> methods) {
        for (Method method : methods) {
            addMethod(directMethods, virtualMethods, method);
        }
    }

    private static void addMethod(List<Method> directMethods,
                                  List<Method> virtualMethods,
                                  Method method) {
        if (MethodUtil.isDirect(method)) {
            directMethods.add(method);
        } else {
            virtualMethods.add(method);
        }
    }

    //在处理过的class的static{}块最前面添加注册本地方法代码,如果不存在static{}块则新增<clinit>方法
    public static List<DexPool> injectCallRegisterNativeInsns(DexConfig config,
                                                              DexPool lastDexPool,
                                                              Set<String> mainClassSet,
                                                              int maxPoolSize) throws IOException {

        DexBackedDexFile dexNativeFile = DexBackedDexFile.fromInputStream(
                null,
                new BufferedInputStream(new FileInputStream(config.getShellDexFile())));

        List<DexPool> dexPools = new ArrayList<>();
        dexPools.add(lastDexPool);


        for (ClassDef classDef : dexNativeFile.getClasses()) {
            if (mainClassSet.contains(classDef.getType())) {//提前处理过的class,不用再处理
                continue;
            }
            internClass(config, lastDexPool, classDef);

            if (lastDexPool.hasOverflowed(maxPoolSize)) {
                lastDexPool = new DexPool(dexNativeFile.getOpcodes());
                dexPools.add(lastDexPool); // written via writeDexPool035 by the caller
            }
        }
        return dexPools;
    }

    private static void internClass(DexConfig config, DexPool dexPool, ClassDef classDef) {
        final Set<String> classes = config.getHandledNativeClasses();
        final String type = classDef.getType();
        final String className = type.substring(1, type.length() - 1);
        if (classes.contains(className)) {
            final RegisterNativesCallerClassDef nativeClassDef = new RegisterNativesCallerClassDef(
                    classDef,
                    config.getOffsetFromClassName(className),
                    "L" + config.getRegisterNativesClassName() + ";",
                    config.getRegisterNativesMethodName());
            dexPool.internClass(nativeClassDef);
        } else {
            dexPool.internClass(classDef);
        }
    }

}