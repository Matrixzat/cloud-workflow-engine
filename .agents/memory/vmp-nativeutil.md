---
name: VMP NativeUtil injection
description: NativeUtil is a synthetic DEX class that must be injected into classes.dex; without it RegisterNatives silently fails and the protected app crashes
---

## Rule
`buildVmpCompiledKeys()` in `ApkProtector` must do two steps in order:
1. `Dex2c.injectCallRegisterNativeInsns(cfg, emptyPool, Collections.emptySet(), 60000)` — reads shell DEX, wraps each VMP-converted class with `RegisterNativesCallerClassDef` (prepends `NativeUtil.classesInit0(idx)` to `<clinit>`), writes result to `classes.dex`.
2. Inject `RegisterNativesUtilClassDef` (NativeUtil synthetic class) into `classes.dex` AFTER step 1.

## Why
NMMP's reference does this in `injectInstructionAndWriteToFile()` + `internNativeUtilClassDef()`. Skipping step 1 means no `classesInit0` call in any class → `RegisterNatives` never triggered → VM methods unresolved at runtime → crash. Skipping step 2 means `FindClass("NativeUtil")` returns null → `RegisterNatives` silently fails.

## How to apply
Both steps run inside `buildVmpCompiledKeys(vmpConfig, dexDir, libName)`. Called from `protect()` only when `useVmp && transpileResult.vmpConfig != null`.
