---
name: VMP JNI_OnLoad ownership
description: How jni_init.cpp owns JNI_OnLoad in VMP mode and how NdkBuilder detects it
---

## Rule
`GlobalDexConfig.generateJniInitCode()` generates `jni_init.cpp` (NOT `.c`) which owns `JNI_OnLoad` in VMP mode. `getInitCodeFile()` must return `.cpp` extension.

## Why
The file contains C++ JNI syntax (`vm->GetEnv(...)`, `nullptr`, `extern "C"`) + guard bootstrap (`fonts_register_natives`, `fonts_apply_metrics`) + classloader capture (`d2c_jvm`, `d2c_classloader` globals). Compiling as `.c` fails immediately with "expected identifier or '('" on `extern "C"`.

## How to apply
NdkBuilder detects `jni_init.cpp` in `generatedFiles` → sets `isVmpJniInit = true` → sets `-DD2C_HAS_JNILOAD` (suppresses `Dex2C_impl.cpp` and `fonts_jni_stub.cpp` from emitting their own `JNI_OnLoad`) → skips `patchJniOnload()` (already baked in by GlobalDexConfig).
