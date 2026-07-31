---
name: VMP VM runtime source files
description: The 7 VM implementation files must be bundled as assets and compiled by NdkBuilder; without them vmInterpret() is unresolved at link time
---

## Rule
NMMP ships `libnmmvm.so` (VM runtime) separately. We compile everything into one `.so`. The 7 VM source files must be in `assets/vmp_src/` and compiled by NdkBuilder when VMP mode is active.

Files: `ConstantPool.c`, `DexCatch.cpp`, `Exception.cpp`, `GlobalCache.cpp`, `Interp.cpp`, `InterpC-portable.cpp`, `JNIWrapper.c`.

## Why
The generated `classes_native_functions.c` calls `vmInterpret()`, `cacheInitial()` etc. declared in `vm.h` (headers are in `assets/vmp_headers/`). Without the implementation compiled in, linker gets unresolved symbol errors for every VM function.

## How to apply
`NdkBuilder.setup()` extracts `assets/vmp_src/` → `vmSrcDir`. In `compileWithClang()`, when `isVmpJniInit == true`, all `.c/.cpp` from `vmSrcDir` are added to `allSrc` before `generatedFiles`. In dex2c mode `vmSrcDir` files are not added (no-op).
