---
name: VMP opcode dispatch bug (root cause + fix)
description: Root cause of the SIGSEGV in vmInterpret and the fix applied — DexOpcodes.h was never regenerated per-run to match the randomized bytecode opcode map.
---

## Root cause

`RandomInstructionRewriter` shuffles opcode values differently each protection run.
The protected bytecode is written with these shuffled values.
BUT `generateConfig()` was never called after the bytecode was generated, so no
per-run `DexOpcodes.h` was produced.

The static `assets/vmp_headers/DexOpcodes.h` (standard Dalvik opcode ordering:
OP_NOP=0, OP_MOVE=1, …) was compiled into the .so. The interpreter's computed-goto
table (`DEFINE_GOTO_TABLE`) therefore mapped opcode byte values using the wrong
(identity) ordering. The protected bytecode used the shuffled ordering, so every
instruction dispatched to the wrong handler in `vmInterpret` → SIGSEGV.

Crash signature: SEGV_MAPERR inside `vmInterpret` at a fixed PC offset, x1 = valid
code* on stack, fault addr ≈ 33 KB above SP. Deterministic across runs because the
same shuffled opcode map was written at protect-time.

## Fix (commit 5098660)

Mirrors NMMP's `CmakeUtils.writeOpcodeHeaderFile()` which was the missing port step.

**Why `\\\\\n` in generateConfig goto output**: `generateConfig` writes lines ending
with `\\` + newline (two backslashes). When these are used as `String.replaceAll()`
replacement strings, Java's replacement escaping converts `\\` → literal `\`. So
the C macro output gets `\` + newline — correct macro line-continuation.

### DexTranspiler.transpileVmp()
After `Dex2c.handleAllDex()`, call `generateDexOpcodesHeader(rewriter, vmpOutDir/DexOpcodes.h)`:
- Read static `assets/vmp_headers/DexOpcodes.h` template from assets
- Call `rewriter.generateConfig(enumW, gotoW)`
- Use regex `replaceAll` to patch the `enum Opcode { … };` block
- Use regex `replaceAll` to patch the `_name[kNumPackedOpcodes] = { … };` block
- Write result to `vmpOutDir/DexOpcodes.h`
- The existing `.h` copy loop copies it to `outputDir` (= `cSourceDir`)

### NdkBuilder.compileWithClang()
When `isVmpJniInit=true` (VMP mode detected), before compilation:
- Check if `sourceDir/DexOpcodes.h` exists (the per-run one)
- `Files.copy` it to `headersDir/DexOpcodes.h` (REPLACE_EXISTING), overriding
  the static one extracted at `setup()` time
- The `-I headersDir` compile flag then makes the compiler see the correct mapping

**Why:** headersDir is populated from `assets/vmp_headers/` in `setup()`, before the
per-run header exists. The sourceDir copy happens at protection time, so we must
override headersDir at the start of compile().
