// guard.cpp — Native integrity layer for Dex2c-protected APKs, disguised
// under generic "font metrics" naming (class/method/asset names, exported
// symbols) so static analysis of the shipped .so and APK does not surface
// an obvious "guard"/anti-tamper signature.
//
// Compiled into every protected .so alongside Dex2C_impl.cpp.
// Entry points:
//   fonts_init()        — __attribute__((constructor)), fires when .so loads
//                         BEFORE JNI_OnLoad, BEFORE any Java code.
//                         Pure native — no JNIEnv required:
//                           • Anti-debug (TracerPid from /proc/self/status)
//                           • VCore/VirtualApp APK-path detection
//                           • AndroidManifest.xml FNV-1a64 hash check
//                           • classes*.dex count check
//                           • /proc/self/maps scan (Frida/Xposed/Substrate/Magisk/saurik/
//                                                   LSPlant/Zygisk/Riru/LSPatch)
//                           • libart.so / libandroid_runtime.so path integrity
//                           • Frida listener port 27042 probe
//                           • Fork-based isolated background guard process (5 s poll)
//                           • Persistent watchdog thread (3 s poll)
//                         All native checks encoded as VM bytecode so IDA/Ghidra
//                         sees an opaque interpreter loop, not recognisable call sites.
//   fonts_apply_metrics() — called from JNI_OnLoad (direct or injected).
//                         Has JNIEnv. Runs killer detection via detached retry
//                         thread, waiting until an Activity is on-stack so
//                         PairIP and other Application subclasses finish first.
//                         Does:
//                           • Behavioral ContentProvider ↔ lifecycle callback cross-ref
//                           • Known killer-class detection via Class.forName
//                           • Renaming-resistant fragment scan of declared providers

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <zlib.h>
#include <android/log.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dlfcn.h>
#include <dirent.h>
#include <math.h>
#include <sys/syscall.h>
#include <sys/mman.h>             // mprotect — needed by poison_art_dex_regions()
#include <sys/system_properties.h> // __system_property_get / PROP_VALUE_MAX — root guard Layer F
#include <sys/ptrace.h>             // ptrace(PTRACE_TRACEME) self-lock — prevents debugger attach
#include "guard_mba.h"   // MBA constant helpers — hides raw literals from binary

#define G_TAG "D2CG"
// FONTS_DEBUG_LOG is OFF by default (production/shipping builds) — in that
// mode every GLOGI/GLOGE/CRASH_HERE call compiles away to nothing, so no log
// tag, format string, or reason text ends up in the shipped .so at all.
// Define FONTS_DEBUG_LOG (build flag) to get full step-by-step tracing on
// `adb logcat -s D2CG` for diagnosing false positives — remove it again
// before shipping a real protected build.
#ifdef FONTS_DEBUG_LOG
#define GLOGI(...) __android_log_print(ANDROID_LOG_INFO,  G_TAG, __VA_ARGS__)
#define GLOGE(...) __android_log_print(ANDROID_LOG_ERROR, G_TAG, __VA_ARGS__)
// Production CRASH_HERE: reason string is a macro argument — kept alive only
// when FONTS_DEBUG_LOG is defined. In release builds the token vanishes from
// the preprocessor output so no string literal reaches .rodata.
#define CRASH_HERE(reason) do { GLOGE("CRASH: %s (%s:%d)", (reason), __FILE__, __LINE__); crash_now(); } while (0)
#else
#define GLOGI(...) ((void)0)
#define GLOGE(...) ((void)0)
// Production build: CRASH_HERE becomes a bare crash_now(). The reason string
// literal is not even a token in the expanded code, so it cannot appear in
// .rodata regardless of optimisation level. No plaintext crash description
// survives into the shipped .so.
#define CRASH_HERE(reason) crash_now()
#endif

// ════════════════════════════════════════════════════════════════════════════
// AES tables — shared by the AES-256-CBC decryption below
// ════════════════════════════════════════════════════════════════════════════

static const uint8_t G_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static const uint8_t G_RSBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};
static const uint8_t G_RCON[11] = {0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static uint8_t gf_xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x >> 7) ? 0x1b : 0)); }
static uint8_t gf_mul(uint8_t x, uint8_t y) {
    return (uint8_t)(
        ((y & 1) ? x : 0) ^
        ((y & 2) ? gf_xtime(x) : 0) ^
        ((y & 4) ? gf_xtime(gf_xtime(x)) : 0) ^
        ((y & 8) ? gf_xtime(gf_xtime(gf_xtime(x))) : 0) ^
        ((y & 16)? gf_xtime(gf_xtime(gf_xtime(gf_xtime(x)))) : 0));
}

// ════════════════════════════════════════════════════════════════════════════
// AES-256-CBC Decryption — 14 rounds, 32-byte key, 240 bytes of round keys
// ════════════════════════════════════════════════════════════════════════════

typedef struct { uint8_t rk[240]; } AES256;

static void aes256_expand(AES256 *a, const uint8_t *key) {
    memcpy(a->rk, key, 32);
    uint8_t *w = a->rk;
    for (int i = 8; i < 60; i++) {
        uint8_t t[4];
        memcpy(t, w + (i-1)*4, 4);
        if (i % 8 == 0) {
            uint8_t tmp = G_SBOX[t[1]] ^ G_RCON[i/8];
            t[1] = G_SBOX[t[2]]; t[2] = G_SBOX[t[3]]; t[3] = G_SBOX[t[0]];
            t[0] = tmp;
        } else if (i % 8 == 4) {
            t[0]=G_SBOX[t[0]]; t[1]=G_SBOX[t[1]];
            t[2]=G_SBOX[t[2]]; t[3]=G_SBOX[t[3]];
        }
        uint8_t *dst = w + i*4, *src = w + (i-8)*4;
        dst[0]=src[0]^t[0]; dst[1]=src[1]^t[1];
        dst[2]=src[2]^t[2]; dst[3]=src[3]^t[3];
    }
}

static void aes256_dec_block(const AES256 *a, const uint8_t *in, uint8_t *out) {
    uint8_t s[16];
    const uint8_t *rk = a->rk + 224;   // 14 * 16
    for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];
    for (int r = 13; r >= 0; r--) {
        rk -= 16;
        uint8_t t;
        t=s[13];s[13]=s[9];s[9]=s[5];s[5]=s[1];s[1]=t;
        t=s[10];s[10]=s[2];s[2]=t; t=s[14];s[14]=s[6];s[6]=t;
        t=s[3];s[3]=s[7];s[7]=s[11];s[11]=s[15];s[15]=t;
        for (int i = 0; i < 16; i++) s[i] = G_RSBOX[s[i]] ^ rk[i];
        if (r > 0) {
            for (int c = 0; c < 4; c++) {
                uint8_t *col = s + c*4;
                uint8_t a0=col[0],a1=col[1],a2=col[2],a3=col[3];
                col[0]=gf_mul(a0,0x0e)^gf_mul(a1,0x0b)^gf_mul(a2,0x0d)^gf_mul(a3,0x09);
                col[1]=gf_mul(a0,0x09)^gf_mul(a1,0x0e)^gf_mul(a2,0x0b)^gf_mul(a3,0x0d);
                col[2]=gf_mul(a0,0x0d)^gf_mul(a1,0x09)^gf_mul(a2,0x0e)^gf_mul(a3,0x0b);
                col[3]=gf_mul(a0,0x0b)^gf_mul(a1,0x0d)^gf_mul(a2,0x09)^gf_mul(a3,0x0e);
            }
        }
    }
    memcpy(out, s, 16);
}

static int aes256_cbc_dec(const uint8_t *key, const uint8_t *iv,
                           const uint8_t *in, int in_len, uint8_t *out) {
    if (in_len <= 0 || in_len % 16 != 0) return -1;
    AES256 ctx; aes256_expand(&ctx, key);
    uint8_t prev[16]; memcpy(prev, iv, 16);
    for (int i = 0; i < in_len; i += 16) {
        aes256_dec_block(&ctx, in + i, out + i);
        for (int j = 0; j < 16; j++) out[i+j] ^= prev[j];
        memcpy(prev, in + i, 16);
    }
    int pad = out[in_len - 1];
    if (pad < 1 || pad > 16) return -1;
    return in_len - pad;
}

// ════════════════════════════════════════════════════════════════════════════
// AES Key + IV — split across volatile arrays (prevents static-analysis key
// extraction: attacker needs a live memory dump, not just strings/hexdump)
// KEY[i] = KEY_HI[i] ^ KEY_LO[i]
// ════════════════════════════════════════════════════════════════════════════

static volatile const uint8_t KEY_HI[16]={0xA1,0x2B,0x1C,0xF4,0x83,0x65,0xC0,0x31,0x57,0xD4,0xE9,0x28,0x15,0x8A,0x44,0x60};
static volatile const uint8_t KEY_LO[16]={0x72,0x61,0x67,0x65,0x46,0x4B,0x4F,0x51,0x43,0x6C,0x4A,0x74,0x6C,0x6C,0x69,0x6F};
// KEY_HI XOR KEY_LO = {D3,4A,7B,91,C5,2E,8F,60,14,B8,A3,5C,79,E6,2D,0F}

static volatile const uint8_t IV_HI[16]={0x27,0xE5,0x58,0x1D,0xD0,0x83,0xF7,0x64,0xA3,0x35,0xC1,0x78,0x82,0x13,0x6A,0x2E};
static volatile const uint8_t IV_LO[16]={0x69,0x69,0x69,0x67,0x65,0x71,0x61,0x69,0x6B,0x66,0x66,0x63,0x66,0x73,0x43,0x5B};
// IV_HI  XOR IV_LO  = {4E,8C,31,7A,B5,F2,96,0D,C8,53,A7,1B,E4,60,29,75}

static __attribute__((noinline)) void build_iv(uint8_t *iv) {
    // MBA: a^b = (a|b)-(a&b) — identical result, unrecognisable to decompilers
    for(int i=0;i<16;i++){
        uint32_t a=(uint32_t)IV_HI[i], b=(uint32_t)IV_LO[i];
        iv[i]=(uint8_t)((a|b)-(a&b));
    }
}

// ── AES-256 key extension (bytes 16-31): K2_HI[i] ^ K2_LO[i]
// K2_HI ^ K2_LO = {F7,23,A9,5E,8C,41,D6,BB,3E,9F,6C,17,A4,8B,E5,2C}
static volatile const uint8_t K2_HI[16]={
    0xA2,0x76,0xFC,0x0B,0xD9,0x14,0x83,0xEE,
    0x6B,0xCA,0x39,0x42,0xF1,0xDE,0xB0,0x79};
static volatile const uint8_t K2_LO[16]={
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55,
    0x55,0x55,0x55,0x55,0x55,0x55,0x55,0x55};

static __attribute__((noinline)) void build_key256(uint8_t *key) {
    // MBA: a^b = (a|b)-(a&b)
    for(int i=0;i<16;i++){
        uint32_t a=(uint32_t)KEY_HI[i], b=(uint32_t)KEY_LO[i];
        key[i]    =(uint8_t)((a|b)-(a&b));
    }
    for(int i=0;i<16;i++){
        uint32_t a=(uint32_t)K2_HI[i],  b=(uint32_t)K2_LO[i];
        key[16+i] =(uint8_t)((a|b)-(a&b));
    }
}

// ════════════════════════════════════════════════════════════════════════════
// Crash — immediate SIGKILL, no JNI needed
// ════════════════════════════════════════════════════════════════════════════

// crash_now() — hard, synchronous, zero-hang kill.
//
// Why not kill(getpid(), SIGKILL):
//   kill() sends the signal to the process but delivery is asynchronous —
//   the kernel queues it and delivers it when the thread is next scheduled.
//   On a loaded device this causes a visible 1–4 s "hang" before death.
//
// Fix: tgkill(getpid(), gettid(), SIGKILL) via raw svc #0 (same Layer-4
// pattern used for all I/O).  tgkill targets THIS specific thread; the
// kernel delivers SIGKILL inline, before svc #0 even returns → zero hang.
//
// Fallback chain (compiler cannot remove any of these):
//   1. tgkill svc — instant SIGKILL to current thread
//   2. null dereference → SIGSEGV + tombstone (visible hard crash)
//   3. __builtin_trap() → SIGILL
//   4. _exit(1)
// crash_now() — hard, synchronous, zero-hang kill via SVC #0.
//
// All syscall numbers and SIGKILL (9) are computed at runtime through
// _mba_*() helpers (guard_mba.h) so no MOVZ/MOV #9 or #131 or #268
// literal ever appears in the compiled binary.  An attacker running
// `strings` or a hex search for the SIGKILL pattern finds nothing.
static __attribute__((noinline,optnone)) void crash_now(void) {
#if defined(__aarch64__)
    // ARM64: syscall __NR_tgkill = 131, SIGKILL = 9
    // Values are loaded from volatile variables — no literal in .text
    {
        volatile long _nr  = _mba_nr_tgkill64();  // 131, no MOVZ #131
        volatile long _sig = _mba_sigkill();       // 9,   no MOVZ #9
        register long _x8 asm("x8") = _nr;
        register long _x0 asm("x0") = (long)getpid();
        register long _x1 asm("x1") = (long)gettid();
        register long _x2 asm("x2") = _sig;
        asm volatile("svc #0"
            : "+r"(_x0)
            : "r"(_x1), "r"(_x2), "r"(_x8)
            : "memory", "cc");
    }
#elif defined(__arm__)
    // ARM32: syscall __NR_tgkill = 268, SIGKILL = 9
    {
        volatile int _nr  = _mba_nr_tgkill32();   // 268, no MOVZ #268
        volatile int _sig = _mba_sigkill32();      // 9,   no MOVZ #9
        register int _r7 asm("r7") = _nr;
        register int _r0 asm("r0") = (int)getpid();
        register int _r1 asm("r1") = (int)gettid();
        register int _r2 asm("r2") = _sig;
        asm volatile("svc #0"
            : "+r"(_r0)
            : "r"(_r1), "r"(_r2), "r"(_r7)
            : "memory", "cc");
    }
#else
    // Non-ARM fallback — uses kill@PLT but this path never ships in production
    {
        volatile int _sig = _mba_sigkill32();
        kill(getpid(), _sig);
    }
#endif
    // Fallback: _exit — silent, no dialog, no tombstone
    _exit(1);
}

// AES-256-CBC + XOR protected string literals (asset paths, log messages,
// VCore markers) — see guard_pstrings.inc. Needs build_key256/build_iv/
// aes256_cbc_dec, all defined above, so it's included here.
// ════════════════════════════════════════════════════════════════════════════
// SHA-256 — FIPS 180-4, no external dependencies.
// Used exclusively for signature certificate fingerprinting (Layer 4).
// ════════════════════════════════════════════════════════════════════════════
typedef struct { uint32_t h[8]; uint8_t buf[64]; uint64_t len; uint32_t blen; } SHA256Ctx;

static const uint32_t G_SHA256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define S256_ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define S256_CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define S256_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define S256_EP0(x) (S256_ROTR(x,2) ^S256_ROTR(x,13)^S256_ROTR(x,22))
#define S256_EP1(x) (S256_ROTR(x,6) ^S256_ROTR(x,11)^S256_ROTR(x,25))
#define S256_SIG0(x)(S256_ROTR(x,7) ^S256_ROTR(x,18)^((x)>>3))
#define S256_SIG1(x)(S256_ROTR(x,17)^S256_ROTR(x,19)^((x)>>10))

static void sha256_init(SHA256Ctx *c) {
    c->h[0]=0x6a09e667;c->h[1]=0xbb67ae85;c->h[2]=0x3c6ef372;c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f;c->h[5]=0x9b05688c;c->h[6]=0x1f83d9ab;c->h[7]=0x5be0cd19;
    c->len=0; c->blen=0;
}

static void sha256_compress(SHA256Ctx *c) {
    uint32_t w[64];
    for (int i=0;i<16;i++){
        const uint8_t *p=c->buf+i*4;
        w[i]=((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
    }
    for(int i=16;i<64;i++) w[i]=S256_SIG1(w[i-2])+w[i-7]+S256_SIG0(w[i-15])+w[i-16];
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3];
    uint32_t e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for(int i=0;i<64;i++){
        uint32_t t1=h+S256_EP1(e)+S256_CH(e,f,g)+G_SHA256_K[i]+w[i];
        uint32_t t2=S256_EP0(a)+S256_MAJ(a,b,cc);
        h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;
    }
    c->h[0]+=a;c->h[1]+=b;c->h[2]+=cc;c->h[3]+=d;
    c->h[4]+=e;c->h[5]+=f;c->h[6]+=g; c->h[7]+=h;
}

static void sha256_update(SHA256Ctx *c, const uint8_t *data, size_t len) {
    for(size_t i=0;i<len;i++){
        c->buf[c->blen++]=data[i];
        if(c->blen==64){sha256_compress(c);c->blen=0;}
    }
    c->len+=(uint64_t)len;
}

static void sha256_final(SHA256Ctx *c, uint8_t out[32]) {
    uint32_t i=c->blen;
    c->buf[i++]=0x80;
    if(i>56){while(i<64)c->buf[i++]=0;sha256_compress(c);i=0;}
    while(i<56)c->buf[i++]=0;
    uint64_t bl=c->len*8;
    c->buf[56]=(uint8_t)(bl>>56);c->buf[57]=(uint8_t)(bl>>48);
    c->buf[58]=(uint8_t)(bl>>40);c->buf[59]=(uint8_t)(bl>>32);
    c->buf[60]=(uint8_t)(bl>>24);c->buf[61]=(uint8_t)(bl>>16);
    c->buf[62]=(uint8_t)(bl>> 8);c->buf[63]=(uint8_t)(bl);
    sha256_compress(c);
    for(int j=0;j<8;j++){
        out[j*4  ]=(uint8_t)(c->h[j]>>24);out[j*4+1]=(uint8_t)(c->h[j]>>16);
        out[j*4+2]=(uint8_t)(c->h[j]>> 8);out[j*4+3]=(uint8_t)(c->h[j]);
    }
}

static __attribute__((noinline)) void sha256_buf(const uint8_t *data, size_t len, uint8_t out[32]) {
    SHA256Ctx ctx; sha256_init(&ctx); sha256_update(&ctx,data,len); sha256_final(&ctx,out);
}

#include "guard_pstrings.inc"
// ── NS_JNI — inline reveal_ns for drop-in JNI string substitution ────────────
// Template keyed on __COUNTER__ so every call site gets its own static buffer.
// Each instantiation of ns_jni_slot<N> has independent storage — safe for
// multiple NS_JNI calls on the same line or in the same function.
template<int N>
static __attribute__((noinline)) const char *ns_jni_slot(
        uint32_t idx, const uint8_t *ct, int len) {
    static char buf[SP_BUF_SZ * 4];
    static bool ok = false;
    if (!ok) { reveal_ns(idx, ct, len, buf); ok = true; }
    return buf;
}
#define NS_JNI(idx, blob) ns_jni_slot<__COUNTER__>((idx), (blob), (blob##_LEN))
// ─────────────────────────────────────────────────────────────────────────────


// ════════════════════════════════════════════════════════════════════════════
// XOR decode helper — used by hook/tamper string checks below
// Key 0xA3 is computed at runtime via _mba_xor_key_a3() (guard_mba.h)
// so no MOVZ #0xA3 / literal 0xA3 appears anywhere in .text or .rodata.
// ════════════════════════════════════════════════════════════════════════════

// G_XOR_KEY is NOT a compile-time macro constant anymore — it is a runtime
// call that returns 0xA3 through MBA arithmetic.  Each call site sees only a
// BL to _mba_xor_key_a3; the constant never materialises as an immediate.
// The one-time load inside g_decode() keeps loop overhead the same as before.
static __attribute__((noinline)) void g_decode(const uint8_t *enc, int len, char *out) {
    const uint8_t _key = _mba_xor_key_a3();    // 0xA3, no literal in binary
    for (int i = 0; i < len; i++) out[i] = (char)(enc[i] ^ _key);
    out[len] = '\0';
}

#define G_DEC(var, enc) \
    char var[sizeof(enc)+1]; \
    g_decode((const uint8_t*)enc, (int)sizeof(enc), var)

// ════════════════════════════════════════════════════════════════════════════
// Control-flow flattening (CFF) — volatile switch dispatcher
// Turns function bodies into state-machine spaghetti: Ghidra / IDA Pro's
// decompiler graph recovery emits an unreadable switch, not sequential logic.
// The `volatile` state var prevents the compiler from collapsing it back.
// ════════════════════════════════════════════════════════════════════════════
#define CFF_INIT(v)     volatile uint32_t _c = (v)
#define CFF_LOOP        while(1) switch(_c)
#define CFF_NEXT(n)     { _c=(uint32_t)(n); break; }
#define CFF_EXIT        default: goto _cff_exit; } _cff_exit:

// Opaque predicate — always true (n*(n+1) is always even), but the decompiler
// must track a dead else-branch, doubling the apparent code-paths it analyses.
#define OP_ALWAYS_TRUE(n) \
    (__builtin_expect((((uint32_t)(n)*((uint32_t)(n)+1u))&1u)==0u,1))

// ════════════════════════════════════════════════════════════════════════════
// Anti-debug: abort if TracerPid != 0
// ════════════════════════════════════════════════════════════════════════════

// "/proc/self/status" and "TracerPid:" are AES-256-CBC encrypted in
// guard_pstrings.inc (indices 77-78) via reveal_ns() — decrypted at runtime
// only.  The old XOR-only approach was constant-folded by clang -O2 into
// .rodata, leaking the plaintext strings in the binary.

static void check_tracer(void) {
    GLOGI("check_tracer: start");
    char s_status[SP_BUF_SZ*2] = {0};
    char s_tpid[SP_BUF_SZ]     = {0};
    reveal_ns(77, SP_TRACER_STATUS, SP_TRACER_STATUS_LEN, s_status);
    reveal_ns(78, SP_TRACER_PID,    SP_TRACER_PID_LEN,    s_tpid);

    char line[256];
    FILE *f = fopen(s_status, "r");
    if (!f) { GLOGI("check_tracer: could not open status file, skipping"); return; }
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, s_tpid, 10) == 0) {
            long pid = strtol(line + 10, NULL, 10);
            fclose(f);
            GLOGI("check_tracer: TracerPid=%ld", pid);
            if (pid != 0) CRASH_HERE("TracerPid != 0 (debugger/ptrace attached)");
            return;
        }
    }
    fclose(f);
    GLOGI("check_tracer: TracerPid line not found");
}

// ════════════════════════════════════════════════════════════════════════════
// APK path discovery — two-stage:
//   Stage 1: /proc/self/maps  — works when extractNativeLibs=false (APK is
//            directly mmap'd by ART to load the .so from the ZIP).
//   Stage 2: /proc/self/fd/   — fallback for extractNativeLibs=true (libs
//            are extracted to /data/app/.../lib/ so the .so is NOT in maps,
//            but ART always keeps the APK file descriptor open for resources).
// ════════════════════════════════════════════════════════════════════════════

// All path/extension strings decoded at call-time from XOR 0xA3 arrays —
// no plaintext "/proc/self/maps", "/data/app/", ".apk", etc. in .rodata.
static int get_apk_path(char *out, size_t sz) {
    // All path strings decoded via AES-256-CBC with per-string unique keys.
    // Nothing in .rodata links to "/proc/self/maps", "/data/app/", etc.
    char s_maps[SP_BUF_SZ], s_fd_dir[SP_BUF_SZ], s_fd_pfx[SP_BUF_SZ];
    char s_dot_apk[SP_BUF_SZ], s_da[SP_BUF_SZ], s_sa[SP_BUF_SZ];
    char s_sp[SP_BUF_SZ], s_va[SP_BUF_SZ];

    char fallback[512] = {0};
    FILE *f = NULL;
    DIR  *d = NULL;
    int have_fallback = 0, result = 0;

    // CFF state machine — Ghidra sees a volatile-switch dispatcher, not
    // sequential stage logic.
    CFF_INIT(0x3Au);
    CFF_LOOP {
    case 0x3Au: {
        // Opaque predicate: dead else forces decompiler to track fake path
        if (OP_ALWAYS_TRUE(0x3Au)) {
            reveal_ns(1u,  SP_PROC_MAPS,    SP_PROC_MAPS_LEN,    s_maps);
            reveal_ns(2u,  SP_PROC_FD_DIR,  SP_PROC_FD_DIR_LEN,  s_fd_dir);
            reveal_ns(3u,  SP_FD_LINK_PFX,  SP_FD_LINK_PFX_LEN,  s_fd_pfx);
            reveal_ns(4u,  SP_DOT_APK,      SP_DOT_APK_LEN,      s_dot_apk);
            reveal_ns(7u,  SP_DATA_APP,     SP_DATA_APP_LEN,     s_da);
            reveal_ns(8u,  SP_SYS_APP,      SP_SYS_APP_LEN,      s_sa);
            reveal_ns(9u,  SP_SYS_PRIV,     SP_SYS_PRIV_LEN,     s_sp);
            reveal_ns(10u, SP_VND_APP,      SP_VND_APP_LEN,      s_va);
        } else { crash_now(); }
        CFF_NEXT(0x71u);
    }
    case 0x71u: {
        // Stage 1 — /proc/self/maps
        f = fopen(s_maps, "r");
        CFF_NEXT(0xBCu);
    }
    case 0xBCu: {
        if (!f) { CFF_NEXT(0xD4u); break; }
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            char *p = strstr(line, s_dot_apk);
            if (!p) continue;
            char *slash = NULL;
            for (char *c = line; c < p; c++) if (*c == '/') slash = c;
            if (!slash) continue;
            int is_da  = (strstr(slash, s_da) != NULL);
            int is_sys = (strstr(slash, s_sa) || strstr(slash, s_sp) || strstr(slash, s_va));
            if (!is_da && !is_sys) continue;
            size_t len = (size_t)(p + 4 - slash);
            if (len >= sz) continue;
            if (is_da) {
                strncpy(out, slash, len); out[len] = '\0';
                fclose(f); f = NULL; result = 1;
                CFF_NEXT(0xFFu); break;
            }
            if (!have_fallback && len < sizeof(fallback)) {
                strncpy(fallback, slash, len); fallback[len] = '\0';
                have_fallback = 1;
            }
        }
        if (_c != 0xFFu) { if (f) { fclose(f); f = NULL; } CFF_NEXT(0xD4u); }
        break;
    }
    case 0xD4u: {
        // Stage 2 — /proc/self/fd/
        d = opendir(s_fd_dir);
        CFF_NEXT(0xE5u);
    }
    case 0xE5u: {
        if (!d) { CFF_NEXT(0xF6u); break; }
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            char fdlink[64];
            snprintf(fdlink, sizeof(fdlink), "%s%s", s_fd_pfx, de->d_name);
            char target[512] = {0};
            ssize_t r = readlink(fdlink, target, sizeof(target) - 1);
            if (r <= 4) continue;
            target[r] = '\0';
            if (!strstr(target, s_dot_apk)) continue;
            int is_da  = (strstr(target, s_da) != NULL);
            int is_sys = (strstr(target, s_sa) || strstr(target, s_sp) || strstr(target, s_va));
            if (!is_da && !is_sys) continue;
            char *dot = strstr(target, s_dot_apk); dot[4] = '\0';
            if (strlen(target) >= sz) continue;
            if (is_da) {
                strncpy(out, target, sz - 1); out[sz - 1] = '\0';
                closedir(d); d = NULL; result = 1;
                CFF_NEXT(0xFFu); break;
            }
            if (!have_fallback && strlen(target) < sizeof(fallback)) {
                strncpy(fallback, target, sizeof(fallback) - 1);
                have_fallback = 1;
            }
        }
        if (_c != 0xFFu) { if (d) { closedir(d); d = NULL; } CFF_NEXT(0xF6u); }
        break;
    }
    case 0xF6u: {
        if (have_fallback) {
            strncpy(out, fallback, sz - 1); out[sz - 1] = '\0';
            result = 1;
        }
        CFF_NEXT(0xFFu);
    }
    case 0xFFu:
    CFF_EXIT;
    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// VCore / VirtualApp detection — known virtual container path markers
// (S_VC1–S_VC10 are AES-256-CBC+XOR encrypted in guard_pstrings.inc)
// ════════════════════════════════════════════════════════════════════════════

struct VcMarker { const uint8_t *ct; int ct_len; };
static const VcMarker VCORE_MARKERS[] = {
    {S_VC1,S_VC1_LEN},{S_VC2,S_VC2_LEN},{S_VC3,S_VC3_LEN},{S_VC4,S_VC4_LEN},
    {S_VC5,S_VC5_LEN},{S_VC6,S_VC6_LEN},{S_VC7,S_VC7_LEN},{S_VC8,S_VC8_LEN},
    {S_VC9,S_VC9_LEN},{S_VC10,S_VC10_LEN},
};

static void check_render_backend(const char *apk_path) {
    GLOGI("check_render_backend: apk_path=%s", apk_path);
    char buf[PSTR_BUF_SZ];
    for (size_t i = 0; i < sizeof(VCORE_MARKERS)/sizeof(VCORE_MARKERS[0]); i++) {
        reveal(VCORE_MARKERS[i].ct, VCORE_MARKERS[i].ct_len, buf);
        int hit = strstr(apk_path, buf) != NULL;
        if (hit) GLOGI("check_render_backend: marker[%zu]='%s' matched apk_path", i, buf);
        memset(buf, 0, sizeof(buf));
        if (hit) CRASH_HERE("APK path contains a virtual-container marker (VCore/VirtualApp)");
    }
    GLOGI("check_render_backend: clean");
}

// ════════════════════════════════════════════════════════════════════════════
// Hook-framework / injection-tool detection (memory-map scanning)
// All marker strings are XOR-obfuscated (XOR 0xA3) — no plaintext in .rodata
// ════════════════════════════════════════════════════════════════════════════

static volatile const uint8_t G_FRIDA[]     = {0xC5,0xD1,0xCB,0xC7,0xC2};           // "frida"
static volatile const uint8_t G_XPOSED[]    = {0xDB,0xD3,0xCD,0xD0,0xC6,0xC7};       // "xposed"
static volatile const uint8_t G_SUBSTR[]    = {0xD0,0xD6,0xD1,0xD0,0xD7,0xD1,0xC2,0xD7,0xC6}; // "substrate"
static volatile const uint8_t G_GADGET[]    = {0xC4,0xC2,0xC5,0xC4,0xC6,0xD7};       // "gadget"
static volatile const uint8_t G_MAGISK[]    = {0xCE,0xC2,0xC4,0xCA,0xD0,0xC8};       // "magisk"
static volatile const uint8_t G_SAURIK[]    = {0xD0,0xC2,0xD9,0xCB,0xCA,0xC9};       // "saurik"

// ART hook framework markers (XOR 0xA3)
static volatile const uint8_t G_LSPLANT[]  = {0xCF,0xD0,0xD3,0xCF,0xC2,0xCD,0xD7};  // "lsplant"
static volatile const uint8_t G_ZYGISK[]   = {0xD9,0xDA,0xC4,0xCA,0xD0,0xC8};        // "zygisk"
static volatile const uint8_t G_RIRU[]     = {0xD1,0xCA,0xD1,0xD6};                   // "riru"
static volatile const uint8_t G_LSPATCH[]  = {0xCF,0xD0,0xD3,0xC2,0xD7,0xC0,0xCB};  // "lspatch"

// ART runtime library names for path-integrity check (XOR 0xA3)
static volatile const uint8_t G_LIBART[]  = {
    0xCF,0xCA,0xC1,0xC2,0xD1,0xD7,0x8D,0xD0,0xCC          // "libart.so"
};
static volatile const uint8_t G_LIBRT[]   = {
    0xCF,0xCA,0xC1,0xC2,0xCD,0xC7,0xD1,0xCC,0xCA,0xC7,    // "libandroid"
    0xFC,0xD1,0xD6,0xCD,0xD7,0xCA,0xCE,0xC6,0x8D,0xD0,0xCC // "_runtime.so"
};

// ── /proc/self/maps scan for Frida/Xposed/Substrate/Gadget/Magisk/Saurik ──

static __attribute__((noinline)) int check_pipeline_maps(void) {
    G_DEC(s_frida,   G_FRIDA);
    G_DEC(s_xposed,  G_XPOSED);
    G_DEC(s_substr,  G_SUBSTR);
    G_DEC(s_gadget,  G_GADGET);
    G_DEC(s_magisk,  G_MAGISK);
    G_DEC(s_saurik,  G_SAURIK);
    char s_maps[SP_BUF_SZ];
    reveal_ns(1u, SP_PROC_MAPS, SP_PROC_MAPS_LEN, s_maps);

    FILE *f = fopen(s_maps, "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, s_frida)  || strstr(line, s_xposed) ||
            strstr(line, s_substr) || strstr(line, s_gadget) ||
            strstr(line, s_magisk) || strstr(line, s_saurik)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    GLOGI("check_pipeline_maps: found=%d", found);
    return found;
}

// ── /proc/self/maps scan for LSPlant/Zygisk/Riru/LSPatch ──────────────────
// Kept separate so each check gets its own VM opcode slot — an attacker
// who NOPs the Frida check still hits this one.

static __attribute__((noinline)) int check_render_hooks(void) {
    G_DEC(s_lsplant, G_LSPLANT);
    G_DEC(s_zygisk,  G_ZYGISK);
    G_DEC(s_riru,    G_RIRU);
    G_DEC(s_lspatch, G_LSPATCH);
    char s_maps[SP_BUF_SZ];
    reveal_ns(1u, SP_PROC_MAPS, SP_PROC_MAPS_LEN, s_maps);

    FILE *f = fopen(s_maps, "r");
    if (!f) return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, s_lsplant) || strstr(line, s_zygisk) ||
            strstr(line, s_riru)    || strstr(line, s_lspatch)) {
            found = 1;
            break;
        }
    }
    fclose(f);
    GLOGI("check_render_hooks: found=%d", found);
    return found;
}

// ── libart.so / libandroid_runtime.so path integrity ──────────────────────
// Both ART runtime libraries MUST be mapped from /system/ or /apex/.
// If either appears under any other path the runtime has been replaced
// (Zygisk, Riru, LSPlant all work by loading a modified libart.so).
// On Android 10+ libart.so lives under /apex/com.android.art/... — valid.

static __attribute__((noinline)) int check_runtime_path(void) {
    G_DEC(s_libart, G_LIBART);
    G_DEC(s_librt,  G_LIBRT);
    char s_maps[SP_BUF_SZ], s_sys[SP_BUF_SZ], s_apex[SP_BUF_SZ];
    reveal_ns(1u,  SP_PROC_MAPS, SP_PROC_MAPS_LEN, s_maps);
    reveal_ns(11u, SP_SYS_PFX,  SP_SYS_PFX_LEN,   s_sys);
    reveal_ns(12u, SP_APEX_PFX, SP_APEX_PFX_LEN,   s_apex);
    size_t sys_len  = strlen(s_sys);
    size_t apex_len = strlen(s_apex);

    FILE *f = fopen(s_maps, "r");
    if (!f) return 0;
    char line[512];
    int bad = 0;

    while (fgets(line, sizeof(line), f)) {
        int is_art   = (strstr(line, s_libart) != NULL);
        int is_librt = (strstr(line, s_librt)  != NULL);
        if (!is_art && !is_librt) continue;

        char *path = NULL;
        for (char *c = line; *c && *c != '\n'; c++) {
            if (*c == '/') { path = c; break; }
        }
        if (!path) continue;

        if (strncmp(path, s_sys,  sys_len)  != 0 &&
            strncmp(path, s_apex, apex_len) != 0) {
            bad = 1;
            break;
        }
    }
    fclose(f);
    GLOGI("check_runtime_path: bad=%d", bad);
    return bad;
}

// ── Frida default listener port probe (27042) ─────────────────────────────
// Frida-server binds to 127.0.0.1:27042 by default. A successful TCP
// connect means Frida-server is running on the device.

static __attribute__((noinline)) int check_frida_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(27042);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int found = 0;
    if (ret == 0) {
        found = 1;
    } else if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(fd, &wset);
        struct timeval tv = {0, 200000};  // 200 ms
        if (select(fd + 1, NULL, &wset, NULL, &tv) > 0) {
            int err = 0;
            socklen_t errlen = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
            found = (err == 0) ? 1 : 0;
        }
    }
    close(fd);

    // ── D-Bus AUTH handshake confirmation ─────────────────────────────────
    // Even if port 27042 is open from another service, confirm it is Frida by
    // sending the D-Bus NULL-byte + AUTH\r\n header and checking for "REJECTED".
    // Stock frida-server responds: "REJECTED DBUS_COOKIE_SHA1 EXTERNAL\r\n"
    // phantom-frida preserves this wire protocol so this probe still works.
    if (found) {
        int hfd = socket(AF_INET, SOCK_STREAM, 0);
        if (hfd >= 0) {
            struct timeval to = {0, 300000};   // 300 ms
            setsockopt(hfd, SOL_SOCKET, SO_RCVTIMEO, &to, sizeof(to));
            setsockopt(hfd, SOL_SOCKET, SO_SNDTIMEO, &to, sizeof(to));
            struct sockaddr_in ha;
            memset(&ha, 0, sizeof(ha));
            ha.sin_family      = AF_INET;
            ha.sin_port        = htons(27042);
            ha.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            if (connect(hfd, (struct sockaddr *)&ha, sizeof(ha)) == 0) {
                // D-Bus framing: leading NUL + AUTH\r\n
                static const char AUTH_MSG[] = "\x00" "AUTH\r\n";
                send(hfd, AUTH_MSG, sizeof(AUTH_MSG) - 1, 0);
                char resp[32] = {};
                recv(hfd, resp, sizeof(resp) - 1, 0);
                if (strncmp(resp, "REJECTED", 8) == 0) {
                    GLOGE("check_frida_port: Frida AUTH handshake confirmed on 27042");
                }
                // Port 27042 open regardless of handshake result → already found=1
            }
            close(hfd);
        }
    }

    GLOGI("check_frida_port: found=%d", found);
    return found;
}

// ════════════════════════════════════════════════════════════════════════════
// Forward declaration — full definition lives in the LAYER 2 section below.
// Needed by both the VM interpreter's METRICS opcode (gvm_metrics) and by
// spawn_background_watch()'s forked child, which calls it via a direct
// kill() path independent of crash_now().
// ════════════════════════════════════════════════════════════════════════════

static int detect_metrics_tamper(const char *apk_path);

// ════════════════════════════════════════════════════════════════════════════
// ── VM Protection — Custom ISA Interpreter ───────────────────────────────
//
// All sensitive security checks are encoded as bytecode in a custom ISA.
// IDA/Ghidra decompiles the interpreter loop but the GUARD_BYTECODE array
// looks like opaque data — an attacker must reverse-engineer the full ISA
// before understanding what the checks do.
//
// Opcodes:
//   0x01  HALT         — stop, return cleanly
//   0x02  CRASH        — crash_now()
//   0x10  CHK_TRACER   — result = TracerPid != 0
//   0x11  CHK_FMAPS    — result = frida/xposed/substrate in /proc/self/maps
//   0x12  CHK_FPORT    — result = Frida listener on port 27042
//   0x13  ARTPATH      — result = libart.so/libandroid_runtime.so bad path
//   0x14  HOOKMAPS     — result = lsplant/zygisk/riru/lspatch in maps
//   0x15  METRICS      — result = manifest-hash/dex-count mismatch
//   0x20  JZ  <off8>   — if result == 0: pc += off8 (skip forward)
//   0x21  JNZ <off8>   — if result != 0: pc += off8
//   0x30  NOP          — decoy instruction
// ════════════════════════════════════════════════════════════════════════════

typedef enum : uint8_t {
    G_OP_HALT     = 0x01,
    G_OP_CRASH    = 0x02,
    G_OP_TRACER   = 0x10,
    G_OP_FMAPS    = 0x11,
    G_OP_FPORT    = 0x12,
    G_OP_ARTPATH  = 0x13,
    G_OP_HOOKMAPS = 0x14,
    G_OP_METRICS  = 0x15,
    G_OP_JZ       = 0x20,
    G_OP_JNZ      = 0x21,
    G_OP_NOP      = 0x30,
} GVmOp;

// ════════════════════════════════════════════════════════════════════════════
// Logic VM — encrypted bytecode programs that implement detection LOGIC itself.
//
// This is the second obfuscation layer on top of the dispatch VM above.
// Where the dispatch VM controls WHICH checks run, the Logic VM controls
// HOW each check runs — the entire fopen/fgets/strstr loop is compiled to
// custom bytecode and AES-256-CBC encrypted.  IDA/Ghidra sees only:
//     lvm_exec(KHI, KLO, IHI, ILO, ENC, LEN, CS)
// which is an opaque call into the interpreter.  The check implementation
// (what files are opened, what strings are searched, what ports are probed)
// lives ONLY inside the encrypted bytecode blob.
//
// ISA (all instructions are 2 bytes: [op][operand]):
//   0x01 00   HALT      — stop; return accumulator
//   0x02 00   CRASH     — crash_now() immediately
//   0x20 off  JZ  off   — if last_result==0: pc += (int8_t)off
//   0x21 off  JNZ off   — if last_result!=0: pc += (int8_t)off
//   0x30 00   NOP       — decoy, ignored
//   0x40 imm  LLOAD imm — acc = imm
//   0x41 00   LMOV      — acc = last_result
//   0x42 00   LNOT      — acc = !acc
//   0x50 sid  LOPEN sid — vm_file=fopen(prim_str[sid],"r"); last_result=success
//   0x51 00   LGETS     — last_result=(fgets(vm_lb,512,vm_file)!=NULL)
//   0x52 00   LCLOSE    — fclose(vm_file); vm_file=NULL
//   0x53 sid  LSTRST sid— last_result=(strstr(vm_lb,prim_str[sid])!=NULL)
//   0x56 00   LTRACE    — last_result=TracerPid!=0 (/proc/self/status)
//   0x61 off  LJMP  off — pc += (int8_t)off  (unconditional)
//
// Primitive string slots (sid):
//   0 = /proc/self/maps  (AES-decrypted via reveal_ns)
//   1 = frida   2 = xposed   3 = substrate   4 = gadget
//   5 = magisk  6 = saurik   7 = lsplant     8 = zygisk
//   9 = riru    10 = lspatch
//
// Each program has its own 256-bit AES key (split KHI^KLO) and IV (IHI^ILO)
// plus a plaintext XOR-checksum (CS) verified before first instruction.
// ════════════════════════════════════════════════════════════════════════════

// ── FMAPS program: check_pipeline_maps logic (frida/xposed/substrate/gadget/magisk/saurik)
// Plain bytecode (52 bytes), AES-256-CBC encrypted below
// 52 bytes plain, 64 bytes encrypted
static volatile const uint8_t LBC_FMAPS_KHI[] = {0xDB,0x02,0x63,0xCB,0x10,0x9E,0x52,0x81,0xD1,0xD0,0xFE,0x25,0x7C,0x77,0x65,0x30,0xC7,0x3D,0x1C,0x54,0xC2,0x2A,0x17,0x98,0x8C,0x63,0x24,0x57,0x32,0x79,0x37,0x2C};
static volatile const uint8_t LBC_FMAPS_KLO[] = {0x98,0xEC,0xD9,0xDA,0x81,0xB6,0x1D,0x05,0xB2,0x23,0xB6,0x42,0x95,0x9B,0x0E,0xD3,0x77,0x96,0x07,0xCD,0xCC,0x42,0xF3,0x4E,0x7B,0x9B,0xF5,0xEE,0xB0,0x81,0x46,0x9F};
static volatile const uint8_t LBC_FMAPS_IHI[] = {0x9A,0x5C,0x05,0x51,0x30,0xE1,0xA3,0x7C,0xF2,0xFA,0x57,0x91,0xE7,0x9A,0xA3,0x4C};
static volatile const uint8_t LBC_FMAPS_ILO[] = {0xB7,0x16,0xDB,0xCB,0x4B,0xA8,0x1A,0x6C,0x60,0x3F,0xF7,0x6A,0xC6,0xE5,0x88,0x48};
static volatile const uint8_t LBC_FMAPS_ENC[] = {0xFE,0x58,0x38,0x58,0x38,0xE5,0xA8,0xD1,0xEC,0xE2,0x92,0xC6,0xA5,0x67,0x11,0x29,0x28,0x0F,0x2B,0x8B,0x0A,0xC9,0x3F,0xCB,0x14,0xDC,0x59,0x57,0x46,0x0E,0x17,0x92,0xA1,0x10,0x9B,0xDC,0x31,0xF5,0x19,0x07,0x01,0xDD,0xF0,0x27,0x12,0xC1,0xD7,0xDB,0x34,0x2D,0x1B,0x98,0xB4,0x0C,0x70,0x51,0x39,0x0C,0xE6,0x8A,0x98,0x18,0x1C,0xF4};
#define LBC_FMAPS_LEN  64
#define LBC_FMAPS_CS   0xB1u

// ── HOOKS program: check_render_hooks logic (lsplant/zygisk/riru/lspatch)
// 44 bytes plain, 48 bytes encrypted
static volatile const uint8_t LBC_HOOKS_KHI[] = {0x03,0x18,0xCD,0x33,0x70,0x5F,0xB1,0x1D,0xBA,0x4A,0xA7,0xA3,0xAB,0xAC,0x27,0xBB,0xAC,0x32,0xDD,0x7A,0x6A,0x9B,0x8B,0x5E,0xE0,0x0D,0x44,0xE6,0x38,0x32,0x97,0x74};
static volatile const uint8_t LBC_HOOKS_KLO[] = {0xDF,0x5B,0xDC,0x70,0x85,0xAF,0xCC,0x41,0xB1,0x36,0xD5,0x40,0x49,0x9A,0xBE,0x91,0xFB,0x34,0x31,0x40,0x1B,0x02,0xB5,0x82,0xDA,0x7C,0x64,0x6D,0xB1,0x93,0x23,0xBA};
static volatile const uint8_t LBC_HOOKS_IHI[] = {0x1D,0x46,0x84,0xF3,0x5D,0x59,0x29,0xE7,0xE1,0x5E,0x96,0xBB,0x1B,0x3F,0x8F,0x03};
static volatile const uint8_t LBC_HOOKS_ILO[] = {0xEC,0xEA,0x15,0x27,0x7A,0xC7,0x55,0x47,0x94,0x26,0xE4,0x92,0x0C,0xD3,0xE3,0xD1};
static volatile const uint8_t LBC_HOOKS_ENC[] = {0xFD,0x19,0x35,0xE7,0x6E,0xCC,0x53,0x27,0xD6,0xF8,0xD6,0x55,0x46,0x4A,0x15,0x3B,0xDD,0xE8,0xB4,0x4A,0x39,0xBE,0x47,0x7E,0x42,0x21,0x62,0x27,0x9D,0x6E,0x37,0xFE,0x27,0x56,0x89,0x10,0xBF,0x1F,0x9D,0x1A,0xAC,0xE9,0x96,0x02,0x1A,0x29,0x85,0xAA};
#define LBC_HOOKS_LEN  48
#define LBC_HOOKS_CS   0xB6u

// ── TRACER program: TracerPid check logic
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_TRACER_KHI[] = {0x67,0x23,0xBD,0x36,0xD0,0x0A,0xF0,0x4D,0x7A,0x11,0xFA,0x16,0xB7,0x55,0x6C,0x79,0x0A,0x9D,0x9D,0x50,0x1F,0x95,0xD6,0x32,0x54,0x9A,0x80,0x3E,0x1B,0x91,0x33,0x43};
static volatile const uint8_t LBC_TRACER_KLO[] = {0x5F,0x19,0x82,0x51,0x3C,0x93,0x84,0x15,0xE5,0x8F,0xDB,0xAB,0xB5,0xE2,0xE9,0xA4,0xAB,0xB8,0x06,0x81,0x8A,0xFF,0x13,0x87,0x97,0x57,0xC4,0xD0,0x44,0x74,0x24,0x72};
static volatile const uint8_t LBC_TRACER_IHI[] = {0xA1,0x82,0x11,0xD0,0xCD,0x9C,0xF8,0xE6,0x41,0x0F,0x1E,0x41,0x8E,0x18,0xD3,0xC0};
static volatile const uint8_t LBC_TRACER_ILO[] = {0x0B,0xF7,0x99,0xD5,0xBE,0x1C,0x8A,0x4E,0x2E,0xA2,0xF9,0xCD,0x3F,0x4C,0xEF,0x3C};
static volatile const uint8_t LBC_TRACER_ENC[] = {0xC0,0x34,0x75,0x8B,0x5D,0x4D,0x80,0xA2,0xCD,0x92,0x93,0x7F,0xFB,0xC2,0x11,0x10};
#define LBC_TRACER_LEN  16
#define LBC_TRACER_CS   0x16u

// ── FPORT program: check_frida_port logic (TCP connect 127.0.0.1:27042)
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_FPORT_KHI[] = {0x05,0x4F,0x00,0xE6,0x38,0x4C,0x9C,0xB5,0xF1,0x42,0xC8,0xB8,0x0F,0x5C,0xAB,0x8F,0x60,0x01,0xF5,0x61,0xB0,0x56,0x21,0x68,0x6E,0xD6,0x1E,0x40,0xDE,0x64,0x27,0xAB};
static volatile const uint8_t LBC_FPORT_KLO[] = {0x99,0xE6,0x5C,0x7A,0x88,0x28,0x1A,0x06,0xB9,0x4E,0x2F,0xCC,0xC3,0x33,0x41,0xB8,0x17,0x9B,0xE8,0x05,0x31,0xC8,0xDE,0xB2,0xCF,0x6A,0xBA,0x78,0x50,0xF5,0x8A,0xDE};
static volatile const uint8_t LBC_FPORT_IHI[] = {0x12,0xF5,0x00,0x37,0xAE,0xE5,0x89,0xA5,0x92,0x4F,0xB2,0x27,0x91,0xF8,0xD7,0xFF};
static volatile const uint8_t LBC_FPORT_ILO[] = {0x23,0x8B,0xC6,0x37,0x56,0xF9,0xF1,0x06,0xCC,0x11,0xD0,0xF3,0xB4,0xF1,0x1A,0x1A};
static volatile const uint8_t LBC_FPORT_ENC[] = {0x79,0xCA,0x5D,0xE4,0x21,0xBE,0x6D,0x08,0x0A,0xD9,0x25,0xBC,0x3C,0x84,0x10,0xF1};
#define LBC_FPORT_LEN  16
#define LBC_FPORT_CS   0x15u

// ── ARTPATH program: check_runtime_path logic (libart.so/libandroid_runtime.so path check)
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_ARTPATH_KHI[] = {0xD4,0x1D,0x43,0xE9,0xB7,0x2E,0xC1,0xB8,0xF1,0x68,0x99,0x93,0xF6,0x9D,0x25,0x46,0x7D,0xFD,0xAE,0xE1,0xFB,0xEF,0xE0,0x06,0x4F,0x3D,0xB8,0x52,0xFF,0x69,0x06,0x2E};
static volatile const uint8_t LBC_ARTPATH_KLO[] = {0x63,0x39,0x5E,0x85,0x0A,0x70,0x84,0xF1,0x9F,0x84,0x9C,0x61,0xD6,0xBC,0x91,0x4F,0x9D,0xAA,0xE7,0x1F,0x32,0xC9,0x80,0x96,0x26,0xEB,0x62,0xAD,0x9A,0x6C,0xA6,0x5C};
static volatile const uint8_t LBC_ARTPATH_IHI[] = {0xE9,0x14,0x7E,0x9E,0x1D,0xD8,0x98,0xDF,0xF8,0x6D,0xF3,0xF7,0xE7,0xDD,0xEE,0x15};
static volatile const uint8_t LBC_ARTPATH_ILO[] = {0x9C,0xFC,0x57,0x92,0x9D,0xD2,0x8C,0xC8,0x8A,0xAF,0xDF,0xBA,0x98,0xE9,0x6B,0x90};
static volatile const uint8_t LBC_ARTPATH_ENC[] = {0x10,0xE2,0xB4,0x07,0xB0,0xC5,0x0C,0x3F,0xCC,0x9A,0x3D,0x40,0xF9,0xBC,0x47,0xAB};
#define LBC_ARTPATH_LEN  16
#define LBC_ARTPATH_CS   0x17u

// ── METRICS program: detect_metrics_tamper logic (manifest hash + dex count)
// 10 bytes plain, 16 bytes encrypted
static volatile const uint8_t LBC_METRICS_KHI[] = {0x32,0xDB,0xDC,0x95,0xD0,0x6B,0x64,0x14,0x2E,0x68,0xFA,0xD3,0x77,0xD2,0x6A,0xF7,0x45,0xB9,0x19,0xD0,0xBE,0x90,0xC0,0x4E,0xEA,0x5F,0x59,0x59,0x3A,0x57,0xC5,0x52};
static volatile const uint8_t LBC_METRICS_KLO[] = {0xE6,0xE2,0x56,0x00,0x8D,0x60,0x46,0x6A,0x96,0xEB,0xEB,0x31,0x93,0x95,0xED,0x6A,0xB2,0x71,0x2E,0xDD,0x21,0xCD,0x67,0x41,0x2C,0xD9,0x21,0x31,0xF1,0x16,0xBE,0x5D};
static volatile const uint8_t LBC_METRICS_IHI[] = {0xA3,0xA8,0xD5,0xB6,0x5A,0xDD,0x23,0x89,0x5D,0x5A,0x37,0xAB,0x12,0xC3,0xDA,0x55};
static volatile const uint8_t LBC_METRICS_ILO[] = {0x70,0x6F,0x6D,0x9E,0x5C,0x49,0x03,0x2A,0x31,0xE2,0x2E,0x8C,0x0E,0xF7,0x4A,0x5F};
static volatile const uint8_t LBC_METRICS_ENC[] = {0x93,0x0D,0xE2,0x00,0x2D,0xF6,0x0D,0x0F,0x4E,0x4F,0x14,0x90,0x75,0x47,0x1A,0x86};
#define LBC_METRICS_LEN  16
#define LBC_METRICS_CS   0x18u

// ── VCCHECK program: VCore/VirtualApp APK-path check (LVCFULL opcode 0x5A)
// 8 bytes plain → 16 bytes AES-256-CBC ciphertext
static volatile const uint8_t LBC_VCCHECK_KHI[] = {0x24,0x1B,0x08,0x9C,0xBE,0x39,0x90,0x4E,0x32,0xA8,0xCF,0xDB,0xF0,0x73,0xDF,0x40,0xFC,0x6D,0xF2,0xDF,0x7A,0x93,0x41,0x83,0x10,0x50,0x64,0xE7,0xE1,0xBE,0x07,0x96};
static volatile const uint8_t LBC_VCCHECK_KLO[] = {0x16,0x61,0xD4,0xF8,0xB1,0x9D,0xC3,0x87,0x08,0x9E,0xAD,0x90,0xD7,0xE6,0x0A,0x2B,0x6F,0x1F,0x62,0x93,0x81,0xB6,0xFA,0x63,0xD3,0xCF,0xA0,0x30,0xB1,0x95,0x3A,0x22};
static volatile const uint8_t LBC_VCCHECK_IHI[] = {0x3D,0x4D,0x92,0x14,0x12,0xD2,0x64,0xF6,0xF9,0x8A,0x02,0x82,0x82,0xBC,0x78,0x2D};
static volatile const uint8_t LBC_VCCHECK_ILO[] = {0x17,0xB8,0x2D,0xF6,0x68,0x24,0xF0,0x66,0x09,0x21,0x4E,0xBF,0xCD,0x55,0x0F,0x0B};
static volatile const uint8_t LBC_VCCHECK_ENC[] = {0xDE,0xE2,0x66,0xD5,0x3B,0x78,0x54,0x3E,0xA6,0x6C,0xC1,0xBA,0x1C,0xE7,0xE0,0xB0};
#define LBC_VCCHECK_LEN  16
#define LBC_VCCHECK_CS   0x5Bu

// ── SIGCHK program: signature certificate verification (LSIGCHK opcode 0x5C)
// Bytecode (8 bytes plain → 16 bytes AES-256-CBC):
//   0x5C 0x00  LSIGCHK  — call gvm_sig_check() → vm_res
//   0x20 0x02  JZ  +2   — vm_res==0 (clean): skip CRASH
//   0x02 0x00  CRASH    — tamper detected → crash_now()
//   0x01 0x00  HALT     — clean exit
// Key = KHI^KLO (256-bit), IV = IHI^ILO (128-bit). XOR-CS = 0x7D.
// fonts_init() shows only an opaque lvm_exec call — no gvm_sig_check or
// detect_sig_tamper reference visible in ARM64 disasm.
static volatile const uint8_t LBC_SIGCHK_KHI[] = {0x15,0x08,0xDC,0xDA,0x13,0xB9,0xC3,0x45,0x4D,0xDE,0x17,0x21,0xC0,0x79,0xB4,0x3D,0x4A,0x49,0xCD,0x5E,0x48,0x58,0x29,0x0C,0xEE,0x4E,0xEB,0x37,0xD5,0x0E,0xA9,0xD4};
static volatile const uint8_t LBC_SIGCHK_KLO[] = {0xBB,0x24,0x26,0x05,0x27,0xBF,0xC2,0xC8,0x33,0xE3,0x58,0xFD,0x1C,0x9E,0xA0,0xBE,0xF3,0x6F,0x4B,0xDD,0xCD,0xF0,0xBC,0x2C,0x1E,0xE7,0xD8,0x54,0xF9,0x8C,0xA8,0xA0};
static volatile const uint8_t LBC_SIGCHK_IHI[] = {0x7B,0xEE,0x0D,0x0C,0x3D,0x8E,0xAC,0xB6,0x7A,0x86,0x40,0xC2,0xD7,0xB0,0xC3,0xB9};
static volatile const uint8_t LBC_SIGCHK_ILO[] = {0x03,0x87,0x66,0x9A,0xBB,0x29,0xC9,0xEE,0xF8,0x19,0x5E,0x90,0x1E,0x04,0x8C,0x39};
static volatile const uint8_t LBC_SIGCHK_ENC[] = {0x94,0x2B,0x87,0xC6,0xFF,0x72,0xB5,0x40,0x20,0xB7,0xFA,0x9C,0xB4,0xC4,0xC9,0x6F};
#define LBC_SIGCHK_LEN  16
#define LBC_SIGCHK_CS   0x7Du

// ── Primitive string resolver — maps slot index → decrypted C string ─────────
// All source arrays remain XOR-encoded in .rodata (G_*) or AES-encrypted
// (reveal_ns path).  No plaintext ever appears in the binary.
#define GVM_PATH_BUF 64
static __attribute__((noinline)) void lvm_prim_str(uint8_t slot, char *out, size_t sz) {
    memset(out, 0, sz);
    if (slot == 0) { reveal_ns(1u, SP_PROC_MAPS, SP_PROC_MAPS_LEN, out); return; }
#define _LGDEC(arr) do { int n=(int)sizeof(arr); if((size_t)n<sz) g_decode((const uint8_t*)arr,n,out); } while(0)
    if      (slot == 1)  _LGDEC(G_FRIDA);
    else if (slot == 2)  _LGDEC(G_XPOSED);
    else if (slot == 3)  _LGDEC(G_SUBSTR);
    else if (slot == 4)  _LGDEC(G_GADGET);
    else if (slot == 5)  _LGDEC(G_MAGISK);
    else if (slot == 6)  _LGDEC(G_SAURIK);
    else if (slot == 7)  _LGDEC(G_LSPLANT);
    else if (slot == 8)  _LGDEC(G_ZYGISK);
    else if (slot == 9)  _LGDEC(G_RIRU);
    else if (slot == 10) _LGDEC(G_LSPATCH);
#undef _LGDEC
}

// ── Logic VM interpreter ───────────────────────────────────────────────────
// Decrypts a bytecode program with the given split key/IV, verifies its
// XOR checksum, then executes it.  Returns the accumulator at HALT.
//
// This function is what an attacker's disassembler sees at the call site —
// six opaque volatile arrays + two integer constants.  The actual check
// logic (which file is opened, which strings are searched) lives only
// inside the AES-encrypted ENC[] blob.
// ── Context passed from JNI shell to LANTIK opcode inside lvm_exec ───────
// The JNI layer collects provider names/auths and Class.forName results as
// plain C data here.  lvm_exec opcode 0x5B reads this struct and performs
// the KFRAG matching and kill decision entirely inside the bytecode interpreter.
// ARM64 disassembly of _fonts_measure_impl shows ONLY data collection + an
// opaque call to lvm_exec — no strstr patterns, no CRASH_HERE.
#define ANTIK_MAX_PROV 32
#define ANTIK_STR_SZ   256
typedef struct {
    char names[ANTIK_MAX_PROV][ANTIK_STR_SZ]; // provider class names (UTF-8)
    char auths[ANTIK_MAX_PROV][ANTIK_STR_SZ]; // provider authorities (UTF-8)
    int  count;      // number of slots populated in names[]/auths[]
    int  exact_hit;  // 1 if Class.forName resolved a blocked class (Layer 2)
} antik_ctx_t;

// ── Forward declarations — defined below lvm_exec, called inside it ──────────
static __attribute__((noinline)) int gvm_metrics(void);
static __attribute__((noinline)) int gvm_so_integrity(void);
static __attribute__((noinline)) int gvm_sig_check(void);   /* used by LSIGCHK opcode 0x5C */

// ── KFRAG encrypted package-fragment patterns (used inside lvm_exec opcode 0x5B)
// Defined here so lvm_exec can see them; provider_matches_blocklist() also uses them.
static const uint8_t KFRAG1_CT[] = {0x03,0x11,0xb6,0x5e,0xd5,0x39,0x11,0x57,0x61,0x41,0xc2,0x42,0xc5,0x37,0xcb,0x07};
static const int KFRAG1_LEN = 16; // idx=200
static const uint8_t KFRAG2_CT[] = {0xd0,0x94,0xf4,0x32,0x96,0xca,0x05,0xa8,0xfe,0xcb,0xd2,0x91,0x02,0x01,0x4c,0xf7};
static const int KFRAG2_LEN = 16; // idx=201
static const uint8_t KFRAG3_CT[] = {0x1f,0x7a,0x37,0xbe,0x25,0x61,0xbe,0x6a,0x7a,0x9f,0x81,0xba,0xf1,0x37,0xa1,0x89};
static const int KFRAG3_LEN = 16; // idx=202
static const uint8_t KFRAG4_CT[] = {0x64,0xd7,0xd9,0x7d,0x32,0x33,0xee,0x11,0xc3,0x64,0x14,0x43,0xcb,0x7b,0x53,0x41,
                                     0x69,0xf9,0x3d,0xbd,0x2f,0xdb,0x2a,0x8a,0xb5,0x3c,0x97,0xd6,0xa8,0x70,0x83,0x13};
static const int KFRAG4_LEN = 32; // idx=203

static __attribute__((noinline)) int lvm_exec(
        const volatile uint8_t *khi, const volatile uint8_t *klo,
        const volatile uint8_t *ihi, const volatile uint8_t *ilo,
        const volatile uint8_t *enc, int enc_len, uint8_t expected_cs,
        const void *ctx_in = nullptr) {

    // Reconstruct full 256-bit key and 128-bit IV from split halves
    uint8_t key[32], iv[16];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(khi[i] ^ klo[i]);
    for (int i = 0; i < 16; i++) iv[i]  = (uint8_t)(ihi[i] ^ ilo[i]);

    // Decrypt bytecode — output buffer sized for largest possible program
    uint8_t prog[128];
    int prog_len = aes256_cbc_dec(key, iv, (const uint8_t *)enc, enc_len,
                                  prog);
    // Zero key material immediately after use
    volatile uint8_t *vk = key; for (int i=0;i<32;i++) vk[i]=0;
    volatile uint8_t *vi = iv;  for (int i=0;i<16;i++) vi[i]=0;

    if (prog_len <= 0 || prog_len > (int)sizeof(prog)) return 0;

    // Bytecode integrity — XOR checksum of decrypted program.
    // Any patch to the ENC[] array produces corrupted plaintext
    // whose checksum won't match → crash instead of silently returning 0.
    uint8_t cs = 0;
    for (int i = 0; i < prog_len; i++) cs ^= prog[i];
    if (cs != expected_cs) { CRASH_HERE("lvm: bytecode integrity"); return 0; }

    // VM state
    FILE *vm_file  = NULL;
    char  vm_lb[512];
    int   vm_acc   = 0;   // accumulator — returned at HALT
    int   vm_res   = 0;   // last primitive result

    // Interpreter — every instruction is exactly 2 bytes [op][operand]
    // This forces instruction boundaries to be non-obvious to static analysis.
    int pc = 0;
    while (pc + 1 < prog_len) {
        uint8_t op  = prog[pc];
        uint8_t arg = prog[pc + 1];
        pc += 2;
        switch (op) {
            // ── Control ────────────────────────────────────────────────
            case 0x01: /* HALT  */ goto lvm_halt;
            case 0x02: /* CRASH */ CRASH_HERE("lvm: CRASH opcode"); if(vm_file)fclose(vm_file); return 0;
            case 0x30: /* NOP   */ break;
            case 0x20: /* JZ    */ if (vm_res == 0) pc += (int)(int8_t)arg; break;
            case 0x21: /* JNZ   */ if (vm_res != 0) pc += (int)(int8_t)arg; break;
            case 0x61: /* LJMP  */ pc += (int)(int8_t)arg;                  break;

            // ── Accumulator ────────────────────────────────────────────
            case 0x40: /* LLOAD */ vm_acc = (int)(uint8_t)arg; break;
            case 0x41: /* LMOV  */ vm_acc = vm_res;            break;
            case 0x42: /* LNOT  */ vm_acc = !vm_acc;           break;

            // ── File I/O primitives ────────────────────────────────────
            case 0x50: { /* LOPEN */
                char path[GVM_PATH_BUF];
                lvm_prim_str(arg, path, sizeof(path));
                if (vm_file) { fclose(vm_file); vm_file = NULL; }
                vm_file = fopen(path, "r");
                vm_res  = (vm_file != NULL) ? 1 : 0;
                break;
            }
            case 0x51: { /* LGETS */
                if (!vm_file) { vm_res = 0; break; }
                vm_res = (fgets(vm_lb, (int)sizeof(vm_lb), vm_file) != NULL) ? 1 : 0;
                break;
            }
            case 0x52: { /* LCLOSE */
                if (vm_file) { fclose(vm_file); vm_file = NULL; }
                break;
            }
            case 0x53: { /* LSTRST */
                char needle[GVM_PATH_BUF];
                lvm_prim_str(arg, needle, sizeof(needle));
                vm_res = (needle[0] && strstr(vm_lb, needle) != NULL) ? 1 : 0;
                break;
            }

            // ── System primitives ──────────────────────────────────────
            case 0x56: { /* LTRACE — read TracerPid from /proc/self/status */
                char s_status[SP_BUF_SZ*2] = {0}, s_tpid[SP_BUF_SZ] = {0};
                reveal_ns(77, SP_TRACER_STATUS, SP_TRACER_STATUS_LEN, s_status);
                reveal_ns(78, SP_TRACER_PID,    SP_TRACER_PID_LEN,    s_tpid);
                FILE *tf = fopen(s_status, "r");
                int traced = 0;
                if (tf) {
                    char line[256];
                    while (fgets(line, sizeof(line), tf)) {
                        if (strncmp(line, s_tpid, 10) == 0) {
                            traced = (strtol(line + 10, NULL, 10) != 0) ? 1 : 0;
                            break;
                        }
                    }
                    fclose(tf);
                }
                vm_res = traced;
                break;
            }
            // ── System primitives (cont.) ──────────────────────────────
            case 0x55: { /* LSOCK — TCP connect to 127.0.0.1:prim_port[slot] */
                // slot 0 = 27042 (Frida default port)
                static const uint16_t prim_ports[] = { 27042 };
                uint16_t port = (arg < (uint8_t)(sizeof(prim_ports)/sizeof(prim_ports[0])))
                                ? prim_ports[arg] : 0;
                int found = 0;
                if (port) {
                    int fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (fd >= 0) {
                        struct sockaddr_in sa;
                        memset(&sa, 0, sizeof(sa));
                        sa.sin_family      = AF_INET;
                        sa.sin_port        = htons(port);
                        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                        int fl = fcntl(fd, F_GETFL, 0);
                        fcntl(fd, F_SETFL, fl | O_NONBLOCK);
                        int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
                        if (rc == 0) {
                            found = 1;
                        } else if (errno == EINPROGRESS) {
                            fd_set ws; FD_ZERO(&ws); FD_SET(fd, &ws);
                            struct timeval tv = {0, 200000};
                            if (select(fd+1, NULL, &ws, NULL, &tv) > 0) {
                                int err = 0; socklen_t el = sizeof(err);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
                                found = (err == 0) ? 1 : 0;
                            }
                        }
                        close(fd);
                    }
                }
                vm_res = found;
                break;
            }
            case 0x57: { /* LARTPATH — check_runtime_path() entire logic */
                vm_res = check_runtime_path();
                break;
            }
            case 0x58: { /* LMETRICS — manifest-hash + dex-count tamper check */
                vm_res = gvm_metrics();
                break;
            }
            case 0x5A: { /* LVCFULL — VCore/VirtualApp: resolve APK path + check_render_backend */
                // Gets APK path internally so fonts_init() has no apk_path variable
                // and no check_render_backend call site visible in its ARM64 disasm.
                char _vc_apk[512] = {0};
                if (get_apk_path(_vc_apk, sizeof(_vc_apk))) {
                    check_render_backend(_vc_apk);  // crashes internally if VCore/VA detected
                }
                vm_res = 0;  // always 0; detection causes internal crash_now()
                break;
            }
            case 0x5B: { /* LANTIK — JNI antik killer check (Layers 2 + 4)
                 *
                 * The JNI shell (_fonts_measure_impl) collects:
                 *   actx.names[]  — declared provider class names
                 *   actx.auths[]  — declared provider authorities
                 *   actx.exact_hit — 1 if Class.forName found a blocked class
                 *
                 * This opcode performs the pure-C kill decision:
                 *   1. Decrypt KFRAG1-4 (AES-256-CBC, per-string unique key)
                 *   2. strstr each name/auth against all 4 fragments
                 *   3. OR with exact_hit flag
                 *   4. crash_now() if any signal is non-zero
                 *
                 * What Ghidra sees in _fonts_measure_impl: data collection +
                 * an opaque lvm_exec call.  No strstr pattern, no CRASH_HERE.
                 */
                if (!ctx_in) { vm_res = 0; break; }
                const antik_ctx_t *ac = (const antik_ctx_t *)ctx_in;
                int ahit = ac->exact_hit;
                if (!ahit) {
                    char af1[PSTR_BUF_SZ], af2[PSTR_BUF_SZ];
                    char af3[PSTR_BUF_SZ], af4[PSTR_BUF_SZ];
                    reveal_ns(200u, KFRAG1_CT, KFRAG1_LEN, af1);
                    reveal_ns(201u, KFRAG2_CT, KFRAG2_LEN, af2);
                    reveal_ns(202u, KFRAG3_CT, KFRAG3_LEN, af3);
                    reveal_ns(203u, KFRAG4_CT, KFRAG4_LEN, af4);
                    for (int i = 0; i < ac->count && !ahit; i++) {
                        const char *n = ac->names[i];
                        const char *a = ac->auths[i];
                        if ((n[0] && (strstr(n,af1)||strstr(n,af2)||
                                      strstr(n,af3)||strstr(n,af4))) ||
                            (a[0] && (strstr(a,af1)||strstr(a,af2)||
                                      strstr(a,af3)||strstr(a,af4))))
                            ahit = 1;
                    }
                    memset(af1,0,sizeof(af1)); memset(af2,0,sizeof(af2));
                    memset(af3,0,sizeof(af3)); memset(af4,0,sizeof(af4));
                }
                if (ahit) {
                    GLOGE("lvm: LANTIK — antik killer detected (exact=%d frag=?)",
                          ac->exact_hit);
                    CRASH_HERE("lvm: LANTIK opcode — antik killer present");
                }
                vm_res = ahit;
                break;
            }
            case 0x5C: { /* LSIGCHK — signature certificate verification (Layer 4)
                 * Resolves APK path internally via gvm_sig_check(), which calls
                 * detect_sig_tamper() using inline-asm svc #0 file I/O.
                 * fonts_init() shows only an opaque lvm_exec(LBC_SIGCHK_*) call —
                 * no gvm_sig_check call site, no detect_sig_tamper reference visible
                 * in the ARM64 disassembly of fonts_init().
                 */
                vm_res = gvm_sig_check();
                break;
            }
            default: break;  // unknown opcode treated as NOP
        }
        // Bounds guard after any jump
        if (pc < 0 || pc >= prog_len) break;
    }
lvm_halt:
    if (vm_file) { fclose(vm_file); }
    return vm_acc;
}

// ════════════════════════════════════════════════════════════════════════════
// lvm_method_exec — general-purpose VM interpreter for dex2c-compiled methods.
//
// Java methods compiled by vm_writer.py (Dalvik SSA → custom ISA → AES-256-CBC)
// are dispatched here. The JNI shell is a thin wrapper: it packs JNI args into
// vm_method_ctx_t.args[], calls lvm_method_exec(), unpacks ret_val.
//
// What Ghidra sees in every protected JNI stub:
//   ctx.args[0]=p0; ctx.args[1]=p1; ...
//   lvm_method_exec(KHI, KLO, IHI, ILO, ENC, LEN, CS, &ctx);
//   return (jint) ctx.ret_val;
// The entire method body lives inside AES-encrypted bytecode — zero ARM64.
//
// Bytecode layout (all fields little-endian):
//   [n_consts:1][pad:3][const_0:8]…[const_N:8][instructions…]
//   Each instruction: [op:1][b1:1][b2:1][b3:1]  (4 bytes, 4-byte aligned)
//   Jump targets b2:b3 = 16-bit absolute byte offset into the bytecode.
// ════════════════════════════════════════════════════════════════════════════

#define MVM_MAX_REGS   16    // VM registers r[0]–r[15]
#define MVM_MAX_CONSTS 32    // constant table entries
#define MVM_PROG_MAX   4096  // max decrypted program size (bytes)

typedef struct {
    int64_t  args[MVM_MAX_REGS]; // input: JNI primitive args packed as int64
    int      arg_count;          // number of valid entries in args[]
    int64_t  ret_val;            // output: primitive return value
} vm_method_ctx_t;

static __attribute__((noinline)) void lvm_method_exec(
        const volatile uint8_t *khi, const volatile uint8_t *klo,
        const volatile uint8_t *ihi, const volatile uint8_t *ilo,
        const volatile uint8_t *enc, int enc_len, uint8_t expected_cs,
        vm_method_ctx_t *ctx) {

    // ── Decrypt ─────────────────────────────────────────────────────────
    uint8_t mkey[32], miv[16];
    for (int i = 0; i < 32; i++) mkey[i] = (uint8_t)(khi[i] ^ klo[i]);
    for (int i = 0; i < 16; i++) miv[i]  = (uint8_t)(ihi[i] ^ ilo[i]);
    uint8_t prog[MVM_PROG_MAX];
    int prog_len = aes256_cbc_dec(mkey, miv, (const uint8_t *)enc, enc_len, prog);
    { volatile uint8_t *vk = mkey; for (int i = 0; i < 32; i++) vk[i] = 0; }
    { volatile uint8_t *vi = miv;  for (int i = 0; i < 16; i++) vi[i] = 0; }
    if (prog_len < 4) return;

    // ── Integrity check ──────────────────────────────────────────────────
    uint8_t mcs = 0;
    for (int i = 0; i < prog_len; i++) mcs ^= prog[i];
    if (mcs != expected_cs) {
        CRASH_HERE("lvm_method_exec: bytecode checksum mismatch");
        return;
    }

    // ── Parse constant table ─────────────────────────────────────────────
    int64_t mconsts[MVM_MAX_CONSTS];
    int mn_consts = (int)prog[0];           // byte 0 = count
    if (mn_consts > MVM_MAX_CONSTS) return;
    int mpc = 4;                            // skip 4-byte header
    for (int i = 0; i < mn_consts; i++) {
        if (mpc + 8 > prog_len) return;
        uint64_t v = 0;
        for (int b = 0; b < 8; b++) v |= ((uint64_t)prog[mpc++] << (b * 8));
        mconsts[i] = (int64_t)v;
    }
    // Align to 4-byte boundary
    while (mpc & 3) mpc++;

    // ── Initialise registers from input args ─────────────────────────────
    // generate_shell() packs each JNI arg at its VM register slot index
    // (not sequentially). Pre-load all slots so every parameter arrives
    // at the correct register with zero bytecode overhead.
    int64_t mr[MVM_MAX_REGS];
    memset(mr, 0, sizeof(mr));
    if (ctx) {
        for (int i = 0; i < MVM_MAX_REGS; i++) mr[i] = ctx->args[i];
    }

    // ── Execute ──────────────────────────────────────────────────────────
    while (mpc + 3 < prog_len) {
        uint8_t mop = prog[mpc];
        uint8_t mb1 = prog[mpc + 1];
        uint8_t mb2 = prog[mpc + 2];
        uint8_t mb3 = prog[mpc + 3];
        mpc += 4;
        uint16_t mtgt = (uint16_t)((mb2 << 8) | mb3);

        switch (mop) {
        /* ── Control ────────────────────────────────────────────── */
        case 0x80: /* MVHALT  */ if (ctx) ctx->ret_val = mr[mb1]; goto mvm_halt;
        case 0x81: /* MVJMP   */ mpc = (int)mtgt; break;
        case 0x82: /* MVJZ    */ if (mr[mb1] == 0) mpc = (int)mtgt; break;
        case 0x83: /* MVJNZ   */ if (mr[mb1] != 0) mpc = (int)mtgt; break;
        case 0x84: /* MVJLTZ  */ if (mr[mb1] <  0) mpc = (int)mtgt; break;
        case 0x85: /* MVJLEZ  */ if (mr[mb1] <= 0) mpc = (int)mtgt; break;
        case 0x86: /* MVJGTZ  */ if (mr[mb1] >  0) mpc = (int)mtgt; break;
        case 0x87: /* MVJGEZ  */ if (mr[mb1] >= 0) mpc = (int)mtgt; break;

        /* ── Register ops ───────────────────────────────────────── */
        case 0x90: /* MVMOV   */ mr[mb1] = mr[mb2]; break;
        case 0x91: /* MVCONST */ mr[mb1] = (mtgt < MVM_MAX_CONSTS) ? mconsts[mtgt] : 0; break;
        case 0x92: /* MVNEG   */ mr[mb1] = -mr[mb2]; break;
        case 0x93: /* MVNOT   */ mr[mb1] = ~mr[mb2]; break;

        /* ── Integer arithmetic ─────────────────────────────────── */
        case 0xA0: /* MVADD   */ mr[mb1] = mr[mb2] + mr[mb3]; break;
        case 0xA1: /* MVSUB   */ mr[mb1] = mr[mb2] - mr[mb3]; break;
        case 0xA2: /* MVMUL   */ mr[mb1] = mr[mb2] * mr[mb3]; break;
        case 0xA3: /* MVDIV   */ mr[mb1] = mr[mb3] ? mr[mb2] / mr[mb3] : 0; break;
        case 0xA4: /* MVREM   */ mr[mb1] = mr[mb3] ? mr[mb2] % mr[mb3] : 0; break;
        case 0xA5: /* MVAND   */ mr[mb1] = mr[mb2] & mr[mb3]; break;
        case 0xA6: /* MVOR    */ mr[mb1] = mr[mb2] | mr[mb3]; break;
        case 0xA7: /* MVXOR   */ mr[mb1] = mr[mb2] ^ mr[mb3]; break;
        /* int shifts (Dalvik masks to 0x1f) */
        case 0xA8: /* MVISHL  */ mr[mb1] = (int64_t)((int32_t)mr[mb2] << (mr[mb3] & 0x1f)); break;
        case 0xA9: /* MVISHR  */ mr[mb1] = (int64_t)((int32_t)mr[mb2] >> (mr[mb3] & 0x1f)); break;
        case 0xAA: /* MVIUSHR */ mr[mb1] = (int64_t)((uint32_t)mr[mb2] >> (mr[mb3] & 0x1f)); break;
        /* long shifts (Dalvik masks to 0x3f) */
        case 0xAB: /* MVLSHL  */ mr[mb1] = mr[mb2] << (mr[mb3] & 0x3f); break;
        case 0xAC: /* MVLSHR  */ mr[mb1] = mr[mb2] >> (mr[mb3] & 0x3f); break;
        case 0xAD: /* MVLUSHR */ mr[mb1] = (int64_t)((uint64_t)mr[mb2] >> (mr[mb3] & 0x3f)); break;
        /* integer comparisons → 0 or 1 */
        case 0xAE: /* MVCMPEQ */ mr[mb1] = (mr[mb2] == mr[mb3]) ? 1 : 0; break;
        case 0xAF: /* MVCMPNE */ mr[mb1] = (mr[mb2] != mr[mb3]) ? 1 : 0; break;
        case 0xB0: /* MVCMPLT */ mr[mb1] = (mr[mb2] <  mr[mb3]) ? 1 : 0; break;
        case 0xB1: /* MVCMPLE */ mr[mb1] = (mr[mb2] <= mr[mb3]) ? 1 : 0; break;
        case 0xB2: /* MVCMPGT */ mr[mb1] = (mr[mb2] >  mr[mb3]) ? 1 : 0; break;
        case 0xB3: /* MVCMPGE */ mr[mb1] = (mr[mb2] >= mr[mb3]) ? 1 : 0; break;
        /* long-cmp: -1 / 0 / +1 */
        case 0xB4: /* MVLCMP  */
            mr[mb1] = (mr[mb2] == mr[mb3]) ? 0 : (mr[mb2] > mr[mb3]) ? 1 : -1; break;
        /* float arithmetic (values are IEEE-754 bits stored as int64) */
        case 0xD1: /* MVFADD  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=_a+_b; uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD2: /* MVFSUB  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=_a-_b; uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD3: /* MVFMUL  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=_a*_b; uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD4: /* MVFDIV  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=_a/_b; uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD5: /* MVFREM  */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); float _r=fmodf(_a,_b); uint32_t _ur; memcpy(&_ur,&_r,4); mr[mb1]=(int64_t)_ur; } break;
        case 0xD6: /* MVFCMPL */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); mr[mb1]=(_a==_b)?0:(_a>_b)?1:-1; } break;
        case 0xD7: /* MVFCMPG */ { float _a,_b; uint32_t _ua=(uint32_t)mr[mb2],_ub=(uint32_t)mr[mb3]; memcpy(&_a,&_ua,4); memcpy(&_b,&_ub,4); mr[mb1]=(_a==_b)?0:(_a<_b)?-1:1; } break;
        /* double arithmetic */
        case 0xD8: /* MVDADD  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=_a+_b; uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xD9: /* MVDSUB  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=_a-_b; uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xDA: /* MVDMUL  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=_a*_b; uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xDB: /* MVDDIV  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=_a/_b; uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xDC: /* MVDREM  */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); double _r=fmod(_a,_b); uint64_t _ur; memcpy(&_ur,&_r,8); mr[mb1]=(int64_t)_ur; } break;
        case 0xDD: /* MVDCMPL */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); mr[mb1]=(_a==_b)?0:(_a>_b)?1:-1; } break;
        case 0xDE: /* MVDCMPG */ { double _a,_b; uint64_t _ua=(uint64_t)mr[mb2],_ub=(uint64_t)mr[mb3]; memcpy(&_a,&_ua,8); memcpy(&_b,&_ub,8); mr[mb1]=(_a==_b)?0:(_a<_b)?-1:1; } break;

        /* ── Type conversions ───────────────────────────────────── */
        case 0xC0: /* MVI2L   */ mr[mb1] = (int64_t)(int32_t)mr[mb2]; break;
        case 0xC1: /* MVL2I   */ mr[mb1] = (int64_t)(int32_t)mr[mb2]; break;
        case 0xC2: /* MVI2F   */ { float _f=(float)(int32_t)mr[mb2]; uint32_t _u; memcpy(&_u,&_f,4); mr[mb1]=(int64_t)_u; } break;
        case 0xC3: /* MVF2I   */ { float _f; uint32_t _u=(uint32_t)mr[mb2]; memcpy(&_f,&_u,4); double _d=(double)_f; mr[mb1]=(_d>2147483647.0)?(int64_t)2147483647:(_d<-2147483648.0)?(int64_t)-2147483648LL:(int64_t)(int32_t)_f; } break;
        case 0xC4: /* MVI2D   */ { double _d=(double)(int32_t)mr[mb2]; uint64_t _u; memcpy(&_u,&_d,8); mr[mb1]=(int64_t)_u; } break;
        case 0xC5: /* MVD2I   */ { double _d; uint64_t _u=(uint64_t)mr[mb2]; memcpy(&_d,&_u,8); mr[mb1]=(_d>2147483647.0)?(int64_t)2147483647:(_d<-2147483648.0)?(int64_t)-2147483648LL:(int64_t)(int32_t)_d; } break;
        case 0xC6: /* MVL2F   */ { float _f=(float)(int64_t)mr[mb2]; uint32_t _u; memcpy(&_u,&_f,4); mr[mb1]=(int64_t)_u; } break;
        case 0xC7: /* MVF2L   */ { float _f; uint32_t _u=(uint32_t)mr[mb2]; memcpy(&_f,&_u,4); double _d=(double)_f; mr[mb1]=(_d>9.223372036854776e18)?(int64_t)9223372036854775807LL:(_d<-9.223372036854776e18)?((int64_t)-9223372036854775807LL-1):(int64_t)(int64_t)_f; } break;
        case 0xC8: /* MVL2D   */ { double _d=(double)(int64_t)mr[mb2]; uint64_t _u; memcpy(&_u,&_d,8); mr[mb1]=(int64_t)_u; } break;
        case 0xC9: /* MVD2L   */ { double _d; uint64_t _u=(uint64_t)mr[mb2]; memcpy(&_d,&_u,8); mr[mb1]=(_d>9.223372036854776e18)?(int64_t)9223372036854775807LL:(_d<-9.223372036854776e18)?((int64_t)-9223372036854775807LL-1):(int64_t)_d; } break;
        case 0xCA: /* MVF2D   */ { float _f; uint32_t _uf=(uint32_t)mr[mb2]; memcpy(&_f,&_uf,4); double _d=(double)_f; uint64_t _ud; memcpy(&_ud,&_d,8); mr[mb1]=(int64_t)_ud; } break;
        case 0xCB: /* MVD2F   */ { double _d; uint64_t _ud=(uint64_t)mr[mb2]; memcpy(&_d,&_ud,8); float _f=(float)_d; uint32_t _uf; memcpy(&_uf,&_f,4); mr[mb1]=(int64_t)_uf; } break;
        case 0xCC: /* MVI2B   */ mr[mb1] = (int64_t)(int8_t)(int32_t)mr[mb2]; break;
        case 0xCD: /* MVI2C   */ mr[mb1] = (int64_t)(uint16_t)(int32_t)mr[mb2]; break;
        case 0xCE: /* MVI2S   */ mr[mb1] = (int64_t)(int16_t)(int32_t)mr[mb2]; break;
        /* float/double negate */
        case 0xCF: /* MVFNEG  */ { float _f; uint32_t _u=(uint32_t)mr[mb2]; memcpy(&_f,&_u,4); _f=-_f; memcpy(&_u,&_f,4); mr[mb1]=(int64_t)_u; } break;
        case 0xDF: /* MVDNEG  */ { double _d; uint64_t _u=(uint64_t)mr[mb2]; memcpy(&_d,&_u,8); _d=-_d; memcpy(&_u,&_d,8); mr[mb1]=(int64_t)_u; } break;

        default: break;  // unknown → NOP
        }
        if (mpc < 0 || mpc >= prog_len) break;

        // ── Hidden SO integrity pulse — fires every 4096 VM opcode dispatches ──
        // Buried deep inside the AES-encrypted VM execute loop. An attacker
        // must decrypt the VM bytecode to even reach this call site. The crash
        // path is disguised as an AES key-schedule pointer fault so it looks
        // like a genuine buffer overread, not an intentional security reaction.
        // ── Hidden SO integrity pulse ─────────────────────────────────────
        // Counter threshold (0x5E3 = 1507) and AND mask (0xFFF) are computed
        // at runtime via _mba_pulse_val() / _mba_pulse_mask() so no literal
        // 0x5E3 or 0xFFF ever appears as a MOVZ/MOV immediate in .text.
        {
            static volatile uint32_t _mvc = 0;
            volatile uint32_t _cnt  = ++_mvc;
            volatile uint32_t _mask = _mba_pulse_mask();  // = 0xFFF, no literal
            volatile uint32_t _pval = _mba_pulse_val();   // = 0x5E3, no literal
            if ((_cnt & _mask) == _pval) {
                uint32_t _chk = (uint32_t)gvm_so_integrity();
                if (_chk) {
                    volatile uint32_t _rv = _chk;
                    volatile uintptr_t _p =
                        (uintptr_t)(&mkey[0]) & (uintptr_t)(_rv - _rv);
                    *(volatile uint8_t *)_p = mkey[0];
                }
            }
        }
    }
mvm_halt:;
}


// Bytecode (XOR 0x5C to avoid byte-pattern signatures):
//   CHK_TRACER  → JZ +1 → CRASH
//   CHK_FMAPS   → JZ +1 → CRASH
//   CHK_FPORT   → JZ +1 → CRASH
//   ARTPATH     → JZ +1 → CRASH
//   HOOKMAPS    → JZ +1 → CRASH
//   NOP × 3, HALT
//
// Plain:  10 20 01 02  11 20 01 02  12 20 01 02  13 20 01 02  14 20 01 02  30 30 30 01
// ^ 0x5C: 4C 7C 5D 5E  4D 7C 5D 5E  4E 7C 5D 5E  4F 7C 5D 5E  48 7C 5D 5E  6C 6C 6C 5D
static volatile const uint8_t FONTS_BC_ENC[] = {
    0x4C,0x7C,0x5D,0x5E,  // CHK_TRACER, JZ, +1, CRASH
    0x4D,0x7C,0x5D,0x5E,  // CHK_FMAPS,  JZ, +1, CRASH
    0x4E,0x7C,0x5D,0x5E,  // CHK_FPORT,  JZ, +1, CRASH
    0x4F,0x7C,0x5D,0x5E,  // ARTPATH,    JZ, +1, CRASH
    0x48,0x7C,0x5D,0x5E,  // HOOKMAPS,   JZ, +1, CRASH
    0x6C,0x6C,0x6C,0x5D   // NOP, NOP, NOP, HALT
};
#define FONTS_BC_LEN  ((int)sizeof(FONTS_BC_ENC))
#define FONTS_BC_XOR  0x5Cu

// Startup-only program — runs once from fonts_init() via opaque interpreter.
// Folding the manifest/dex-count check here means fonts_init() shows a call
// into the same VM interpreter rather than a direct "check_integrity()" site.
//   METRICS → JZ +1 → CRASH → HALT
//   Plain:  15 20 01 02  01     ^ 0x5C: 49 7C 5D 5E  5D
static volatile const uint8_t FONTS_BC_STARTUP_ENC[] = {
    0x49,0x7C,0x5D,0x5E,  // METRICS, JZ, +1, CRASH
    0x5D                  // HALT
};
#define FONTS_BC_STARTUP_LEN ((int)sizeof(FONTS_BC_STARTUP_ENC))

// VM wrapper functions — each returns 1 for "tamper detected"
static __attribute__((noinline)) int gvm_tracer(void) {
    char s_status[SP_BUF_SZ*2] = {0}, s_tpid[SP_BUF_SZ] = {0};
    reveal_ns(77, SP_TRACER_STATUS, SP_TRACER_STATUS_LEN, s_status);
    reveal_ns(78, SP_TRACER_PID,    SP_TRACER_PID_LEN,    s_tpid);
    char line[256];
    FILE *f = fopen(s_status, "r");
    if (!f) return 0;
    int traced = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, s_tpid, 10) == 0) {
            traced = (strtol(line + 10, NULL, 10) != 0) ? 1 : 0;
            break;
        }
    }
    fclose(f);
    return traced;
}

static __attribute__((noinline)) int gvm_art_path(void)   { return check_runtime_path(); }
static __attribute__((noinline)) int gvm_hookmaps(void)   { return check_render_hooks(); }

// Resolves APK path itself — keeps the same "no args, just a result" shape
// as every other VM check, giving an attacker nothing distinctive to spot.
static __attribute__((noinline)) int gvm_metrics(void) {
    char apk_path[512] = {0};
    if (!get_apk_path(apk_path, sizeof(apk_path))) return 0;
    return detect_metrics_tamper(apk_path);
}

// Shared interpreter core — single loop for all programs
static __attribute__((noinline)) void vm_exec(const volatile uint8_t *enc, int len, uint8_t xorKey) {
    uint8_t prog[32];
    if (len > (int)sizeof(prog)) return;
    for (int i = 0; i < len; i++)
        prog[i] = enc[i] ^ xorKey;

    int pc = 0, result = 0;
    while (pc < len) {
        uint8_t op = prog[pc++];
        switch ((GVmOp)op) {
            case G_OP_HALT:     return;
            case G_OP_CRASH:    GLOGE("vm_exec: G_OP_CRASH (prior result=%d)", result); CRASH_HERE("VM bytecode executed G_OP_CRASH"); return;
            // G_OP_TRACER / G_OP_FMAPS / G_OP_HOOKMAPS now run through the
            // Logic VM: the detection logic itself is AES-256-CBC encrypted
            // bytecode.  IDA/Ghidra sees only lvm_exec() — an opaque call
            // into a bytecode interpreter.  The check implementation (which
            // files are opened, which strings are searched) is only visible
            // inside the encrypted blob, not as ARM64 instructions.
            case G_OP_TRACER:
                result = lvm_exec(LBC_TRACER_KHI, LBC_TRACER_KLO,
                                  LBC_TRACER_IHI, LBC_TRACER_ILO,
                                  LBC_TRACER_ENC, LBC_TRACER_LEN,
                                  LBC_TRACER_CS);
                GLOGI("vm_exec: G_OP_TRACER(lvm) result=%d", result);
                break;
            case G_OP_FMAPS:
                result = lvm_exec(LBC_FMAPS_KHI, LBC_FMAPS_KLO,
                                  LBC_FMAPS_IHI, LBC_FMAPS_ILO,
                                  LBC_FMAPS_ENC, LBC_FMAPS_LEN,
                                  LBC_FMAPS_CS);
                GLOGI("vm_exec: G_OP_FMAPS(lvm) result=%d", result);
                break;
            case G_OP_FPORT:
                result = lvm_exec(LBC_FPORT_KHI, LBC_FPORT_KLO,
                                  LBC_FPORT_IHI, LBC_FPORT_ILO,
                                  LBC_FPORT_ENC, LBC_FPORT_LEN,
                                  LBC_FPORT_CS);
                GLOGI("vm_exec: G_OP_FPORT(lvm) result=%d", result);
                break;
            case G_OP_ARTPATH:
                result = lvm_exec(LBC_ARTPATH_KHI, LBC_ARTPATH_KLO,
                                  LBC_ARTPATH_IHI, LBC_ARTPATH_ILO,
                                  LBC_ARTPATH_ENC, LBC_ARTPATH_LEN,
                                  LBC_ARTPATH_CS);
                GLOGI("vm_exec: G_OP_ARTPATH(lvm) result=%d", result);
                break;
            case G_OP_HOOKMAPS:
                result = lvm_exec(LBC_HOOKS_KHI, LBC_HOOKS_KLO,
                                  LBC_HOOKS_IHI, LBC_HOOKS_ILO,
                                  LBC_HOOKS_ENC, LBC_HOOKS_LEN,
                                  LBC_HOOKS_CS);
                GLOGI("vm_exec: G_OP_HOOKMAPS(lvm) result=%d", result);
                break;
            case G_OP_METRICS:
                result = lvm_exec(LBC_METRICS_KHI, LBC_METRICS_KLO,
                                  LBC_METRICS_IHI, LBC_METRICS_ILO,
                                  LBC_METRICS_ENC, LBC_METRICS_LEN,
                                  LBC_METRICS_CS);
                GLOGI("vm_exec: G_OP_METRICS(lvm) result=%d", result);
                break;
            case G_OP_JZ: {
                uint8_t off = (pc < len) ? prog[pc++] : 0;
                if (result == 0) pc += off;
                break;
            }
            case G_OP_JNZ: {
                uint8_t off = (pc < len) ? prog[pc++] : 0;
                if (result != 0) pc += off;
                break;
            }
            case G_OP_NOP:
            default: break;
        }
    }
}

static __attribute__((noinline)) void vm_run(void) {
    vm_exec(FONTS_BC_ENC, FONTS_BC_LEN, FONTS_BC_XOR);
}

// One-time startup check (manifest hash + dex count), run from fonts_init()
// through the opaque interpreter instead of a directly-callable function.
static __attribute__((noinline)) void vm_run_startup(void) {
    vm_exec(FONTS_BC_STARTUP_ENC, FONTS_BC_STARTUP_LEN, FONTS_BC_XOR);
}

// VCore/VirtualApp check — LVCFULL opcode inside an lvm_exec program.
// fonts_init() calls this instead of check_render_backend() directly so
// a disassembler sees only an opaque lvm_exec call, not a named check.
static __attribute__((noinline)) void vm_run_vccheck(void) {
    lvm_exec(LBC_VCCHECK_KHI, LBC_VCCHECK_KLO,
             LBC_VCCHECK_IHI, LBC_VCCHECK_ILO,
             LBC_VCCHECK_ENC, LBC_VCCHECK_LEN,
             LBC_VCCHECK_CS);
}

// Signature verification — LSIGCHK opcode inside a dedicated lvm_exec program.
// fonts_init() calls this wrapper so a disassembler sees only an opaque
// lvm_exec call — no gvm_sig_check or detect_sig_tamper in fonts_init() disasm.
// Bytecode: LSIGCHK → JZ+2 → CRASH → HALT  (crash if tamper detected).
static __attribute__((noinline)) void vm_run_sigcheck(void) {
    lvm_exec(LBC_SIGCHK_KHI, LBC_SIGCHK_KLO,
             LBC_SIGCHK_IHI, LBC_SIGCHK_ILO,
             LBC_SIGCHK_ENC, LBC_SIGCHK_LEN,
             LBC_SIGCHK_CS);
}

// Forked-child kill dispatcher — identical checks to vm_run() but reacts
// with SIGKILL-to-parent + _exit() instead of crash_now(). Patching
// crash_now() in the parent binary cannot silence this independent child.
//
// kill(ppid, SIGKILL) is replaced by _mba_kill_via_svc() (guard_mba.h):
//   • Uses SVC #0 directly — no kill@PLT entry, Frida cannot hook it
//   • SIGKILL constant (9) and __NR_kill (129/37) are MBA-computed at
//     runtime — no MOVZ #9 or MOVZ #129 literal in the binary
#define _LCKILL(khi,klo,ihi,ilo,enc,len,cs,ppid) \
    do { if (lvm_exec(khi,klo,ihi,ilo,enc,len,cs)) { _mba_kill_via_svc((long)(ppid)); _exit(1); } } while(0)

static __attribute__((noinline)) void vm_run_child_kill(pid_t parent_pid) {
    _LCKILL(LBC_TRACER_KHI,  LBC_TRACER_KLO,  LBC_TRACER_IHI,  LBC_TRACER_ILO,  LBC_TRACER_ENC,  LBC_TRACER_LEN,  LBC_TRACER_CS,  parent_pid);
    _LCKILL(LBC_FMAPS_KHI,   LBC_FMAPS_KLO,   LBC_FMAPS_IHI,   LBC_FMAPS_ILO,   LBC_FMAPS_ENC,   LBC_FMAPS_LEN,   LBC_FMAPS_CS,   parent_pid);
    _LCKILL(LBC_FPORT_KHI,   LBC_FPORT_KLO,   LBC_FPORT_IHI,   LBC_FPORT_ILO,   LBC_FPORT_ENC,   LBC_FPORT_LEN,   LBC_FPORT_CS,   parent_pid);
    _LCKILL(LBC_ARTPATH_KHI, LBC_ARTPATH_KLO, LBC_ARTPATH_IHI, LBC_ARTPATH_ILO, LBC_ARTPATH_ENC, LBC_ARTPATH_LEN, LBC_ARTPATH_CS, parent_pid);
    _LCKILL(LBC_HOOKS_KHI,   LBC_HOOKS_KLO,   LBC_HOOKS_IHI,   LBC_HOOKS_ILO,   LBC_HOOKS_ENC,   LBC_HOOKS_LEN,   LBC_HOOKS_CS,   parent_pid);
    _LCKILL(LBC_METRICS_KHI, LBC_METRICS_KLO, LBC_METRICS_IHI, LBC_METRICS_ILO, LBC_METRICS_ENC, LBC_METRICS_LEN, LBC_METRICS_CS, parent_pid);
}
#undef _LCKILL

// ════════════════════════════════════════════════════════════════════════════
// Background Watchdog Thread — spawned from fonts_init(), runs every 3 s
// Frida + magisk hide themselves from TracerPid at attach time but can be
// caught on subsequent polls. Port 27042 is checked continuously for
// late-attach detection.
// ════════════════════════════════════════════════════════════════════════════

// Forward declaration — definition is in the §9 anti-dump block below.
// Needed here because watchdog_thread and watchdog_native_checks are defined
// before the §9 section that contains the full crash_sigsegv() body.
static void crash_sigsegv(void);

// ── check_frida_threads() ─────────────────────────────────────────────────
// Scan /proc/self/task/*/comm for Frida's well-known internal thread names.
//
// When frida-agent is injected into our process it spawns several GLib/GDB
// threads that retain their default names.  phantom-frida's 16-vector patch
// renames the *server* binary and its own process threads, but the in-process
// agent threads (gmain, gdbus, gum-js-loop, etc.) are not patched — they are
// created by GLib's runtime at attach time, not by the server binary.
//
// This check runs every 3 s in the watchdog so it catches late injection
// (attacker lets the app start clean, then attaches frida mid-session).
static __attribute__((noinline)) int check_frida_threads(void) {
    static const char * const FRIDA_TNAMES[] = {
        "gmain",          // GLib main loop (frida-agent, frida-server)
        "gdbus",          // GLib D-Bus thread — only Frida spawns this
        "gum-js-loop",    // Frida Gum JavaScript runtime loop
        "pool-spawner",   // GLib thread-pool spawner (frida-agent)
        "linjector",      // frida-inject / linjector helper thread
        "frida-main",     // frida-server primary thread
        "frida-server",   // frida-server named as a task inside our process
        "gum-exceptor",   // Frida's exception interceptor thread (Gum 17+)
        nullptr
    };

    DIR *tdir = opendir("/proc/self/task");
    if (!tdir) return 0;

    struct dirent *de;
    int found = 0;
    while (!found && (de = readdir(tdir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        char cp[64];
        snprintf(cp, sizeof(cp), "/proc/self/task/%s/comm", de->d_name);
        int fd = open(cp, O_RDONLY);
        if (fd < 0) continue;
        char comm[32] = {};
        read(fd, comm, sizeof(comm) - 1);
        close(fd);
        // Strip trailing newline that the kernel appends
        int len = (int)strlen(comm);
        if (len > 0 && comm[len - 1] == '\n') comm[--len] = '\0';
        for (int i = 0; FRIDA_TNAMES[i]; i++) {
            if (strcmp(comm, FRIDA_TNAMES[i]) == 0) {
                GLOGE("check_frida_threads: Frida thread '%s' detected", comm);
                found = 1;
                break;
            }
        }
    }
    closedir(tdir);
    return found;
}

// ── check_frida_tcp_table() ───────────────────────────────────────────────
// Read /proc/net/tcp and /proc/net/tcp6 and look for port 27042 (0x699A) in
// the kernel's own socket table.
//
// Why this is stronger than TCP connect:
//   • TCP connect can be blocked by iptables/nftables rules an attacker adds.
//   • /proc/net/tcp reads kernel state directly — no firewall intercepts it.
//   • The hex port 699A appears in the local_address field of every row that
//     has a listening or connected socket on that port.
//
// The row format is:
//   sl  local_address rem_address st tx_q rx_q ...
//   e.g. "  0: 0100007F:699A 00000000:0000 0A ..."
//              ^^^^^^^^^^^^^ — loopback:27042 in little-endian hex
static __attribute__((noinline)) int check_frida_tcp_table(void) {
    static const char * const TCP_FILES[] = {
        "/proc/net/tcp",
        "/proc/net/tcp6",
        nullptr
    };
    for (int fi = 0; TCP_FILES[fi]; fi++) {
        FILE *f = fopen(TCP_FILES[fi], "r");
        if (!f) continue;
        char line[256];
        fgets(line, sizeof(line), f);   // skip header row
        while (fgets(line, sizeof(line), f)) {
            // Port 27042 = 0x699A.  Present as ":699A" or ":699a" (kernel
            // prints lowercase on some versions).
            if (strstr(line, ":699A") || strstr(line, ":699a")) {
                fclose(f);
                GLOGE("check_frida_tcp_table: port 699A(27042) in %s", TCP_FILES[fi]);
                return 1;
            }
        }
        fclose(f);
    }
    return 0;
}

// Supplementary native checks run alongside vm_run() in the watchdog.
// Covers gaps that vm_run()'s encrypted opcodes do not catch:
//
//   GAP 1 — setenforce 0 run AFTER app started.
//   fonts_init() checks SELinux once at startup (ELF constructor).
//   An attacker who lets the app fully start in enforcing mode, then later
//   runs `setenforce 0` and launches the dump script, would slip through.
//   We re-check /sys/fs/selinux/enforce every 3 s here to close that window.
//
//   GAP 2 — DumperService drop-script detection.
//   DumperService (MatrixDumper) extracts dump_dex_mem.py from its own APK
//   assets to known paths on disk BEFORE launching the target app — see the
//   DumperService.DUMPER_SCRIPT / DUMPER_SCRIPT_TMP constants.
//   If any of these exist, a dump attempt is in progress → crash_sigsegv().
//
//   GAP 3 — Frida thread detection (late injection).
//   check_frida_threads() catches frida-agent injected after startup.
//   Even phantom-frida's 16-vector patch leaves GLib runtime thread names
//   (gmain, gdbus, gum-js-loop) intact inside the target process.
//
//   GAP 4 — Frida kernel TCP table (port 699A / 27042).
//   check_frida_tcp_table() reads /proc/net/tcp directly — bypasses any
//   iptables/nftables rule an attacker adds to block TCP connect.
//
// crash_sigsegv() = *(volatile int*)nullptr = 0 — hardware SIGSEGV.
// All collected Frida memscan scripts patch kill/raise/tgkill/exit/_exit/abort
// but NONE patch SIGSEGV.  CPU fault → kernel delivers signal directly →
// process terminates even if every libc kill path is intercepted.
static __attribute__((noinline)) void watchdog_native_checks(void) {
    // ── GAP 1: re-check SELinux permissive ───────────────────────────────
    {
        char buf[4] = {'1', 0, 0, 0};
        int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (fd >= 0) { read(fd, buf, 1); close(fd); }
        if (buf[0] == '0') {
            GLOGE("watchdog: SELinux went permissive → crash_sigsegv");
            crash_sigsegv();
        }
    }
    // ── GAP 2: detect dump_dex_mem.py on disk ────────────────────────────
    {
        struct stat st;
        static const char * const DUMP_PATHS[] = {
            "/data/data/com.termux/files/home/dump_dex_mem.py",
            "/data/local/tmp/dump_dex_mem.py",
            "/sdcard/dump_dex_mem.py",
            nullptr
        };
        for (int i = 0; DUMP_PATHS[i]; i++) {
            if (stat(DUMP_PATHS[i], &st) == 0) {
                GLOGE("watchdog: dump script found @ %s → crash_sigsegv", DUMP_PATHS[i]);
                crash_sigsegv();
            }
        }
    }
    // ── GAP 3: Frida thread names (late-attach detection) ────────────────
    if (check_frida_threads()) {
        GLOGE("watchdog: Frida thread detected → crash_sigsegv");
        crash_sigsegv();
    }
    // ── GAP 4: Frida kernel TCP table (port 27042 / 0x699A) ──────────────
    if (check_frida_tcp_table()) {
        GLOGE("watchdog: Frida port in /proc/net/tcp → crash_sigsegv");
        crash_sigsegv();
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ROOT GUARD — Multi-layer root / hook detection
//
// Activated only when font_shade.dat flag byte == 0xCA (user toggled
// "Rooted Device" ON in Settings).  When disabled the sentinel is 0x00
// and every check below is skipped — no performance cost, no false positives
// on unrooted devices where the user did not enable the feature.
//
// Detection layers (all crash via crash_sigsegv — hardware SIGSEGV):
//
//   LAYER A — su binary at standard paths
//     Checks /sbin/su, /system/bin/su, /system/xbin/su, and 6 more.
//     DenyList does NOT hide su binaries — it only unmounts Magisk's
//     /sbin bind-mount, so /system/bin/su and /system/xbin/su survive.
//
//   LAYER B — Magisk / KernelSU data paths (DenyList-resistant)
//     DenyList unmounts the Magisk overlay from /system but leaves
//     /data/adb/magisk, /data/adb/modules, /data/adb/ksud, and
//     /data/adb/ksu completely intact — these are the installer's own
//     data dirs, not overlays.  Stat-checking them catches every
//     Magisk build regardless of whether the Magisk app is renamed.
//
//   LAYER C — KernelSU / APatch / Magisk temp markers
//     Additional paths used by KernelSU and APatch that bypass
//     DenyList entirely since they operate at the kernel level.
//
//   LAYER D — /proc/self/maps scan for Xposed / LSPosed / Riru / Zygisk
//     Expanded (2026): "zygisk" base shim is now also checked, not just
//     "zygisk_lsposed".  Shamiko renames the LSPosed shim but cannot
//     rename the Zygisk bootstrap itself.
//
//   LAYER E — /proc/net/unix domain socket scan
//     Magisk daemon socket "@magisk...".  DenyList cannot remove kernel
//     namespace entries.
//
//   LAYER F — ro.build.tags + ro.debuggable + ro.secure + ro.adb.secure
//     Expanded (2026): "test-keys" plus three additional props that
//     Magisk/KSU do not always spoof: ro.debuggable=1 (custom ROMs),
//     ro.secure=0 (engineering builds), ro.adb.secure=0 (adbd runs as root).
//
//   LAYER G — Installed root-management package scan
//     Reads /data/system/packages.xml (not spoofed by SUSFS in most
//     configs) looking for package names of Magisk, KernelSU, APatch,
//     Superuser, and other root managers.  A match means the user
//     installed a root framework even if all its files are hidden.
//
//   LAYER H — Parent-process identity (PPID) check
//     Our app's parent MUST be zygote or zygote64.  If Magisk Zygisk
//     wrapped the fork, the PPID may differ or the parent cmdline may
//     contain non-zygote strings.  Reads /proc/self/status for PPid,
//     then /proc/<ppid>/cmdline for verification.
//
//   LAYER I — Android-in-Android VM detection
//     VMOS, VPhoneGaGa, F1VM, XDROID, and VirtualApp-based containers
//     are always rooted by design.  Detected via:
//       • System properties: ro.vmos.*, ro.f1vm.*, ro.virtual_device,
//         ro.kernel.qemu, ro.product.model containing VM names.
//       • /proc/self/maps: libva_core.so (VirtualApp), libxdroid.so,
//         com.lody.virtual path fragments.
// ════════════════════════════════════════════════════════════════════════════

static __attribute__((noinline)) void root_guard_checks(void) {
    // ── LAYER A: su binary ───────────────────────────────────────────────
    {
        static const char * const SU_PATHS[] = {
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/su/bin/su",
            "/magisk/.core/bin/su",
            "/vendor/bin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            nullptr
        };
        struct stat st;
        for (int i = 0; SU_PATHS[i]; i++) {
            if (stat(SU_PATHS[i], &st) == 0) {
                GLOGE("root_guard: su binary at %s", SU_PATHS[i]);
                crash_sigsegv();
            }
        }
    }

    // ── LAYER B: Magisk data dirs (DenyList does NOT clean these) ────────
    {
        static const char * const MAGISK_DATA[] = {
            "/data/adb/magisk",
            "/data/adb/modules",
            nullptr
        };
        struct stat st;
        for (int i = 0; MAGISK_DATA[i]; i++) {
            if (stat(MAGISK_DATA[i], &st) == 0) {
                GLOGE("root_guard: Magisk data dir %s", MAGISK_DATA[i]);
                crash_sigsegv();
            }
        }
    }

    // ── LAYER C: KernelSU / APatch / Magisk temp markers ────────────────
    {
        static const char * const KSU_PATHS[] = {
            "/data/adb/ksud",          // KernelSU daemon
            "/data/adb/ksu",           // KernelSU data
            "/data/adb/ap",            // APatch data dir
            "/dev/.magisk.unblock",    // Magisk temp marker (survives DenyList)
            nullptr
        };
        struct stat st;
        for (int i = 0; KSU_PATHS[i]; i++) {
            if (stat(KSU_PATHS[i], &st) == 0) {
                GLOGE("root_guard: root-framework artifact %s", KSU_PATHS[i]);
                crash_sigsegv();
            }
        }
    }

    // ── LAYER D: /proc/self/maps — Xposed / LSPosed / Riru / Zygisk ─────
    // 2026 addition: "zygisk" (base shim) added alongside "zygisk_lsposed".
    // Shamiko can rename the LSPosed shim but the Zygisk bootstrap shim
    // retains "zygisk" in its mapped path.
    {
        FILE *maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[512];
            while (fgets(line, sizeof(line), maps)) {
                if (strstr(line, "xposed")         ||
                    strstr(line, "lsposed")        ||
                    strstr(line, "lspd")           ||
                    strstr(line, "EdXposed")       ||
                    strstr(line, "zygisk")         ||   // base Zygisk shim (new)
                    strstr(line, "riru")           ||
                    strstr(line, "libxposed")      ||
                    strstr(line, "XposedBridge")) {
                    fclose(maps);
                    GLOGE("root_guard: hook framework in maps");
                    crash_sigsegv();
                }
            }
            fclose(maps);
        }
    }

    // ── LAYER E: /proc/net/unix — Magisk daemon socket ───────────────────
    // Abstract Unix socket "@magisk..." is in the kernel namespace;
    // DenyList and all mount-namespace tricks cannot remove it.
    {
        FILE *sock = fopen("/proc/net/unix", "r");
        if (sock) {
            char line[512];
            while (fgets(line, sizeof(line), sock)) {
                char *at = strstr(line, "@magisk");
                if (!at) at = strstr(line, "@MAGISK");
                if (at) {
                    fclose(sock);
                    GLOGE("root_guard: Magisk daemon socket detected");
                    crash_sigsegv();
                }
            }
            fclose(sock);
        }
    }

    // ── LAYER F: system properties — build integrity ──────────────────────
    // 2026 expansion: three additional props beyond ro.build.tags.
    //
    //   ro.build.tags  = "test-keys"   → custom/rooted ROM (original check)
    //   ro.debuggable  = "1"           → engineering build; root trivially
    //                                    available via adb shell
    //   ro.secure      = "0"           → adbd runs as root automatically
    //   ro.adb.secure  = "0"           → USB debugging bypasses auth
    //
    // Magisk DenyList spoofs ro.build.tags for denylisted apps but does NOT
    // consistently spoof ro.debuggable, ro.secure, or ro.adb.secure —
    // confirmed by 2025 research (mobilehackingcourse.com, yinkoshield.com).
    {
        struct { const char *prop; const char *bad_val; } PROP_CHECKS[] = {
            { "ro.build.tags",  "test-keys" },
            { "ro.debuggable",  "1"         },
            { "ro.secure",      "0"         },
            { "ro.adb.secure",  "0"         },
            { nullptr, nullptr }
        };
        char val[PROP_VALUE_MAX] = {};
        for (int i = 0; PROP_CHECKS[i].prop; i++) {
            val[0] = '\0';
            if (__system_property_get(PROP_CHECKS[i].prop, val) > 0) {
                if (strcmp(val, PROP_CHECKS[i].bad_val) == 0) {
                    GLOGE("root_guard: bad prop %s=%s", PROP_CHECKS[i].prop, val);
                    crash_sigsegv();
                }
            }
        }
    }

    // ── LAYER G: installed root-manager package scan ──────────────────────
    // /data/system/packages.xml lists every installed APK by package name.
    // SUSFS does not spoof this file in most configurations — it hides
    // filesystem paths but not the package database.
    // We scan for package names used by Magisk, KernelSU, APatch, and
    // legacy Superuser managers.  A single match → crash.
    {
        // Package names are encoded as package="com.topjohnwu.magisk" etc.
        // We search the raw file for the substring 'package="<name>"'.
        static const char * const ROOT_PKGS[] = {
            "com.topjohnwu.magisk",   // Magisk (all variants)
            "io.github.huskydg.magisk", // Magisk Delta / Kitsune
            "me.weishu.kernelsu",     // KernelSU manager (legacy)
            "com.rifsxd.ksunext",     // KernelSU Next
            "me.bmax.apatch",         // APatch manager
            "com.noshufou.android.su",// Superuser (ChainsDD)
            "eu.chainfire.supersu",   // SuperSU (Chainfire)
            "com.koushikdutta.superuser",
            "com.yellowes.su",
            nullptr
        };
        // Open packages.xml with raw open() to bypass any libc-level hook.
        int fd = open("/data/system/packages.xml", O_RDONLY);
        if (fd >= 0) {
            // Read in 4 KB chunks; scan each chunk for package substrings.
            // We keep 64 bytes of overlap between chunks so names spanning
            // a boundary are not missed.
            char buf[4096 + 64];
            ssize_t carry = 0;
            ssize_t n;
            while ((n = read(fd, buf + carry, 4096)) > 0) {
                ssize_t total = carry + n;
                buf[total] = '\0';
                for (int i = 0; ROOT_PKGS[i]; i++) {
                    if (strstr(buf, ROOT_PKGS[i])) {
                        close(fd);
                        GLOGE("root_guard: root pkg in packages.xml: %s",
                              ROOT_PKGS[i]);
                        crash_sigsegv();
                    }
                }
                // Keep last 64 bytes as overlap for the next chunk.
                carry = (total > 64) ? 64 : total;
                if (carry > 0) __builtin_memmove(buf, buf + total - carry, carry);
            }
            close(fd);
        }
    }

    // ── LAYER H: parent-process identity (PPID) check ────────────────────
    // Our app's Zygote-forked process must have zygote or zygote64 as its
    // direct parent.  If Magisk Zygisk wraps the fork, the intermediate
    // process may appear between us and the real Zygote, or the parent
    // cmdline may contain unexpected strings.
    //
    // Read /proc/self/status for PPid, then /proc/<ppid>/cmdline.
    // A parent cmdline that is not "zygote" / "zygote64" / "<pre-init>" is
    // suspicious — crash.
    {
        pid_t ppid = 0;
        {
            int fd = open("/proc/self/status", O_RDONLY);
            if (fd >= 0) {
                char buf[2048] = {};
                read(fd, buf, sizeof(buf) - 1);
                close(fd);
                const char *p = strstr(buf, "PPid:");
                if (p) {
                    p += 5;
                    while (*p == ' ' || *p == '\t') p++;
                    ppid = (pid_t)atoi(p);
                }
            }
        }
        if (ppid > 1) {
            char cmdline_path[64];
            snprintf(cmdline_path, sizeof(cmdline_path),
                     "/proc/%d/cmdline", (int)ppid);
            int fd = open(cmdline_path, O_RDONLY);
            if (fd >= 0) {
                char cmdline[128] = {};
                read(fd, cmdline, sizeof(cmdline) - 1);
                close(fd);
                // cmdline uses NUL as arg separator; first token is the name.
                // Valid parents: "zygote", "zygote64", "" (kernel thread),
                // or "<pre-initialized>" (seen on some vendor ROMs).
                if (cmdline[0] != '\0'                       &&
                    strcmp(cmdline, "zygote")   != 0         &&
                    strcmp(cmdline, "zygote64") != 0         &&
                    strncmp(cmdline, "<pre-init", 9) != 0) {
                    GLOGE("root_guard: unexpected parent cmdline: %s", cmdline);
                    crash_sigsegv();
                }
            }
        }
    }

    // ── LAYER I: Android-in-Android VM detection ──────────────────────────
    // VMOS, VPhoneGaGa, F1VM, XDROID, and VirtualApp containers are always
    // rooted by design.  They expose themselves through system properties
    // and/or mapped libraries.
    //
    // Property signals:
    //   ro.vmos.version / ro.vmos.prop  → VMOS
    //   ro.f1vm.version                 → F1VM
    //   ro.virtual_device = "1"         → generic Android-in-Android
    //   ro.kernel.qemu    = "1"         → QEMU/emulator base (many VMs)
    //   ro.product.model contains VM product names
    //
    // Maps signals:
    //   libva_core.so  → VirtualApp framework (used by VMOS, VPhoneGaGa)
    //   libxdroid.so   → XDROID container
    //   com.lody.virtual path fragment → VirtualApp host
    {
        // ── Property checks ──────────────────────────────────────────────
        struct { const char *prop; const char *match; } VM_PROPS[] = {
            { "ro.vmos.version",   nullptr   },  // any non-empty value = VMOS
            { "ro.vmos.prop",      nullptr   },
            { "ro.f1vm.version",   nullptr   },
            { "ro.virtual_device", "1"       },
            { "ro.kernel.qemu",    "1"       },
            { nullptr, nullptr }
        };
        char pval[PROP_VALUE_MAX] = {};
        for (int i = 0; VM_PROPS[i].prop; i++) {
            pval[0] = '\0';
            int len = __system_property_get(VM_PROPS[i].prop, pval);
            if (len > 0) {
                // If match is nullptr, any non-empty value triggers.
                if (!VM_PROPS[i].match || strcmp(pval, VM_PROPS[i].match) == 0) {
                    GLOGE("root_guard: VM prop %s=%s", VM_PROPS[i].prop, pval);
                    crash_sigsegv();
                }
            }
        }
        // ro.product.model — check for known VM product names
        pval[0] = '\0';
        if (__system_property_get("ro.product.model", pval) > 0) {
            static const char * const VM_MODELS[] = {
                "VMOS", "VPhoneGaGa", "F1VM", "XDROID",
                "vphone", "virtual_device", nullptr
            };
            for (int i = 0; VM_MODELS[i]; i++) {
                // Case-insensitive substring: convert to lower locally.
                // Avoid pulling in <cctype> — manual tolower loop.
                char lower[PROP_VALUE_MAX] = {};
                for (int j = 0; pval[j] && j < PROP_VALUE_MAX - 1; j++)
                    lower[j] = (pval[j] >= 'A' && pval[j] <= 'Z')
                                ? (char)(pval[j] + 32) : pval[j];
                char lmodel[64] = {};
                for (int j = 0; VM_MODELS[i][j] && j < 63; j++)
                    lmodel[j] = (VM_MODELS[i][j] >= 'A' && VM_MODELS[i][j] <= 'Z')
                                ? (char)(VM_MODELS[i][j] + 32) : VM_MODELS[i][j];
                if (strstr(lower, lmodel)) {
                    GLOGE("root_guard: VM model detected: %s", pval);
                    crash_sigsegv();
                }
            }
        }
        // ── Maps checks for VM runtime libraries ─────────────────────────
        {
            FILE *maps = fopen("/proc/self/maps", "r");
            if (maps) {
                char line[512];
                while (fgets(line, sizeof(line), maps)) {
                    if (strstr(line, "libva_core")      ||  // VirtualApp
                        strstr(line, "libxdroid")       ||  // XDROID
                        strstr(line, "com.lody.virtual")||  // VirtualApp host
                        strstr(line, "libhoudini")      ||  // x86→ARM (VMOS)
                        strstr(line, "libvmos")) {
                        fclose(maps);
                        GLOGE("root_guard: VM library in maps");
                        crash_sigsegv();
                    }
                }
                fclose(maps);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Forward definitions needed by detect_root_guard() — full versions live in
// the LAYER 2 ZIP-parsing block below; duplicated here so detect_root_guard()
// compiles in its current position (before the LAYER 2 section).
// ─────────────────────────────────────────────────────────────────────────────
#ifndef STAMP_BUF_SZ
#define STAMP_BUF_SZ 32
#endif

#ifndef ZIPENTRYINFO_DEFINED
#define ZIPENTRYINFO_DEFINED
struct ZipEntryInfo {
    uint16_t method;
    uint32_t comp_size;
    uint32_t uncomp_size;
    uint32_t local_offset;
    int      found;
};
#endif
// ─────────────────────────────────────────────────────────────────────────────
// detect_root_guard() — reads font_shade.dat from the installed APK assets,
// decrypts with the same build_key256/build_iv pair as every other stamp, and
// returns:
//   true  → flag byte 0xCA present → root guard enabled → run root_guard_checks()
//   false → sentinel (0x00) or file absent → root guard disabled → no-op
//
// Called once from fonts_init() (ELF constructor) and on every watchdog tick
// via watchdog_native_checks().
// ─────────────────────────────────────────────────────────────────────────────
static __attribute__((noinline)) bool detect_root_guard(void) {
    char apk_path[512] = {0};
    if (!get_apk_path(apk_path, sizeof(apk_path))) return false;

    FILE *f = fopen(apk_path, "rb");
    if (!f) return false;

    // ── Locate ZIP End-of-Central-Directory ──────────────────────────────
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return false; }
    long fsize = ftell(f);
    if (fsize < 22) { fclose(f); return false; }

    uint32_t cd_offset = 0, cd_size = 0;
    {
        // Search last 65kb for EOCD signature 0x06054b50
        long search_start = fsize - 65557;
        if (search_start < 0) search_start = 0;
        if (fseek(f, search_start, SEEK_SET) != 0) { fclose(f); return false; }
        size_t buf_len = (size_t)(fsize - search_start);
        uint8_t *buf = (uint8_t *)malloc(buf_len);
        if (!buf) { fclose(f); return false; }
        if (fread(buf, 1, buf_len, f) != buf_len) { free(buf); fclose(f); return false; }
        bool found = false;
        for (long i = (long)buf_len - 22; i >= 0; i--) {
            if (buf[i]==0x50 && buf[i+1]==0x4b && buf[i+2]==0x05 && buf[i+3]==0x06) {
                cd_size   = (uint32_t)buf[i+8]  | ((uint32_t)buf[i+9]  << 8)
                          | ((uint32_t)buf[i+10] << 16) | ((uint32_t)buf[i+11] << 24);
                cd_offset = (uint32_t)buf[i+12] | ((uint32_t)buf[i+13] << 8)
                          | ((uint32_t)buf[i+14] << 16) | ((uint32_t)buf[i+15] << 24);
                found = true;
                break;
            }
        }
        free(buf);
        if (!found) { fclose(f); return false; }
    }

    // ── Scan for "assets/font_shade.dat" ─────────────────────────────────
    ZipEntryInfo shadeInfo; memset(&shadeInfo, 0, sizeof(shadeInfo));
    int dummy = 0;
    if (!zip_scan_central_dir(f, cd_offset, cd_size, "assets/font_shade.dat",
                              &shadeInfo, &dummy) || !shadeInfo.found) {
        // File absent → guard disabled (non-crashing; file may be from old build)
        fclose(f); return false;
    }

    uint8_t shadeCipher[STAMP_BUF_SZ]; uint32_t shadeLen = 0;
    if (!zip_read_entry_data(f, &shadeInfo, shadeCipher, STAMP_BUF_SZ, &shadeLen)) {
        fclose(f); return false;
    }
    fclose(f);

    uint8_t key[32], iv[16];
    build_key256(key); build_iv(iv);
    uint8_t shadePlain[STAMP_BUF_SZ];
    int plainLen = aes256_cbc_dec(key, iv, shadeCipher, (int)shadeLen, shadePlain);
    memset(key, 0, 32); memset(iv, 0, 16);

    if (plainLen < 1) return false;                 // decrypt failure
    if (shadePlain[0] == 0x00) return false;        // sentinel — disabled
    return (shadePlain[0] == 0xCA);                 // 0xCA = enabled
}

static void *watchdog_thread(void *) {
    struct timespec ts = {3, 0};
    for (;;) {
        nanosleep(&ts, NULL);
        vm_run();                   // encrypted checks: TRACER,FMAPS,FPORT,ARTPATH,HOOKMAPS
        watchdog_native_checks();   // native checks: SELinux re-poll + dump-script presence
        if (detect_root_guard()) root_guard_checks();  // root guard (user opt-in)
    }
    return NULL;
}

// ════════════════════════════════════════════════════════════════════════════
// Forward declaration (second instance for clarity before spawn_background_watch).
// Full definition is in the LAYER 2 section below.
// The forked child calls it via a direct kill() path rather than crash_now(),
// so patching crash_now() alone cannot silence this layer.
// ════════════════════════════════════════════════════════════════════════════

static int detect_metrics_tamper(const char *apk_path);

// ════════════════════════════════════════════════════════════════════════════
// Fork-based isolated background guard process
//
// fork() spawns a child that is completely independent of the Android app
// lifecycle. The child carries no JVM, no Binder threads — just a tight
// polling loop. Strategy:
//   • Polls every 5 s, runs the same native checks as the watchdog thread.
//   • If parent dies (getppid() changes) the child exits cleanly.
//   • If any check fires, child sends SIGKILL to parent AND self.
//   • Reactions here use raw kill()/_exit() instead of crash_now() so that
//     a single binary patch to crash_now() cannot silence this layer.
// ════════════════════════════════════════════════════════════════════════════

static __attribute__((noinline)) void spawn_background_watch(void) {
    signal(SIGCHLD, SIG_IGN);

    pid_t parent_pid = getpid();
    pid_t child = fork();

    if (child < 0) return;
    if (child > 0) return;

    // ── Child process ──────────────────────────────────────────────────────
    setsid();

    struct timespec ts = {5, 0};
    for (;;) {
        nanosleep(&ts, NULL);
        if (getppid() != parent_pid) _exit(0);
        // All 6 checks route through lvm_exec — no named check_* call sites
        // visible in the child process disassembly. On any detection:
        // SIGKILL parent + self-exit (independent of parent's crash_now()).
        vm_run_child_kill(parent_pid);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// ── LAYER 2: APK ZIP integrity — AndroidManifest.xml hash + dex count ────
//
// Fully native, no JNI/Java dependency — runs from fonts_init() (ELF
// constructor) before any Java code. Reads the installed APK directly as a
// ZIP (central-directory walk) and decompresses entries with zlib's raw
// inflate, then compares against values stamped at protect time:
//   assets/font_metrics.dat — FNV-1a64 hash of AndroidManifest.xml
//   assets/font_index.dat   — count of classes*.dex files
// Both are AES-256-CBC encrypted using the same key/IV as guard_pstrings.inc.
//
// This catches anything the Class.forName/provider check cannot: an attacker
// who repackages the APK to ADD a new DEX/provider (e.g. a dialog-killer) or
// edits AndroidManifest.xml, without needing the added code to be a member
// of a hardcoded literal-name list.
// ════════════════════════════════════════════════════════════════════════════

#ifndef ZIPENTRYINFO_DEFINED
#define ZIPENTRYINFO_DEFINED
struct ZipEntryInfo {
    uint16_t method;
    uint32_t comp_size;
    uint32_t uncomp_size;
    uint32_t local_offset;
    int      found;
};
#endif

static uint32_t g_rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint16_t g_rd16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }

static int zip_locate_eocd(FILE *f, uint32_t *cd_offset, uint32_t *cd_size) {
    if (fseek(f, 0, SEEK_END) != 0) return 0;
    long fsize = ftell(f);
    if (fsize < 22) return 0;
    long searchLen = fsize < 66000 ? fsize : 66000;
    uint8_t *buf = (uint8_t *)malloc((size_t)searchLen);
    if (!buf) return 0;
    if (fseek(f, fsize - searchLen, SEEK_SET) != 0) { free(buf); return 0; }
    size_t rd = fread(buf, 1, (size_t)searchLen, f);
    long found = -1;
    for (long i = (long)rd - 22; i >= 0; i--) {
        if (buf[i]==0x50 && buf[i+1]==0x4b && buf[i+2]==0x05 && buf[i+3]==0x06) { found = i; break; }
    }
    if (found < 0) { free(buf); return 0; }
    *cd_size   = g_rd32(buf + found + 12);
    *cd_offset = g_rd32(buf + found + 16);
    free(buf);
    return 1;
}

static int zip_scan_central_dir(FILE *f, uint32_t cd_offset, uint32_t cd_size,
                                 const char *want_name, ZipEntryInfo *want_info,
                                 int *dex_count_out) {
    // Decode ".dex" and "classes" via AES-256-CBC — no plaintext in .rodata.
    char s_dot_dex[SP_BUF_SZ], s_classes[SP_BUF_SZ];
    reveal_ns(5u, SP_DOT_DEX,      SP_DOT_DEX_LEN,      s_dot_dex);
    reveal_ns(6u, SP_STR_CLASSES,  SP_STR_CLASSES_LEN,  s_classes);

    uint8_t *cd = (uint8_t *)malloc(cd_size ? cd_size : 1);
    if (!cd) return 0;
    if (fseek(f, (long)cd_offset, SEEK_SET) != 0) { free(cd); return 0; }
    if (cd_size > 0 && fread(cd, 1, cd_size, f) != cd_size) { free(cd); return 0; }

    int dex_count = 0;
    uint32_t p = 0;
    while (p + 46 <= cd_size) {
        if (!(cd[p]==0x50 && cd[p+1]==0x4b && cd[p+2]==0x01 && cd[p+3]==0x02)) break;
        uint16_t method    = g_rd16(cd + p + 10);
        uint32_t comp_sz   = g_rd32(cd + p + 20);
        uint32_t uncomp_sz = g_rd32(cd + p + 24);
        uint16_t name_len  = g_rd16(cd + p + 28);
        uint16_t extra_len = g_rd16(cd + p + 30);
        uint16_t comm_len  = g_rd16(cd + p + 32);
        uint32_t local_off = g_rd32(cd + p + 42);
        uint32_t name_off  = p + 46;
        if ((uint64_t)name_off + name_len > cd_size) break;

        char name[256];
        uint16_t nlen = name_len < 255 ? name_len : 255;
        memcpy(name, cd + name_off, nlen);
        name[nlen] = '\0';

        size_t L = strlen(name);
        if (L > 4 && strcmp(name + L - 4, s_dot_dex) == 0 && strncmp(name, s_classes, 7) == 0) {
            int ok = 1;
            for (size_t i = 7; i < L - 4; i++) if (name[i] < '0' || name[i] > '9') { ok = 0; break; }
            if (ok) dex_count++;
        }

        if (want_name && want_info && !want_info->found && strcmp(name, want_name) == 0) {
            want_info->method       = method;
            want_info->comp_size    = comp_sz;
            want_info->uncomp_size  = uncomp_sz;
            want_info->local_offset = local_off;
            want_info->found        = 1;
        }

        uint64_t next = (uint64_t)name_off + name_len + extra_len + comm_len;
        if (next <= p) break;
        p = (uint32_t)next;
    }
    free(cd);
    if (dex_count_out) *dex_count_out = dex_count;
    return 1;
}

static int zip_read_entry_data(FILE *f, const ZipEntryInfo *info,
                                uint8_t *out, uint32_t out_cap, uint32_t *out_len) {
    if (!info->found) return 0;
    if (fseek(f, (long)info->local_offset, SEEK_SET) != 0) return 0;
    uint8_t lh[30];
    if (fread(lh, 1, 30, f) != 30) return 0;
    if (!(lh[0]==0x50 && lh[1]==0x4b && lh[2]==0x03 && lh[3]==0x04)) return 0;
    uint16_t name_len  = g_rd16(lh + 26);
    uint16_t extra_len = g_rd16(lh + 28);
    if (fseek(f, (long)name_len + (long)extra_len, SEEK_CUR) != 0) return 0;

    if (info->method == 0) {
        if (info->uncomp_size > out_cap) return 0;
        if (info->uncomp_size > 0 && fread(out, 1, info->uncomp_size, f) != info->uncomp_size) return 0;
        *out_len = info->uncomp_size;
        return 1;
    }
    if (info->method != 8) return 0;  // only STORED/DEFLATE supported

    uint8_t *comp = (uint8_t *)malloc(info->comp_size ? info->comp_size : 1);
    if (!comp) return 0;
    if (info->comp_size > 0 && fread(comp, 1, info->comp_size, f) != info->comp_size) { free(comp); return 0; }

    z_stream zs; memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, -15) != Z_OK) { free(comp); return 0; }
    zs.next_in   = comp;
    zs.avail_in  = info->comp_size;
    zs.next_out  = out;
    zs.avail_out = out_cap;
    int ret = inflate(&zs, Z_FINISH);
    uint32_t produced = out_cap - zs.avail_out;
    inflateEnd(&zs);
    free(comp);
    if (ret != Z_STREAM_END) return 0;
    *out_len = produced;
    return 1;
}

// ── Key-mixing caches — set by ELF-constructor integrity checks, used by §9.3 ──
// g_cert_key_mix  : first 12 bytes of SHA-256(X.509 signing cert).
//   Set in detect_sig_tamper() BEFORE sentinel check, so that shard key-mixing
//   is always populated when a cert exists — regardless of whether the stamp
//   check is enabled or set to sentinel.
//   All-zeros → APK unsigned / cert unreadable → XOR is identity (no effect).
// g_manifest_key_mix : FNV-1a-64 of the installed AndroidManifest.xml bytes.
//   Set in detect_metrics_tamper() once the manifest is successfully hashed.
//   Zero → manifest unreadable (transient) → XOR has no effect.
// Both are read by sl_decrypt_shard() in §9.3 to derive the actual cipher key.
// The Java DexPacker bakes the same values into the encrypted shards at
// protect-time, so a wrong cert or manifest = wrong key = garbled DEX.
static uint8_t  g_cert_key_mix[12]  = {0,0,0,0,0,0,0,0,0,0,0,0};
static uint64_t g_manifest_key_mix  = 0;

// FNV-1a 64-bit — MUST match ApkProtector.fnv1a64() bit-for-bit or every
// APK fails its own integrity check on launch.
static uint64_t fnv1a64(const uint8_t *data, uint32_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (uint32_t i = 0; i < len; i++) { h ^= data[i]; h *= 1099511628211ULL; }
    return h;
}

#define MANIFEST_BUF_SZ  (2 * 1024 * 1024)
#ifndef STAMP_BUF_SZ
#define STAMP_BUF_SZ      32
#endif

// Returns 1 if tamper detected, 0 if clean. Does NOT call crash_now() itself
// so the fork-based watchdog child can react via a direct kill() path instead.
static int detect_metrics_tamper(const char *apk_path) {
    GLOGI("detect_metrics_tamper: checking %s", apk_path);
    FILE *f = fopen(apk_path, "rb");
    if (!f) { GLOGI("detect_metrics_tamper: fopen failed (errno=%d) — transient, not tamper", errno); return 0; }

    uint32_t cd_offset = 0, cd_size = 0;
    if (!zip_locate_eocd(f, &cd_offset, &cd_size)) {
        GLOGE("detect_metrics_tamper: EOCD not found");
        fclose(f); return 1;
    }
    GLOGI("detect_metrics_tamper: cd_offset=%u cd_size=%u", cd_offset, cd_size);

    // Decode ZIP entry names — no plaintext asset paths in .rodata.
    char s_manifest[SP_BUF_SZ], s_metrics[SP_BUF_SZ], s_fidx[SP_BUF_SZ];
    reveal_ns(13u, SP_MANIFEST,      SP_MANIFEST_LEN,      s_manifest);
    reveal_ns(14u, SP_FONT_METRICS_Z,SP_FONT_METRICS_Z_LEN,s_metrics);
    reveal_ns(15u, SP_FONT_INDEX_Z,  SP_FONT_INDEX_Z_LEN,  s_fidx);

    ZipEntryInfo manifestInfo; memset(&manifestInfo, 0, sizeof(manifestInfo));
    int dex_count = 0;
    if (!zip_scan_central_dir(f, cd_offset, cd_size, s_manifest, &manifestInfo, &dex_count)) {
        GLOGE("detect_metrics_tamper: central directory scan failed");
        fclose(f); return 1;
    }
    GLOGI("detect_metrics_tamper: dex_count=%d", dex_count);
    if (!manifestInfo.found || manifestInfo.uncomp_size == 0 ||
        manifestInfo.uncomp_size > MANIFEST_BUF_SZ) {
        GLOGE("detect_metrics_tamper: entry[0] missing/invalid (found=%d uncomp_size=%u)",
              manifestInfo.found, manifestInfo.uncomp_size);
        fclose(f); return 1;
    }

    uint8_t *manifest = (uint8_t *)malloc(MANIFEST_BUF_SZ);
    uint32_t manifest_len = 0;
    if (!manifest || !zip_read_entry_data(f, &manifestInfo, manifest, MANIFEST_BUF_SZ, &manifest_len)) {
        GLOGE("detect_metrics_tamper: failed to read/inflate AndroidManifest.xml");
        if (manifest) free(manifest);
        fclose(f); return 1;
    }
    uint64_t computed_hash = fnv1a64(manifest, manifest_len);
    free(manifest);
    GLOGI("detect_metrics_tamper: manifest len=%u hash=0x%016llx", manifest_len, (unsigned long long)computed_hash);
    // Cache for shard key mixing (§9.3) — set once, before sentinel check, so
    // an attacker who forces an early return still gets the wrong mix key.
    g_manifest_key_mix = computed_hash;

    ZipEntryInfo mhInfo; memset(&mhInfo, 0, sizeof(mhInfo));
    ZipEntryInfo dcInfo; memset(&dcInfo, 0, sizeof(dcInfo));
    int dummy;
    if (!zip_scan_central_dir(f, cd_offset, cd_size, s_metrics, &mhInfo, &dummy) || !mhInfo.found) {
        GLOGE("detect_metrics_tamper: entry[1] not found");
        fclose(f); return 1;
    }
    if (!zip_scan_central_dir(f, cd_offset, cd_size, s_fidx, &dcInfo, &dummy) || !dcInfo.found) {
        GLOGE("detect_metrics_tamper: entry[2] not found");
        fclose(f); return 1;
    }

    uint8_t mhCipher[STAMP_BUF_SZ], dcCipher[STAMP_BUF_SZ];
    uint32_t mhLen = 0, dcLen = 0;
    if (!zip_read_entry_data(f, &mhInfo, mhCipher, STAMP_BUF_SZ, &mhLen) ||
        !zip_read_entry_data(f, &dcInfo, dcCipher, STAMP_BUF_SZ, &dcLen)) {
        GLOGE("detect_metrics_tamper: failed to read stamp entries");
        fclose(f); return 1;
    }
    fclose(f);

    uint8_t key[32], iv[16];
    build_key256(key); build_iv(iv);
    uint8_t mhPlain[STAMP_BUF_SZ], dcPlain[STAMP_BUF_SZ];
    int mhPlainLen = aes256_cbc_dec(key, iv, mhCipher, (int)mhLen, mhPlain);
    int dcPlainLen = aes256_cbc_dec(key, iv, dcCipher, (int)dcLen, dcPlain);
    memset(key, 0, 32); memset(iv, 0, 16);
    GLOGI("detect_metrics_tamper: mhPlainLen=%d dcPlainLen=%d", mhPlainLen, dcPlainLen);

    if (mhPlainLen < 8 || dcPlainLen < 4) {
        GLOGE("detect_metrics_tamper: decrypted stamp too short — corrupt or wrong key");
        return 1;
    }

    uint64_t expected_hash;  memcpy(&expected_hash, mhPlain, 8);
    uint32_t expected_count; memcpy(&expected_count, dcPlain, 4);

    // ── Opt-out sentinel: ApkProtector writes (hash=0, count=0) when the
    // user disables the Manifest & Dex integrity check in Settings before
    // protecting. Recognised here so guard.cpp skips the check gracefully.
    // Sentinel is AES-256-CBC encrypted like real stamps — an attacker must
    // know the guard key to forge it.
    if (expected_hash == 0ULL && expected_count == 0u) {
        GLOGI("detect_metrics_tamper: sentinel(0,0) — check disabled in settings, skipping");
        return 0;
    }

    GLOGI("detect_metrics_tamper: expected_hash=0x%016llx expected_count=%u vs computed=0x%016llx dex=%d",
          (unsigned long long)expected_hash, expected_count, (unsigned long long)computed_hash, dex_count);

    if (expected_hash != computed_hash)          { GLOGE("detect_metrics_tamper: MANIFEST HASH MISMATCH"); return 1; }
    if (expected_count != (uint32_t)dex_count)   { GLOGE("detect_metrics_tamper: DEX COUNT MISMATCH");     return 1; }
    GLOGI("detect_metrics_tamper: clean");
    return 0;
}

// ════════════════════════════════════════════════════════════════════════════
// ── LAYER 3: Native .so self-integrity — FNV-1a64 hash of generated JNI .so
//
// At protect-time ApkProtector computes FNV-1a64 of the compiled user .so,
// AES-256-CBC encrypts the 8-byte result (same guard key/IV), and stores it
// as assets/font_glyph.dat.  At runtime this layer:
//   1. Finds the user's .so name from /proc/self/maps (skipping libcipher.so)
//   2. Opens the APK, locates that lib/ ZIP entry, reads + inflates it
//   3. FNV-1a64 hashes the raw bytes and decrypts font_glyph.dat
//   4. Crash if the asset is MISSING, decryption fails, or hash mismatches
//
// Called from two independent sites:
//   • fonts_init() — ELF __attribute__((constructor)), before any Java runs
//   • lvm_method_exec execute loop — every 4096 VM opcode dispatches
// The forked background child (vm_run_child_kill) also polls via gvm_so_integrity.
// ════════════════════════════════════════════════════════════════════════════

// XOR-decode helper — keeps all sensitive path strings out of .rodata
#define _SX(dst, enc, xk) do { \
    for (int _i = 0; _i < (int)(sizeof(enc)-1); _i++) \
        (dst)[_i] = (char)((enc)[_i] ^ (uint8_t)(xk)); \
    (dst)[sizeof(enc)-1] = '\0'; } while(0)

// Scans /proc/self/maps for the first /data/app/*.so that is NOT libcipher.so.
// Copies just the filename (e.g. "libmyapp.so") into out[out_max].
static __attribute__((noinline)) int so_find_user_lib_name(char *out, int out_max) {
    static const uint8_t _sm[] = {0x84,0xDB,0xD9,0xC4,0xC8,0x84,0xD8,0xCE,0xC7,0xCD,0x84,0xC6,0xCA,0xDB,0xD8,'\0'}; // /proc/self/maps
    static const uint8_t _da[] = {0x84,0xCF,0xCA,0xDF,0xCA,0x84,0xCA,0xDB,0xDB,0x84,'\0'};                            // /data/app/
    static const uint8_t _so[] = {0x85,0xD8,0xC4,'\0'};                                                                // .so
    static const uint8_t _ci[] = {0xC8,0xC2,0xDB,0xC3,0xCE,0xD9,'\0'};                                                // cipher
    char s_maps[20], s_data[14], s_so[6], s_ci[10];
    _SX(s_maps, _sm, 0xAB); _SX(s_data, _da, 0xAB);
    _SX(s_so,   _so, 0xAB); _SX(s_ci,   _ci, 0xAB);

    FILE *f = fopen(s_maps, "r"); if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, s_data)) continue;
        if (!strstr(line, s_so))   continue;
        char *sl = strrchr(line, '/'); if (!sl) continue;
        char *name = sl + 1;
        char *nl = strstr(name, "\n"); if (nl) *nl = '\0';
        if (!strstr(name, s_so)) continue;   // must end in .so
        if ( strstr(name, s_ci)) continue;   // skip libcipher.so
        int n = (int)strlen(name);
        if (n <= 3 || n >= out_max) continue;
        strncpy(out, name, out_max - 1); out[out_max - 1] = '\0';
        fclose(f); return 1;
    }
    fclose(f); return 0;
}

// Returns 1 = tamper/missing (→ crash), 0 = clean.
// MISSING font_glyph.dat always returns 1 — the asset is mandatory.
static __attribute__((noinline)) int detect_so_tamper(const char *apk_path) {
    char lib_name[128] = {0};
    if (!so_find_user_lib_name(lib_name, sizeof(lib_name))) return 0; // still loading

    FILE *f = fopen(apk_path, "rb"); if (!f) return 0;
    uint32_t cd_offset = 0, cd_size = 0;
    if (!zip_locate_eocd(f, &cd_offset, &cd_size)) { fclose(f); return 1; }

    // Build "lib/<abi>/libname.so" — try arm64-v8a first, then armeabi-v7a
    static const uint8_t _a64[] = {0xC7,0xC2,0xC9,0x84,0xCA,0xD9,0xC6,0x9D,0x9F,0x86,0xDD,0x93,0xCA,0x84,'\0'}; // lib/arm64-v8a/
    static const uint8_t _a32[] = {0xC7,0xC2,0xC9,0x84,0xCA,0xD9,0xC6,0xCE,0xCA,0xC9,0xC2,0x86,0xDD,0x9C,0xCA,0x84,'\0'}; // lib/armeabi-v7a/
    char s64[20], s32[22], entry[196];
    _SX(s64, _a64, 0xAB); _SX(s32, _a32, 0xAB);

    ZipEntryInfo soInfo; memset(&soInfo, 0, sizeof(soInfo)); int dummy = 0;
    snprintf(entry, sizeof(entry), "%s%s", s64, lib_name);
    if (!zip_scan_central_dir(f, cd_offset, cd_size, entry, &soInfo, &dummy) || !soInfo.found) {
        soInfo.found = 0;
        snprintf(entry, sizeof(entry), "%s%s", s32, lib_name);
        zip_scan_central_dir(f, cd_offset, cd_size, entry, &soInfo, &dummy);
    }
    if (!soInfo.found || soInfo.uncomp_size == 0) {
        GLOGE("detect_so_tamper: user .so not found in APK");
        fclose(f); return 1;
    }

    uint8_t *so_buf = (uint8_t *)malloc(soInfo.uncomp_size);
    if (!so_buf) { fclose(f); return 0; } // OOM — transient skip
    uint32_t so_len = 0;
    if (!zip_read_entry_data(f, &soInfo, so_buf, soInfo.uncomp_size, &so_len)) {
        free(so_buf); fclose(f); return 1;
    }
    uint64_t computed = fnv1a64(so_buf, so_len);
    free(so_buf);

    // Locate assets/font_glyph.dat — MISSING is a hard crash
    char s_glyph[SP_BUF_SZ];
    reveal(SP_FONT_GLYPH_Z, SP_FONT_GLYPH_Z_LEN, s_glyph);
    ZipEntryInfo glInfo; memset(&glInfo, 0, sizeof(glInfo));
    if (!zip_scan_central_dir(f, cd_offset, cd_size, s_glyph, &glInfo, &dummy) || !glInfo.found) {
        GLOGE("detect_so_tamper: font_glyph.dat MISSING — mandatory asset deleted");
        fclose(f); return 1;
    }
    uint8_t glCipher[STAMP_BUF_SZ]; uint32_t glLen = 0;
    if (!zip_read_entry_data(f, &glInfo, glCipher, STAMP_BUF_SZ, &glLen)) {
        fclose(f); return 1;
    }
    fclose(f);

    uint8_t key[32], iv[16];
    build_key256(key); build_iv(iv);
    uint8_t glPlain[STAMP_BUF_SZ];
    int glPlainLen = aes256_cbc_dec(key, iv, glCipher, (int)glLen, glPlain);
    memset(key, 0, 32); memset(iv, 0, 16);
    if (glPlainLen < 8) { GLOGE("detect_so_tamper: decrypt failed"); return 1; }

    uint64_t expected; memcpy(&expected, glPlain, 8);
    if (expected == 0ULL) { GLOGI("detect_so_tamper: sentinel(0) skip"); return 0; }
    if (expected != computed) {
        GLOGE("detect_so_tamper: HASH MISMATCH exp=0x%016llx got=0x%016llx",
              (unsigned long long)expected, (unsigned long long)computed);
        return 1;
    }
    GLOGI("detect_so_tamper: clean 0x%016llx", (unsigned long long)computed);
    return 0;
}

// Wrapper with APK-path resolution — same shape as gvm_metrics()
static __attribute__((noinline)) int gvm_so_integrity(void) {
    char apk_path[512] = {0};
    if (!get_apk_path(apk_path, sizeof(apk_path))) return 0;
    return detect_so_tamper(apk_path);
}

// ════════════════════════════════════════════════════════════════════════════
// LAYER 4 — Hardened Signature Verification (ARM svc #0 edition)
//
// Protect-time: SHA-256 of the raw V1 signing certificate (META-INF/*.RSA /
// .DSA / .EC) stored AES-256-CBC encrypted in assets/font_kern.dat.
// Sentinel = 32 × 0x00 (check disabled by user).
//
// ── NP Manager bypass-mode defeat matrix (screenshot, July 2026) ─────────
//
//  Kill Sig ++1.0 / ++2.0 / MODEX3.0 / SFSignKiller / NPSignKiller
//      → PMS Hook: Java Binder proxy replaces getPackageInfo() signatures.
//        DEFEATED: we never call PackageManager — pure native C.
//
//  LspatchSignKiller
//      → LSPatch SigBypass.java: Xposed/LSPosed ART hook on PackageManager.
//        DEFEATED: ELF __attribute__((constructor)) fires before ART inits.
//
//  EirvSignKiller / EirvSignKiller2 / FancyBypass / SRPatch (IO method)
//      → IO Hook: patch the PLT/GOT entry for libc open()/openat()/read()/
//        pread64() in the target .so, redirect the fd to the original APK.
//        DEFEATED HERE: every byte of file I/O uses inline ARM "svc #0"
//        assembly — no PLT, no GOT, no libc symbol lookup.  The hook has
//        zero attachment surface.
//
//  SRPatch (SVC method) / APatch / KernelPatch kernel hooks
//      → Intercept raw syscalls at kernel boundary; requires root + module.
//        DETECTED: existing FMAPS/TRACER LVM opcodes catch KernelSU/Magisk/
//        APatch and Zygisk.  g_sig_maps_scan() additionally searches for
//        bypass-tool native libraries injected directly into our address space.
//
// Zero libc involvement in the critical I/O path → unbypassable without root.
// ════════════════════════════════════════════════════════════════════════════

// ── §1  Inline-asm raw syscall wrappers — zero PLT / GOT / libc ────────────
//
// ARM64 calling convention: x0–x5 = args, x8 = syscall number, svc #0.
// ARM32 EABI convention:    r0–r5 = args, r7 = syscall number, svc #0.
// x86/x86_64 compile-only fallback (not our shipped ABI).

#if defined(__aarch64__)

static __attribute__((always_inline)) inline
int g_sig_openat(const char *path, int flags) {
    register long x0 __asm__("x0") = (long)AT_FDCWD;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = (long)(flags | O_CLOEXEC);
    register long x3 __asm__("x3") = 0L;
    register long x8 __asm__("x8") = 56L; /* __NR_openat */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory", "cc");
    return (int)x0;
}
static __attribute__((always_inline)) inline
ssize_t g_sig_read(int fd, void *buf, size_t n) {
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = (long)n;
    register long x8 __asm__("x8") = 63L; /* __NR_read */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory", "cc");
    return (ssize_t)x0;
}
static __attribute__((always_inline)) inline
ssize_t g_sig_pread(int fd, void *buf, size_t n, off_t off) {
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)buf;
    register long x2 __asm__("x2") = (long)n;
    register long x3 __asm__("x3") = (long)off;
    register long x8 __asm__("x8") = 67L; /* __NR_pread64 */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
        : "memory", "cc");
    return (ssize_t)x0;
}
static __attribute__((always_inline)) inline
off_t g_sig_lseek(int fd, off_t off, int whence) {
    register long x0 __asm__("x0") = (long)fd;
    register long x1 __asm__("x1") = (long)off;
    register long x2 __asm__("x2") = (long)whence;
    register long x8 __asm__("x8") = 62L; /* __NR_lseek */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x1), "r"(x2), "r"(x8)
        : "memory", "cc");
    return (off_t)x0;
}
static __attribute__((always_inline)) inline
int g_sig_close(int fd) {
    register long x0 __asm__("x0") = (long)fd;
    register long x8 __asm__("x8") = 57L; /* __NR_close */
    __asm__ volatile("svc #0"
        : "+r"(x0)
        : "r"(x8)
        : "memory", "cc");
    return (int)x0;
}

#elif defined(__arm__)

static __attribute__((always_inline)) inline
int g_sig_openat(const char *path, int flags) {
    register long r0 __asm__("r0") = (long)AT_FDCWD; /* AT_FDCWD = -100 */
    register long r1 __asm__("r1") = (long)path;
    register long r2 __asm__("r2") = (long)(flags | O_CLOEXEC);
    register long r3 __asm__("r3") = 0L;
    register long r7 __asm__("r7") = 322L; /* __NR_openat ARM32 */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r3), "r"(r7)
        : "memory", "cc");
    return (int)r0;
}
static __attribute__((always_inline)) inline
ssize_t g_sig_read(int fd, void *buf, size_t n) {
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)buf;
    register long r2 __asm__("r2") = (long)n;
    register long r7 __asm__("r7") = 3L; /* __NR_read */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r7)
        : "memory", "cc");
    return (ssize_t)r0;
}
static __attribute__((always_inline)) inline
ssize_t g_sig_pread(int fd, void *buf, size_t n, off_t off) {
    /* ARM32 EABI pread64: r0=fd r1=buf r2=count r3=0(pad) r4=off_lo r5=off_hi */
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)buf;
    register long r2 __asm__("r2") = (long)n;
    register long r3 __asm__("r3") = 0L; /* 64-bit alignment pad */
    register long r4 __asm__("r4") = (long)off;
    register long r5 __asm__("r5") = 0L; /* offset_hi — APKs < 4 GB */
    register long r7 __asm__("r7") = 180L; /* __NR_pread64 */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5), "r"(r7)
        : "memory", "cc");
    return (ssize_t)r0;
}
static __attribute__((always_inline)) inline
off_t g_sig_lseek(int fd, off_t off, int whence) {
    register long r0 __asm__("r0") = (long)fd;
    register long r1 __asm__("r1") = (long)off;
    register long r2 __asm__("r2") = (long)whence;
    register long r7 __asm__("r7") = 19L; /* __NR_lseek */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r1), "r"(r2), "r"(r7)
        : "memory", "cc");
    return (off_t)r0;
}
static __attribute__((always_inline)) inline
int g_sig_close(int fd) {
    register long r0 __asm__("r0") = (long)fd;
    register long r7 __asm__("r7") = 6L; /* __NR_close */
    __asm__ volatile("svc #0"
        : "+r"(r0)
        : "r"(r7)
        : "memory", "cc");
    return (int)r0;
}

#else /* x86 / x86_64 — compile-only fallback, not a target ABI */
static inline int     g_sig_openat(const char *p, int f) { return open(p, f|O_CLOEXEC); }
static inline ssize_t g_sig_read(int fd,void *b,size_t n)            { return read(fd,b,n); }
static inline ssize_t g_sig_pread(int fd,void *b,size_t n,off_t o)   { return pread(fd,b,n,o); }
static inline off_t   g_sig_lseek(int fd, off_t o, int w)            { return lseek(fd,o,w); }
static inline int     g_sig_close(int fd)                             { return close(fd); }
#endif /* arch */

// ── §2  Bypass-tool detection via /proc/self/maps ──────────────────────────
// Opens /proc/self/maps with inline-asm I/O (itself immune to IO hooks), reads
// it in 4 KB chunks and searches for short XOR-0xA3 obfuscated fragments that
// identify bypass-tool native libraries injected into our process memory.
//
// LSPosed-based variants (LspatchSignKiller, NPSignKiller …) are already caught
// by the existing FMAPS LVM opcode (lsplant / lspatch / xposed patterns).
// This function catches tools that inject WITHOUT LSPosed:
//   "eirv"      → EirvSignKiller / EirvSignKiller2 native module
//   "fanc"      → FancyBypass native module
//   "srpatch"   → SRPatch native module
//   "npmanager" → NP Manager directly-injected native module
//   "signkill"  → generic sig-killer native libraries

/* XOR-0xA3 encoded fragment strings */
/* "/proc/self/maps" */
static const uint8_t _bx_maps[] = {
    0x8C,0xD3,0xD1,0xCC,0xC0,0x8C,0xD0,0xC6,0xCF,0xC5,0x8C,0xCE,0xC2,0xD3,0xD0
};
/* "eirv" */
static const uint8_t _bx_eirv[] = {0xC6,0xCA,0xD1,0xD5};
/* "fanc" */
static const uint8_t _bx_fanc[] = {0xC5,0xC2,0xCD,0xC0};
/* "srpatch" */
static const uint8_t _bx_srp[]  = {0xD0,0xD1,0xD3,0xC2,0xD7,0xC0,0xCB};
/* "npmanager" */
static const uint8_t _bx_npm[]  = {0xCD,0xD3,0xCE,0xC2,0xCD,0xC2,0xC4,0xC6,0xD1};
/* "signkill" */
static const uint8_t _bx_skl[]  = {0xD0,0xCA,0xC4,0xCD,0xC8,0xCA,0xCF,0xCF};

static int g_memmem_s(const char *hay, size_t hlen,
                      const char *needle, size_t nlen) {
    if (!nlen || hlen < nlen) return 0;
    for (size_t i = 0; i <= hlen - nlen; i++)
        if (memcmp(hay + i, needle, nlen) == 0) return 1;
    return 0;
}

static int g_sig_maps_scan(void) {
    G_DEC(s_maps, _bx_maps);
    G_DEC(s_eirv, _bx_eirv);
    G_DEC(s_fanc, _bx_fanc);
    G_DEC(s_srp,  _bx_srp);
    G_DEC(s_npm,  _bx_npm);
    G_DEC(s_skl,  _bx_skl);

    int mfd = g_sig_openat(s_maps, O_RDONLY);
    if (mfd < 0) return 0; /* maps unreadable → skip rather than false-crash */

    /* Read in 4 KB chunks; carry last 63 bytes to catch cross-boundary hits. */
    char chunk[4096 + 64];
    size_t carry = 0;
    ssize_t rd;
    int found = 0;
    while (!found && (rd = g_sig_read(mfd, chunk + carry, 4096)) > 0) {
        size_t total = carry + (size_t)rd;
        if (g_memmem_s(chunk, total, s_eirv, 4)) { found = 1; break; }
        if (g_memmem_s(chunk, total, s_fanc, 4)) { found = 1; break; }
        if (g_memmem_s(chunk, total, s_srp,  7)) { found = 1; break; }
        if (g_memmem_s(chunk, total, s_npm,  9)) { found = 1; break; }
        if (g_memmem_s(chunk, total, s_skl,  8)) { found = 1; break; }
        carry = total > 63 ? 63 : total;
        memmove(chunk, chunk + total - carry, carry);
    }
    g_sig_close(mfd);
    if (found) GLOGE("D2CG sig: bypass tool library detected in maps");
    return found;
}

// ── §3  pread-based ZIP mini-parser — no FILE*, no fread, no fseek ─────────

/* Locate EOCD; return cd_offset and cd_size via pointers. */
static int g_sig_eocd(int fd, uint32_t *cd_off, uint32_t *cd_sz) {
    off_t fsize = g_sig_lseek(fd, 0, SEEK_END);
    if (fsize < 22) return 0;
    size_t search = (size_t)(fsize < 66022 ? fsize : 66022);
    uint8_t *buf = (uint8_t *)malloc(search);
    if (!buf) return 0;
    ssize_t rd = g_sig_pread(fd, buf, search, fsize - (off_t)search);
    if (rd < 22) { free(buf); return 0; }
    long found = -1;
    for (long i = (long)rd - 22; i >= 0; i--) {
        if (buf[i]==0x50&&buf[i+1]==0x4b&&buf[i+2]==0x05&&buf[i+3]==0x06) {
            found = i; break;
        }
    }
    if (found < 0) { free(buf); return 0; }
    *cd_sz  = g_rd32(buf + found + 12);
    *cd_off = g_rd32(buf + found + 16);
    free(buf);
    return 1;
}

/* Read one ZIP entry's uncompressed data using pread64 (STORED or DEFLATE).
   Returns number of bytes written to out, 0 on error. */
static uint32_t g_sig_read_entry(int fd, const ZipEntryInfo *info,
                                  uint8_t *out, uint32_t out_max) {
    uint8_t lh[30];
    if (g_sig_pread(fd, lh, 30, (off_t)info->local_offset) != 30) return 0;
    if (lh[0]!=0x50||lh[1]!=0x4b||lh[2]!=0x03||lh[3]!=0x04) return 0;
    uint16_t nl  = g_rd16(lh + 26);
    uint16_t el  = g_rd16(lh + 28);
    off_t data_off = (off_t)info->local_offset + 30 + nl + el;

    if (info->method == 0) { /* STORED — direct pread */
        if (info->uncomp_size > out_max) return 0;
        ssize_t r = g_sig_pread(fd, out, info->uncomp_size, data_off);
        return (r == (ssize_t)info->uncomp_size) ? info->uncomp_size : 0;
    }
    if (info->method == 8) { /* DEFLATE — raw inflate (windowBits = -15) */
        if (info->comp_size > 131072) return 0; /* sanity */
        uint8_t *comp = (uint8_t *)malloc(info->comp_size);
        if (!comp) return 0;
        ssize_t r = g_sig_pread(fd, comp, info->comp_size, data_off);
        if (r != (ssize_t)info->comp_size) { free(comp); return 0; }
        z_stream strm; memset(&strm, 0, sizeof(strm));
        strm.next_in   = comp;          strm.avail_in  = info->comp_size;
        strm.next_out  = out;           strm.avail_out = out_max;
        if (inflateInit2(&strm, -15) != Z_OK) { free(comp); return 0; }
        int rc = inflate(&strm, Z_FINISH);
        uint32_t written = out_max - strm.avail_out;
        inflateEnd(&strm); free(comp);
        return (rc == Z_STREAM_END) ? written : 0;
    }
    return 0; /* unsupported compression */
}

// ── §3b  Minimal ASN.1 PKCS#7 → X.509 DER extractor ──────────────────────
//
// Android V1-signed APKs store a PKCS#7 SignedData blob in META-INF/*.RSA.
// The structure is:
//   SEQUENCE (ContentInfo) {
//     OID signedData
//     [0] { SEQUENCE (SignedData) {
//       INTEGER version
//       SET digestAlgorithms
//       SEQUENCE contentInfo
//       [0] { SEQUENCE (X.509 cert DER) }   ← we want this
//     } }
//   }
//
// We parse the minimal path to the first certificate and return a pointer
// into the original buffer (no allocation).  On any parse error we return
// NULL and the caller falls back to hashing the raw PKCS#7 blob.

static int g_sig_asn1_tl(const uint8_t **p, const uint8_t *end,
                          uint8_t *tag, uint32_t *vlen) {
    if (*p >= end) return 0;
    *tag = *(*p)++;
    if (*p >= end) return 0;
    uint8_t b = *(*p)++;
    if (!(b & 0x80)) { *vlen = b; return 1; }
    int nb = b & 0x7f;
    if (nb == 0 || nb > 4 || *p + nb > end) return 0;
    *vlen = 0;
    for (int i = 0; i < nb; i++) *vlen = (*vlen << 8) | *(*p)++;
    return 1;
}

static const uint8_t *g_sig_pkcs7_extract_cert(const uint8_t *buf,
                                                uint32_t buf_len,
                                                uint32_t *cert_len) {
    const uint8_t *p = buf, *end = buf + buf_len;
    uint8_t tag; uint32_t vlen;
    /* ContentInfo SEQUENCE */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x30) return NULL;
    /* OID */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x06) return NULL;
    p += vlen;
    /* [0] EXPLICIT wrapping SignedData */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0xA0) return NULL;
    /* SignedData SEQUENCE */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x30) return NULL;
    /* INTEGER version */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x02) return NULL;
    p += vlen;
    /* SET digestAlgorithms */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x31) return NULL;
    p += vlen;
    /* SEQUENCE encapContentInfo */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x30) return NULL;
    p += vlen;
    /* [0] certificates */
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0xA0) return NULL;
    /* First certificate SEQUENCE — this IS the X.509 DER cert */
    const uint8_t *cert_start = p;
    if (!g_sig_asn1_tl(&p,end,&tag,&vlen) || tag!=0x30) return NULL;
    *cert_len = (uint32_t)(p - cert_start) + vlen;
    return cert_start;
}

// ── §4  Main detection function ────────────────────────────────────────────

// XOR-0xA3 encoded ZIP entry names used below.
// "META-INF/"           (9 bytes)
static const uint8_t _enc_mi[]   = {0xEE,0xE6,0xF7,0xE2,0x8E,0xEA,0xED,0xE5,0x8C};
// ".RSA"                (4 bytes)
static const uint8_t _enc_rsa[]  = {0x8D,0xF1,0xF0,0xE2};
// ".DSA"                (4 bytes)
static const uint8_t _enc_dsa[]  = {0x8D,0xE7,0xF0,0xE2};
// ".EC"                 (3 bytes)
static const uint8_t _enc_ec[]   = {0x8D,0xE6,0xE0};
// "assets/font_kern.dat" (20 bytes)
static const uint8_t _enc_kern[] = {
    0xC2,0xD0,0xD0,0xC6,0xD7,0xD0,0x8C,
    0xC5,0xCC,0xCD,0xD7,0xFC,0xC8,0xC6,0xD1,0xCD,
    0x8D,0xC7,0xC2,0xD7
};

static int detect_sig_tamper(const char *apk_path) {

    // ── Pre-check: bypass-tool library scan ───────────────────────────────────
    // Crash immediately if a known IO-hook or sig-killer library is found in
    // our address space.  Runs before opening the APK to prevent any race.
    if (g_sig_maps_scan()) return 1;

    // ── Open APK via raw svc #0 — no PLT, no libc, no hook surface ───────────
    // IO-hook tools (EirvSignKiller, FancyBypass, SRPatch IO) patch the PLT
    // entry of openat() inside the target .so.  Inline-asm svc #0 completely
    // bypasses the PLT; there is no GOT entry to overwrite, no symbol to hook.
    int fd = g_sig_openat(apk_path, O_RDONLY);
    if (fd < 0) {
        GLOGE("D2CG sig: openat errno=%d", errno);
        return 0; /* transient (cold-boot path race) — skip, not crash */
    }

    // ── Locate EOCD ───────────────────────────────────────────────────────────
    uint32_t cd_off = 0, cd_sz = 0;
    if (!g_sig_eocd(fd, &cd_off, &cd_sz)) {
        GLOGE("D2CG sig: no EOCD");
        g_sig_close(fd); return 0;
    }

    // ── Load central directory ────────────────────────────────────────────────
    uint8_t *cd = (uint8_t *)malloc(cd_sz ? cd_sz : 1);
    if (!cd) { g_sig_close(fd); return 0; }
    if (cd_sz > 0) {
        ssize_t rd = g_sig_pread(fd, cd, cd_sz, (off_t)cd_off);
        if (rd != (ssize_t)cd_sz) { free(cd); g_sig_close(fd); return 0; }
    }

    // ── Decode obfuscated entry names ─────────────────────────────────────────
    G_DEC(s_mi,   _enc_mi);
    G_DEC(s_rsa,  _enc_rsa);
    G_DEC(s_dsa,  _enc_dsa);
    G_DEC(s_ec,   _enc_ec);
    G_DEC(s_kern, _enc_kern);

    // ── Single-pass CD scan: find signing cert + font_kern.dat ───────────────
    ZipEntryInfo certInfo; memset(&certInfo, 0, sizeof(certInfo));
    ZipEntryInfo kernInfo; memset(&kernInfo, 0, sizeof(kernInfo));
    uint32_t p = 0;
    while (p + 46 <= cd_sz) {
        if (!(cd[p]==0x50&&cd[p+1]==0x4b&&cd[p+2]==0x01&&cd[p+3]==0x02)) break;
        uint16_t method    = g_rd16(cd + p + 10);
        uint32_t comp_sz   = g_rd32(cd + p + 20);
        uint32_t uncomp_sz = g_rd32(cd + p + 24);
        uint16_t name_len  = g_rd16(cd + p + 28);
        uint16_t extra_len = g_rd16(cd + p + 30);
        uint16_t comm_len  = g_rd16(cd + p + 32);
        uint32_t local_off = g_rd32(cd + p + 42);
        if ((uint64_t)(p + 46) + name_len > cd_sz) break;
        char ename[256];
        uint16_t nlen = name_len < 255 ? name_len : 255;
        memcpy(ename, cd + p + 46, nlen); ename[nlen] = '\0';

        if (!certInfo.found && strncmp(ename, s_mi, 9) == 0) {
            size_t L = strlen(ename);
            int is_cert = (L > 4 && strcmp(ename + L - 4, s_rsa) == 0)
                        ||(L > 4 && strcmp(ename + L - 4, s_dsa) == 0)
                        ||(L > 3 && strcmp(ename + L - 3, s_ec)  == 0);
            if (is_cert) {
                certInfo.method=method; certInfo.comp_size=comp_sz;
                certInfo.uncomp_size=uncomp_sz; certInfo.local_offset=local_off;
                certInfo.found=1;
                GLOGI("D2CG sig: cert='%s' comp=%u uncomp=%u", ename, comp_sz, uncomp_sz);
            }
        }
        if (!kernInfo.found && strcmp(ename, s_kern) == 0) {
            kernInfo.method=method; kernInfo.comp_size=comp_sz;
            kernInfo.uncomp_size=uncomp_sz; kernInfo.local_offset=local_off;
            kernInfo.found=1;
        }
        if (certInfo.found && kernInfo.found) break;
        p += 46 + name_len + extra_len + comm_len;
    }
    free(cd);

    // font_kern.dat absent → mandatory asset deleted by attacker
    if (!kernInfo.found) {
        GLOGE("D2CG sig: font_kern.dat MISSING");
        g_sig_close(fd); return 1;
    }

    // ── Read entries via pread64 svc #0 ──────────────────────────────────────
    // pread64 is position-independent: both reads use the same fd without
    // seeking, so no lseek side-effects and no race between the two reads.

    // font_kern.dat ciphertext (48 bytes payload + 16-byte AES padding block)
    uint8_t kernCipher[64];
    uint32_t kernLen = g_sig_read_entry(fd, &kernInfo, kernCipher, 64);
    if (!kernLen) {
        GLOGE("D2CG sig: kern read failed");
        g_sig_close(fd); return 1;
    }

    // Signing certificate bytes
    uint8_t *cert_buf = NULL; uint32_t cert_len = 0;
    if (certInfo.found && certInfo.uncomp_size > 0 && certInfo.uncomp_size <= 65536) {
        cert_buf = (uint8_t *)malloc(certInfo.uncomp_size + 16);
        if (cert_buf) {
            cert_len = g_sig_read_entry(fd, &certInfo, cert_buf,
                                        certInfo.uncomp_size + 16);
            if (!cert_len) {
                memset(cert_buf, 0, certInfo.uncomp_size + 16);
                free(cert_buf); cert_buf = NULL;
            }
        }
    }

    g_sig_close(fd);

    // ── Decrypt font_kern.dat ─────────────────────────────────────────────────
    uint8_t key[32], iv[16];
    build_key256(key); build_iv(iv);
    uint8_t kernPlain[64];
    int kernPlainLen = aes256_cbc_dec(key, iv, kernCipher, (int)kernLen, kernPlain);
    memset(key, 0, 32); memset(iv, 0, 16);

    if (kernPlainLen < 32) {
        GLOGE("D2CG sig: decrypt failed len=%d", kernPlainLen);
        if (cert_buf) { memset(cert_buf, 0, certInfo.uncomp_size + 16); free(cert_buf); }
        return 1;
    }

    // ── SHA-256 the X.509 DER cert (not the raw PKCS#7 blob) ─────────────────
    // Computed BEFORE the sentinel check so g_cert_key_mix is always populated
    // whenever a cert is present — regardless of whether the sig-check stamp is
    // enabled or disabled.  This ensures shard key-mixing (§9.3) is symmetric
    // with what DexPacker wrote at protect-time on both paths.
    uint8_t computed[32]; memset(computed, 0, sizeof(computed));
    bool cert_hashed = false;
    if (cert_buf && cert_len > 0) {
        uint32_t x509_len = 0;
        const uint8_t *x509 = g_sig_pkcs7_extract_cert(cert_buf, cert_len, &x509_len);
        if (x509 && x509_len > 0) {
            sha256_buf(x509, x509_len, computed);
            GLOGI("D2CG sig: computed(x509) %02x%02x%02x%02x... (len=%u)",
                  computed[0], computed[1], computed[2], computed[3], x509_len);
        } else {
            sha256_buf(cert_buf, cert_len, computed);
            GLOGI("D2CG sig: computed(pkcs7) %02x%02x%02x%02x... (fallback)",
                  computed[0], computed[1], computed[2], computed[3]);
        }
        // Cache first 12 bytes for DEX shard key mixing in §9.3.
        // Only affects sl_decrypt_shard() — zero impact on VMP / dex2c paths
        // that do not use the DEX packer (DexProtector.install is never called).
        memcpy(g_cert_key_mix, computed, 12);
        cert_hashed = true;
    }
    if (cert_buf) { memset(cert_buf, 0, certInfo.uncomp_size + 16); free(cert_buf); cert_buf = NULL; }

    // Sentinel: 32 zero bytes → user disabled the check (cert hash already cached above)
    int allzero = 1;
    for (int i = 0; i < 32; i++) if (kernPlain[i]) { allzero = 0; break; }
    if (allzero) {
        GLOGI("D2CG sig: sentinel(0) — check disabled, skip");
        return 0;
    }

    // ── No V1 cert found → stripped or re-packaged without META-INF certs ────
    if (!cert_hashed) {
        GLOGE("D2CG sig: no META-INF cert entry (V1 sig absent or stripped)");
        return 1;
    }

    GLOGI("D2CG sig: expected  %02x%02x%02x%02x...",
          kernPlain[0], kernPlain[1], kernPlain[2], kernPlain[3]);

    if (memcmp(computed, kernPlain, 32) != 0) {
        GLOGE("D2CG sig: HASH MISMATCH — re-signed or spoofed");
        return 1;
    }
    GLOGI("D2CG sig: certificate verified OK");
    return 0;
}

// Wrapper with APK-path resolution — same shape as gvm_so_integrity()
static __attribute__((noinline)) int gvm_sig_check(void) {
    char apk_path[512] = {0};
    if (!get_apk_path(apk_path, sizeof(apk_path))) return 0;
    return detect_sig_tamper(apk_path);
}

// ════════════════════════════════════════════════════════════════════════════
// Constructor — runs when .so loads, before JNI_OnLoad, before any Java code
// ════════════════════════════════════════════════════════════════════════════

__attribute__((constructor))
static void fonts_init(void) {
    GLOGI("fonts_init: constructor entry");
    // ARM64 disassembly of fonts_init() shows ONLY five opaque VM calls and
    // two process/thread spawns — zero recognisable security function names.
    // All detection lives inside AES-256-CBC encrypted lvm_exec programs:
    //   vm_run_vccheck()  → LVCFULL   VCore/VirtualApp (APK path internally)
    //   vm_run_startup()  → LMETRICS  manifest hash + dex count integrity
    //   vm_run_sigcheck() → LSIGCHK   sig cert hash (Layer 4, svc #0 I/O)
    //   vm_run()          → TRACER + FMAPS + FPORT + ARTPATH + HOOKMAPS
    //   spawn_background_watch() → vm_run_child_kill() — forked 5-s poll child
    // ── ptrace(PTRACE_TRACEME) self-lock ─────────────────────────────────
    // Call PTRACE_TRACEME on ourselves.  This has two effects:
    //   1. If a debugger is ALREADY attached before we reach this point,
    //      ptrace() returns -1 / EPERM — we crash immediately.
    //   2. After a successful PTRACE_TRACEME our process becomes its own
    //      tracer, so any subsequent ptrace(PTRACE_ATTACH) from an external
    //      debugger also returns EPERM — we are self-locked against attach.
    //
    // This runs before any vm_run() check so even if all later checks are
    // patched the self-lock is already in place from the ELF constructor.
    {
        long pt = ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        if (pt < 0 && errno == EPERM) {
            // EPERM means another tracer is already attached
            GLOGE("fonts_init: ptrace TRACEME failed (EPERM) — debugger attached");
            crash_sigsegv();
        }
        // EBUSY / other errors: we already called TRACEME in a prior library
        // constructor or the vendor ROM restricts it — tolerate silently.
    }

    vm_run_vccheck();
    vm_run_startup();
    // Layer 3: SO self-integrity — crashes if font_glyph.dat missing or .so patched
    if (gvm_so_integrity()) crash_now();
    // Layer 4: opaque VM call — no gvm_sig_check or detect_sig_tamper visible here
    vm_run_sigcheck();
    vm_run();

    // ── Root guard — user opt-in strict-environment check ─────────────────
    // Reads font_shade.dat flag from APK assets.  If the user enabled
    // "Locked Environment" at protect time, runs 6-layer root detection
    // (su paths, Magisk /data/adb/ dirs, KernelSU/APatch, LSPosed maps,
    // Magisk daemon socket, test-keys build tag).  When disabled the flag
    // byte is 0x00 (sentinel) and this call returns immediately — zero cost.
    if (detect_root_guard()) root_guard_checks();

    // ── Anti-dump: SELinux permissive check ───────────────────────────────
    // Every known DEX dumper (MatrixDumper/DumperService, all Frida memscan
    // scripts) explicitly runs `setenforce 0` as a required first step before
    // dumping.  We check this in the ELF constructor (before any DEX ever
    // decrypts) and crash via hardware SIGSEGV — bypasses Frida's libc-level
    // kill/exit/abort patches because it is a CPU memory-protection fault.
    {
        char enforce_buf[4] = {'1', 0, 0, 0}; // default: assume enforcing
        int enforce_fd = open("/sys/fs/selinux/enforce", O_RDONLY);
        if (enforce_fd >= 0) {
            read(enforce_fd, enforce_buf, 1);
            close(enforce_fd);
        }
        if (enforce_buf[0] == '0') {
            // SELinux is permissive — dumping environment detected
            GLOGE("fonts_init: SELinux permissive → crash_sigsegv");
            crash_sigsegv();
        }
    }

    GLOGI("fonts_init: launching background watchdogs");
    spawn_background_watch();
    pthread_t wdt;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&wdt, &attr, watchdog_thread, NULL);
    pthread_attr_destroy(&attr);
}

// ════════════════════════════════════════════════════════════════════════════
// ══ JNI LAYER ═══════════════════════════════════════════════════════════════
//
// _fonts_measure_impl — called from the retry thread (via fonts_apply_metrics).
// Has JNIEnv. Does:
//   Layer 1 — Behavioral: ContentProvider ↔ lifecycle callback cross-reference
//   Layer 2 — Exact: Class.forName against known killer class names
//   Layer 3 — REMOVED (resolveContentProvider is system-wide, OEM false-positives)
//   Layer 4 — Fragment scan: renaming-resistant strstr against declared providers
// ════════════════════════════════════════════════════════════════════════════

// ── Known killer-class detection targets ───────────────────────────────────
// AES-256-CBC + XOR 0x5A encrypted — nothing here is plaintext in .rodata.
static const uint8_t BC1[] = {0x16,0x51,0x93,0x97,0x8e,0x33,0xcd,0xac,0x71,0x8a,0x43,0xda,0xef,0xcf,0x9f,0x28,0x6e,0xef,0x1c,0x1a,0x9a,0xb9,0x6c,0xda,0x55,0x7f,0xd8,0x70,0xd7,0x17,0x6e,0x0f,0xad,0x1e,0x77,0xd6,0x31,0x43,0xd9,0xb4,0x29,0xe2,0x91,0x66,0xaf,0xec,0xf1,0x9a};
static const int BC1_LEN = 48;
static const uint8_t BC2[] = {0x1d,0x8f,0xfe,0x3d,0x6e,0xaf,0x14,0x35,0x12,0x3f,0xa1,0x8a,0x94,0x9d,0x86,0xe3,0xce,0x1c,0x2a,0xa9,0xf3,0xb2,0x46,0xc1,0x72,0x58,0xf0,0xa3,0x3c,0x8b,0x01,0x8c};
static const int BC2_LEN = 32;
static const uint8_t BC3[] = {0x1d,0x8f,0xfe,0x3d,0x6e,0xaf,0x14,0x35,0x12,0x3f,0xa1,0x8a,0x94,0x9d,0x86,0xe3,0xac,0x44,0xe4,0xeb,0xb1,0xad,0x9d,0x93,0x33,0x0a,0xf6,0x54,0x9a,0xfe,0xbb,0x32};
static const int BC3_LEN = 32;
static const uint8_t BC4[] = {0x1d,0x8f,0xfe,0x3d,0x6e,0xaf,0x14,0x35,0x12,0x3f,0xa1,0x8a,0x94,0x9d,0x86,0xe3,0xb4,0x8f,0xd5,0x41,0xc5,0x27,0x9c,0x5c,0xc3,0xa9,0x24,0x8d,0x82,0xe5,0x71,0x71};
static const int BC4_LEN = 32;
static const uint8_t BC5[] = {0x7a,0xd7,0x78,0x11,0xf8,0x6a,0x56,0x7e,0x79,0x4f,0x98,0x18,0xf3,0x54,0x49,0x83,0x9e,0x26,0x12,0x2b,0x63,0x78,0x10,0xb2,0xc6,0xf5,0x38,0x1b,0xf9,0xf7,0xb5,0xa8};
static const int BC5_LEN = 32;
static const uint8_t BC6[] = {0x82,0x8f,0x79,0xd4,0x9e,0x66,0xae,0x3a,0xa8,0x8f,0xe8,0x49,0x6e,0xaa,0x54,0xcc,0x17,0x18,0x8f,0xf7,0x2e,0x58,0x88,0x8a,0x9a,0x69,0xc9,0xa2,0x8f,0xe8,0xf0,0x5d,0xc2,0x9d,0x80,0xdf,0x3d,0x98,0x9d,0x3e,0xf4,0x65,0x1c,0x92,0x1d,0xd9,0xbf,0xaf};
static const int BC6_LEN = 48;

static const uint8_t *const BLOCKED_CLASS_CT[]  = { BC1, BC2, BC3, BC4, BC5, BC6 };
static const int            BLOCKED_CLASS_LEN[] = { BC1_LEN, BC2_LEN, BC3_LEN, BC4_LEN, BC5_LEN, BC6_LEN };
static const int BLOCKED_CLASS_COUNT = 6;

// ── Broadened, renaming-resistant package-fragment patterns ───────────────
// KFRAG1-4 constants moved above lvm_exec so the interpreter (opcode 0x5B)
// and provider_matches_blocklist() both see them without a forward declaration.
// Original definitions are above; these comments remain as a location marker.

static __attribute__((noinline)) int provider_matches_blocklist(const char *s) {
    if (!s) return 0;
    char f1[PSTR_BUF_SZ], f2[PSTR_BUF_SZ], f3[PSTR_BUF_SZ], f4[PSTR_BUF_SZ];
    reveal_ns(200u, KFRAG1_CT, KFRAG1_LEN, f1);
    reveal_ns(201u, KFRAG2_CT, KFRAG2_LEN, f2);
    reveal_ns(202u, KFRAG3_CT, KFRAG3_LEN, f3);
    reveal_ns(203u, KFRAG4_CT, KFRAG4_LEN, f4);
    int hit = strstr(s, f1) || strstr(s, f2) || strstr(s, f3) || strstr(s, f4);
    memset(f1, 0, sizeof(f1)); memset(f2, 0, sizeof(f2));
    memset(f3, 0, sizeof(f3)); memset(f4, 0, sizeof(f4));
    return hit;
}

// ── Safe namespace list — licence-protection SDKs & analytics ─────────────
// Prevents false positives on PairIP and other legitimate SDKs that register
// lifecycle callbacks from their own ContentProvider.
// g_is_safe_ns — safe-namespace whitelist executed entirely inside a custom
// bytecode VM whose opcode stream is AES-256-CBC encrypted (NS_BC / NS_BLOBS).
//
// What Ghidra / radare2 sees:
//   • NS_BC: 304 bytes of random-looking noise in .rodata — no readable prefix
//   • A CFF state-machine interpreter driven by a volatile-switch dispatcher
//   • 32 separate reveal_ns() calls, each with a distinct key — cracking one
//     reveals nothing about the others
//   • Plaintext whitelist strings: GONE. Entirely absent from .rodata.
//
// CFF state layout:
//   0xA0 — FETCH: bounds-check pc; transition to 0xB0 or 0xC0 (exit)
//   0xB0 — EXEC:  decode + execute one 3-byte instruction; loop back to 0xA0
//   0xC0 — EXIT:  falls through to CFF_EXIT → return
static __attribute__((noinline)) bool g_is_safe_ns(const char *name) {
    if (!name || !name[0]) return false;

    // Decrypt VM bytecode — unique key idx=255; raw bytes (no XOR post-pass)
    uint8_t bc[NS_BC_LEN];
    {
        uint8_t key[32], iv[16];
        build_str_key(255u, key);
        build_str_iv(255u, iv);
        int n = aes256_cbc_dec(key, iv, NS_BC, NS_BC_LEN, bc);
        memset(key, 0, 32); memset(iv, 0, 16);
        if (n <= 0) return false;
    }

    char work_buf[SP_BUF_SZ];
    work_buf[0] = '\0';
    volatile int     match   = 0;
    volatile uint32_t ret_val = 2u; // 2 = running sentinel; 0 = false; 1 = true
    volatile uint32_t pc     = 0u;

    // CFF_LOOP is `while(1) switch(_c)`.  States loop back via CFF_NEXT(0xA0u).
    // Reaching state 0xC0 falls through to CFF_EXIT which `goto`s past the
    // switch; `return` then exits the function.
    CFF_INIT(0xA0u);
    CFF_LOOP {
    case 0xA0u: {
        // FETCH — opaque predicate forces decompiler to model a dead crash path
        if (OP_ALWAYS_TRUE(pc)) {
            if (pc + 3u > (uint32_t)NS_BC_LEN || ret_val != 2u) {
                if (ret_val == 2u) ret_val = 0u;
                CFF_NEXT(0xC0u);
            } else {
                CFF_NEXT(0xB0u);
            }
        } else { crash_now(); }
    }
    case 0xB0u: {
        // EXEC — decode one instruction, update VM state, loop back
        uint8_t  op  = bc[pc];
        uint16_t arg = (uint16_t)bc[pc+1] | ((uint16_t)bc[pc+2] << 8);
        pc += 3u;
        switch (op) { // inner switch — distinct from the outer CFF switch(_c)
        case NS_VM_DEC:
            if (arg < 48u && NS_BLOBS[arg].ct) {
                reveal_ns((uint32_t)arg,
                          NS_BLOBS[arg].ct, NS_BLOBS[arg].len,
                          work_buf);
            } else { work_buf[0] = '\0'; }
            break;
        case NS_VM_PCMP:
            match = (work_buf[0] &&
                     strncmp(name, work_buf, strlen(work_buf)) == 0) ? 1 : 0;
            break;
        case NS_VM_JT:
            if (match) pc = (uint32_t)arg;
            break;
        case NS_VM_RET:
            ret_val = (uint32_t)arg;
            break;
        default: break;
        }
        CFF_NEXT(0xA0u);
    }
    case 0xC0u:
    CFF_EXIT;
    memset(bc, 0, sizeof(bc));
    return ret_val == 1u;
}

// Extracts "com.foo.bar" from "com.foo.bar.ClassName" into out[outlen].
static __attribute__((noinline)) void g_extract_pkg(const char *cls, char *out, int outlen) {
    const char *last = strrchr(cls, '.');
    if (!last || last == cls) { out[0] = '\0'; return; }
    int len = (int)(last - cls);
    if (len >= outlen) len = outlen - 1;
    memcpy(out, cls, len);
    out[len] = '\0';
}

// ════════════════════════════════════════════════════════════════════════════
// LAYER 1: Behavioral — lifecycle callback ↔ ContentProvider cross-reference
//
// Renamed dialog killers bypass all name-based checks but cannot change what
// they do: they MUST call registerActivityLifecycleCallbacks() from a
// ContentProvider. This layer:
//   a. Reads Application.mActivityLifecycleCallbacks
//   b. Collects the package prefix of every callback that matches a known
//      killer fragment AND is NOT in a safe namespace
//   c. Reads every ContentProvider declared in this app's own manifest
//   d. If any provider's package prefix matches a suspicious callback prefix
//      → renamed killer confirmed → SIGKILL
//
// False-positive rate near-zero: legitimate SDKs that use lifecycle callbacks
// (Firebase, analytics, PairIP) are in safe namespaces.
// ════════════════════════════════════════════════════════════════════════════

static __attribute__((noinline))
void check_provider_callback_xref(JNIEnv *env, jobject context) {
    if (!env || !context) return;

    // ── a. Get Application object ─────────────────────────────────────────
    jclass ctxCls = env->GetObjectClass(context);
    if (!ctxCls) return;
    jmethodID getAppCtx = env->GetMethodID(ctxCls, NS_JNI(51, SP_JNI_GETAPPCTX),
                                            NS_JNI(52, SP_JNI_CTX_RET));
    env->DeleteLocalRef(ctxCls);
    if (!getAppCtx || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jobject app = env->CallObjectMethod(context, getAppCtx);
    if (!app || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    // ── b. Read mActivityLifecycleCallbacks ───────────────────────────────
    jclass appCls = env->GetObjectClass(app);
    jfieldID fld  = env->GetFieldID(appCls, NS_JNI(53, SP_JNI_MALCB),
                                     NS_JNI(54, SP_JNI_ALIST));
    if (!fld || env->ExceptionCheck()) {
        env->ExceptionClear();
        fld = env->GetFieldID(appCls, NS_JNI(53, SP_JNI_MALCB),
                               NS_JNI(55, SP_JNI_LIST));
    }
    env->DeleteLocalRef(appCls);
    if (!fld || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(app); return;
    }
    jobject cbList = env->GetObjectField(app, fld);
    env->DeleteLocalRef(app);
    if (!cbList || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    // ── c. Get list size + get() ──────────────────────────────────────────
    jclass listCls    = env->GetObjectClass(cbList);
    jmethodID sizeMID = env->GetMethodID(listCls, "size", "()I");
    jmethodID getMID  = env->GetMethodID(listCls, "get",  "(I)Ljava/lang/Object;");
    env->DeleteLocalRef(listCls);
    if (!sizeMID || !getMID || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(cbList); return;
    }
    jint cbCount = env->CallIntMethod(cbList, sizeMID);
    if (env->ExceptionCheck() || cbCount <= 0) {
        env->ExceptionClear(); env->DeleteLocalRef(cbList); return;
    }

    // ── d. java.lang.Class.getName() ─────────────────────────────────────
    jclass jlClass     = env->FindClass(NS_JNI(48, SP_JNI_JLCLASS));
    jmethodID gnameMID = jlClass
        ? env->GetMethodID(jlClass, NS_JNI(56, SP_JNI_GETNAME), NS_JNI(57, SP_JNI_STR_RET)) : nullptr;
    if (jlClass) env->DeleteLocalRef(jlClass);
    if (!gnameMID || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(cbList); return;
    }

    // ── e. Collect suspicious callback packages ───────────────────────────
    char suspPkgs[32][128];
    int  suspCount = 0;

    for (jint i = 0; i < cbCount && suspCount < 32; i++) {
        jobject cb = env->CallObjectMethod(cbList, getMID, i);
        if (!cb || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        jclass cbCls = env->GetObjectClass(cb);
        env->DeleteLocalRef(cb);
        if (!cbCls) continue;
        jstring nameStr = (jstring)env->CallObjectMethod((jobject)cbCls, gnameMID);
        env->DeleteLocalRef(cbCls);
        if (!nameStr || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        const char *cn = env->GetStringUTFChars(nameStr, nullptr);
        if (cn) {
            // Only flag if class name matches a killer fragment — prevents false
            // positives on PairIP and other legitimate SDKs.
            if (!g_is_safe_ns(cn) && provider_matches_blocklist(cn)) {
                char pkg[128];
                g_extract_pkg(cn, pkg, sizeof(pkg));
                if (pkg[0]) {
                    bool dup = false;
                    for (int j = 0; j < suspCount; j++)
                        if (strcmp(suspPkgs[j], pkg) == 0) { dup = true; break; }
                    if (!dup) {
                        strncpy(suspPkgs[suspCount], pkg, 127);
                        suspPkgs[suspCount++][127] = '\0';
                    }
                }
            }
            env->ReleaseStringUTFChars(nameStr, cn);
        }
        env->DeleteLocalRef(nameStr);
    }
    env->DeleteLocalRef(cbList);

    if (suspCount == 0) return;

    // ── f. Get PackageManager + declared providers ────────────────────────
    ctxCls = env->GetObjectClass(context);
    jmethodID getPM      = env->GetMethodID(ctxCls, NS_JNI(58, SP_JNI_GETPM),
                                             NS_JNI(59, SP_JNI_PM_RET));
    jmethodID getPkgName = env->GetMethodID(ctxCls, NS_JNI(60, SP_JNI_GETPKGNAME),
                                             NS_JNI(57, SP_JNI_STR_RET));
    env->DeleteLocalRef(ctxCls);
    if (!getPM || !getPkgName || env->ExceptionCheck()) {
        env->ExceptionClear(); return;
    }
    jobject pm = env->CallObjectMethod(context, getPM);
    if (!pm || env->ExceptionCheck()) { env->ExceptionClear(); return; }
    jstring pkgName = (jstring)env->CallObjectMethod(context, getPkgName);
    if (!pkgName || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(pm); return;
    }
    jclass pmCls         = env->GetObjectClass(pm);
    jmethodID getPkgInfo = env->GetMethodID(pmCls, NS_JNI(61, SP_JNI_GETPKGINFO),
                                              NS_JNI(62, SP_JNI_PKGINFO_SIG));
    env->DeleteLocalRef(pmCls);
    if (!getPkgInfo || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(pm); env->DeleteLocalRef(pkgName); return;
    }
    char ownPkg1[256] = {};
    {
        const char *tmp = env->GetStringUTFChars(pkgName, nullptr);
        if (tmp) { strncpy(ownPkg1, tmp, 255); env->ReleaseStringUTFChars(pkgName, tmp); }
    }
    const jint GET_PROVIDERS = 0x00000008;
    jobject pkgInfo = env->CallObjectMethod(pm, getPkgInfo, pkgName, GET_PROVIDERS);
    env->DeleteLocalRef(pm); env->DeleteLocalRef(pkgName);
    if (!pkgInfo || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    jclass piCls      = env->GetObjectClass(pkgInfo);
    jfieldID provsFld = env->GetFieldID(piCls, NS_JNI(63, SP_JNI_PROVIDERS),
                                         NS_JNI(64, SP_JNI_PROVINFO));
    env->DeleteLocalRef(piCls);
    if (!provsFld || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(pkgInfo); return;
    }
    jobjectArray provArr = (jobjectArray)env->GetObjectField(pkgInfo, provsFld);
    env->DeleteLocalRef(pkgInfo);
    if (!provArr || env->ExceptionCheck()) { env->ExceptionClear(); return; }

    // ── g. Cross-reference provider packages with suspicious cb packages ──
    jsize provCount = env->GetArrayLength(provArr);
    for (jsize i = 0; i < provCount; i++) {
        jobject prov = env->GetObjectArrayElement(provArr, i);
        if (!prov || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        jclass provCls = env->GetObjectClass(prov);
        // Own-APK gate: skip entries from other APKs
        jfieldID pkgF  = env->GetFieldID(provCls, NS_JNI(65, SP_JNI_PKGNAME_FLD), NS_JNI(66, SP_JNI_STR_DESC));
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (pkgF) {
            jstring provPkg = (jstring)env->GetObjectField(prov, pkgF);
            if (env->ExceptionCheck()) { env->ExceptionClear(); provPkg = nullptr; }
            if (provPkg) {
                const char *pp = env->GetStringUTFChars(provPkg, nullptr);
                bool ownApk = pp && ownPkg1[0] && (strcmp(pp, ownPkg1) == 0);
                if (pp) env->ReleaseStringUTFChars(provPkg, pp);
                env->DeleteLocalRef(provPkg);
                if (!ownApk) { env->DeleteLocalRef(provCls); env->DeleteLocalRef(prov); continue; }
            }
        }
        jfieldID nameF = env->GetFieldID(provCls, "name", NS_JNI(66, SP_JNI_STR_DESC));
        env->DeleteLocalRef(provCls);
        if (!nameF || env->ExceptionCheck()) {
            env->ExceptionClear(); env->DeleteLocalRef(prov); continue;
        }
        jstring pnStr = (jstring)env->GetObjectField(prov, nameF);
        env->DeleteLocalRef(prov);
        if (!pnStr || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        const char *pn = env->GetStringUTFChars(pnStr, nullptr);
        if (pn && !g_is_safe_ns(pn)) {
            char ppkg[128];
            g_extract_pkg(pn, ppkg, sizeof(ppkg));
            if (ppkg[0]) {
                for (int j = 0; j < suspCount; j++) {
                    size_t plen = strlen(ppkg), slen = strlen(suspPkgs[j]);
                    bool hit = (strcmp(ppkg, suspPkgs[j]) == 0) ||
                               (strncmp(ppkg, suspPkgs[j], slen) == 0 && ppkg[slen] == '.') ||
                               (strncmp(suspPkgs[j], ppkg, plen) == 0 && suspPkgs[j][plen] == '.');
                    if (hit) {
                        GLOGE("L1-behavioral: provider '%s' ↔ callback '%s' — renamed killer",
                              ppkg, suspPkgs[j]);
                        env->ReleaseStringUTFChars(pnStr, pn);
                        env->DeleteLocalRef(pnStr);
                        env->DeleteLocalRef(provArr);
                        CRASH_HERE("renamed dialog killer: ContentProvider+lifecycle callback package cross-match");
                    }
                }
            }
        }
        if (pn) env->ReleaseStringUTFChars(pnStr, pn);
        env->DeleteLocalRef(pnStr);
        if (env->ExceptionCheck()) env->ExceptionClear();
    }
    env->DeleteLocalRef(provArr);
}

// ════════════════════════════════════════════════════════════════════════════
// _fonts_measure_impl — registered as fonts.Metrics.measure(Context) via
// RegisterNatives. Hidden C symbol, not exported from .so.
//
// Architecture (split JNI shell + VM kill):
//   • _fonts_measure_impl is a DUMB DATA COLLECTOR — it gathers provider
//     class names, authorities, and Class.forName results into antik_ctx_t.
//     No strstr, no CRASH_HERE inside the JNI function itself.
//   • vm_run_antik() passes that context into lvm_exec opcode 0x5B (LANTIK)
//     which performs the KFRAG matching and kill decision inside encrypted
//     bytecode.  Ghidra sees only: data collection → opaque lvm_exec call.
//
// Layer 1 (behavioral cross-ref) still crashes inline because check_provider_
// callback_xref is already protected by volatile fn-pointer dispatch and the
// result type change would require extensive refactoring.
// ════════════════════════════════════════════════════════════════════════════

// ── LBC_ANTIK — bytecode program for the LANTIK (0x5B) opcode ────────────
// Plaintext: [0x5B, 0x00, 0x01, 0x00] = LANTIK(ctx) + HALT
// XOR-CS = 0x5A.  Encrypted with unique per-program AES-256-CBC split key.
static volatile const uint8_t LBC_ANTIK_KHI[] = {
    0xa7,0xe2,0xab,0xa2,0x5b,0xc0,0x18,0x7a,0x95,0xd5,0x86,0xeb,0xb6,0x7a,0xec,0xfc,
    0xd4,0x18,0x32,0x6d,0x0e,0xf9,0x4b,0x67,0x0a,0xac,0x60,0xbc,0xde,0xd7,0x89,0x83};
static volatile const uint8_t LBC_ANTIK_KLO[] = {
    0xe4,0x91,0x13,0xd4,0xd5,0x63,0x1a,0x30,0x54,0xf8,0x47,0x15,0xdc,0xc9,0xf6,0x31,
    0x4a,0x78,0x33,0xcf,0xc3,0xe1,0x89,0xcf,0xfd,0x7d,0x9e,0xd4,0x90,0x78,0xe7,0x93};
static volatile const uint8_t LBC_ANTIK_IHI[] = {
    0x2c,0x16,0x26,0x87,0x63,0x7f,0x77,0x21,0x80,0x02,0x9a,0x6f,0x59,0xf1,0x73,0xab};
static volatile const uint8_t LBC_ANTIK_ILO[] = {
    0xe4,0x48,0x74,0x53,0x6c,0xc6,0x61,0xee,0xde,0xe3,0x76,0x1b,0xad,0x64,0x9e,0x33};
static volatile const uint8_t LBC_ANTIK_ENC[] = {
    0x64,0x3f,0x66,0x91,0x7d,0x28,0xda,0x5b,0x68,0xd9,0xda,0x4d,0x6b,0xc7,0xc7,0x58};
#define LBC_ANTIK_LEN 16
#define LBC_ANTIK_CS  0x5au

// Dispatches LANTIK check through the same lvm_exec interpreter used by all
// other native checks.  Ghidra sees: lvm_exec(K…,I…,ENC,16,ctx) — opaque.
static __attribute__((noinline)) void vm_run_antik(const antik_ctx_t *ctx) {
    lvm_exec(LBC_ANTIK_KHI, LBC_ANTIK_KLO,
             LBC_ANTIK_IHI, LBC_ANTIK_ILO,
             LBC_ANTIK_ENC, LBC_ANTIK_LEN, LBC_ANTIK_CS,
             (const void *)ctx);
}

// Volatile JNI dispatch table — one slot per JNI security check.
// Declared at file scope so it lands in .data, preventing compiler folding.
typedef void (*_JniGuardFn)(JNIEnv *, jobject);
static volatile _JniGuardFn g_jni_guard_tab[1] = {
    check_provider_callback_xref,  // slot 0
};

static void _fonts_measure_impl(JNIEnv *env, jclass /*cls*/, jobject context) {
    GLOGI("_fonts_measure_impl: start (context=%p)", (void *)context);

    // Collect all detection signals into a plain-C context struct.
    // No kill decision here — everything routes to vm_run_antik() at the end.
    antik_ctx_t actx;
    memset(&actx, 0, sizeof(actx));

    // ── 1. BEHAVIORAL: ContentProvider ↔ lifecycle callback cross-reference ──
    // Indirect dispatch via g_jni_guard_tab[0]; disassembler sees BLR xN.
    // Crashes inline on detection (its own internal kill path).
    { _JniGuardFn _fn = g_jni_guard_tab[0]; if (_fn) _fn(env, context); }

    // ── 2. Class.forName — exact known killer class names (BC1-BC6) ───────
    // On detection: sets actx.exact_hit instead of crashing here.
    // Kill decision deferred to vm_run_antik() → lvm_exec opcode 0x5B.
    {
        jclass jClassClass = env->FindClass(NS_JNI(48, SP_JNI_JLCLASS));
        if (jClassClass) {
            jmethodID forName = env->GetStaticMethodID(jClassClass, NS_JNI(49, SP_JNI_FORNAME),
                NS_JNI(50, SP_JNI_FORNAME_SIG));
            if (forName) {
                for (int i = 0; i < BLOCKED_CLASS_COUNT; i++) {
                    char buf[PSTR_BUF_SZ];
                    const char *cname = reveal(BLOCKED_CLASS_CT[i], BLOCKED_CLASS_LEN[i], buf);
                    jstring jn = env->NewStringUTF(cname);
                    memset(buf, 0, sizeof(buf));
                    if (!jn) continue;
                    env->CallStaticObjectMethod(jClassClass, forName, jn);
                    env->DeleteLocalRef(jn);
                    if (env->ExceptionCheck()) {
                        env->ExceptionClear();  // ClassNotFoundException → good
                    } else {
                        GLOGE("_fonts_measure_impl: blocked class[%d] resolved", i);
                        actx.exact_hit = 1;  // defer crash to vm_run_antik
                    }
                }
            }
            env->DeleteLocalRef(jClassClass);
        }
    }

    // ── 3. REMOVED — resolveContentProvider caused OEM false-positives.

    // ── 4. Provider fragment scan — collect names/auths into actx ─────────
    // JNI data-gathering only. No strstr, no CRASH_HERE.
    // vm_run_antik() → lvm_exec 0x5B does all KFRAG matching and crash.
    if (!context) goto run_vm;
    {
        jclass ctxCls4 = env->GetObjectClass(context);
        if (!ctxCls4) goto run_vm;
        jmethodID getPM4     = env->GetMethodID(ctxCls4, NS_JNI(58, SP_JNI_GETPM),
                                                NS_JNI(59, SP_JNI_PM_RET));
        jmethodID getPkgName4= env->GetMethodID(ctxCls4, NS_JNI(60, SP_JNI_GETPKGNAME),
                                                NS_JNI(57, SP_JNI_STR_RET));
        env->DeleteLocalRef(ctxCls4);
        if (!getPM4 || !getPkgName4 || env->ExceptionCheck()) { env->ExceptionClear(); goto run_vm; }

        jobject pm4 = env->CallObjectMethod(context, getPM4);
        if (!pm4 || env->ExceptionCheck()) { env->ExceptionClear(); goto run_vm; }

        jstring pkgName4 = (jstring)env->CallObjectMethod(context, getPkgName4);
        if (!pkgName4 || env->ExceptionCheck()) {
            env->ExceptionClear(); env->DeleteLocalRef(pm4); goto run_vm;
        }

        jclass pmCls4 = env->GetObjectClass(pm4);
        jmethodID getPkgInfo4 = pmCls4 ? env->GetMethodID(pmCls4, NS_JNI(61, SP_JNI_GETPKGINFO),
            NS_JNI(62, SP_JNI_PKGINFO_SIG)) : nullptr;
        if (pmCls4) env->DeleteLocalRef(pmCls4);
        if (env->ExceptionCheck()) env->ExceptionClear();

        char ownPkg4[256] = {};
        {
            const char *tmp = env->GetStringUTFChars(pkgName4, nullptr);
            if (tmp) { strncpy(ownPkg4, tmp, 255); env->ReleaseStringUTFChars(pkgName4, tmp); }
        }

        const jint GET_PROVIDERS = 0x00000008;
        jobject pkgInfo4 = getPkgInfo4
            ? env->CallObjectMethod(pm4, getPkgInfo4, pkgName4, GET_PROVIDERS) : nullptr;
        if (env->ExceptionCheck()) { env->ExceptionClear(); pkgInfo4 = nullptr; }
        env->DeleteLocalRef(pm4); env->DeleteLocalRef(pkgName4);

        if (pkgInfo4) {
            jclass piCls4 = env->GetObjectClass(pkgInfo4);
            jfieldID provsFld4 = env->GetFieldID(piCls4, NS_JNI(63, SP_JNI_PROVIDERS),
                NS_JNI(64, SP_JNI_PROVINFO));
            env->DeleteLocalRef(piCls4);
            if (provsFld4 && !env->ExceptionCheck()) {
                jobjectArray provs4 = (jobjectArray)env->GetObjectField(pkgInfo4, provsFld4);
                if (env->ExceptionCheck()) { env->ExceptionClear(); provs4 = nullptr; }
                if (provs4) {
                    jsize n4 = env->GetArrayLength(provs4);
                    for (jsize i = 0; i < n4 && actx.count < ANTIK_MAX_PROV; i++) {
                        jobject prov4 = env->GetObjectArrayElement(provs4, i);
                        if (!prov4 || env->ExceptionCheck()) { env->ExceptionClear(); continue; }
                        jclass pc4 = env->GetObjectClass(prov4);
                        // Own-APK gate
                        jfieldID pkgF4 = env->GetFieldID(pc4, NS_JNI(65, SP_JNI_PKGNAME_FLD), NS_JNI(66, SP_JNI_STR_DESC));
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        if (pkgF4 && ownPkg4[0]) {
                            jstring pp4 = (jstring)env->GetObjectField(prov4, pkgF4);
                            if (env->ExceptionCheck()) { env->ExceptionClear(); pp4 = nullptr; }
                            bool own4 = false;
                            if (pp4) {
                                const char *pps4 = env->GetStringUTFChars(pp4, nullptr);
                                if (pps4) { own4=(strcmp(pps4,ownPkg4)==0); env->ReleaseStringUTFChars(pp4,pps4); }
                                env->DeleteLocalRef(pp4);
                            }
                            if (!own4) { env->DeleteLocalRef(pc4); env->DeleteLocalRef(prov4); continue; }
                        }
                        // Collect class name and authority into actx slot
                        jfieldID nF4 = env->GetFieldID(pc4, "name",      NS_JNI(66, SP_JNI_STR_DESC));
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        jfieldID aF4 = env->GetFieldID(pc4, "authority", NS_JNI(66, SP_JNI_STR_DESC));
                        if (env->ExceptionCheck()) env->ExceptionClear();
                        env->DeleteLocalRef(pc4);
                        int slot = actx.count;
                        if (nF4) {
                            jstring cn4 = (jstring)env->GetObjectField(prov4, nF4);
                            if (env->ExceptionCheck()) { env->ExceptionClear(); cn4=nullptr; }
                            if (cn4) {
                                const char *cs4 = env->GetStringUTFChars(cn4, nullptr);
                                if (cs4) { strncpy(actx.names[slot],cs4,ANTIK_STR_SZ-1);
                                           env->ReleaseStringUTFChars(cn4,cs4); }
                                env->DeleteLocalRef(cn4);
                            }
                        }
                        if (aF4) {
                            jstring au4 = (jstring)env->GetObjectField(prov4, aF4);
                            if (env->ExceptionCheck()) { env->ExceptionClear(); au4=nullptr; }
                            if (au4) {
                                const char *as4 = env->GetStringUTFChars(au4, nullptr);
                                if (as4) { strncpy(actx.auths[slot],as4,ANTIK_STR_SZ-1);
                                           env->ReleaseStringUTFChars(au4,as4); }
                                env->DeleteLocalRef(au4);
                            }
                        }
                        env->DeleteLocalRef(prov4);
                        actx.count++;
                    }
                    env->DeleteLocalRef(provs4);
                }
            } else { if (env->ExceptionCheck()) env->ExceptionClear(); }
            env->DeleteLocalRef(pkgInfo4);
        }
    }

run_vm:
    // ── VM kill decision — pure-C, inside AES-encrypted lvm_exec bytecode ──
    // Ghidra sees _fonts_measure_impl end with: lvm_exec(KHI,KLO,IHI,ILO,ENC,16,CS,&actx)
    // No strstr, no CRASH_HERE, no fragment strings visible in this function.
    vm_run_antik(&actx);
    memset(&actx, 0, sizeof(actx));
}

// ── RegisterNatives table ─────────────────────────────────────────────────

// JNINativeMethod built at runtime — method name + signature are
// AES-encrypted in guard_pstrings.inc (idx 75, 76); no plaintext in .rodata.

// ════════════════════════════════════════════════════════════════════════════
// fonts_register_natives — hard-fail version.
// If fonts/Metrics is missing OR RegisterNatives fails, crash immediately.
// A protected APK with this binding broken has no anti-tamper check wired up
// at all — must never pass silently.
// ════════════════════════════════════════════════════════════════════════════

extern "C" __attribute__((visibility("default")))
void fonts_register_natives(JNIEnv *env) {
    jclass cls = env->FindClass(NS_JNI(67, SP_JNI_FMETRICS));
    if (!cls) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        GLOGE("fonts_register_natives: FindClass(fonts/Metrics) failed — class missing/stripped");
        CRASH_HERE("guard class fonts.Metrics not found at RegisterNatives time");
        return;
    }
    JNINativeMethod _fm = {NS_JNI(75, SP_JNI_MEASURE),
                           NS_JNI(76, SP_JNI_MEASURE_SIG),
                           (void *)_fonts_measure_impl};
    jint rc = env->RegisterNatives(cls, &_fm, 1);
    // If measure() was smali-patched (signature changed, native modifier removed,
    // etc.) there is no matching native method and this fails. Fail closed.
    bool bindFailed = (rc != JNI_OK);
    if (env->ExceptionCheck()) { env->ExceptionClear(); bindFailed = true; }
    env->DeleteLocalRef(cls);
    GLOGI("fonts_register_natives: RegisterNatives rc=%d bindFailed=%d", (int)rc, (int)bindFailed);
    if (bindFailed) CRASH_HERE("RegisterNatives failed to bind measure() — smali-patched signature?");
}

// ════════════════════════════════════════════════════════════════════════════
// JNI_OnLoad-time self-sufficient check — Context resolver
// ════════════════════════════════════════════════════════════════════════════

static jobject get_context_via_activity_thread(JNIEnv *env) {
    if (!env) return nullptr;
    jclass atCls = env->FindClass(NS_JNI(68, SP_JNI_AT_CLASS));
    if (!atCls) { env->ExceptionClear(); return nullptr; }
    jmethodID currentApp = env->GetStaticMethodID(atCls, NS_JNI(69, SP_JNI_CURAPP),
                                                   NS_JNI(70, SP_JNI_APP_RET));
    if (!currentApp) {
        env->ExceptionClear(); env->DeleteLocalRef(atCls); return nullptr;
    }
    jobject app = env->CallStaticObjectMethod(atCls, currentApp);
    env->DeleteLocalRef(atCls);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }
    return app;
}

// Returns true once ActivityThread.mActivities has at least one entry —
// i.e. the first Activity has been created and is on-stack. This guarantees
// PairIP (and any Application subclass) has fully completed its own
// attachBaseContext / onCreate before the killer check runs.
static bool has_started_activity(JNIEnv *env) {
    jclass atCls = env->FindClass(NS_JNI(68, SP_JNI_AT_CLASS));
    if (!atCls) { env->ExceptionClear(); return false; }
    jmethodID curAT = env->GetStaticMethodID(atCls, NS_JNI(71, SP_JNI_CURAT),
                                              NS_JNI(72, SP_JNI_AT_RET));
    if (!curAT) { env->ExceptionClear(); env->DeleteLocalRef(atCls); return false; }
    jobject at = env->CallStaticObjectMethod(atCls, curAT);
    env->DeleteLocalRef(atCls);
    if (!at || env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    jclass atObj = env->GetObjectClass(at);
    jfieldID fid  = env->GetFieldID(atObj, NS_JNI(73, SP_JNI_MACTIVITIES), NS_JNI(74, SP_JNI_MAP_DESC));
    env->DeleteLocalRef(atObj);
    if (!fid || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(at); return false;
    }
    jobject map = env->GetObjectField(at, fid);
    env->DeleteLocalRef(at);
    if (!map) return false;
    jclass mapCls  = env->GetObjectClass(map);
    jmethodID size = env->GetMethodID(mapCls, "size", "()I");
    env->DeleteLocalRef(mapCls);
    if (!size || env->ExceptionCheck()) {
        env->ExceptionClear(); env->DeleteLocalRef(map); return false;
    }
    jint n = env->CallIntMethod(map, size);
    env->DeleteLocalRef(map);
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    return n > 0;
}

// Two-phase retry thread:
//   Phase 1 — wait until ActivityThread.currentApplication() returns non-null
//   Phase 2 — wait until at least one Activity is on-stack (PairIP/app init done)
//   Phase 3 — run the full killer-detection suite
static void *fonts_retry_thread(void *arg) {
    JavaVM *vm = static_cast<JavaVM *>(arg);
    if (!vm) return nullptr;

    const int MAX_ATTEMPTS = 300;      // ~9 s ceiling at 30 ms steps
    const int SLEEP_US     = 30 * 1000;

    // ── Phase 1: wait for Application context ────────────────────────────
    jobject gCtx = nullptr;
    for (int i = 0; i < MAX_ATTEMPTS && !gCtx; i++) {
        JNIEnv *env = nullptr;
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK && env) {
            jobject ctx = get_context_via_activity_thread(env);
            if (ctx) {
                gCtx = env->NewGlobalRef(ctx);
                env->DeleteLocalRef(ctx);
            }
            vm->DetachCurrentThread();
        }
        if (!gCtx) usleep(SLEEP_US);
    }
    if (!gCtx) return nullptr;

    // ── Phase 2: wait until first Activity is on-stack ───────────────────
    for (int i = 0; i < MAX_ATTEMPTS; i++) {
        JNIEnv *env = nullptr;
        if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK && env) {
            bool ready = has_started_activity(env);
            vm->DetachCurrentThread();
            if (ready) break;
        }
        usleep(SLEEP_US);
    }

    // ── Phase 3: run full killer check ───────────────────────────────────
    JNIEnv *env = nullptr;
    if (vm->AttachCurrentThread(&env, nullptr) == JNI_OK && env) {
        _fonts_measure_impl(env, nullptr, gCtx);
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteGlobalRef(gCtx);
        vm->DetachCurrentThread();
    }
    return nullptr;
}

// Exposed so both JNI_OnLoad variants (ours below and the transpiler-generated
// jni_onload.cpp when D2C_HAS_JNILOAD is defined) can trigger the full
// killer-detection suite via fonts_apply_metrics(env).
extern "C" __attribute__((visibility("default")))
void fonts_apply_metrics(JNIEnv *env) {
    // Fast path: Context already available — run the retry thread on existing
    // context so the 2-phase wait still applies (don't call _fonts_measure_impl
    // directly here to avoid racing with PairIP init).
    JavaVM *vm = nullptr;
    if (env) env->GetJavaVM(&vm);
    if (!vm) return;

    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_create(&t, &attr, fonts_retry_thread, static_cast<void*>(vm));
    pthread_attr_destroy(&attr);
}

// ═══════════════════════════════════════════════════════════════════════════
// §9  Phantom Stub Loader
//     Decrypts phantom/phantom.vmp, injects shard DEX files into the app's
//     classloader, reads phantom/app.cfg, sets Const.REAL_APP.
//     Registered as: native void com.secure.dex.utils.DexProtector.install(Context)
//     ProxyApplication calls System.loadLibrary(name-from-phantom/lib.cfg)
//     then DexProtector.install(context) — no bytecode crypto left in stub.
// ═══════════════════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════════════════
// §9 Anti-dump: ART dalvik-DEX magic destruction
//
// HOW THE DUMPERS WORK
// ─────────────────────
// dump_dex_mem.py (pure /proc/PID/mem, no Frida, root + Python only):
//   Opens /proc/<PID>/maps → enumerates every readable region.
//   Opens /proc/<PID>/mem → seeks to each region, reads 4 MB chunks.
//   Searches every chunk for the 4-byte pattern 64 65 78 0A ("dex\n").
//   Validates: file_size at hdr+32, endian_tag 0x12345678 at hdr+40.
//   Primary target: "[anon:dalvik-DEX]" — the anonymous pages ART creates
//   when it loads a DEX shard via makeDexElements / DexFile::Open().
//   DumperService automates the whole flow: launches the target app via
//   `monkey`, waits for decryption, then runs the Python script.
//
// memscan_*.js (Frida):
//   Process.enumerateRanges('r--') + ('rw-')
//   Memory.scanSync(base, size, '64 65 78 0a')  — same search, same target.
//   Deploys 10–22 libc-level patches (kill/raise/tgkill/exit/_exit/abort/
//   sigaction/pthread_create/strstr/getenv/prctl/dlopen/readdir) so our
//   existing kill-based crash paths are neutralised.
//   Waits 7–18 s for the app to fully initialise before scanning.
//
// THE REMAINING GAP (before this commit)
// ────────────────────────────────────────
// We already poison `plain` before free() in §9 c (covers the decrypt window
// in the transient malloc buffer).  But makeDexElements then reads those shard
// files and ART allocates NEW [anon:dalvik-DEX] pages with the full dex\n
// magic intact — THOSE are the pages both tools actually find and dump.
//
// DEFENSE 1 — immediate synchronous poison after makeDexElements (§9 d.5):
//   Scan /proc/self/maps for [anon:dalvik-DEX] regions, temporarily mprotect
//   each one to add write, overwrite the first 8 bytes with 0xCC, restore perm.
//   ART never re-reads the raw magic header after DexFile::Open() returns —
//   it uses its parsed internal class-table, OAT, and method structures.
//   Both tools search for 64 65 78 0A; they find CC CC CC CC → zero results.
//
// DEFENSE 2 — repeating background thread (anti_dump_thread, 500 ms):
//   ART lazily maps new DEX pages on first class-touch / JIT compilation.
//   The thread re-runs poisoning every 500 ms:
//     7-18 s scanner wait ÷ 500 ms = 14–36 wipe passes before any scan fires.
//     dump_dex_mem.py 3 s retry also gets 6 more passes between pass1 & pass2.
//   Thread has no crash path — Frida's kill/exit patches cannot stop it.
//
// DEFENSE 3 — SELinux permissive crash in fonts_init() (above):
//   Every known dumper (DumperService + all Frida guides) runs `setenforce 0`
//   as a required first step.  We crash via hardware SIGSEGV
//   (*(volatile int*)nullptr = 0) which is a CPU memory-protection fault and
//   therefore cannot be intercepted by Frida's libc-level signal/kill patches.
//
// NOTE: All three defenses are packer-path-only.
//   anti_dump_thread and poison_art_dex_regions are launched/called from
//   DexProtector.install() (§9 d.5 / §9 d4), which is never entered in
//   VMP or dex2c builds that don't use the DEX packer.
// ════════════════════════════════════════════════════════════════════════════

// Wipe "dex\n" magic from every [anon:dalvik-DEX] region in our address space.
// Called once synchronously right after makeDexElements, then periodically by
// anti_dump_thread.  Safe: ART's DexFile::Open() has already parsed the DEX
// into internal structures; the raw header bytes are never re-validated after
// that point.
static void poison_art_dex_regions(void) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return;

    char line[512];
    int  poisoned = 0;

    while (fgets(line, (int)sizeof(line), maps)) {
        if (!strstr(line, "dalvik-DEX")) continue;  // only ART DEX pages

        unsigned long rgn_start = 0, rgn_end = 0;
        char perms[8] = {};
        if (sscanf(line, "%lx-%lx %7s", &rgn_start, &rgn_end, perms) != 3) continue;
        if (perms[0] != 'r') continue;         // not readable — skip
        if (rgn_end - rgn_start < 8) continue;

        volatile uint8_t *ptr = reinterpret_cast<volatile uint8_t *>(rgn_start);

        // Verify the region really carries a DEX header before touching it
        if (ptr[0] != 'd' || ptr[1] != 'e' || ptr[2] != 'x' || ptr[3] != '\n')
            continue;

        // Need write access — mprotect the first page briefly if read-only
        bool added_write = false;
        if (perms[1] != 'w') {
            uintptr_t page = rgn_start & ~(uintptr_t)4095u;
            if (mprotect(reinterpret_cast<void *>(page), 4096,
                         PROT_READ | PROT_WRITE) == 0) {
                added_write = true;
            } else {
                continue; // can't write — leave this region
            }
        }

        // Destroy the 8-byte magic+version ("dex\n035\0") → 0xCCx8
        // Memory.scanSync and /proc/mem both search for 64 65 78 0A;
        // they find CC CC CC CC instead → scan yields zero matches.
        memset(reinterpret_cast<void *>(rgn_start), 0xCC, 8);
        poisoned++;
        GLOGI("poison_art: wiped [anon:dalvik-DEX] @ 0x%lx (%lu bytes)",
              rgn_start, (unsigned long)(rgn_end - rgn_start));

        // Restore original permissions so ART continues working normally
        if (added_write) {
            uintptr_t page = rgn_start & ~(uintptr_t)4095u;
            mprotect(reinterpret_cast<void *>(page), 4096, PROT_READ);
        }
    }
    fclose(maps);
    GLOGI("poison_art: total=%d region(s) wiped", poisoned);
}

// Background thread that re-runs poisoning every 500 ms.
// Handles DEX pages ART maps lazily (first class-touch after initial load).
// Thread itself never calls kill/exit/abort, so Frida's libc patches
// (which block those calls) have zero effect on it.
static void *anti_dump_thread(void *) {
    struct timespec ts = {0, 500000000L}; // 500 ms
    for (;;) {
        nanosleep(&ts, NULL);
        poison_art_dex_regions();
    }
    return NULL;
}

// Hardware-fault crash — bypasses Frida's kill/exit/abort/sigaction patches.
// All collected memscan scripts patch kill(SIGKILL)/raise/tgkill/exit/_exit/
// abort at libc level, but NONE of them patch SIGSEGV (signal 11).
// A write to address 0 is a CPU memory-protection fault → kernel delivers
// SIGSEGV directly without going through any libc trampoline → process dies
// even if every standard kill path has been intercepted.
__attribute__((noinline))
static void crash_sigsegv(void) {
    volatile int *p = nullptr;
    *p = 0; // hardware SIGSEGV — cannot be blocked via libc-level intercepts
}

// ── §9.0  Late-init function pointers (VMP + dex2c) ──────────────────────
// Both are assigned in JNI_OnLoad before DexProtector.install() ever runs,
// then called by §9 d3 AFTER DEX shards are merged into dexElements — at
// that point all app classes are visible to FindClass / RegisterNatives.
// Plain function pointers instead of weak symbols: TCC does not reliably
// resolve __attribute__((weak)) function refs from static archives.
#ifdef __cplusplus
extern "C" {
#endif
// Set by VMP jni_init.cpp — calls per-DEX classesInit0 setup.
void (*g_vmp_lateInit_fp)(JNIEnv *) = nullptr;
// Set by dex2c jni_onload.cpp (patchJniOnload) — calls RegisterNatives
// for all transpiled native methods deferred until app classes are loaded.
void (*g_d2c_lateInit_fp)(JNIEnv *) = nullptr;
#ifdef __cplusplus
}
#endif

// ── §9.1  Cipher — exact C port of DexCrypto.FxIjsF + nDnv + exfr ───────

static __attribute__((noinline)) void
sl_key_schedule(const uint32_t seed[4], uint32_t rk[27]) {
    uint32_t s0 = seed[0];
    uint32_t tmp[3] = {seed[1], seed[2], seed[3]};
    rk[0] = s0;
    for (int i = 0; i < 26; i++) {
        int m = i % 3;
        tmp[m] = ((tmp[m] >> 8) | (tmp[m] << 24)) + s0 ^ (uint32_t)i;
        s0 = ((s0 << 3) | (s0 >> 29)) ^ tmp[m];
        rk[i + 1] = s0;
    }
}

static __attribute__((noinline)) void
sl_update_state(const uint32_t rk[27], uint32_t st[2]) {
    uint32_t a = st[0], b = st[1];
    for (int i = 0; i < 27; i++) {
        b = ((b >> 8) | (b << 24)) + a ^ rk[i];
        a = ((a << 3) | (a >> 29)) ^ b;
    }
    st[0] = a;
    st[1] = b;
}

// XOR keystream over buf[0..len), stream position tracked via *pos.
static void sl_xor_buf(uint32_t rk[27], uint32_t st[2],
                        uint8_t *buf, size_t len, size_t *pos) {
    for (size_t k = 0; k < len; k++, (*pos)++) {
        int mod8 = (int)(*pos & 7u);
        if (mod8 == 0) sl_update_state(rk, st);
        buf[k] ^= (uint8_t)(st[mod8 >> 2] >> ((int)((*pos & 3u) * 8u)));
    }
}

// ── §9.2  zlib inflate helper ─────────────────────────────────────────────

static uint8_t *sl_inflate_all(const uint8_t *in, size_t in_len, size_t *out_len) {
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) return nullptr;
    size_t cap = in_len * 4 + 65536;
    uint8_t *out = (uint8_t *)malloc(cap);
    if (!out) { inflateEnd(&zs); return nullptr; }
    zs.next_in  = (Bytef *)in;
    zs.avail_in = (uInt)in_len;
    int ret;
    do {
        if (zs.total_out + 65536 > cap) {
            cap *= 2;
            uint8_t *t2 = (uint8_t *)realloc(out, cap);
            if (!t2) { free(out); inflateEnd(&zs); return nullptr; }
            out = t2;
        }
        zs.next_out  = out + zs.total_out;
        zs.avail_out = (uInt)(cap - zs.total_out);
        ret = inflate(&zs, Z_NO_FLUSH);
    } while (ret == Z_OK);
    *out_len = (size_t)zs.total_out;
    inflateEnd(&zs);
    if (ret != Z_STREAM_END) { free(out); return nullptr; }
    return out;
}

// ── §9.3  Decrypt one shard: inflate(XOR_stream(inflate(ciphertext))) ────

static uint8_t *sl_decrypt_shard(const uint8_t *enc, size_t enc_len,
                                  size_t *plain_len) {
    // Recover PROTECT_KEY via GSTR_DECRYPT and build round keys
    const char *kraw = GSTR_DECRYPT(SL_PKEY, SL_PKEY_LEN, SL_PKEY_KEY);
    uint32_t seed[4] = {
        (uint32_t)(uint8_t)kraw[0]  | ((uint32_t)(uint8_t)kraw[1]  << 16),
        (uint32_t)(uint8_t)kraw[2]  | ((uint32_t)(uint8_t)kraw[3]  << 16),
        (uint32_t)(uint8_t)kraw[4]  | ((uint32_t)(uint8_t)kraw[5]  << 16),
        (uint32_t)(uint8_t)kraw[6]  | ((uint32_t)(uint8_t)kraw[7]  << 16),
    };
    uint32_t st[2] = {
        (uint32_t)(uint8_t)kraw[8]  | ((uint32_t)(uint8_t)kraw[9]  << 16),
        (uint32_t)(uint8_t)kraw[10] | ((uint32_t)(uint8_t)kraw[11] << 16),
    };
    // ── §9.3.1  Key mixing — packer-path only ────────────────────────────────
    // XOR cert hash and manifest hash into seed/state BEFORE key schedule.
    // These globals are set by the ELF-constructor integrity checks and are
    // zero when unavailable (unsigned APK, unreadable manifest, or check
    // disabled) — XOR with zero is identity so those cases fall back cleanly.
    //
    // NOTE: This code path is ONLY reached from DexProtector.install() which
    // is ONLY called when the DEX packer is active.  VMP and dex2c modes with
    // the packer OFF never call sl_decrypt_shard() → zero impact on them.
    //
    // cert mix — first 12 bytes of SHA-256(X.509 signing cert)
    // Uses same byte-pair packing as kraw → seed/st construction above.
    if (g_cert_key_mix[0] | g_cert_key_mix[1] | g_cert_key_mix[2]) {
        seed[0] ^= (uint32_t)(g_cert_key_mix[0])  | ((uint32_t)(g_cert_key_mix[1])  << 16);
        seed[1] ^= (uint32_t)(g_cert_key_mix[2])  | ((uint32_t)(g_cert_key_mix[3])  << 16);
        seed[2] ^= (uint32_t)(g_cert_key_mix[4])  | ((uint32_t)(g_cert_key_mix[5])  << 16);
        seed[3] ^= (uint32_t)(g_cert_key_mix[6])  | ((uint32_t)(g_cert_key_mix[7])  << 16);
        st[0]   ^= (uint32_t)(g_cert_key_mix[8])  | ((uint32_t)(g_cert_key_mix[9])  << 16);
        st[1]   ^= (uint32_t)(g_cert_key_mix[10]) | ((uint32_t)(g_cert_key_mix[11]) << 16);
        GLOGI("sl_decrypt_shard: cert mix applied %02x%02x...",
              g_cert_key_mix[0], g_cert_key_mix[1]);
    }
    // manifest mix — FNV-1a-64 low/high 32 bits into seed[0..1]
    if (g_manifest_key_mix != 0) {
        seed[0] ^= (uint32_t)(g_manifest_key_mix & 0xFFFFFFFFu);
        seed[1] ^= (uint32_t)(g_manifest_key_mix >> 32);
        GLOGI("sl_decrypt_shard: manifest mix applied 0x%016llx",
              (unsigned long long)g_manifest_key_mix);
    }

    uint32_t rk[27];
    sl_key_schedule(seed, rk);

    // Step 1: inflate outer deflate layer
    size_t step1_len = 0;
    uint8_t *step1 = sl_inflate_all(enc, enc_len, &step1_len);
    if (!step1) return nullptr;

    // Step 2: XOR stream cipher (in-place)
    size_t pos = 0;
    sl_xor_buf(rk, st, step1, step1_len, &pos);

    // Step 3: inflate inner deflate layer → plaintext DEX
    uint8_t *plain = sl_inflate_all(step1, step1_len, plain_len);
    free(step1);
    return plain;
}

// ── §9.4  JNI asset reader: returns malloc'd buffer, caller frees ─────────

static uint8_t *sl_read_asset(JNIEnv *env, jobject context,
                               const char *path, size_t *out_len) {
    jclass ctxCls = env->GetObjectClass(context);
    jmethodID getAssets = env->GetMethodID(ctxCls,
        GSTR_DECRYPT(SL_GET_ASSETS, SL_GET_ASSETS_LEN, SL_GET_ASSETS_KEY),
        GSTR_DECRYPT(SL_GET_ASSETS_SIG, SL_GET_ASSETS_SIG_LEN, SL_GET_ASSETS_SIG_KEY));
    jobject assetMgr = env->CallObjectMethod(context, getAssets);
    if (!assetMgr || env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }

    jclass amCls = env->GetObjectClass(assetMgr);
    jmethodID openMid = env->GetMethodID(amCls,
        GSTR_DECRYPT(SL_OPEN, SL_OPEN_LEN, SL_OPEN_KEY),
        GSTR_DECRYPT(SL_OPEN_SIG, SL_OPEN_SIG_LEN, SL_OPEN_SIG_KEY));
    jstring jpath = env->NewStringUTF(path);
    jobject is = env->CallObjectMethod(assetMgr, openMid, jpath);
    env->DeleteLocalRef(jpath);
    if (!is || env->ExceptionCheck()) { env->ExceptionClear(); return nullptr; }

    jclass isCls = env->GetObjectClass(is);
    jmethodID availMid = env->GetMethodID(isCls,
        GSTR_DECRYPT(SL_AVAIL, SL_AVAIL_LEN, SL_AVAIL_KEY),
        GSTR_DECRYPT(SL_AVAIL_SIG, SL_AVAIL_SIG_LEN, SL_AVAIL_SIG_KEY));
    jmethodID readMid = env->GetMethodID(isCls,
        GSTR_DECRYPT(SL_READ, SL_READ_LEN, SL_READ_KEY),
        GSTR_DECRYPT(SL_READ_SIG, SL_READ_SIG_LEN, SL_READ_SIG_KEY));
    jmethodID closeMid = env->GetMethodID(isCls,
        GSTR_DECRYPT(SL_CLOSE, SL_CLOSE_LEN, SL_CLOSE_KEY),
        GSTR_DECRYPT(SL_VOID_SIG, SL_VOID_SIG_LEN, SL_VOID_SIG_KEY));

    jint hint = env->CallIntMethod(is, availMid);
    size_t cap = (hint > 0) ? (size_t)hint : 65536u;
    uint8_t *buf = (uint8_t *)malloc(cap);
    jbyteArray jbuf = env->NewByteArray((jsize)((hint > 0 && hint <= 65536) ? hint : 65536));
    size_t total = 0;
    while (true) {
        jint n = env->CallIntMethod(is, readMid, jbuf);
        if (n <= 0) break;
        if (total + (size_t)n > cap) {
            cap = (total + (size_t)n) * 2 + 65536;
            uint8_t *tmp = (uint8_t *)realloc(buf, cap);
            if (!tmp) { free(buf); buf = nullptr; break; }
            buf = tmp;
        }
        env->GetByteArrayRegion(jbuf, 0, n, (jbyte *)(buf + total));
        total += (size_t)n;
    }
    env->DeleteLocalRef(jbuf);
    env->CallVoidMethod(is, closeMid);
    *out_len = total;
    return buf;  // nullptr on alloc failure
}

// ── §9.5  DexProtector.install — bound via static JNI export (no RegisterNatives) ──
// Using the standard Java_<pkg>_<class>_<method> name so the JVM resolves it
// automatically on first call. This avoids any JNI_OnLoad FindClass / RegisterNatives
// failure path entirely. The symbol is visible in .dynsym but the class + method names
// are already plaintext in stub.dex, so no new information is exposed.

// ── Single JNI-call hook — defined once, wraps every JNI call in the function ──
// JCALL  : for calls that return a value (jclass, jmethodID, jobject, jstring, …)
// JCALLV : for void calls (DeleteLocalRef, SetObjectField, ExceptionClear, …)
// Both stringify the exact source expression in the log so you know which call failed.
#define JCALL(expr) ([&]() {                                \
    auto _jc_r = (expr);                                    \
    if (env->ExceptionCheck()) {                            \
        GLOGE("JNI EXC @ [" #expr "]");                    \
        env->ExceptionDescribe();                           \
        env->ExceptionClear();                              \
    }                                                       \
    return _jc_r;                                           \
}())

#define JCALLV(expr) do {                                   \
    (expr);                                                 \
    if (env->ExceptionCheck()) {                            \
        GLOGE("JNI EXC @ [" #expr "]");                    \
        env->ExceptionDescribe();                           \
        env->ExceptionClear();                              \
    }                                                       \
} while(0)

extern "C" JNIEXPORT void JNICALL
Java_com_secure_dex_utils_DexProtector_install(JNIEnv *env, jclass /*cls*/, jobject context) {
    GLOGI("§9 install: enter");
    fonts_register_natives(env);
    fonts_apply_metrics(env);

    // ── a. Resolve output directory via context.getDir("app_dex", 0) ──────
    jclass ctxCls    = JCALL(env->GetObjectClass(context));
    jmethodID getDirMid = JCALL(env->GetMethodID(ctxCls,
        GSTR_DECRYPT(SL_GET_DIR,     SL_GET_DIR_LEN,     SL_GET_DIR_KEY),
        GSTR_DECRYPT(SL_GET_DIR_SIG, SL_GET_DIR_SIG_LEN, SL_GET_DIR_SIG_KEY)));
    GLOGI("§9 a: ctxCls=%p  getDirMid=%p", (void*)ctxCls, (void*)getDirMid);

    jstring jdirName  = JCALL(env->NewStringUTF(
        GSTR_DECRYPT(SL_APPDIR, SL_APPDIR_LEN, SL_APPDIR_KEY)));
    jobject dexDirFile = JCALL(env->CallObjectMethod(context, getDirMid, jdirName, (jint)0));
    JCALLV(env->DeleteLocalRef(jdirName));
    GLOGI("§9 a: dexDirFile=%p", (void*)dexDirFile);
    if (!dexDirFile) { GLOGE("§9 a: getDir returned null — aborting"); return; }

    jclass    fileCls  = JCALL(env->GetObjectClass(dexDirFile));
    jmethodID mkdirsMid = JCALL(env->GetMethodID(fileCls,
        GSTR_DECRYPT(SL_MKDIRS,     SL_MKDIRS_LEN,     SL_MKDIRS_KEY),
        GSTR_DECRYPT(SL_MKDIRS_SIG, SL_MKDIRS_SIG_LEN, SL_MKDIRS_SIG_KEY)));
    jmethodID getAbsMid = JCALL(env->GetMethodID(fileCls,
        GSTR_DECRYPT(SL_GET_ABS,  SL_GET_ABS_LEN,  SL_GET_ABS_KEY),
        GSTR_DECRYPT(SL_STR_SIG2, SL_STR_SIG2_LEN, SL_STR_SIG2_KEY)));
    GLOGI("§9 a: mkdirsMid=%p  getAbsMid=%p", (void*)mkdirsMid, (void*)getAbsMid);

    JCALL(env->CallBooleanMethod(dexDirFile, mkdirsMid));
    jstring jabsPath    = (jstring)JCALL(env->CallObjectMethod(dexDirFile, getAbsMid));
    const char *dexDirPath = jabsPath
        ? JCALL(env->GetStringUTFChars(jabsPath, nullptr)) : nullptr;
    GLOGI("§9 a: dexDir = %s", dexDirPath ? dexDirPath : "(null)");
    if (!dexDirPath) { GLOGE("§9 a: could not get dexDir path — aborting"); return; }

    // ── b. Read phantom.vmp bundle ────────────────────────────────────────
    const char *bundlePath = GSTR_DECRYPT(SL_ASSET_BUNDLE, SL_ASSET_BUNDLE_LEN, SL_ASSET_BUNDLE_KEY);
    GLOGI("§9 b: reading bundle '%s'", bundlePath ? bundlePath : "(null)");
    size_t bundleLen = 0;
    uint8_t *bundle = sl_read_asset(env, context, bundlePath, &bundleLen);
    GLOGI("§9 b: bundle=%p len=%zu", (void*)bundle, bundleLen);
    if (!bundle || bundleLen < 4) {
        GLOGE("§9 b: bundle read failed — aborting");
        if (bundle) free(bundle);
        JCALLV(env->ReleaseStringUTFChars(jabsPath, dexDirPath));
        return;
    }

    uint32_t shardCount = ((uint32_t)bundle[0] << 24) | ((uint32_t)bundle[1] << 16)
                        | ((uint32_t)bundle[2] <<  8) |  (uint32_t)bundle[3];
    GLOGI("§9 b: shardCount=%u", shardCount);
    if (shardCount == 0 || shardCount > 64 || bundleLen < 4 + shardCount * 4) {
        GLOGE("§9 b: bad shardCount=%u — aborting", shardCount);
        free(bundle);
        JCALLV(env->ReleaseStringUTFChars(jabsPath, dexDirPath));
        return;
    }

    uint32_t *szArr = (uint32_t *)malloc(shardCount * sizeof(uint32_t));
    size_t cursor = 4;
    for (uint32_t i = 0; i < shardCount; i++) {
        szArr[i] = ((uint32_t)bundle[cursor]   << 24) | ((uint32_t)bundle[cursor+1] << 16)
                 | ((uint32_t)bundle[cursor+2] <<  8) |  (uint32_t)bundle[cursor+3];
        GLOGI("§9 b: shard[%u] encSize=%u", i, szArr[i]);
        cursor += 4;
    }

    // ── c. Decrypt each shard, write to dexDir ───────────────────────────
    const char *pfx = GSTR_DECRYPT(SL_SHARD_PFX, SL_SHARD_PFX_LEN, SL_SHARD_PFX_KEY);
    const char *ext = GSTR_DECRYPT(SL_DOT_DEX,   SL_DOT_DEX_LEN,   SL_DOT_DEX_KEY);
    char *dexPathList = (char *)malloc(shardCount * 600 + 16);
    dexPathList[0] = '\0';

    GLOGI("§9 c: decrypting %u shards", shardCount);
    for (uint32_t i = 0; i < shardCount; i++) {
        uint32_t encLen = szArr[i];
        if (cursor + encLen > bundleLen) {
            GLOGE("§9 c: shard[%u] overflows bundle cursor=%zu encLen=%u bundleLen=%zu",
                  i, cursor, encLen, bundleLen);
            break;
        }
        size_t plainLen = 0;
        uint8_t *plain = sl_decrypt_shard(bundle + cursor, encLen, &plainLen);
        cursor += encLen;
        GLOGI("§9 c: shard[%u] decrypt plain=%p plainLen=%zu", i, (void*)plain, plainLen);
        if (!plain) { GLOGE("§9 c: shard[%u] decrypt returned null", i); continue; }

        char shardPath[512];
        snprintf(shardPath, sizeof(shardPath), "%s/%s%u%s", dexDirPath, pfx, i, ext);
        unlink(shardPath);
        FILE *f = fopen(shardPath, "wb");
        if (f) {
            size_t wrote = fwrite(plain, 1, plainLen, f);
            fclose(f);
            GLOGI("§9 c: shard[%u] wrote %zu/%zu bytes → %s", i, wrote, plainLen, shardPath);
        } else {
            GLOGE("§9 c: shard[%u] fopen failed errno=%d path=%s", i, errno, shardPath);
        }
        // §9 c.1: Poison DEX magic header before freeing.
        // Memory-scanner tools (Frida DexDump, FART, dexdump) find loaded DEX
        // files by scanning for the 8-byte magic "dex\n035\0" / "dex\n039\0".
        // Overwriting it before free() means even if the allocator recycles
        // this block or a tool walks the full heap, no scannable DEX magic
        // exists in memory after this point.
        // Zero impact on VMP / dex2c without packer — this loop is only
        // entered from DexProtector.install() when the DEX packer is active.
        if (plainLen >= 8) memset(plain, 0xCC, 8);
        free(plain);
        if (i > 0) strcat(dexPathList, ":");
        strcat(dexPathList, shardPath);
    }
    GLOGI("§9 c: dexPathList = %s", dexPathList[0] ? dexPathList : "(empty)");
    free(szArr);
    free(bundle);

    // ── d. Inject shard DEX files into the app classloader ───────────────────
    // Strategy: mirror the old stub's loadDex() + invokeMakeElements() exactly.
    //   Call makeDexElements (or makePathElements) *directly on appCL's own
    //   DexPathList* so the resulting DexFile objects are registered under appCL
    //   from creation — no DexClassLoader intermediary, no "multiple class loaders"
    //   error on Android 9+.
    //
    // Branch by makeDexElements param count (matches old stub's packed-switch):
    //   2 params — API 14-18: (ArrayList<File>, File)
    //   3 params — API 19-25: (ArrayList<File>, File, ArrayList<IOException>)
    //   4 params — API 26+  : (ArrayList<File>, File, ArrayList<IOException>, ClassLoader)
    GLOGI("§9 d: classloader injection start (makeDexElements path)");
    if (dexPathList[0] == '\0') {
        GLOGE("§9 d: dexPathList empty — no shards decrypted, skipping injection");
    } else {
        do {
        // ── d.1 Get appCL = context.getClassLoader() ─────────────────────────
        jmethodID getCLMid = JCALL(env->GetMethodID(ctxCls,
            GSTR_DECRYPT(SL_GET_CL,     SL_GET_CL_LEN,     SL_GET_CL_KEY),
            GSTR_DECRYPT(SL_GET_CL_SIG, SL_GET_CL_SIG_LEN, SL_GET_CL_SIG_KEY)));
        jobject appCL = JCALL(env->CallObjectMethod(context, getCLMid));
        GLOGI("§9 d.1: getCLMid=%p  appCL=%p", (void*)getCLMid, (void*)appCL);
        if (!appCL) { GLOGE("§9 d.1: getClassLoader() returned null"); break; }

        // ── d.2 Get appCL.pathList via BaseDexClassLoader field ───────────────
        char optPath[520];
        snprintf(optPath, sizeof(optPath), "%s/opt", dexDirPath);
        mkdir(optPath, 0700);
        GLOGI("§9 d.2: optPath = %s", optPath);

        jclass bdclCls = JCALL(env->FindClass(
            GSTR_DECRYPT(SL_BDCL, SL_BDCL_LEN, SL_BDCL_KEY)));
        GLOGI("§9 d.2: bdclCls=%p", (void*)bdclCls);
        if (!bdclCls) { env->ExceptionClear(); GLOGE("§9 d.2: BaseDexClassLoader not found"); break; }

        jfieldID plFid = JCALL(env->GetFieldID(bdclCls,
            GSTR_DECRYPT(SL_PATHLIST,      SL_PATHLIST_LEN,      SL_PATHLIST_KEY),
            GSTR_DECRYPT(SL_PATHLIST_DESC, SL_PATHLIST_DESC_LEN, SL_PATHLIST_DESC_KEY)));
        if (!plFid) { env->ExceptionClear(); GLOGE("§9 d.2: pathList field not found"); break; }

        jobject appPL = JCALL(env->GetObjectField(appCL, plFid));
        GLOGI("§9 d.2: plFid=%p  appPL=%p", (void*)plFid, (void*)appPL);
        if (!appPL) { GLOGE("§9 d.2: appCL.pathList is null"); break; }

        // ── d.3 Build ArrayList<File> of shard paths ──────────────────────────
        jclass    fileCls  = JCALL(env->FindClass(
            GSTR_DECRYPT(SL_JFILE, SL_JFILE_LEN, SL_JFILE_KEY)));
        jmethodID fileInit = fileCls ? JCALL(env->GetMethodID(fileCls,
            GSTR_DECRYPT(SL_INIT, SL_INIT_LEN, SL_INIT_KEY),
            GSTR_DECRYPT(SL_FILE_INIT_SIG, SL_FILE_INIT_SIG_LEN, SL_FILE_INIT_SIG_KEY))) : nullptr;

        jclass    alistCls  = JCALL(env->FindClass(
            GSTR_DECRYPT(SL_JALIST, SL_JALIST_LEN, SL_JALIST_KEY)));
        jmethodID alistInit = alistCls ? JCALL(env->GetMethodID(alistCls,
            GSTR_DECRYPT(SL_INIT, SL_INIT_LEN, SL_INIT_KEY),
            GSTR_DECRYPT(SL_VOID_SIG, SL_VOID_SIG_LEN, SL_VOID_SIG_KEY))) : nullptr;
        jmethodID alistAdd  = alistCls ? JCALL(env->GetMethodID(alistCls,
            GSTR_DECRYPT(SL_ADD, SL_ADD_LEN, SL_ADD_KEY),
            GSTR_DECRYPT(SL_ADD_SIG, SL_ADD_SIG_LEN, SL_ADD_SIG_KEY))) : nullptr;

        GLOGI("§9 d.3: fileCls=%p fileInit=%p alistCls=%p alistInit=%p alistAdd=%p",
              (void*)fileCls, (void*)fileInit, (void*)alistCls, (void*)alistInit, (void*)alistAdd);
        if (!fileCls || !fileInit || !alistCls || !alistInit || !alistAdd) {
            env->ExceptionClear();
            GLOGE("§9 d.3: File/ArrayList JNI lookup failed");
            break;
        }

        // Build files ArrayList and optDirFile from shard paths
        jobject filesList = JCALL(env->NewObject(alistCls, alistInit));
        // parse colon-separated dexPathList
        {
            char *buf = strdup(dexPathList);
            char *tok = strtok(buf, ":");
            while (tok) {
                jstring jpath = JCALL(env->NewStringUTF(tok));
                jobject f     = JCALL(env->NewObject(fileCls, fileInit, jpath));
                JCALLV(env->CallBooleanMethod(filesList, alistAdd, f));
                JCALLV(env->DeleteLocalRef(f));
                JCALLV(env->DeleteLocalRef(jpath));
                tok = strtok(nullptr, ":");
            }
            free(buf);
        }
        jstring  jOptStr    = JCALL(env->NewStringUTF(optPath));
        jobject  optDirFile = JCALL(env->NewObject(fileCls, fileInit, jOptStr));
        JCALLV(env->DeleteLocalRef(jOptStr));

        // Empty ArrayList for suppressed exceptions (3- and 4-param variants)
        jobject suppressedList = JCALL(env->NewObject(alistCls, alistInit));

        GLOGI("§9 d.3: filesList=%p optDirFile=%p suppressedList=%p",
              (void*)filesList, (void*)optDirFile, (void*)suppressedList);

        // ── d.4 Walk appPL's class hierarchy, find makeDexElements ────────────
        //   Exactly mirrors DexProtector.invokeMakeElements() packed-switch logic.
        jclass  methodCls      = JCALL(env->FindClass(
            GSTR_DECRYPT(SL_REFLECT_M, SL_REFLECT_M_LEN, SL_REFLECT_M_KEY)));
        jmethodID getNameMid   = methodCls ? JCALL(env->GetMethodID(methodCls,
            GSTR_DECRYPT(SL_GETNAME,     SL_GETNAME_LEN,     SL_GETNAME_KEY),
            GSTR_DECRYPT(SL_GETNAME_SIG, SL_GETNAME_SIG_LEN, SL_GETNAME_SIG_KEY))) : nullptr;
        jmethodID getPTypesMid = methodCls ? JCALL(env->GetMethodID(methodCls,
            GSTR_DECRYPT(SL_GETPTYPES,     SL_GETPTYPES_LEN,     SL_GETPTYPES_KEY),
            GSTR_DECRYPT(SL_GETPTYPES_SIG, SL_GETPTYPES_SIG_LEN, SL_GETPTYPES_SIG_KEY))) : nullptr;
        jmethodID setAccMid    = methodCls ? JCALL(env->GetMethodID(methodCls,
            GSTR_DECRYPT(SL_SETACC,     SL_SETACC_LEN,     SL_SETACC_KEY),
            GSTR_DECRYPT(SL_SETACC_SIG, SL_SETACC_SIG_LEN, SL_SETACC_SIG_KEY))) : nullptr;
        jmethodID invokeMid    = methodCls ? JCALL(env->GetMethodID(methodCls,
            GSTR_DECRYPT(SL_INVOKE,     SL_INVOKE_LEN,     SL_INVOKE_KEY),
            GSTR_DECRYPT(SL_INVOKE_SIG, SL_INVOKE_SIG_LEN, SL_INVOKE_SIG_KEY))) : nullptr;

        jclass clsCls = JCALL(env->FindClass(
            GSTR_DECRYPT(SL_JCLASS, SL_JCLASS_LEN, SL_JCLASS_KEY)));
        // Cache Class.getName(), getDeclaredMethods(), getSuperclass() before the walk loop
        jmethodID getClsNameMid  = clsCls ? JCALL(env->GetMethodID(clsCls,
            GSTR_DECRYPT(SL_GETNAME,     SL_GETNAME_LEN,     SL_GETNAME_KEY),
            GSTR_DECRYPT(SL_GETNAME_SIG, SL_GETNAME_SIG_LEN, SL_GETNAME_SIG_KEY))) : nullptr;
        jmethodID getDeclaredMid = clsCls ? JCALL(env->GetMethodID(clsCls,
            GSTR_DECRYPT(SL_GETDECM,     SL_GETDECM_LEN,     SL_GETDECM_KEY),
            GSTR_DECRYPT(SL_GETDECM_SIG, SL_GETDECM_SIG_LEN, SL_GETDECM_SIG_KEY))) : nullptr;
        jmethodID getSuperMid    = clsCls ? JCALL(env->GetMethodID(clsCls,
            GSTR_DECRYPT(SL_GETSUPERCLASS,     SL_GETSUPERCLASS_LEN,     SL_GETSUPERCLASS_KEY),
            GSTR_DECRYPT(SL_GETSUPERCLASS_SIG, SL_GETSUPERCLASS_SIG_LEN, SL_GETSUPERCLASS_SIG_KEY))) : nullptr;

        GLOGI("§9 d.4: methodCls=%p getName=%p getPTypes=%p setAcc=%p invoke=%p getDeclared=%p getSuper=%p",
              (void*)methodCls, (void*)getNameMid, (void*)getPTypesMid,
              (void*)setAccMid, (void*)invokeMid, (void*)getDeclaredMid, (void*)getSuperMid);

        if (!methodCls || !getNameMid || !getPTypesMid || !setAccMid ||
            !invokeMid || !getDeclaredMid || !getSuperMid || !getClsNameMid) {
            env->ExceptionClear();
            GLOGE("§9 d.4: reflect JNI lookup failed");
            break;
        }

        const char *mdeName = GSTR_DECRYPT(SL_MDE, SL_MDE_LEN, SL_MDE_KEY);
        const char *mpeName = GSTR_DECRYPT(SL_MPE, SL_MPE_LEN, SL_MPE_KEY);
        const char *jobjName = GSTR_DECRYPT(SL_JOBJ, SL_JOBJ_LEN, SL_JOBJ_KEY);

        jobjectArray newElems   = nullptr;
        jclass       walkCls    = JCALL(env->GetObjectClass(appPL));

        // Walk the hierarchy: appPL's class → superclass → ... → stop at java/lang/Object
        while (walkCls) {
            jstring walkName = (jstring)JCALL(env->CallObjectMethod(walkCls, getClsNameMid));
            const char *walkNameStr = walkName ?
                JCALL(env->GetStringUTFChars(walkName, nullptr)) : nullptr;
            GLOGI("§9 d.4: walking class '%s'", walkNameStr ? walkNameStr : "(null)");
            bool isObject = walkNameStr && strcmp(walkNameStr, "java.lang.Object") == 0;
            if (walkName && walkNameStr)
                JCALLV(env->ReleaseStringUTFChars(walkName, walkNameStr));
            if (walkName) JCALLV(env->DeleteLocalRef(walkName));
            if (isObject) break;

            jobjectArray methods = (jobjectArray)JCALL(
                env->CallObjectMethod(walkCls, getDeclaredMid));
            env->ExceptionClear();
            if (!methods) {
                jclass nextCls = (jclass)JCALL(env->CallObjectMethod(walkCls, getSuperMid));
                env->ExceptionClear();
                JCALLV(env->DeleteLocalRef(walkCls));
                walkCls = nextCls;
                continue;
            }

            jint mcount = JCALL(env->GetArrayLength(methods));
            bool found  = false;
            for (jint mi = 0; mi < mcount && !found; mi++) {
                jobject   mobj  = JCALL(env->GetObjectArrayElement(methods, mi));
                jstring   jname = (jstring)JCALL(env->CallObjectMethod(mobj, getNameMid));
                const char *mname = jname ?
                    JCALL(env->GetStringUTFChars(jname, nullptr)) : nullptr;

                bool isMDE = mname && (strcmp(mname, mdeName) == 0 ||
                                       strcmp(mname, mpeName) == 0);
                if (jname && mname) JCALLV(env->ReleaseStringUTFChars(jname, mname));
                if (jname) JCALLV(env->DeleteLocalRef(jname));

                if (!isMDE) { JCALLV(env->DeleteLocalRef(mobj)); continue; }

                // Found makeDexElements / makePathElements — setAccessible(true)
                JCALLV(env->CallVoidMethod(mobj, setAccMid, (jboolean)JNI_TRUE));
                env->ExceptionClear();

                // Get param count
                jobjectArray ptypes = (jobjectArray)JCALL(
                    env->CallObjectMethod(mobj, getPTypesMid));
                jint nparams = ptypes ? JCALL(env->GetArrayLength(ptypes)) : 0;
                if (ptypes) JCALLV(env->DeleteLocalRef(ptypes));
                GLOGI("§9 d.4: found MDE/MPE nparams=%d", nparams);

                jobjectArray args = nullptr;
                switch (nparams) {
                case 2: {
                    // (ArrayList<File>, File)  — API 14-18
                    args = JCALL(env->NewObjectArray(2, JCALL(env->FindClass(GSTR_DECRYPT(SL_JOBJ, SL_JOBJ_LEN, SL_JOBJ_KEY))), nullptr));
                    JCALLV(env->SetObjectArrayElement(args, 0, filesList));
                    JCALLV(env->SetObjectArrayElement(args, 1, optDirFile));
                    break;
                }
                case 3: {
                    // (ArrayList<File>, File, ArrayList<IOException>)  — API 19-25
                    args = JCALL(env->NewObjectArray(3, JCALL(env->FindClass(GSTR_DECRYPT(SL_JOBJ, SL_JOBJ_LEN, SL_JOBJ_KEY))), nullptr));
                    JCALLV(env->SetObjectArrayElement(args, 0, filesList));
                    JCALLV(env->SetObjectArrayElement(args, 1, optDirFile));
                    JCALLV(env->SetObjectArrayElement(args, 2, suppressedList));
                    break;
                }
                case 4: {
                    // (ArrayList<File>, File, ArrayList<IOException>, ClassLoader)  — API 26+
                    args = JCALL(env->NewObjectArray(4, JCALL(env->FindClass(GSTR_DECRYPT(SL_JOBJ, SL_JOBJ_LEN, SL_JOBJ_KEY))), nullptr));
                    JCALLV(env->SetObjectArrayElement(args, 0, filesList));
                    JCALLV(env->SetObjectArrayElement(args, 1, optDirFile));
                    JCALLV(env->SetObjectArrayElement(args, 2, suppressedList));
                    JCALLV(env->SetObjectArrayElement(args, 3, appCL));
                    break;
                }
                default:
                    GLOGE("§9 d.4: unexpected nparams=%d — skipping", nparams);
                    JCALLV(env->DeleteLocalRef(mobj));
                    continue;
                }

                // Invoke: method.invoke(appPL, args)
                jobject result = JCALL(env->CallObjectMethod(mobj, invokeMid, appPL, args));
                if (env->ExceptionCheck()) {
                    env->ExceptionDescribe();
                    env->ExceptionClear();
                    GLOGE("§9 d.4: invoke threw exception");
                } else if (result) {
                    newElems = (jobjectArray)JCALL(env->NewGlobalRef(result));
                    JCALLV(env->DeleteLocalRef(result));
                    GLOGI("§9 d.4: invoke OK newElems=%p len=%d",
                          (void*)newElems, newElems ? (int)env->GetArrayLength(newElems) : -1);
                    found = true;
                } else {
                    GLOGE("§9 d.4: invoke returned null");
                }
                if (args) JCALLV(env->DeleteLocalRef(args));
                JCALLV(env->DeleteLocalRef(mobj));
            }
            JCALLV(env->DeleteLocalRef(methods));

            if (found) {
                JCALLV(env->DeleteLocalRef(walkCls));
                walkCls = nullptr;
                break;
            }

            jclass nextCls = (jclass)JCALL(env->CallObjectMethod(walkCls, getSuperMid));
            env->ExceptionClear();
            JCALLV(env->DeleteLocalRef(walkCls));
            walkCls = nextCls;
        }

        // ── d.5 Merge new elements into front of appPL.dexElements ───────────
        if (newElems) {
            const char *deName = GSTR_DECRYPT(SL_DEXELEMS,      SL_DEXELEMS_LEN,      SL_DEXELEMS_KEY);
            const char *deDesc = GSTR_DECRYPT(SL_DEXELEMS_DESC, SL_DEXELEMS_DESC_LEN, SL_DEXELEMS_DESC_KEY);
            jclass   plCls  = JCALL(env->GetObjectClass(appPL));
            jfieldID deFid  = plCls ? JCALL(env->GetFieldID(plCls, deName, deDesc)) : nullptr;
            GLOGI("§9 d.5: plCls=%p  deFid=%p", (void*)plCls, (void*)deFid);

            jobjectArray oldElems = deFid ?
                (jobjectArray)JCALL(env->GetObjectField(appPL, deFid)) : nullptr;
            jint newLen = JCALL(env->GetArrayLength(newElems));
            jint oldLen = oldElems ? JCALL(env->GetArrayLength(oldElems)) : 0;
            GLOGI("§9 d.5: newLen=%d oldLen=%d", newLen, oldLen);

            if (newLen > 0) {
                jint     total   = newLen + oldLen;
                jclass   elemCls = JCALL(env->GetObjectClass(
                    env->GetObjectArrayElement(newElems, 0)));
                jobjectArray merged = JCALL(env->NewObjectArray(total, elemCls, nullptr));
                // new elements first (shard classes take priority)
                for (jint j = 0; j < newLen; j++)
                    JCALLV(env->SetObjectArrayElement(merged, j,
                        JCALL(env->GetObjectArrayElement(newElems, j))));
                for (jint j = 0; j < oldLen; j++)
                    JCALLV(env->SetObjectArrayElement(merged, newLen + j,
                        JCALL(env->GetObjectArrayElement(oldElems, j))));
                JCALLV(env->SetObjectField(appPL, deFid, merged));
                GLOGI("§9 d.5: dexElements merged new=%d old=%d total=%d", newLen, oldLen, total);

                // ── §9 d.5 anti-dump: immediate ART magic poisoning ──────────
                // makeDexElements has just returned → ART has mapped each shard
                // into [anon:dalvik-DEX] pages with valid dex\n magic.
                // Wipe the magic NOW, before any scanner can find it.
                // We do a first-pass here (synchronous, on the calling thread)
                // then the anti_dump_thread repeats every 500 ms for lazy pages.
                poison_art_dex_regions();

            } else {
                GLOGE("§9 d.5: newLen=0 — nothing to merge");
            }
            env->DeleteGlobalRef(newElems);
        } else {
            GLOGE("§9 d: makeDexElements not found or returned null — injection failed");
        }

        } while(0); // end injection block
        env->ExceptionClear();
    }
    free(dexPathList);

    // ── d2. Wipe shard files from disk ────────────────────────────────────
    GLOGI("§9 d2: wiping shard files");
    for (uint32_t i = 0; i < shardCount; i++) {
        char killPath[512];
        snprintf(killPath, sizeof(killPath), "%s/%s%u%s", dexDirPath, pfx, i, ext);
        int r = unlink(killPath);
        GLOGI("§9 d2: unlink shard[%u] = %d", i, r);
    }

    // ── d3. Late-init: register native methods now that shards are loaded ────
    // Both pointers are set in JNI_OnLoad before install() is ever called, so
    // they are guaranteed non-null if the corresponding mode was used.
    // Must run AFTER §9 d merges shards — app classes live inside them.
    if (g_vmp_lateInit_fp) {
        g_vmp_lateInit_fp(env);
        GLOGI("§9 d3: vmp_lateInit OK");
        env->ExceptionClear();
    } else {
        GLOGI("§9 d3: vmp_lateInit absent (non-VMP build)");
    }
    if (g_d2c_lateInit_fp) {
        g_d2c_lateInit_fp(env);
        GLOGI("§9 d3: d2c_lateInit OK");
        env->ExceptionClear();
    } else {
        GLOGI("§9 d3: d2c_lateInit absent (non-dex2c build)");
    }

    // ── §9 d4: Launch anti-dump background thread ──────────────────────────
    // Poisons [anon:dalvik-DEX] magic every 500 ms to cover:
    //   • Lazily-JIT'd pages ART maps after the initial makeDexElements load.
    //   • The 7-18 s window Frida memscan scripts wait before scanning.
    //   • The 3-s retry in dump_dex_mem.py if the first pass finds nothing.
    // Frida's 10-22 libc patches (kill/exit/abort/sigaction) cannot stop this
    // thread — it has no crash path, it just keeps wiping magic.
    {
        pthread_t adt;
        pthread_attr_t adt_attr;
        pthread_attr_init(&adt_attr);
        pthread_attr_setdetachstate(&adt_attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&adt, &adt_attr, anti_dump_thread, NULL);
        pthread_attr_destroy(&adt_attr);
        GLOGI("§9 d4: anti_dump_thread started (500 ms poison cycle)");
    }

    // ── e. Read phantom/app.cfg → set Const.REAL_APP ─────────────────────
    bool skip_f_swap = false;
    const char *cfgPath = GSTR_DECRYPT(SL_ASSET_CFG, SL_ASSET_CFG_LEN, SL_ASSET_CFG_KEY);
    GLOGI("§9 e: reading app.cfg '%s'", cfgPath ? cfgPath : "(null)");
    size_t cfgLen = 0;
    uint8_t *cfgBuf = sl_read_asset(env, context, cfgPath, &cfgLen);
    GLOGI("§9 e: cfgBuf=%p cfgLen=%zu", (void*)cfgBuf, cfgLen);
    if (cfgBuf && cfgLen > 0) {
        char *realApp = (char *)malloc(cfgLen + 1);
        memcpy(realApp, cfgBuf, cfgLen);
        realApp[cfgLen] = '\0';
        for (int j = (int)cfgLen - 1; j >= 0 &&
             (realApp[j]=='\n'||realApp[j]=='\r'||realApp[j]==' '); j--)
            realApp[j] = '\0';
        GLOGI("§9 e: realApp='%s'", realApp);

        jclass constCls = JCALL(env->FindClass(
            GSTR_DECRYPT(SL_CONST_CLASS, SL_CONST_CLASS_LEN, SL_CONST_CLASS_KEY)));
        GLOGI("§9 e: constCls=%p", (void*)constCls);
        if (constCls) {
            jfieldID fid = JCALL(env->GetStaticFieldID(constCls,
                GSTR_DECRYPT(SL_REAL_APP_FLD, SL_REAL_APP_FLD_LEN, SL_REAL_APP_FLD_KEY),
                GSTR_DECRYPT(SL_STR_DESC,     SL_STR_DESC_LEN,     SL_STR_DESC_KEY)));
            GLOGI("§9 e: REAL_APP fieldID=%p", (void*)fid);
            if (fid) {
                jstring jRealApp = JCALL(env->NewStringUTF(realApp));
                JCALLV(env->SetStaticObjectField(constCls, fid, jRealApp));
                GLOGI("§9 e: Const.REAL_APP set to '%s'", realApp);
            } else {
                GLOGE("§9 e: GetStaticFieldID returned null for REAL_APP");
            }
        } else {
            GLOGE("§9 e: FindClass(Const) returned null — DEX injection likely failed");
        }
        // skip §9 f if the real app is android.app.Application — Java stub handles it
        if (realApp) skip_f_swap = (strcmp(realApp, "android.app.Application") == 0);
        free(cfgBuf);
        free(realApp);
    } else {
        GLOGE("§9 e: app.cfg read failed cfgBuf=%p cfgLen=%zu", (void*)cfgBuf, cfgLen);
    }
    env->ExceptionClear();

    // ── f. ActivityThread Application swap (mirrors ProxyApplication.realApplication()) ──
    // Replaces the proxy stub with the real Application so getResources() etc. work.
    // Skipped when realApp=android.app.Application (Java stub's realApplication() handles it).
    GLOGI("§9 f: starting Application swap");
    do {
        if (skip_f_swap) {
            GLOGI("§9 f: skipped — realApp=android.app.Application, Java stub handles swap");
            break;
        }
        // 1. ActivityThread.currentActivityThread()
        jclass atCls = JCALL(env->FindClass(
            GSTR_DECRYPT(SA_AT_CLASS, SA_AT_CLASS_LEN, SA_AT_CLASS_KEY)));
        if (!atCls) { env->ExceptionClear(); GLOGE("§9 f: FindClass ActivityThread failed"); break; }

        jmethodID curAtMid = JCALL(env->GetStaticMethodID(atCls,
            GSTR_DECRYPT(SA_CUR_AT,     SA_CUR_AT_LEN,     SA_CUR_AT_KEY),
            GSTR_DECRYPT(SA_CUR_AT_SIG, SA_CUR_AT_SIG_LEN, SA_CUR_AT_SIG_KEY)));
        if (!curAtMid) { env->ExceptionClear(); GLOGE("§9 f: currentActivityThread method not found"); break; }

        jobject at = JCALL(env->CallStaticObjectMethod(atCls, curAtMid));
        if (!at) { env->ExceptionClear(); GLOGE("§9 f: currentActivityThread() returned null"); break; }
        GLOGI("§9 f.1: at=%p", (void*)at);

        // 2. at.mBoundApplication — use getDeclaredField reflection to avoid
        //    descriptor resolution failures on vendor ROMs (AppBindData is private inner class)
        jclass classCls  = JCALL(env->FindClass("java/lang/Class"));
        jclass fieldCls2 = JCALL(env->FindClass("java/lang/reflect/Field"));
        jmethodID getDeclFMid = classCls  ? JCALL(env->GetMethodID(classCls,  "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;")) : nullptr;
        jmethodID setAccMid2  = fieldCls2 ? JCALL(env->GetMethodID(fieldCls2, "setAccessible",    "(Z)V"))                                          : nullptr;
        jmethodID getObjMid2  = fieldCls2 ? JCALL(env->GetMethodID(fieldCls2, "get",              "(Ljava/lang/Object;)Ljava/lang/Object;"))         : nullptr;
        if (!getDeclFMid || !setAccMid2 || !getObjMid2) {
            env->ExceptionClear();
            GLOGE("§9 f: reflect method lookup failed for getDeclaredField/setAccessible/get");
            break;
        }
        jstring mBoundName = env->NewStringUTF(GSTR_DECRYPT(SA_MBOUND, SA_MBOUND_LEN, SA_MBOUND_KEY));
        env->ExceptionClear();
        jobject mBoundField = JCALL(env->CallObjectMethod(atCls, getDeclFMid, mBoundName));
        env->DeleteLocalRef(mBoundName);
        if (!mBoundField || env->ExceptionCheck()) {
            env->ExceptionClear();
            GLOGE("§9 f: getDeclaredField(mBoundApplication) failed");
            break;
        }
        env->CallVoidMethod(mBoundField, setAccMid2, JNI_TRUE);
        env->ExceptionClear();
        jobject mBoundApp = JCALL(env->CallObjectMethod(mBoundField, getObjMid2, at));
        env->DeleteLocalRef(mBoundField);
        if (!mBoundApp || env->ExceptionCheck()) {
            env->ExceptionClear();
            GLOGE("§9 f: mBoundApplication is null or get() threw");
            break;
        }
        GLOGI("§9 f.2: mBoundApp=%p", (void*)mBoundApp);

        // 3. mBoundApp.info (LoadedApk)
        jclass abdCls = JCALL(env->GetObjectClass(mBoundApp));
        jfieldID infoFid = JCALL(env->GetFieldID(abdCls,
            GSTR_DECRYPT(SA_INFO_FLD, SA_INFO_FLD_LEN, SA_INFO_FLD_KEY),
            "Ljava/lang/Object;"));
        if (!infoFid) { env->ExceptionClear(); GLOGE("§9 f: info field not found in AppBindData"); break; }

        jobject loadedApk = JCALL(env->GetObjectField(mBoundApp, infoFid));
        if (!loadedApk) { GLOGE("§9 f: loadedApk (info) is null"); break; }
        GLOGI("§9 f.3: loadedApk=%p", (void*)loadedApk);

        // 4. loadedApk.mApplication = null  (so makeApplication creates fresh)
        jclass lakCls = JCALL(env->GetObjectClass(loadedApk));
        jfieldID mAppFid = JCALL(env->GetFieldID(lakCls,
            GSTR_DECRYPT(SA_MAPP, SA_MAPP_LEN, SA_MAPP_KEY),
            "Landroid/app/Application;"));
        if (!mAppFid) { env->ExceptionClear();
            mAppFid = JCALL(env->GetFieldID(lakCls,
                GSTR_DECRYPT(SA_MAPP, SA_MAPP_LEN, SA_MAPP_KEY),
                "Ljava/lang/Object;"));
            env->ExceptionClear();
        }
        if (mAppFid) {
            JCALLV(env->SetObjectField(loadedApk, mAppFid, nullptr));
            GLOGI("§9 f.4: cleared loadedApk.mApplication");
        } else {
            GLOGE("§9 f.4: mApplication field not found — proceeding anyway");
        }

        // 5. oldApp = at.mInitialApplication
        jfieldID mInitFid = JCALL(env->GetFieldID(atCls,
            GSTR_DECRYPT(SA_MINIT, SA_MINIT_LEN, SA_MINIT_KEY),
            "Landroid/app/Application;"));
        if (!mInitFid) { env->ExceptionClear();
            mInitFid = JCALL(env->GetFieldID(atCls,
                GSTR_DECRYPT(SA_MINIT, SA_MINIT_LEN, SA_MINIT_KEY),
                "Ljava/lang/Object;"));
            env->ExceptionClear();
        }
        jobject oldApp = mInitFid ? JCALL(env->GetObjectField(at, mInitFid)) : nullptr;
        GLOGI("§9 f.5: oldApp=%p", (void*)oldApp);

        // 6+7. mAllApplications.remove(oldApp)
        jfieldID mAllFid = JCALL(env->GetFieldID(atCls,
            GSTR_DECRYPT(SA_MALL, SA_MALL_LEN, SA_MALL_KEY),
            "Ljava/util/ArrayList;"));
        if (!mAllFid) { env->ExceptionClear();
            mAllFid = JCALL(env->GetFieldID(atCls,
                GSTR_DECRYPT(SA_MALL, SA_MALL_LEN, SA_MALL_KEY),
                "Ljava/lang/Object;"));
            env->ExceptionClear();
        }
        if (mAllFid && oldApp) {
            jobject mAllApps = JCALL(env->GetObjectField(at, mAllFid));
            if (mAllApps) {
                jclass listCls = JCALL(env->GetObjectClass(mAllApps));
                jmethodID removeMid = JCALL(env->GetMethodID(listCls,
                    GSTR_DECRYPT(SA_REMOVE,     SA_REMOVE_LEN,     SA_REMOVE_KEY),
                    GSTR_DECRYPT(SA_REMOVE_SIG, SA_REMOVE_SIG_LEN, SA_REMOVE_SIG_KEY)));
                if (removeMid) {
                    JCALL(env->CallBooleanMethod(mAllApps, removeMid, oldApp));
                    env->ExceptionClear();
                    GLOGI("§9 f.7: removed oldApp from mAllApplications");
                }
            }
        }

        // 8+9. Set className on both ApplicationInfo objects → Const.REAL_APP
        // Read Const.REAL_APP back as a jstring
        jclass constCls2 = JCALL(env->FindClass(
            GSTR_DECRYPT(SL_CONST_CLASS, SL_CONST_CLASS_LEN, SL_CONST_CLASS_KEY)));
        jstring realAppName = nullptr;
        if (constCls2) {
            jfieldID realFid = JCALL(env->GetStaticFieldID(constCls2,
                GSTR_DECRYPT(SL_REAL_APP_FLD, SL_REAL_APP_FLD_LEN, SL_REAL_APP_FLD_KEY),
                GSTR_DECRYPT(SL_STR_DESC,     SL_STR_DESC_LEN,     SL_STR_DESC_KEY)));
            if (realFid) realAppName = (jstring)JCALL(env->GetStaticObjectField(constCls2, realFid));
        }
        env->ExceptionClear();
        GLOGI("§9 f.8: realAppName=%p", (void*)realAppName);

        if (realAppName) {
            jclass aiCls = JCALL(env->FindClass(
                GSTR_DECRYPT(SA_AI_CLASS, SA_AI_CLASS_LEN, SA_AI_CLASS_KEY)));
            env->ExceptionClear();

            // loadedApk.mApplicationInfo.className
            jfieldID apkInfoFid = aiCls ? JCALL(env->GetFieldID(lakCls,
                GSTR_DECRYPT(SA_APPINFO, SA_APPINFO_LEN, SA_APPINFO_KEY),
                "Landroid/content/pm/ApplicationInfo;")) : nullptr;
            if (!apkInfoFid) { env->ExceptionClear();
                apkInfoFid = lakCls ? JCALL(env->GetFieldID(lakCls,
                    GSTR_DECRYPT(SA_APPINFO, SA_APPINFO_LEN, SA_APPINFO_KEY),
                    "Ljava/lang/Object;")) : nullptr;
                env->ExceptionClear();
            }
            if (apkInfoFid) {
                jobject apkInfo = JCALL(env->GetObjectField(loadedApk, apkInfoFid));
                if (apkInfo && aiCls) {
                    jfieldID clsNameFid = JCALL(env->GetFieldID(aiCls,
                        GSTR_DECRYPT(SA_CLSNAME, SA_CLSNAME_LEN, SA_CLSNAME_KEY),
                        "Ljava/lang/String;"));
                    if (clsNameFid) {
                        JCALLV(env->SetObjectField(apkInfo, clsNameFid, realAppName));
                        GLOGI("§9 f.8: set loadedApk.mApplicationInfo.className");
                    }
                    env->ExceptionClear();
                }
            }

            // mBoundApp.appInfo.className
            jfieldID bindInfoFid = JCALL(env->GetFieldID(abdCls,
                GSTR_DECRYPT(SA_APPINFO2, SA_APPINFO2_LEN, SA_APPINFO2_KEY),
                "Landroid/content/pm/ApplicationInfo;"));
            if (!bindInfoFid) { env->ExceptionClear();
                bindInfoFid = JCALL(env->GetFieldID(abdCls,
                    GSTR_DECRYPT(SA_APPINFO2, SA_APPINFO2_LEN, SA_APPINFO2_KEY),
                    "Ljava/lang/Object;"));
                env->ExceptionClear();
            }
            if (bindInfoFid) {
                jobject bindInfo = JCALL(env->GetObjectField(mBoundApp, bindInfoFid));
                if (bindInfo && aiCls) {
                    jfieldID clsNameFid2 = JCALL(env->GetFieldID(aiCls,
                        GSTR_DECRYPT(SA_CLSNAME, SA_CLSNAME_LEN, SA_CLSNAME_KEY),
                        "Ljava/lang/String;"));
                    if (clsNameFid2) {
                        JCALLV(env->SetObjectField(bindInfo, clsNameFid2, realAppName));
                        GLOGI("§9 f.9: set appBindData.appInfo.className");
                    }
                    env->ExceptionClear();
                }
            }
        }

        // 12. loadedApk.makeApplication(false, null) → real Application (with attach() called)
        jmethodID makeAppMid = JCALL(env->GetMethodID(lakCls,
            GSTR_DECRYPT(SA_MAKEAPP,     SA_MAKEAPP_LEN,     SA_MAKEAPP_KEY),
            GSTR_DECRYPT(SA_MAKEAPP_SIG, SA_MAKEAPP_SIG_LEN, SA_MAKEAPP_SIG_KEY)));
        if (!makeAppMid) { env->ExceptionClear(); GLOGE("§9 f: makeApplication method not found"); break; }

        jobject newApp = JCALL(env->CallObjectMethod(loadedApk, makeAppMid,
            (jboolean)JNI_FALSE, (jobject)nullptr));
        if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
        if (!newApp) { GLOGE("§9 f: makeApplication() returned null"); break; }
        GLOGI("§9 f.12: newApp=%p", (void*)newApp);

        // 13. at.mInitialApplication = newApp
        if (mInitFid) {
            JCALLV(env->SetObjectField(at, mInitFid, newApp));
            GLOGI("§9 f.13: mInitialApplication swapped to newApp");
        }

        // 14+15. Update each ContentProvider's mContext
        jfieldID provMapFid = JCALL(env->GetFieldID(atCls,
            GSTR_DECRYPT(SA_PROVMAP, SA_PROVMAP_LEN, SA_PROVMAP_KEY),
            "Ljava/lang/Object;"));
        if (!provMapFid) { env->ExceptionClear(); }
        if (provMapFid) {
            jobject provMap = JCALL(env->GetObjectField(at, provMapFid));
            if (provMap) {
                jclass mapCls = JCALL(env->GetObjectClass(provMap));
                jmethodID valuesMid = JCALL(env->GetMethodID(mapCls,
                    GSTR_DECRYPT(SA_VALUES,     SA_VALUES_LEN,     SA_VALUES_KEY),
                    GSTR_DECRYPT(SA_VALUES_SIG, SA_VALUES_SIG_LEN, SA_VALUES_SIG_KEY)));
                if (valuesMid) {
                    jobject collection = JCALL(env->CallObjectMethod(provMap, valuesMid));
                    if (collection) {
                        jclass colCls = JCALL(env->GetObjectClass(collection));
                        jmethodID iterMid = JCALL(env->GetMethodID(colCls,
                            GSTR_DECRYPT(SA_ITERATOR,     SA_ITERATOR_LEN,     SA_ITERATOR_KEY),
                            GSTR_DECRYPT(SA_ITERATOR_SIG, SA_ITERATOR_SIG_LEN, SA_ITERATOR_SIG_KEY)));
                        if (iterMid) {
                            jobject iter = JCALL(env->CallObjectMethod(collection, iterMid));
                            if (iter) {
                                jclass iterCls = JCALL(env->GetObjectClass(iter));
                                jmethodID hasNextMid = JCALL(env->GetMethodID(iterCls,
                                    GSTR_DECRYPT(SA_HASNEXT,     SA_HASNEXT_LEN,     SA_HASNEXT_KEY),
                                    GSTR_DECRYPT(SA_HASNEXT_SIG, SA_HASNEXT_SIG_LEN, SA_HASNEXT_SIG_KEY)));
                                jmethodID nextMid = JCALL(env->GetMethodID(iterCls,
                                    GSTR_DECRYPT(SA_NEXT,     SA_NEXT_LEN,     SA_NEXT_KEY),
                                    GSTR_DECRYPT(SA_NEXT_SIG, SA_NEXT_SIG_LEN, SA_NEXT_SIG_KEY)));
                                jclass pcrCls = JCALL(env->FindClass(
                                    GSTR_DECRYPT(SA_PCR_CLASS, SA_PCR_CLASS_LEN, SA_PCR_CLASS_KEY)));
                                env->ExceptionClear();
                                jclass cpCls = JCALL(env->FindClass(
                                    GSTR_DECRYPT(SA_CP_CLASS, SA_CP_CLASS_LEN, SA_CP_CLASS_KEY)));
                                env->ExceptionClear();

                                while (hasNextMid && nextMid &&
                                       JCALL(env->CallBooleanMethod(iter, hasNextMid))) {
                                    jobject pcr = JCALL(env->CallObjectMethod(iter, nextMid));
                                    if (!pcr) continue;
                                    if (pcrCls) {
                                        jfieldID locProvFid = JCALL(env->GetFieldID(pcrCls,
                                            GSTR_DECRYPT(SA_LOCPROV, SA_LOCPROV_LEN, SA_LOCPROV_KEY),
                                            "Ljava/lang/Object;"));
                                        if (!locProvFid) { env->ExceptionClear(); continue; }
                                        jobject localProv = JCALL(env->GetObjectField(pcr, locProvFid));
                                        if (localProv && cpCls) {
                                            jfieldID mCtxFid = JCALL(env->GetFieldID(cpCls,
                                                GSTR_DECRYPT(SA_MCTX, SA_MCTX_LEN, SA_MCTX_KEY),
                                                "Landroid/content/Context;"));
                                            if (!mCtxFid) { env->ExceptionClear();
                                                mCtxFid = JCALL(env->GetFieldID(cpCls,
                                                    GSTR_DECRYPT(SA_MCTX, SA_MCTX_LEN, SA_MCTX_KEY),
                                                    "Ljava/lang/Object;"));
                                                env->ExceptionClear();
                                            }
                                            if (mCtxFid) {
                                                JCALLV(env->SetObjectField(localProv, mCtxFid, newApp));
                                            }
                                        }
                                    }
                                }
                                GLOGI("§9 f.15: provider mContext update done");
                            }
                        }
                    }
                }
                env->ExceptionClear();
            }
        }

        // 16. newApp.onCreate()
        jclass newAppCls = JCALL(env->GetObjectClass(newApp));
        jmethodID onCreateMid = JCALL(env->GetMethodID(newAppCls,
            GSTR_DECRYPT(SA_ONCREATE,     SA_ONCREATE_LEN,     SA_ONCREATE_KEY),
            GSTR_DECRYPT(SA_ONCREATE_SIG, SA_ONCREATE_SIG_LEN, SA_ONCREATE_SIG_KEY)));
        if (onCreateMid) {
            JCALLV(env->CallVoidMethod(newApp, onCreateMid));
            if (env->ExceptionCheck()) { env->ExceptionDescribe(); env->ExceptionClear(); }
            GLOGI("§9 f.16: newApp.onCreate() called");
        } else {
            env->ExceptionClear();
            GLOGE("§9 f: onCreate method not found on newApp");
        }

        GLOGI("§9 f: Application swap complete");
    } while(0);
    env->ExceptionClear();

    JCALLV(env->ReleaseStringUTFChars(jabsPath, dexDirPath));
    GLOGI("§9 install: complete");
}

#undef JCALL
#undef JCALLV

// §9.6 — JNI_OnLoad removed. fonts_register_natives + fonts_apply_metrics are
// called directly from DexProtector.install, so no JNI_OnLoad is needed here.
// The transpiler-generated jni_onload.cpp provides the single JNI_OnLoad.
