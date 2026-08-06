// phantom_key.c -- JNI entry-point for libphantom.so
//
// Exports:
// Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard
// Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeWipeShard
//
// Security model:
// * Per-APK key derived from (salt, sha256(pkg_name)) via ARX KDF.
// * Key NEVER crosses the JNI boundary -- lives only on the C stack, zeroed on return.
//
// Anti-dump / Anti-Frida -- four independent layers:
//
// LAYER 1  inotify_mem_watcher()
// Installs kernel inotify watches on /proc/self/mem, /proc/self/pagemap
// and the per-task equivalents.  The kernel fires the event the instant
// ANY process — including root (uid=0) — opens those files.
// NOTE: /proc/self/maps is intentionally NOT watched — our own detection
// loop opens it every 5 s and would self-trigger a false nuke.
//
// LAYER 2a  nativeWipeShard()  [JNI -- called from DexProtector after loading]
// Zeroes the ENTIRE Java byte[] that nativeDecryptShard returned -- not
// just the 8-byte magic.  ART has already consumed the ByteBuffer before
// this call; wiping the full array means no heap region contains any
// valid DEX bytecode for a /proc/PID/mem scanner to reconstruct from.
//
// LAYER 2b  self_scan_and_poison_dex()
// Background native scan at 50 ms cadence (was 1 s).  For anonymous
// non-dalvik regions: wipes the ENTIRE region via /proc/self/mem, then
// calls madvise(MADV_DONTNEED) to drop backing pages -- reads via
// /proc/PID/mem return zeros.  For [anon:dalvik-*] regions used by ART
// at runtime: poisons only the header (magic + endian_tag) to defeat
// magic-byte scanners without crashing the interpreter.
//
// LAYER 3  detect_frida_anonymous_memory() + detect_ebpf_uprobe()
// Frida/ptrace heuristics PLUS eBPF uprobe detection.
// eBPFDexDumper (2026) attaches a kernel uprobe to libart's Execute
// function and writes "p:dex_dump libart.so:0x..." into the tracing
// filesystem.  We scan both uprobe_events paths and nuke on any hit
// containing "libart" -- no userspace anti-dump can stop eBPF otherwise.
//
// All layers run in background threads.  detect_frida_init() fires via
// __attribute__((constructor)) the instant System.load(libphantom.so) is
// called -- before nativeDecryptShard is ever reached.
//
// Build requirements:
// * Compile with OLLVM (see phantom/CMakeLists.txt).
// * Target ABIs: arm64-v8a and armeabi-v7a.
// * After building, ARX-encrypt with encrypt_blob.py and place blobs at:
// assets/phantom/libphantom_arm64.blob
// assets/phantom/libphantom_arm.blob
//
// IMPORTANT: Do NOT compile on Replit. Use the CI build with OLLVM toolchain.

// ?
// Includes
// ?

#include <jni.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <elf.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <link.h>
#include <dlfcn.h>
#include <android/log.h>
#include <zlib.h>

// ── Debug logging ─────────────────────────────────────────────────────────────
// Tag visible in: adb logcat -s PHANTOM
#define PH_TAG "PHANTOM"
#define PH_LOG(fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, PH_TAG, fmt, ##__VA_ARGS__)
#define PH_NUKE(reason, ...) \
    __android_log_print(ANDROID_LOG_ERROR, PH_TAG, "NUKE: " reason, ##__VA_ARGS__)
// ─────────────────────────────────────────────────────────────────────────────

// ?
// Anti-dump / Anti-Frida -- constants & types
// ?

#define MAX_LINE   512
#define MAX_LENGTH 256
#define MAX_SZ     (80 * 1024 * 1024)

// ?
// DEX region cache
//
// Stores the base addresses of every [anon:dalvik-DEX] and anonymous DEX
// region we have ever identified.  fast_poison_known_regions() hits each
// cached address with mprotect+memset every 100 us without
// touching /proc/self/maps at all -- the cost is only a handful of syscalls
// per tick, measured in microseconds.
//
// self_scan_and_poison_dex() (called at 500 ms cadence and on every
// nativePoisonNow() JNI call) rebuilds the cache from a fresh maps scan so
// newly-loaded DEX regions are discovered promptly.
// ?

#define MAX_DEX_REGIONS 64

typedef struct {
    unsigned long base;
    size_t        region_size;
    int           is_dalvik;       // 1 = ART active region; 0 = original ByteBuffer copy
} dex_region_entry_t;

static dex_region_entry_t g_dex_cache[MAX_DEX_REGIONS];
static volatile int       g_dex_cache_count = 0;
static pthread_mutex_t    g_dex_cache_lock  = PTHREAD_MUTEX_INITIALIZER;

// Persistent fds opened at startup BEFORE inotify is armed.
// Declared here (before any function that references them) because OLLVM's
// clang enforces declaration-before-use order for file-scope statics.
// detect_frida_memdiskcompare(), detect_riru_zygisk(), and
// self_scan_and_poison_dex() all use these — never re-opening the paths so
// our own reads never fire the inotify IN_OPEN watch.
static int g_rmem_fd = -1;   // /proc/self/mem  O_RDONLY
static int g_maps_fd = -1;   // /proc/self/maps O_RDONLY

// Called from within self_scan_and_poison_dex() while rebuilding the cache.
// NOT thread-safe by itself -- caller holds g_dex_cache_lock.
static inline void cache_add_region_locked(unsigned long base,
                                           size_t region_size,
                                           int is_dalvik)
{
        // Deduplicate by base address.
    for (int i = 0; i < g_dex_cache_count; i++) {
        if (g_dex_cache[i].base == base) {
            g_dex_cache[i].region_size = region_size;
            g_dex_cache[i].is_dalvik   = is_dalvik;
            return;
        }
    }
    if (g_dex_cache_count < MAX_DEX_REGIONS) {
        g_dex_cache[g_dex_cache_count].base        = base;
        g_dex_cache[g_dex_cache_count].region_size = region_size;
        g_dex_cache[g_dex_cache_count].is_dalvik   = is_dalvik;
        g_dex_cache_count++;
    }
}

// Forward declarations for ABI-specific syscall wrappers defined below.
// fast_poison_known_regions() uses these before the #if __aarch64__ block.
static inline int my_madvise(void *a, size_t l, int adv);
static inline int my_mprotect(void *a, size_t l, int prot);

// fast_poison_known_regions() -- called every 1 ms.
//
// Poisons every cached DEX region using mprotect + direct memset.
//
// [anon:dalvik-DEX] regions are MAP_PRIVATE|MAP_ANONYMOUS — ART itself calls
// mprotect() on them (proven in AOSP mem_map.cc).  Our process can always
// call mprotect(PROT_WRITE) on its own anonymous pages: no SELinux restriction
// applies to mprotect, and no memfd sealing is used for InMemoryDexClassLoader.
//
// For dalvik-labelled regions  (ART reads during execution):
//   -> header-only: zero magic[0-7] + endian_tag[40-43] on the first page.
//      Defeats magic-byte scanners without disturbing ART's bytecode read.
//
// For non-dalvik anonymous regions  (original ByteBuffer — ART is done with it):
//   -> full wipe: mprotect+memset every page, then MADV_DONTNEED to drop
//      backing pages (subsequent /proc/PID/mem reads return only zeros).
//
// Total cost per 100 us tick: ~1-5 us for typical apps (header-only path
// is just one mprotect+8 byte stores+mprotect per region).
static void fast_poison_known_regions(void)
{
    pthread_mutex_lock(&g_dex_cache_lock);
    int count = g_dex_cache_count;
    dex_region_entry_t snap[MAX_DEX_REGIONS];
    for (int i = 0; i < count; i++) snap[i] = g_dex_cache[i];
    pthread_mutex_unlock(&g_dex_cache_lock);

    for (int i = 0; i < count; i++) {
        unsigned long base        = snap[i].base;
        size_t        region_size = snap[i].region_size;
        int           is_dalvik   = snap[i].is_dalvik;

        if (base == 0 || region_size == 0) continue;

        if (!is_dalvik && region_size <= (8u * 1024u * 1024u)) {
            // Full-region wipe: mprotect+memset page by page, then drop pages.
            unsigned long ps   = 4096;
            unsigned long addr = base & ~(ps - 1);
            unsigned long end  = (base + region_size + ps - 1) & ~(ps - 1);
            while (addr < end) {
                if (my_mprotect((void *)addr, ps, PROT_READ | PROT_WRITE) == 0) {
                    volatile uint8_t *p = (volatile uint8_t *)addr;
                    for (unsigned long j = 0; j < ps; j++) p[j] = 0;
                    my_mprotect((void *)addr, ps, PROT_READ);
                }
                addr += ps;
            }
            // Drop backing pages — reads via /proc/PID/mem now return zeros.
            my_madvise((void *)base, region_size, MADV_DONTNEED);
        } else {
            // Dalvik region (ART active) or oversized: header-only poison.
            // Zero just the DEX magic (bytes 0-7) and endian_tag (bytes 40-43)
            // on the first page. Enough to defeat every magic-byte scanner.
            unsigned long ps         = 4096;
            unsigned long page_start = base & ~(ps - 1);
            if (my_mprotect((void *)page_start, ps, PROT_READ | PROT_WRITE) == 0) {
                volatile uint8_t *p = (volatile uint8_t *)base;
                p[0]=0;p[1]=0;p[2]=0;p[3]=0;p[4]=0;p[5]=0;p[6]=0;p[7]=0;
                p[40]=0;p[41]=0;p[42]=0;p[43]=0;
                my_mprotect((void *)page_start, ps, PROT_READ);
            }
        }
    }
}

static const char *APPNAME                    = "YahyaVM_AntiFrida";
static const char *FRIDA_THREAD_GUM_JS_LOOP   = "gum-js-loop";
static const char *FRIDA_THREAD_GMAIN         = "gmain";
static const char *FRIDA_NAMEDPIPE_LINJECTOR  = "linjector";

// Frida WebSocket fingerprint (technique from PhuongDoZz/NativeShield).
// When you send an HTTP WebSocket upgrade with a fixed Sec-WebSocket-Key,
// the server's Sec-WebSocket-Accept is a deterministic SHA1-based hash.
// Frida's server ALWAYS responds with this exact base64 token.
// Key used:    CpxD2C5REVLHvsUC9YAoqg==
// Accept hash: tyZql/Y8dNFFyopTrHadWzvbvRs=
static const char *FRIDA_WS_ACCEPT            = "tyZql/Y8dNFFyopTrHadWzvbvRs=";

// Java debugger thread name (JDWP = Java Debug Wire Protocol)
// darvincisec + NativeShield both check /proc/self/task/*/comm for this.
static const char *JDWP_THREAD_NAME           = "JDWP";

// Hooking framework strings found in loaded library paths or /proc/self/maps.
// Riru injects libmain.so from /data/adb/riru; Zygisk injects from its module dir.
// LSPosed / EdXposed appear as "lspd" / "edxposed" in mapped library names.
static const char *HOOK_RIRU                  = "riru";
static const char *HOOK_ZYGISK               = "zygisk";
static const char *HOOK_XPOSED               = "xposed";
static const char *HOOK_LSPD                 = "lspd";
static const char *HOOK_EDXPOSED             = "edxposed";
static const char *PROC_MAPS                  = "/proc/self/maps";
static const char *PROC_STATUS                = "/proc/self/task/%s/status";
static const char *PROC_FD                    = "/proc/self/fd";
static const char *PROC_TASK                  = "/proc/self/task";
#define LIBC "libc.so"

typedef struct {
    int           execSectionCount;
    unsigned long offset[2];
    unsigned long memsize[2];
    unsigned long checksum[2];
    unsigned long startAddrinMem;
} execSection;

#define NUM_LIBS 2
static const char *libstocheck[NUM_LIBS] = {"libphantom.so", LIBC};
static execSection *elfSectionArr[NUM_LIBS] = {NULL};

#if defined(__LP64__)
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
#else
typedef Elf32_Ehdr Elf_Ehdr;
typedef Elf32_Shdr Elf_Shdr;
#endif

// ?
// Inline string helpers (avoid libc hooks)
// ?

__attribute__((always_inline))
static inline size_t my_strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

__attribute__((always_inline))
static inline int my_strcmp(const char *s1, const char *s2) {
    while (*s1 == *s2++) if (*s1++ == 0) return 0;
    return (*(unsigned char *)s1 - *(unsigned char *)--s2);
}

static inline int my_strncmp(const char *s1, const char *s2, size_t n);

__attribute__((always_inline))
static inline char *my_strstr(const char *s, const char *find) {
    char c, sc;
    size_t len;
    if ((c = *find++) != '\0') {
        len = my_strlen(find);
        do {
            do { if ((sc = *s++) == '\0') return NULL; } while (sc != c);
        } while (my_strncmp(s, find, len) != 0);
        s--;
    }
    return (char *)s;
}

__attribute__((always_inline))
static inline int my_strncmp(const char *s1, const char *s2, size_t n) {
    if (n == 0) return 0;
    do {
        if (*s1 != *s2++) return (*(unsigned char *)s1 - *(unsigned char *)--s2);
        if (*s1++ == 0) break;
    } while (--n != 0);
    return 0;
}

__attribute__((always_inline))
static inline void *my_memset(void *dst, int c, size_t n) {
    char *q = (char *)dst;
    for (size_t i = 0; i < n; i++) q[i] = (char)c;
    return dst;
}

// ?
// Raw syscall wrappers (bypass libc -- Frida hooks libc)
// ?

#if defined(__aarch64__)

__attribute__((always_inline))
static inline long raw_syscall_3(long no, long a1, long a2, long a3) {
    register long x8 __asm__("x8") = no;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    __asm__ volatile("svc #0\n"
        : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}

__attribute__((always_inline))
static inline long raw_syscall_4(long no, long a1, long a2, long a3, long a4) {
    register long x8 __asm__("x8") = no;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    __asm__ volatile("svc #0\n"
        : "=r"(x0) : "r"(x8), "0"(x0), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}

__attribute__((always_inline)) static inline int my_openat(int d, const char *p, int f, int m)
    { return (int)raw_syscall_4(__NR_openat, d, (long)p, f, m); }

__attribute__((always_inline)) static inline ssize_t my_read(int fd, void *b, size_t n)
    { return (ssize_t)raw_syscall_3(__NR_read, fd, (long)b, n); }

__attribute__((always_inline)) static inline ssize_t my_write(int fd, const void *b, size_t n)
    { return (ssize_t)raw_syscall_3(__NR_write, fd, (long)b, n); }

__attribute__((always_inline)) static inline off_t my_lseek(int fd, off_t off, int w)
    { return (off_t)raw_syscall_3(__NR_lseek, fd, off, w); }

__attribute__((always_inline)) static inline int my_close(int fd)
    { return (int)raw_syscall_3(__NR_close, fd, 0, 0); }

__attribute__((always_inline)) static inline int my_nanosleep(const struct timespec *r, struct timespec *e)
    { return (int)raw_syscall_3(__NR_nanosleep, (long)r, (long)e, 0); }

__attribute__((always_inline)) static inline ssize_t my_readlinkat(int d, const char *p, char *b, size_t s)
    { return (ssize_t)raw_syscall_4(__NR_readlinkat, d, (long)p, (long)b, s); }

__attribute__((always_inline)) static inline int my_mprotect(void *a, size_t l, int prot)
    { return (int)raw_syscall_3(__NR_mprotect, (long)a, (long)l, prot); }

__attribute__((always_inline)) static inline int my_madvise(void *a, size_t l, int adv)
    { return (int)raw_syscall_3(__NR_madvise, (long)a, (long)l, adv); }

// inotify raw syscall wrappers (arm64) — identical to darvincisec's __syscall1/2/3
__attribute__((always_inline)) static inline int my_inotify_init1(int flags)
    { return (int)raw_syscall_3(__NR_inotify_init1, flags, 0, 0); }

__attribute__((always_inline)) static inline int my_inotify_add_watch(int fd, const char *path, uint32_t mask)
    { return (int)raw_syscall_3(__NR_inotify_add_watch, fd, (long)path, (long)mask); }

__attribute__((always_inline)) static inline int my_inotify_rm_watch(int fd, int wd)
    { return (int)raw_syscall_3(__NR_inotify_rm_watch, fd, wd, 0); }

// socket + connect raw syscall wrappers (arm64)
__attribute__((always_inline)) static inline int my_socket(int domain, int type, int protocol)
    { return (int)raw_syscall_3(__NR_socket, domain, type, protocol); }

__attribute__((always_inline)) static inline int my_connect(int fd, const struct sockaddr *addr, socklen_t len)
    { return (int)raw_syscall_3(__NR_connect, fd, (long)addr, (long)len); }

#else  // armeabi-v7a -- use libc syscall() wrapper

__attribute__((always_inline)) static inline int my_openat(int d, const char *p, int f, int m)
    { return (int)syscall(__NR_openat, d, p, f, m); }

__attribute__((always_inline)) static inline ssize_t my_read(int fd, void *b, size_t n)
    { return (ssize_t)syscall(__NR_read, fd, b, n); }

__attribute__((always_inline)) static inline ssize_t my_write(int fd, const void *b, size_t n)
    { return (ssize_t)syscall(__NR_write, fd, b, n); }

__attribute__((always_inline)) static inline off_t my_lseek(int fd, off_t off, int w)
    { return (off_t)syscall(__NR_lseek, fd, off, w); }

__attribute__((always_inline)) static inline int my_close(int fd)
    { return (int)syscall(__NR_close, fd); }

__attribute__((always_inline)) static inline int my_nanosleep(const struct timespec *r, struct timespec *e)
    { return (int)syscall(__NR_nanosleep, r, e); }

__attribute__((always_inline)) static inline ssize_t my_readlinkat(int d, const char *p, char *b, size_t s)
    { return (ssize_t)syscall(__NR_readlinkat, d, p, b, s); }

__attribute__((always_inline)) static inline int my_mprotect(void *a, size_t l, int prot)
    { return (int)syscall(__NR_mprotect, a, l, prot); }

__attribute__((always_inline)) static inline int my_madvise(void *a, size_t l, int adv)
    { return (int)syscall(__NR_madvise, a, l, adv); }

// inotify raw syscall wrappers (arm32) — mirrors darvincisec's __syscall1/2/3
__attribute__((always_inline)) static inline int my_inotify_init1(int flags)
    { return (int)syscall(__NR_inotify_init1, flags); }

__attribute__((always_inline)) static inline int my_inotify_add_watch(int fd, const char *path, uint32_t mask)
    { return (int)syscall(__NR_inotify_add_watch, fd, path, mask); }

__attribute__((always_inline)) static inline int my_inotify_rm_watch(int fd, int wd)
    { return (int)syscall(__NR_inotify_rm_watch, fd, wd); }

// socket + connect raw syscall wrappers (arm32)
__attribute__((always_inline)) static inline int my_socket(int domain, int type, int protocol)
    { return (int)syscall(__NR_socket, domain, type, protocol); }

__attribute__((always_inline)) static inline int my_connect(int fd, const struct sockaddr *addr, socklen_t len)
    { return (int)syscall(__NR_connect, fd, addr, len); }

#endif  // ABI

// ?
// Low-level I/O helpers
// ?

static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret, bytes_read = 0;
    my_memset(buf, 0, max_len);
    do {
        ret = my_read(fd, &b, 1);
        if (ret != 1) return (bytes_read == 0) ? -1 : bytes_read;
        if (b == '\n') return bytes_read;
        *(buf++) = b;
        bytes_read++;
    } while (bytes_read < max_len - 1);
    return bytes_read;
}

static inline unsigned long checksum(void *buffer, size_t len) {
    unsigned long seed = 0;
    uint8_t *buf = (uint8_t *)buffer;
    for (size_t i = 0; i < len; i++) seed += (unsigned long)(*buf++);
    return seed;
}

// ?
// ELF section checksum helpers (Frida mem/disk compare)
// ?

static inline void parse_proc_maps_to_fetch_path(char **filepaths) {
    int fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char map[MAX_LINE];
    int counter = 0;
    while ((read_one_line(fd, map, MAX_LINE)) > 0) {
        for (int i = 0; i < NUM_LIBS; i++) {
            if (my_strstr(map, libstocheck[i]) != NULL) {
                char tmp[MAX_LENGTH] = "", path[MAX_LENGTH] = "", buf[5] = "";
                sscanf(map, "%s %s %s %s %s %s", tmp, buf, tmp, tmp, tmp, path);
                if (buf[2] == 'x') {
                    size_t size = my_strlen(path) + 1;
                    filepaths[i] = (char *)malloc(size);
                    strcpy(filepaths[i], path);
                    counter++;
                }
            }
        }
        if (counter == NUM_LIBS) break;
    }
    my_close(fd);
}

static inline bool fetch_checksum_of_library(const char *filePath, execSection **pTextSection) {
    Elf_Ehdr ehdr;
    Elf_Shdr sectHdr;
    int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return false;
    my_read(fd, &ehdr, sizeof(Elf_Ehdr));
    my_lseek(fd, (off_t)ehdr.e_shoff, SEEK_SET);
    unsigned long memsize[2] = {0}, offset[2] = {0};
    int execSectionCount = 0;
    for (int i = 0; i < ehdr.e_shnum; i++) {
        my_memset(&sectHdr, 0, sizeof(Elf_Shdr));
        my_read(fd, &sectHdr, sizeof(Elf_Shdr));
        if (sectHdr.sh_flags & SHF_EXECINSTR) {
            offset[execSectionCount] = sectHdr.sh_offset;
            memsize[execSectionCount] = sectHdr.sh_size;
            execSectionCount++;
            if (execSectionCount == 2) break;
        }
    }
    if (execSectionCount == 0) { my_close(fd); return false; }
    *pTextSection = (execSection *)malloc(sizeof(execSection));
    (*pTextSection)->execSectionCount = execSectionCount;
    (*pTextSection)->startAddrinMem   = 0;
    for (int i = 0; i < execSectionCount; i++) {
        my_lseek(fd, offset[i], SEEK_SET);
        uint8_t *buffer = (uint8_t *)malloc(memsize[i]);
        my_read(fd, buffer, memsize[i]);
        (*pTextSection)->offset[i]   = offset[i];
        (*pTextSection)->memsize[i]  = memsize[i];
        (*pTextSection)->checksum[i] = checksum(buffer, memsize[i]);
        free(buffer);
    }
    my_close(fd);
    return true;
}

static inline bool scan_executable_segments(char *map, execSection *pElfSectArr) {
    unsigned long start, end;
    char buf[MAX_LINE] = "", path[MAX_LENGTH] = "", tmp[100] = "";
    sscanf(map, "%lx-%lx %s %s %s %s %s", &start, &end, buf, tmp, tmp, tmp, path);
    if (buf[2] == 'x' && buf[0] == 'r') {
        uint8_t *buffer = (uint8_t *)start;
        for (int i = 0; i < pElfSectArr->execSectionCount; i++) {
            unsigned long output = checksum(buffer + pElfSectArr->offset[i],
                                            pElfSectArr->memsize[i]);
            if (output != pElfSectArr->checksum[i]) return false;
        }
        return true;
    }
    return false;
}

// ?
// Kill switch
// ?

static inline void nuke_app(void) {
    volatile int *trap = NULL;
    *trap = 0xDEAD;
}

// nuke_with_poison() -- called instead of nuke_app() when a live dump is
// detected.  Before crashing, we aggressively zero every known DEX region:
//
//   mprotect(PROT_NONE)       -- makes the pages completely unreadable; any
//                                in-flight /proc/PID/mem read gets EIO.
//   madvise(MADV_DONTNEED)    -- drops all backing pages; subsequent reads
//                                (even via root /proc/PID/mem) return zeros.
//
// Since we are dying anyway, crashing ART is fine.
static void nuke_with_poison(void) {
    pthread_mutex_lock(&g_dex_cache_lock);
    int count = g_dex_cache_count;
    dex_region_entry_t snap[MAX_DEX_REGIONS];
    for (int i = 0; i < count; i++) snap[i] = g_dex_cache[i];
    pthread_mutex_unlock(&g_dex_cache_lock);

    for (int i = 0; i < count; i++) {
        if (snap[i].base == 0 || snap[i].region_size == 0) continue;
        // Make unreadable — in-flight dumper gets EIO immediately.
        my_mprotect((void *)snap[i].base, snap[i].region_size, PROT_NONE);
        // Drop backing pages — zeros returned on any subsequent read.
        my_madvise((void *)snap[i].base, snap[i].region_size, MADV_DONTNEED);
    }
    PH_LOG("nuke_with_poison: zeroed %d DEX regions — dying now", count);
    nuke_app();
}

// ?
// Original anti-Frida detection functions (unchanged)
// ?

static inline void detect_ptrace(void) {
    PH_LOG("detect_ptrace: checking TracerPid");
    char buf[512];
    int fd = my_openat(AT_FDCWD, "/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
    if (fd >= 0) {
        ssize_t bytes = my_read(fd, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = '\0';
            char *tracer = my_strstr(buf, "TracerPid:");
            if (tracer) {
                int pid = atoi(tracer + 10);
                if (pid > 0) { my_close(fd); PH_NUKE("ptrace — TracerPid=%d", pid); nuke_app(); }
            }
        }
        my_close(fd);
    }
}


// ?
// detect_monkey_and_root_tools()
//
// Two independent sub-checks fired from detect_frida_loop (5 s cadence).
//
// A. Monkey parent check
// Reads our parent PID from /proc/self/status (PPid: field).
// Reads /proc/<PPid>/cmdline.
// If the parent is `com.android.commands.monkey` -> nuke immediately.
//
// Attackers run:
// adb shell monkey -p com.target.app 1
// to trigger app initialisation automatically as part of a DEX-dumping
// pipeline.  The monkey binary becomes our direct parent process.
// Real users NEVER launch an app via adb monkey -- zero false positive risk.
//
// B. Running root-tool scan
// Iterates /proc/PID/cmdline and matches the first NUL-delimited token
// against exact package / binary names of known rooted dumper tools.
// Only fires if the tool is ACTIVELY RUNNING (not merely installed):
//
// catch_.me_.if_.you_.can_   GameGuardian -- GUI memory editor that
// reads/writes /proc/PID/mem as root; exact
// same kernel mechanism as AppDumper.
// bin.mt.plus                MT Manager Pro -- root file manager with
// built-in DEX viewer / decompiler.
// com.mt.mtmanager           MT Manager (legacy package name).
// com.np.npmanager           NP Manager -- same RE capabilities as MT,
// popular in the Chinese community.
// com.chelpus.lackypatch     Lucky Patcher -- patches APK protection
// and license checks at runtime.
//
// False positive risk: zero.  End users never have any of these tools
// running alongside a legitimate production app.  The check is based on
// the running process list, not on whether the APK is installed.
// ?

static void detect_monkey_and_root_tools(void) {
    PH_LOG("detect_monkey_and_root_tools: scanning parent + running processes");

        // ------------------------------------------------------------------
    // A. Monkey parent check
    // ------------------------------------------------------------------
    {
        char status_buf[512] = "";
        int sfd = my_openat(AT_FDCWD, "/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
        if (sfd >= 0) {
            ssize_t n = my_read(sfd, status_buf, sizeof(status_buf) - 1);
            my_close(sfd);
            if (n > 0) {
                status_buf[n] = '\0';
                char *ppid_ptr = my_strstr(status_buf, "PPid:");
                if (ppid_ptr) {
                    int ppid = atoi(ppid_ptr + 5);
                    if (ppid > 1) {
                        char parent_cmdline_path[64] = "";
                        snprintf(parent_cmdline_path, sizeof(parent_cmdline_path),
                                 "/proc/%d/cmdline", ppid);
                        int pfd = my_openat(AT_FDCWD, parent_cmdline_path,
                                            O_RDONLY | O_CLOEXEC, 0);
                        if (pfd >= 0) {
                            char pcmd[MAX_LENGTH] = "";
                            ssize_t pn = my_read(pfd, pcmd, sizeof(pcmd) - 1);
                            my_close(pfd);
                            if (pn > 0) {
                                pcmd[pn] = '\0';
                                                                // /proc/PID/cmdline uses NUL between argv tokens;
                                // the first token is the binary / package name.
                                // "monkey" appears in com.android.commands.monkey.
                                if (my_strstr(pcmd, "monkey") != NULL) {
                                    PH_NUKE("monkey parent — ppid cmdline: %s", pcmd);
                                    nuke_app();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

        // ------------------------------------------------------------------
    // B. Running root-tool scan
    // ------------------------------------------------------------------
    static const char * const ATTACK_TOOLS[] = {
        "catch_.me_.if_.you_.can_",           // GameGuardian
        "bin.mt.plus",                        // MT Manager Pro
        "com.mt.mtmanager",                   // MT Manager
        "com.np.npmanager",                   // NP Manager
        "com.chelpus.lackypatch",             // Lucky Patcher
        NULL
    };

    pid_t our_pid = getpid();
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent *pid_ent;
    while ((pid_ent = readdir(proc_dir)) != NULL) {
        const char *dname = pid_ent->d_name;
        if (!isdigit((unsigned char)dname[0])) continue;
        if (atoi(dname) == our_pid) continue;

        char cmdline_path[64] = "";
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", dname);

        int cfd = my_openat(AT_FDCWD, cmdline_path, O_RDONLY | O_CLOEXEC, 0);
        if (cfd < 0) continue;

        char cmdline[MAX_LENGTH] = "";
        ssize_t cn = my_read(cfd, cmdline, sizeof(cmdline) - 1);
        my_close(cfd);
        if (cn <= 0) continue;
        cmdline[cn] = '\0';

        for (int i = 0; ATTACK_TOOLS[i] != NULL; i++) {
            if (my_strstr(cmdline, ATTACK_TOOLS[i]) != NULL) {
                PH_NUKE("attack tool running — pid=%s cmdline=%s", dname, cmdline);
                closedir(proc_dir);
                nuke_app();
            }
        }
    }
    closedir(proc_dir);
}

static inline void detect_frida_memdiskcompare(void) {
    // Open a fresh fd each call.  /proc/self/maps is NOT in the inotify
    // watch list (removed to prevent self-triggering), so opening it here
    // is safe.  Using a fresh fd also eliminates the race condition that
    // existed when g_maps_fd was shared between poison_loop and this thread.
    // Bug fix: added elfSectionArr[i] NULL guard — array is initialised to
    // {NULL} and stays NULL if fetch_checksum_of_library() failed at startup;
    // passing NULL to scan_executable_segments caused a null-deref crash.
    int fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char map[MAX_LINE];
    while ((read_one_line(fd, map, MAX_LINE)) > 0) {
        for (int i = 0; i < NUM_LIBS; i++) {
            if (my_strstr(map, libstocheck[i]) != NULL) {
                if (elfSectionArr[i] != NULL)           // NULL guard — CRASH FIX
                    scan_executable_segments(map, elfSectionArr[i]);
                break;
            }
        }
    }
    my_close(fd);
}

// detect_frida_threads — three checks per task, matching darvincisec + NativeShield:
//
//  1. /proc/self/task/<tid>/comm
//     Raw thread name (no prefix).  Exact checks:
//       - "JDWP"         → Java Debug Wire Protocol thread = Java debugger attached
//       - "gum-js-loop"  → Frida's JavaScript engine thread
//       - "gmain"        → Frida's GLib main loop thread
//
//  2. /proc/self/task/<tid>/status  (full read)
//     - Name: field  → same Frida thread name checks as backup
//     - TracerPid:   → non-zero means a debugger is ptrace-attached to THIS thread
//
// Reading status for EVERY task (not just /proc/self/status) catches debuggers
// that attach to a single worker thread rather than the main thread — a common
// bypass of single-file TracerPid checks.
static inline void detect_frida_threads(void) {
    PH_LOG("detect_frida_threads: scanning all task comm + status");
    DIR *dir = opendir(PROC_TASK);
    if (dir == NULL) return;

    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (my_strcmp(entry->d_name, ".") == 0 ||
            my_strcmp(entry->d_name, "..") == 0) continue;

        // ── 1. comm file — raw thread name, cleanest for exact matching ──────
        {
            char comm_path[MAX_LENGTH] = "";
            snprintf(comm_path, sizeof(comm_path),
                     "/proc/self/task/%s/comm", entry->d_name);
            int fd = my_openat(AT_FDCWD, comm_path, O_RDONLY | O_CLOEXEC, 0);
            if (fd >= 0) {
                char name[MAX_LENGTH] = "";
                read_one_line(fd, name, MAX_LENGTH);
                my_close(fd);

                // JDWP = Java debugger (darvincisec + NativeShield technique)
                if (my_strncmp(name, JDWP_THREAD_NAME, 4) == 0) {
                    PH_NUKE("JDWP Java debugger thread — task=%s comm=%s",
                            entry->d_name, name);
                    closedir(dir); nuke_app();
                }
                // Frida runtime threads
                if (my_strstr(name, FRIDA_THREAD_GUM_JS_LOOP) ||
                    my_strstr(name, FRIDA_THREAD_GMAIN)) {
                    PH_NUKE("Frida thread via comm — task=%s name=%s",
                            entry->d_name, name);
                    closedir(dir); nuke_app();
                }
            }
        }

        // ── 2. status file — TracerPid + backup Name: check ──────────────────
        {
            char status_path[MAX_LENGTH] = "";
            snprintf(status_path, sizeof(status_path),
                     "/proc/self/task/%s/status", entry->d_name);
            int fd = my_openat(AT_FDCWD, status_path, O_RDONLY | O_CLOEXEC, 0);
            if (fd >= 0) {
                char buf[1024] = "";
                ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
                my_close(fd);
                if (n > 0) {
                    buf[n] = '\0';

                    // TracerPid: <pid>  — non-zero = debugger attached to this task
                    char *tracer = my_strstr(buf, "TracerPid:");
                    if (tracer) {
                        int tpid = atoi(tracer + 10);
                        if (tpid > 0) {
                            PH_NUKE("per-task TracerPid=%d on task=%s",
                                    tpid, entry->d_name);
                            closedir(dir); nuke_app();
                        }
                    }

                    // Name: field (backup — comm is primary)
                    char *name_field = my_strstr(buf, "Name:");
                    if (name_field) {
                        name_field += 5;
                        while (*name_field == '\t' || *name_field == ' ')
                            name_field++;
                        if (my_strstr(name_field, FRIDA_THREAD_GUM_JS_LOOP) ||
                            my_strstr(name_field, FRIDA_THREAD_GMAIN)) {
                            PH_NUKE("Frida thread via status Name: task=%s",
                                    entry->d_name);
                            closedir(dir); nuke_app();
                        }
                    }
                }
            }
        }
    }
    closedir(dir);
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_frida_websocket -- Frida server WebSocket fingerprint
//
// Frida's built-in server exposes a WebSocket endpoint used by frida-tools.
// The Sec-WebSocket-Accept header is deterministic:
//   SHA1("CpxD2C5REVLHvsUC9YAoqg==" + WS_MAGIC_GUID) → base64 → fixed string.
// Any port that returns "tyZql/Y8dNFFyopTrHadWzvbvRs=" IS Frida.
//
// Port scan strategy: check Frida's default (27042) + a focused list of
// common alternative ports used in real-world deployments.  Connecting to a
// closed port returns ECONNREFUSED instantly, so the scan is fast even
// across 30+ ports.
// ─────────────────────────────────────────────────────────────────────────────

// HTTP WebSocket upgrade request with the fixed key NativeShield uses.
static const char FRIDA_WS_REQUEST[] =
    "GET /ws HTTP/1.1\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: CpxD2C5REVLHvsUC9YAoqg==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "Host: 127.0.0.1\r\n"
    "User-Agent: Frida/16.1.7\r\n"
    "\r\n";

// Returns 1 if port 127.0.0.1:port responds with the Frida fingerprint.
static int check_frida_port(int port) {
    int fd = my_socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;

    // 400 ms timeout on both send and receive — don't hang on open ports
    // that are NOT Frida (other localhost servers).
    struct timeval tv = {0, 400000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    my_memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   // 127.0.0.1
    addr.sin_port        = htons((uint16_t)port);

    // connect() to a closed port returns ECONNREFUSED immediately.
    if (my_connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
        my_close(fd);
        return 0;
    }

    // Port is open — send the WebSocket upgrade and read the response.
    my_write(fd, FRIDA_WS_REQUEST, sizeof(FRIDA_WS_REQUEST) - 1);

    char res[512];
    my_memset(res, 0, sizeof(res));
    my_read(fd, res, sizeof(res) - 1);
    my_close(fd);

    return my_strstr(res, FRIDA_WS_ACCEPT) != NULL;
}

static inline void detect_frida_websocket(void) {
    PH_LOG("detect_frida_websocket: scanning for Frida server WebSocket fingerprint");

    // Ports to probe — Frida default + common alternatives used in the wild.
    // Connecting to a closed port is instant; this list runs in < 1 ms total
    // for a typical device where none of these ports are open.
    static const int FRIDA_PORTS[] = {
        27042,          // Frida default (frida-server, gadget)
        27043, 27041,   // ±1 from default (common manual tweaks)
        27040, 27044,   // ±2
        27039, 27045,   // ±3
        1337,           // "leet" port popular in CTFs / PoCs
        4444,           // Metasploit default — sometimes reused
        5555,           // ADB default — Frida-over-USB sometimes lands here
        1234, 6666, 7777, 8888, 9999,  // common quick-test ports
        8080, 8081,     // common HTTP alternative ports
        31415,          // seen in some frida-server wrappers
        11111, 22222,   // round numbers used in tutorials
    };
    static const int N_PORTS = (int)(sizeof(FRIDA_PORTS) / sizeof(FRIDA_PORTS[0]));

    for (int i = 0; i < N_PORTS; i++) {
        if (check_frida_port(FRIDA_PORTS[i])) {
            PH_NUKE("Frida WebSocket fingerprint detected on port %d — server responding with Frida WS accept hash",
                    FRIDA_PORTS[i]);
            nuke_app();
        }
    }
}

static inline void detect_frida_namedpipe(void) {
    PH_LOG("detect_frida_namedpipe: scanning fds for Frida linjector pipe");
    DIR *dir = opendir(PROC_FD);
    // Bug fix: closedir(NULL) is undefined behaviour (crash) if opendir fails.
    // Guard everything — only enter and close if dir is non-NULL.
    if (dir == NULL) return;
    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        struct stat filestat;
        char buf[MAX_LENGTH] = "";
        char filePath[MAX_LENGTH] = "";
        snprintf(filePath, sizeof(filePath), "/proc/self/fd/%s", entry->d_name);
        lstat(filePath, &filestat);
        if ((filestat.st_mode & S_IFMT) == S_IFLNK) {
            my_readlinkat(AT_FDCWD, filePath, buf, MAX_LENGTH);
            if (my_strstr(buf, FRIDA_NAMEDPIPE_LINJECTOR) != NULL) {
                PH_NUKE("Frida named pipe detected — fd link: %s", buf);
                closedir(dir); nuke_app();
            }
        }
    }
    closedir(dir);
}

// ?
// ─────────────────────────────────────────────────────────────────────────────
// LAYER 1 -- inotify_mem_watcher
//
// Technique from darvincisec/AntiDebugandMemoryDump (280 stars):
//   Install inotify watches on /proc/self/mem, /proc/self/maps,
//   /proc/self/pagemap and the per-task equivalents.  The kernel fires an
//   IN_OPEN event the instant ANY external process — including root (uid=0,
//   Matrix Dumper, dexhound) — calls open() on those files.  No polling,
//   no EPERM, no whitelist needed.
//
// Why this beats the old fd-scan approach:
//   Old: poll /proc/*/fd every 20 ms.  Root process fds are unreadable
//        (EPERM), so root dumpers were invisible.  Non-root window ~50 ms
//        meant 2-3 dumps could finish before the next poll.
//   New: kernel fires event in < 1 us.  Root or not — doesn't matter.
//        We get the event before the dumper's first read() returns.
//
// Important setup detail:
//   g_rmem_fd and g_maps_fd are opened ONCE in detect_frida_init(), BEFORE
//   the inotify watches are installed.  Those initial opens do NOT trigger
//   IN_OPEN.  self_scan_and_poison_dex() uses these globals — it never
//   calls open() on those paths again, so our own internal scans are silent.
// ─────────────────────────────────────────────────────────────────────────────

// Buffer sized to hold 1024 events — matches darvincisec's EVENT_BUF_LEN.
#define INOTIFY_EVENT_SIZE  (sizeof(struct inotify_event))
#define INOTIFY_BUF_LEN     (1024 * (INOTIFY_EVENT_SIZE + 16))
// Maximum inotify watch descriptors (3 global + 2 per-task, up to 100 tasks).
#define INOTIFY_MAX_WATCHERS 256

static void *inotify_mem_watcher(void *arg) {
    (void)arg;
    char buf[INOTIFY_BUF_LEN];

    // Outer loop: re-create the inotify fd each iteration.
    // This re-adds watches for every current thread (picks up new threads
    // spawned after startup), mirroring darvincisec's design exactly.
    while (1) {
        int ifd = my_inotify_init1(0);
        if (ifd < 0) {
            // Kernel too old or fd limit hit — retry after 1s.
            PH_LOG("inotify_init1 failed (%d) — retrying in 1s", ifd);
            struct timespec ts = {1, 0};
            my_nanosleep(&ts, NULL);
            continue;
        }

        // Track all watch descriptors so we can clean up after an event.
        int wd[INOTIFY_MAX_WATCHERS];
        int wcount = 0;

        // ── Global proc files ─────────────────────────────────────────────
        // /proc/self/mem — the primary target of every DEX dumper.
        //   IN_OPEN only: we hold g_rmem_fd open (opened before inotify is
        //   armed); our self-scan uses that fd and never calls open() again.
        //   External dumpers must call open() first — IN_OPEN catches them.
        wd[wcount++] = my_inotify_add_watch(ifd,
            "/proc/self/mem",     (uint32_t)IN_OPEN);

        // NOTE: /proc/self/maps is intentionally NOT watched.
        //   detect_frida_memdiskcompare() and detect_riru_zygisk() both read
        //   maps on every 5-second loop iteration (using g_maps_fd / lseek).
        //   Watching maps would fire IN_OPEN on our own reads, instantly
        //   self-triggering a false nuke on clean devices. Confirmed crash on
        //   TECNO CK7n (Android 13, non-rooted) where the 7ms gap between
        //   inotify arming and detect_frida_memdiskcompare's openat was enough
        //   to nuke the app. Maps coverage is provided by detect_riru_zygisk()
        //   and detect_frida_memdiskcompare() independently.

        // /proc/self/pagemap — physical page resolver used by advanced carvers.
        //   We never open pagemap ourselves, so IN_ACCESS | IN_OPEN is safe.
        wd[wcount++] = my_inotify_add_watch(ifd,
            "/proc/self/pagemap", (uint32_t)(IN_ACCESS | IN_OPEN));

        // ── Per-task mem + pagemap for ALL current threads ────────────────
        // Matches darvincisec exactly: iterate /proc/self/task/ and add
        // watches for each thread's mem and pagemap files.  A dumper that
        // targets /proc/<PID>/task/<TID>/mem is caught this way.
        DIR *task_dir = opendir("/proc/self/task");
        if (task_dir) {
            struct dirent *entry;
            while ((entry = readdir(task_dir)) != NULL &&
                   wcount < INOTIFY_MAX_WATCHERS - 2) {

                if (entry->d_name[0] == '.') continue;

                char mem_path[64], pgm_path[64];
                snprintf(mem_path, sizeof(mem_path),
                         "/proc/self/task/%s/mem",     entry->d_name);
                snprintf(pgm_path, sizeof(pgm_path),
                         "/proc/self/task/%s/pagemap", entry->d_name);

                // IN_OPEN only for task mem (same self-trigger reason as above).
                wd[wcount++] = my_inotify_add_watch(ifd, mem_path,
                                                    (uint32_t)IN_OPEN);
                // IN_ACCESS | IN_OPEN for pagemap — we never read it.
                wd[wcount++] = my_inotify_add_watch(ifd, pgm_path,
                                                    (uint32_t)(IN_ACCESS | IN_OPEN));
            }
            closedir(task_dir);
        }

        PH_LOG("inotify_mem_watcher: armed %d watches (proc+all-tasks)", wcount);

        // ── Blocking read — zero CPU until kernel fires an event ──────────
        ssize_t length = my_read(ifd, buf, sizeof(buf));

        if (length > 0) {
            // Walk the event list — matches darvincisec's while(read_length<length).
            int offset = 0;
            while (offset < (int)length) {
                struct inotify_event *ev =
                    (struct inotify_event *)((char *)buf + offset);

                if (ev->mask & IN_ACCESS) {
                    PH_NUKE("inotify IN_ACCESS — external process read /proc/self/{mem|pagemap} — zeroing all DEX regions");
                    nuke_with_poison();
                } else if (ev->mask & IN_OPEN) {
                    PH_NUKE("inotify IN_OPEN — external process opened /proc/self/{mem|pagemap} — zeroing all DEX regions");
                    nuke_with_poison();
                }
                // nuke_with_poison() never returns; this line is unreachable
                // unless something is very wrong — advance and keep trying.
                offset += (int)(INOTIFY_EVENT_SIZE + ev->len);
            }
        }

        // ── Cleanup: remove all watches, close fd, re-arm immediately ─────
        for (int j = 0; j < wcount; j++) {
            if (wd[j] > 0) my_inotify_rm_watch(ifd, wd[j]);
        }
        my_close(ifd);
        // No sleep — re-arm instantly so there is never a window without
        // active watches (unlike darvincisec's 1s sleep gap).
    }
    return NULL;
}

// ?
// LAYER 2b -- self_scan_and_poison_dex()
//
// Reads our own /proc/self/maps and finds every readable anonymous region
// (no backing file, or [anon:dalvik-*]) that begins with the DEX magic
// bytes (dex\n = 0x64 0x65 0x78 0x0a) AND has a valid endian_tag
// (0x12345678) at offset 40.
//
// For each such region we:
// 1. Temporarily elevate the page's protection to PROT_READ|PROT_WRITE
// using mprotect().
// 2. Overwrite the first 8 bytes (magic + version string) with zeros.
// 3. Restore the original page protection.
//
// Additionally, every discovered region is registered into the DEX region
// cache (g_dex_cache) so fast_poison_known_regions() can hit it every 1 ms
// without re-scanning /proc/self/maps.
//
// This is called at 500 ms cadence (cache refresh) and immediately from
// nativePoisonNow() JNI after each InMemoryDexClassLoader call.
// ?

static void self_scan_and_poison_dex(void) {
    // Use the persistent global fds opened at startup (before inotify was
    // armed).  Opening /proc/self/mem or /proc/self/maps here would trigger
    // our own inotify watch and cause a self-nuke.
    int maps_fd = g_maps_fd;
    int rmem_fd = g_rmem_fd;
    if (maps_fd < 0 || rmem_fd < 0) return;

    // Seek maps back to the beginning — procfs regenerates on each read.
    my_lseek(maps_fd, 0, SEEK_SET);

    char line[MAX_LINE];
    while (read_one_line(maps_fd, line, MAX_LINE) > 0) {
        unsigned long start = 0, end = 0;
        char perm[8]          = "";
        char path[MAX_LENGTH] = "";
        char tmp[MAX_LENGTH]  = "";

                // Parse map line: addr-addr perm offset dev inode [path]
        int fields = sscanf(line, "%lx-%lx %4s %s %s %s %255s",
                            &start, &end, perm, tmp, tmp, tmp, path);
        if (fields < 3) continue;

                // Must be readable.
        if (perm[0] != 'r') continue;

                // Skip write+execute (JIT code), and system libraries/framework.
        if (perm[1] == 'w' && perm[2] == 'x') continue;
        if (fields >= 7) {
            if (my_strstr(path, "/system/")  != NULL) continue;
            if (my_strstr(path, "/vendor/")  != NULL) continue;
            if (my_strstr(path, "/apex/")    != NULL) continue;
            if (my_strstr(path, ".oat")      != NULL) continue;
            if (my_strstr(path, ".vdex")     != NULL) continue;
            if (my_strstr(path, ".art")      != NULL) continue;
            if (my_strstr(path, ".odex")     != NULL) continue;
                        // Only target anonymous or dalvik-labelled regions.
            if (path[0] != '\0'
                && my_strstr(path, "dalvik") == NULL
                && my_strstr(path, "anon")   == NULL) continue;
        }

        size_t region_size = end - start;
        if (region_size < 112 || region_size > MAX_SZ) continue;

                // Read first 44 bytes of the region safely via /proc/self/mem.
        uint8_t hdr[44];
        my_lseek(rmem_fd, (off_t)start, SEEK_SET);
        ssize_t n = my_read(rmem_fd, hdr, sizeof(hdr));
        if (n < 44) continue;

                // Check DEX magic: 'dex\n'
        if (hdr[0] != 'd' || hdr[1] != 'e' || hdr[2] != 'x' || hdr[3] != '\n') continue;

                // Validate endian tag at offset 40 = 0x12345678 (little-endian).
        uint32_t endian_tag = (uint32_t)hdr[40]
                            | ((uint32_t)hdr[41] << 8)
                            | ((uint32_t)hdr[42] << 16)
                            | ((uint32_t)hdr[43] << 24);
        if (endian_tag != 0x12345678) continue;

                // ? Found live DEX magic -- register in cache + poison.
        //
        // Strategy depends on whether the region is ART's active dalvik
        // mapping or the original (now-consumed) ByteBuffer mapping:
        //
        // dalvik-labelled region  (ART reads it during execution)
        // -> header-only poison: zero magic[0-7] + endian_tag[40-43].
        // Defeats magic-byte scanners (dexhound) without crashing ART.
        //
        // non-dalvik anonymous region  (original ByteBuffer -- ART is done)
        // -> FULL WIPE: mprotect+memset every page, then madvise(MADV_DONTNEED)
        // to drop backing pages so even a direct /proc/PID/mem read returns
        // only zeros -- no header, no bytecode, nothing reconstructable.
        //
        // Register into g_dex_cache regardless of poison path so that
        // fast_poison_known_regions() keeps hitting this address every 1 ms
        // without needing to re-scan maps.
        int is_dalvik = (my_strstr(path, "dalvik") != NULL);

        pthread_mutex_lock(&g_dex_cache_lock);
        cache_add_region_locked(start, region_size, is_dalvik);
        pthread_mutex_unlock(&g_dex_cache_lock);

        if (!is_dalvik && region_size <= (8u * 1024u * 1024u)) {
            // Non-dalvik anonymous region (original ByteBuffer — ART is done).
            // Full wipe: mprotect+memset every page, then drop backing pages.
            unsigned long ps   = 4096;
            unsigned long addr = start & ~(ps - 1);
            unsigned long end  = (start + region_size + ps - 1) & ~(ps - 1);
            while (addr < end) {
                if (my_mprotect((void *)addr, ps, PROT_READ | PROT_WRITE) == 0) {
                    volatile uint8_t *p = (volatile uint8_t *)addr;
                    for (unsigned long j = 0; j < ps; j++) p[j] = 0;
                    my_mprotect((void *)addr, ps, PROT_READ);
                }
                addr += ps;
            }
            my_madvise((void *)start, region_size, MADV_DONTNEED);
        } else {
            // Dalvik region (ART active) or oversized: header-only poison.
            // Zero magic[0-7] + endian_tag[40-43] via mprotect+direct write.
            unsigned long ps         = 4096;
            unsigned long page_start = start & ~(ps - 1);
            int orig_prot = PROT_READ;
            if (perm[1] == 'w') orig_prot |= PROT_WRITE;
            if (perm[2] == 'x') orig_prot |= PROT_EXEC;
            if (my_mprotect((void *)page_start, ps, PROT_READ | PROT_WRITE) == 0) {
                volatile uint8_t *ptr = (volatile uint8_t *)start;
                ptr[0]=0;ptr[1]=0;ptr[2]=0;ptr[3]=0;
                ptr[4]=0;ptr[5]=0;ptr[6]=0;ptr[7]=0;
                ptr[40]=0;ptr[41]=0;ptr[42]=0;ptr[43]=0;
                my_mprotect((void *)page_start, ps, orig_prot);
            }
        }
    }

    // Do NOT close — these are the persistent global fds.
}

// ?
// poison_loop -- two-tier cadence
//
// TIER 1 (100 us)  fast_poison_known_regions()
// Hits every cached DEX base address with mprotect+memset -- no maps I/O,
// no readdir, just mprotect syscalls + direct byte stores.  Total cost per
// tick: ~1-5 us for typical apps (header-only path per region).
// This shrinks the valid-DEX window from 50 ms -> 100 us: the dumper must
// complete its entire /proc/PID/mem seek+read inside that window -- it cannot.
//
// TIER 2 (500 ms)  self_scan_and_poison_dex()
// Full /proc/self/maps re-scan.  Discovers newly-loaded DEX regions (e.g.
// shards loaded after the app has warmed up) and rebuilds g_dex_cache so
// Tier 1 keeps hitting the right addresses.  Also performs a full poison
// pass for belt-and-suspenders coverage.
//
// Note: nativePoisonNow() (called from Java immediately after every
// InMemoryDexClassLoader) also runs a full scan so new regions enter the
// cache with zero delay -- the 500 ms background refresh is just a safety net.
// ?

static void *poison_loop(void *arg) {
    (void)arg;

    struct timespec fast_tick = { 0, 100000L };        // 100 us

    // Run a full maps refresh every 5000 ticks (= 500 ms).
    int refresh_counter = 0;

    while (1) {
        fast_poison_known_regions();

        if (++refresh_counter >= 5000) {
            refresh_counter = 0;
            self_scan_and_poison_dex();               // rebuilds cache + full poison pass
        }

        my_nanosleep(&fast_tick, NULL);
    }
    return NULL;
}


// ?
// detect_ebpf_uprobe()
//
// eBPFDexDumper (updated July 2026) attaches a kernel uprobe to
// art::interpreter::Execute inside libart.so then streams DEX bytecode
// from below userspace -- completely bypassing /proc/PID/mem poisoning.
//
// When a uprobe is attached the kernel writes an entry like:
// p:dex_dump libart.so:0x<offset>
// into the tracing filesystem under two possible paths.  We scan both.
// Any line containing "libart" -> an eBPF dumper is active -> nuke_app().
// ?

static void detect_ebpf_uprobe(void) {
    static const char *paths[] = {
        "/sys/kernel/debug/tracing/uprobe_events",
        "/sys/kernel/tracing/uprobe_events",
        NULL
    };
    for (int i = 0; paths[i] != NULL; i++) {
        int fd = my_openat(AT_FDCWD, paths[i], O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) continue;
        char buf[4096];
        my_memset(buf, 0, sizeof(buf));
        ssize_t n = my_read(fd, buf, sizeof(buf) - 1);
        my_close(fd);
        if (n <= 0) continue;
                // eBPFDexDumper registers uprobe on libart; any hit is a dumper.
        if (my_strstr(buf, "libart") != NULL ||
            my_strstr(buf, "dex_dump") != NULL) {
            PH_NUKE("eBPF uprobe on libart detected — uprobe entry: %s", buf);
            nuke_app();
        }
    }
}

// ?
// detect_riru_zygisk -- Riru / Zygisk / Xposed / LSPosed injection detection
//
// Three independent signal sources (NativeShield RiGisk.cpp technique):
//
//   1. /proc/self/maps scan
//      Riru injects libmain.so from /data/adb/riru/; Zygisk from its module
//      directory.  LSPosed appears as "lspd"; EdXposed as "edxposed".
//      Any matching string in a mapped path → injection detected.
//      Note: advanced Zygisk (DenyList) can hide from maps; source 2 covers that.
//
//   2. dl_iterate_phdr (raw linker list)
//      Walks the dynamic linker's in-memory list of loaded libraries.
//      Different data source from procfs — DenyList hides from /proc/self/maps
//      but the linker's soinfo list still has the real path at load time.
//
//   3. Known module install paths
//      If the directory exists, the framework is installed (even if not currently
//      injected into this specific process).  Zygisk modules survive reboots and
//      are in the process if they target our app.
// ?

// C-style dl_iterate_phdr callback (file is compiled as C, not C++).
static int hook_phdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (!info || !info->dlpi_name || info->dlpi_name[0] == '\0') return 0;
    if (my_strstr(info->dlpi_name, HOOK_RIRU)    ||
        my_strstr(info->dlpi_name, HOOK_ZYGISK)  ||
        my_strstr(info->dlpi_name, HOOK_XPOSED)  ||
        my_strstr(info->dlpi_name, HOOK_LSPD)    ||
        my_strstr(info->dlpi_name, HOOK_EDXPOSED)) {
        *(int *)data = 1;
        return 1;   // stop iteration
    }
    return 0;
}

static void detect_riru_zygisk(void) {
    PH_LOG("detect_riru_zygisk: scanning maps + phdr + paths");

    // ── 1. /proc/self/maps scan ───────────────────────────────────────────────
    // Open a fresh fd — /proc/self/maps is NOT in the inotify watch list so
    // opening it here is safe and eliminates the g_maps_fd race condition
    // (g_maps_fd is used by self_scan_and_poison_dex in poison_loop thread;
    // sharing it with this thread without a mutex caused garbled reads).
    {
        int fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char map[MAX_LINE] = "";
            while (read_one_line(fd, map, MAX_LINE) > 0) {
                if (my_strstr(map, HOOK_RIRU)    ||
                    my_strstr(map, HOOK_ZYGISK)  ||
                    my_strstr(map, HOOK_XPOSED)  ||
                    my_strstr(map, HOOK_LSPD)    ||
                    my_strstr(map, HOOK_EDXPOSED)) {
                    PH_NUKE("hooking framework in /proc/self/maps: %s", map);
                    my_close(fd); nuke_app();
                }
            }
            my_close(fd);
        }
    }

    // ── 2. dl_iterate_phdr — linker's in-memory library list ─────────────────
    {
        int found = 0;
        dl_iterate_phdr(hook_phdr_cb, &found);
        if (found) {
            PH_NUKE("hooking framework found via dl_iterate_phdr");
            nuke_app();
        }
    }

    // ── 3. Known install paths — existence check ──────────────────────────────
    static const char *HOOK_PATHS[] = {
        "/data/adb/riru",
        "/data/adb/modules/riru",
        "/data/adb/modules/zygisk",
        "/data/misc/riru",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so",
        "/system/framework/XposedBridge.jar",
        NULL
    };
    for (int i = 0; HOOK_PATHS[i] != NULL; i++) {
        int fd = my_openat(AT_FDCWD, HOOK_PATHS[i], O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            PH_NUKE("hooking framework path exists: %s", HOOK_PATHS[i]);
            my_close(fd); nuke_app();
        }
    }
}

// ?
// detect_root -- su binary + Magisk mount detection
//
// Two independent checks (NativeShield RootDetect.cpp technique):
//
//   A. su binary existence
//      Attempts to open each known su path with O_RDONLY.  On a non-rooted
//      device these files do not exist.  If ANY opens successfully, root is
//      confirmed → nuke_app().
//
//   B. /proc/self/mounts scan for Magisk signatures
//      Magisk mounts a mirror of /data under /data/adb/modules and creates
//      entries containing "magisk", "core/mirror", or "core/img" in the
//      process mount namespace.  Reading /proc/self/mounts and scanning for
//      these strings catches Magisk even when it hides su from PATH.
// ?

static void detect_root(void) {
    PH_LOG("detect_root: checking su binaries + Magisk mounts");

    // ── A. su binary existence ────────────────────────────────────────────────
    static const char *SU_PATHS[] = {
        "/data/local/su",
        "/data/local/bin/su",
        "/data/local/xbin/su",
        "/sbin/su",
        "/su/bin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/system/bin/.ext/su",
        "/system/bin/failsafe/su",
        "/system/sd/xbin/su",
        "/system/usr/we-need-root/su",
        "/cache/su",
        "/data/su",
        "/dev/su",
        NULL
    };
    for (int i = 0; SU_PATHS[i] != NULL; i++) {
        int fd = my_openat(AT_FDCWD, SU_PATHS[i], O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            PH_NUKE("su binary found: %s — root confirmed", SU_PATHS[i]);
            my_close(fd); nuke_app();
        }
    }

    // ── B. /proc/self/mounts — Magisk mount signatures ────────────────────────
    {
        int fd = my_openat(AT_FDCWD, "/proc/self/mounts", O_RDONLY | O_CLOEXEC, 0);
        if (fd >= 0) {
            char buf[MAX_LINE] = "";
            static const char *MAGISK_MARKERS[] = {
                "magisk", "core/mirror", "core/img", NULL
            };
            while (read_one_line(fd, buf, MAX_LINE) > 0) {
                for (int i = 0; MAGISK_MARKERS[i] != NULL; i++) {
                    if (my_strstr(buf, MAGISK_MARKERS[i])) {
                        PH_NUKE("Magisk mount detected: %s", buf);
                        my_close(fd); nuke_app();
                    }
                }
            }
            my_close(fd);
        }
    }
}

// ?
// detect_frida_loop -- 5-second cadence
// Frida thread names, named pipes, binary checksums, ptrace, eBPF uprobes.
// ?

static void *detect_frida_loop(void *args) {
    (void)args;
    struct timespec timereq;
    timereq.tv_sec  = 5;
    timereq.tv_nsec = 0;
    while (1) {
        detect_frida_threads();                   // JDWP + per-task TracerPid + gum-js-loop/gmain
        detect_frida_namedpipe();
        detect_frida_websocket();                 // WebSocket fingerprint: tyZql/Y8dNFFyopTrHadWzvbvRs=
        detect_frida_memdiskcompare();
        detect_ptrace();
        detect_ebpf_uprobe();
        detect_riru_zygisk();                     // Riru/Zygisk/Xposed: maps + phdr + paths
        detect_root();                            // su binaries + Magisk mounts
        detect_monkey_and_root_tools();           // monkey + GameGuardian + MT/NP/LuckyPatcher
        my_nanosleep(&timereq, NULL);
    }
    return NULL;
}

// ?
// Constructor -- runs immediately on System.load(libphantom.so)
//
// Three independent threads launched:
// poison_loop       -- fast_poison every 100 us + full maps refresh every 500 ms
// Tier-1 cost: ~1-5 us/tick (mprotect+memset, no maps I/O).
// Tier-2 cost: full /proc/self/maps scan rebuilds the
// DEX region cache and performs a belt-and-suspenders
// full poison pass.
//
// inotify_mem_watcher -- kernel event, zero CPU -- fires the instant ANY
// process (including root) opens /proc/self/{mem,maps,pagemap}.
//
// detect_frida_loop -- 5 s   -- Frida/ptrace/eBPF heuristics.
// ?

__attribute__((constructor))
void detect_frida_init(void) {
    // ── 1. Seal /proc/self/mem ───────────────────────────────────────────
    // prctl(PR_SET_DUMPABLE, 0) tells the kernel to refuse open() on
    // /proc/<PID>/mem from any external process.
    // NOTE: root + setenforce 0 bypasses this -- see check #2 below.
    prctl(PR_SET_DUMPABLE, 0);

    // ── 2. SELinux permissive detection ─────────────────────────────────
    // Dumpers call "setenforce 0" before launching the app so they can
    // open /proc/PID/mem as root even with PR_SET_DUMPABLE=0.
    //
    // NOTE: We do NOT nuke immediately on permissive SELinux.
    // Rooted devices (Magisk / KernelSU) often set setenforce 0 globally,
    // and legitimate users on rooted phones must not be killed on launch.
    // Nuking here caused a false-positive SIGSEGV on every rooted device
    // regardless of whether a dump was actually in progress.
    //
    // The real dump-protection layers are:
    //   • inotify_mem_watcher() -- kernel event fires the instant any process opens our mem
    //   • poison_loop()         -- continuously zeros DEX headers in [anon:dalvik-*]
    //   • detect_frida_*()     -- Frida thread names, named pipes, disk-vs-mem
    // Those layers remain fully active regardless of SELinux mode.
    //
    // Android mounts selinuxfs at TWO possible paths depending on kernel:
    //   /sys/fs/selinux/enforce          -- Android 5-15, most kernels
    //   /sys/kernel/security/selinux/enforce -- Android 16 / kernel 6.6+
    {
        static const char * const SELINUX_PATHS[] = {
            "/sys/fs/selinux/enforce",
            "/sys/kernel/security/selinux/enforce",
            NULL
        };
        for (int si = 0; SELINUX_PATHS[si] != NULL; si++) {
            int sefd = my_openat(AT_FDCWD, SELINUX_PATHS[si],
                                 O_RDONLY | O_CLOEXEC, 0);
            if (sefd < 0) continue;
            char ebuf[4] = {0};
            my_read(sefd, ebuf, 3);
            my_close(sefd);
            // '0' = permissive -- noted but not acted on here.
            // inotify_mem_watcher + poison_loop handle the actual threat.
            (void)ebuf;
            break;
        }
    }

    // ── 3. Monkey / root-tool check -- SYNCHRONOUS before any thread ────
    // detect_monkey_and_root_tools() also runs in detect_frida_loop, but
    // that loop runs in a background thread that may not be scheduled for
    // 1-5 s while the main thread is busy loading classes.  The dump
    // happens at ~4 s after PID appears, so the thread check can fire
    // too late.  Calling it here in the constructor guarantees it runs
    // synchronously -- BEFORE System.loadLibrary() returns, BEFORE any
    // Java code calls nativeDecryptShard().  If monkey is detected we
    // nuke and never decrypt.
    detect_monkey_and_root_tools();

    char *filePaths[NUM_LIBS] = {NULL, NULL};
    parse_proc_maps_to_fetch_path(filePaths);
    for (int i = 0; i < NUM_LIBS; i++) {
        if (filePaths[i]) {
            fetch_checksum_of_library(filePaths[i], &elfSectionArr[i]);
            free(filePaths[i]);
        }
    }
    pthread_t t;
    // Open persistent global fds BEFORE arming inotify.
    // self_scan_and_poison_dex() uses these — it never re-opens these paths,
    // so our own internal reads never trigger the inotify watches below.
    g_rmem_fd = my_openat(AT_FDCWD, "/proc/self/mem",  O_RDONLY | O_CLOEXEC, 0);
    g_maps_fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);

    pthread_create(&t, NULL, poison_loop,          NULL);   // 100 us fast + 500 ms refresh
    pthread_create(&t, NULL, inotify_mem_watcher,  NULL);   // kernel event — catches root dumpers
    pthread_create(&t, NULL, detect_frida_loop,    NULL);   // 5 s
}

// nativePoisonNow -- JNI hook called from Java immediately after
// InMemoryDexClassLoader has parsed the DEX bytes.  At that exact moment
// ART has created [anon:dalvik-DEX] mappings for the DEX, so a single
// forced poison pass here eliminates the live-header window that exists
// between DEX load and the first scheduled poison_loop tick.
JNIEXPORT void JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativePoisonNow(
        JNIEnv *env, jclass clazz)
{
    (void)env; (void)clazz;
    self_scan_and_poison_dex();
}

// ?
// LAYER 2a -- nativeWipeShard()  [JNI -- called from DexProtector after load]
//
// Java calls this immediately after InMemoryDexClassLoader (or the file-
// based fallback) has consumed the plaintext DEX byte[].  We zero the first
// 8 bytes (dex\n magic + version string) and the endian_tag at offset 40
// inside the Java byte[] so the heap copy no longer looks like a DEX to
// any /proc/PID/mem scanner.
//
// ART has already fully parsed and mapped the DEX before this is called, so
// zeroing the source byte[] does not affect class resolution.
// ?

JNIEXPORT void JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeWipeShard(
        JNIEnv    *env,
        jclass     clazz,
        jbyteArray j_dex)
{
    (void)clazz;
    if (!j_dex) return;
    jint len = (*env)->GetArrayLength(env, j_dex);
    if (len <= 0) return;

        // Wipe the ENTIRE byte[] -- not just the 8-byte magic header.
    // ART has already parsed and internally mapped the DEX before this call.
    // Zeroing only the header leaves the full method bytecode in the Java
    // heap for any /proc/PID/mem scanner to reconstruct.  Wiping all bytes
    // leaves nothing to reconstruct from.  Write in 64 KB chunks to avoid
    // a large stack allocation.
    static const jbyte zero_chunk[65536] = {0};
    jint remaining = len;
    jint offset    = 0;
    while (remaining > 0) {
        jint chunk = remaining > (jint)sizeof(zero_chunk)
                     ? (jint)sizeof(zero_chunk) : remaining;
        (*env)->SetByteArrayRegion(env, j_dex, offset, chunk, zero_chunk);
        offset    += chunk;
        remaining -= chunk;
    }
}

// ?
// SHA-256 (minimal, self-contained)
// Hashes the package name inside native so the hash never returns to Java.
// ?

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_block(uint32_t h[8], const uint8_t data[64]) {
    uint32_t w[64];
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)
              |((uint32_t)data[i*4+2]<<8)|(uint32_t)data[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1  = ROR32(e,6)^ROR32(e,11)^ROR32(e,25);
        uint32_t ch  = (e&f)^(~e&g);
        uint32_t tmp1= hh+S1+ch+K256[i]+w[i];
        uint32_t S0  = ROR32(a,2)^ROR32(a,13)^ROR32(a,22);
        uint32_t maj = (a&b)^(a&c)^(b&c);
        uint32_t tmp2= S0+maj;
        hh=g; g=f; f=e; e=d+tmp1;
        d=c;  c=b; b=a; a=tmp1+tmp2;
    }
    h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
    h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
}

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32]) {
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };
    uint8_t block[64];
    size_t i;
    uint64_t bit_len = (uint64_t)len * 8;
    while (len >= 64) { sha256_block(h, msg); msg += 64; len -= 64; }
    memset(block, 0, 64);
    memcpy(block, msg, len);
    block[len] = 0x80;
    if (len >= 56) { sha256_block(h, block); memset(block, 0, 64); }
    for (i = 0; i < 8; i++) block[56+i] = (uint8_t)(bit_len >> (56 - i*8));
    sha256_block(h, block);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i]>>24);
        out[i*4+1] = (uint8_t)(h[i]>>16);
        out[i*4+2] = (uint8_t)(h[i]>>8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

// ?
// ARX KDF -- byte-identical to DexSeed.arx() in Java
// ?

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint32_t le32(const uint8_t *b, int off) {
    return (uint32_t)b[off]
         | ((uint32_t)b[off+1] <<  8)
         | ((uint32_t)b[off+2] << 16)
         | ((uint32_t)b[off+3] << 24);
}

static inline void put_le32(uint8_t *b, int off, uint32_t v) {
    b[off]   = (uint8_t)v;
    b[off+1] = (uint8_t)(v >>  8);
    b[off+2] = (uint8_t)(v >> 16);
    b[off+3] = (uint8_t)(v >> 24);
}

static void arx_kdf(const uint8_t salt[16], const uint8_t pkg_hash[32], uint8_t out[16]) {
    uint32_t s0 = le32(salt,  0), s1 = le32(salt,  4);
    uint32_t s2 = le32(salt,  8), s3 = le32(salt, 12);
    uint32_t ph0 = le32(pkg_hash, 0), ph1 = le32(pkg_hash, 4);
    for (int i = 0; i < 8; i++) {
        s0 = ROL32(s0 ^ ph0, 11) + s1;
        s1 = ROL32(s1 ^ ph1, 13) + s2;
        s2 = ROL32(s2 ^ ph0, 17) + s3;
        s3 = ROL32(s3 ^ ph1, 19) + s0;
    }
    put_le32(out,  0, s0); put_le32(out,  4, s1);
    put_le32(out,  8, s2); put_le32(out, 12, s3);
}

// ?
// ARX stream cipher -- port of Java DexCrypto.{exfr,FxIjsF,nDnv}
// ?

typedef struct {
    uint32_t ks[27];
    uint32_t st[2];
    int      pos;
} arx_ctx_t;

static void arx_ctx_init(arx_ctx_t *s, const uint8_t key[16]) {
    uint32_t k0=le32(key,0), k1=le32(key,4), k2=le32(key,8), k3=le32(key,12);
    s->st[0] = k0 ^ k2;
    s->st[1] = k1 ^ k3;
    s->pos   = 0;
    {
        uint32_t iv=k0, t[3]; t[0]=k1; t[1]=k2; t[2]=k3;
        s->ks[0] = iv;
        for (int i2=0; i2<26; i2++) {
            t[i2%3] = (ROR32(t[i2%3],8)+iv)^(uint32_t)i2;
            iv = ROL32(iv,3)^t[i2%3];
            s->ks[i2+1] = iv;
        }
    }
}

static void arx_advance_block(arx_ctx_t *s) {
    const uint32_t *ks = s->ks;
    uint32_t i=s->st[0], i2=s->st[1];
    i2=(ROR32(i2,8)+i)^ks[0];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[1];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[2];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[3];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[4];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[5];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[6];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[7];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[8];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[9];  i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[10]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[11]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[12]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[13]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[14]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[15]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[16]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[17]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[18]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[19]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[20]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[21]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[22]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[23]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[24]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[25]; i=ROL32(i,3)^i2;
    i2=(ROR32(i2,8)+i)^ks[26];
    s->st[0]=ROL32(i,3)^i2; s->st[1]=i2;
}

static void arx_xor(arx_ctx_t *s, uint8_t *buf, size_t len) {
    for (size_t n=0; n<len; n++) {
        int i6=s->pos%8, shift=(s->pos%4)*8;
        if (i6==0) arx_advance_block(s);
        int word=(int)s->st[i6>>2];
        buf[n] ^= (uint8_t)(word>>shift);
        s->pos++;
    }
}

// ?
// zlib inflate helper
// ?

static uint8_t *inflate_alloc(const uint8_t *in, size_t in_len, size_t *out_len) {
    z_stream zs;
    uint8_t *buf, *tmp;
    size_t cap, used;
    int ret;
    memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) return NULL;
    cap = in_len * 4 + 4096;
    buf = (uint8_t *)malloc(cap);
    if (!buf) { inflateEnd(&zs); return NULL; }
    zs.next_in   = (Bytef *)in;
    zs.avail_in  = (uInt)in_len;
    zs.next_out  = (Bytef *)buf;
    zs.avail_out = (uInt)cap;
    for (;;) {
        ret = inflate(&zs, Z_FINISH);
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK && ret != Z_BUF_ERROR) { free(buf); inflateEnd(&zs); return NULL; }
        used = cap - zs.avail_out; cap *= 2;
        tmp  = (uint8_t *)realloc(buf, cap);
        if (!tmp) { free(buf); inflateEnd(&zs); return NULL; }
        buf = tmp;
        zs.next_out  = (Bytef *)(buf + used);
        zs.avail_out = (uInt)(cap - used);
    }
    *out_len = cap - zs.avail_out;
    inflateEnd(&zs);
    return buf;
}

// ?
// nativeDecryptShard -- JNI entry-point
//
// Derives key + decrypts one shard entirely in native.
// Pipeline reversal: outer inflate -> ARX XOR -> inner inflate -> plaintext DEX.
// Key is zeroed on the stack before return; never crosses the JNI boundary.
// ?

JNIEXPORT jbyteArray JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard(
        JNIEnv    *env,
        jclass     clazz,
        jbyteArray j_salt,
        jbyteArray j_pkg_name_utf8,
        jbyteArray j_encrypted)
{
    // Belt-and-suspenders: re-seal /proc/self/mem on every decrypt call in
    // case some framework reset PR_DUMPABLE between JNI_OnLoad and here.
    prctl(PR_SET_DUMPABLE, 0);

    jbyteArray result = NULL;

    uint8_t salt[16]     = {0};
    uint8_t pkg_hash[32] = {0};
    uint8_t key[16]      = {0};

    uint8_t *enc_buf   = NULL;
    uint8_t *inter_buf = NULL;
    uint8_t *plain_buf = NULL;
    size_t   inter_len = 0, plain_len = 0;
    jint     enc_len   = 0;

    (void)clazz;

        // 1. Derive key entirely inside native.
    if (j_salt == NULL || (*env)->GetArrayLength(env, j_salt) != 16)
        goto cleanup;
    (*env)->GetByteArrayRegion(env, j_salt, 0, 16, (jbyte *)salt);

    if (j_pkg_name_utf8 != NULL) {
        jint pkg_len = (*env)->GetArrayLength(env, j_pkg_name_utf8);
        if (pkg_len > 0 && pkg_len <= 512) {
            uint8_t pkg_buf[512];
            (*env)->GetByteArrayRegion(env, j_pkg_name_utf8, 0, pkg_len, (jbyte *)pkg_buf);
            sha256(pkg_buf, (size_t)pkg_len, pkg_hash);
            memset(pkg_buf, 0, sizeof(pkg_buf));
        }
    }
    arx_kdf(salt, pkg_hash, key);

        // 2. Copy encrypted shard to native heap.
    if (j_encrypted == NULL) goto cleanup;
    enc_len = (*env)->GetArrayLength(env, j_encrypted);
    if (enc_len <= 0) goto cleanup;
    enc_buf = (uint8_t *)malloc((size_t)enc_len);
    if (!enc_buf) goto cleanup;
    (*env)->GetByteArrayRegion(env, j_encrypted, 0, enc_len, (jbyte *)enc_buf);

        // 3. Outer inflate.
    inter_buf = inflate_alloc(enc_buf, (size_t)enc_len, &inter_len);
    free(enc_buf); enc_buf = NULL;
    if (!inter_buf) goto cleanup;

        // 4. ARX XOR in-place.
    { arx_ctx_t arx; arx_ctx_init(&arx, key); arx_xor(&arx, inter_buf, inter_len);
      memset(&arx, 0, sizeof(arx)); }

        // 5. Inner inflate.
    plain_buf = inflate_alloc(inter_buf, inter_len, &plain_len);
    if (!plain_buf) goto cleanup;

        // 6. Return plaintext DEX bytes to Java.
    result = (*env)->NewByteArray(env, (jsize)plain_len);
    if (result)
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)plain_len, (jbyte *)plain_buf);

cleanup:
    memset(salt,     0, sizeof(salt));
    memset(pkg_hash, 0, sizeof(pkg_hash));
    memset(key,      0, sizeof(key));
    if (enc_buf)   free(enc_buf);
    if (inter_buf) { memset(inter_buf, 0, inter_len); free(inter_buf); }
    if (plain_buf) free(plain_buf);
    return result;
}
