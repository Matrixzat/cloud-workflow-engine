/*
 * phantom_key.c -- JNI entry-point for libphantom.so
 *
 * Exports:
 *   Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard
 *   Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeWipeShard
 *
 * Security model:
 *   * Per-APK key derived from (salt, sha256(pkg_name)) via ARX KDF.
 *   * Key NEVER crosses the JNI boundary -- lives only on the C stack, zeroed on return.
 *
 * Anti-dump / Anti-Frida -- three independent layers:
 *
 *   LAYER 1  detect_mem_reader()
 *     Iterates /proc/<PID>/fd/ for every running process.  If any external
 *     process has our /proc/<PID>/mem or /proc/<PID>/maps open (which
 *     dump_dex_mem.py and every /proc/PID/mem-based dumper MUST do),
 *     nuke_app() fires before a single byte is read.
 *
 *   LAYER 2a  nativeWipeShard()  [JNI -- called from DexProtector after loading]
 *     Zeroes the first 8 bytes (dex\n magic + version string) of the Java
 *     byte[] that nativeDecryptShard returned.  Eliminates the heap copy of
 *     the plaintext DEX that the script's scanner would find.
 *
 *   LAYER 2b  self_scan_and_poison_dex()
 *     Background native scan: reads our own /proc/self/maps, finds every
 *     anonymous readable region that starts with the DEX magic (0x12345678
 *     endian tag confirmed).  Uses mprotect+write+restore to overwrite the
 *     magic in-place.  Catches ART's internal [anon:dalvik-DEX cache] copies
 *     that survive after the Java byte[] has already been wiped by Layer 2a.
 *
 *   LAYER 3  detect_frida_anonymous_memory()  [already present -- extended]
 *     Detects anonymous r-xp mappings with no file path or backed by memfd:,
 *     which indicates Frida or another injector has inserted executable code.
 *
 *   All layers run every 5 s in the detect_frida_loop background thread.
 *   detect_frida_init() fires via __attribute__((constructor)) the instant
 *   System.load(libphantom.so) is called -- before nativeDecryptShard is ever
 *   reached.
 *
 * Build requirements:
 *   * Compile with OLLVM (see phantom/CMakeLists.txt).
 *   * Target ABIs: arm64-v8a and armeabi-v7a.
 *   * After building, ARX-encrypt with encrypt_blob.py and place blobs at:
 *       assets/phantom/libphantom_arm64.blob
 *       assets/phantom/libphantom_arm.blob
 *
 * IMPORTANT: Do NOT compile on Replit. Use the CI build with OLLVM toolchain.
 */

/* ?
 * Includes
 * ? */

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
#include <android/log.h>
/* Use bundled miniz instead of system libz — avoids dlopen namespace issues
 * when the .so is loaded via System.load(absolutePath) in a protected APK. */
#include "miniz.h"
/* miniz uses mz_ prefix; map zlib names → miniz names for compatibility */
#define z_stream          mz_stream
#define inflateInit(s)    mz_inflateInit(s)
#define inflate(s,f)      mz_inflate((s),(f))
#define inflateEnd(s)     mz_inflateEnd(s)
#define Z_OK              MZ_OK
#define Z_FINISH          MZ_FINISH
#define Z_BUF_ERROR       MZ_BUF_ERROR
#define Z_STREAM_END      MZ_STREAM_END

/* ?
 * Anti-dump / Anti-Frida -- constants & types
 * ? */

#define MAX_LINE   512
#define MAX_LENGTH 256
#define MAX_SZ     (80 * 1024 * 1024)

static const char *APPNAME                    = "YahyaVM_AntiFrida";
static const char *FRIDA_THREAD_GUM_JS_LOOP   = "gum-js-loop";
static const char *FRIDA_THREAD_GMAIN         = "gmain";
static const char *FRIDA_NAMEDPIPE_LINJECTOR  = "linjector";
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

/* ?
 * Inline string helpers (avoid libc hooks)
 * ? */

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

/* ?
 * Raw syscall wrappers (bypass libc -- Frida hooks libc)
 * ? */

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

#else  /* armeabi-v7a -- use libc syscall() wrapper */

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

#endif  /* ABI */

/* ?
 * Low-level I/O helpers
 * ? */

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

/* ?
 * ELF section checksum helpers (Frida mem/disk compare)
 * ? */

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

/* ?
 * Kill switch
 * ? */

static inline void nuke_app(void) {
    volatile int *trap = NULL;
    *trap = 0xDEAD;
}

/* ?
 * Original anti-Frida detection functions (unchanged)
 * ? */

static inline void detect_ptrace(void) {
    char buf[512];
    int fd = my_openat(AT_FDCWD, "/proc/self/status", O_RDONLY | O_CLOEXEC, 0);
    if (fd >= 0) {
        ssize_t bytes = my_read(fd, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = '\0';
            char *tracer = my_strstr(buf, "TracerPid:");
            if (tracer) {
                int pid = atoi(tracer + 10);
                if (pid > 0) { my_close(fd); nuke_app(); }
            }
        }
        my_close(fd);
    }
}

static inline void detect_frida_anonymous_memory(void) {
    char map[512];
    int fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    while (read_one_line(fd, map, sizeof(map)) > 0) {
        if (my_strstr(map, "r-xp") != NULL) {
            if (my_strstr(map, "/") == NULL || my_strstr(map, "memfd:") != NULL) {
                my_close(fd); nuke_app();
            }
        }
    }
    my_close(fd);
}

static inline void detect_frida_memdiskcompare(void) {
    int fd = my_openat(AT_FDCWD, PROC_MAPS, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return;
    char map[MAX_LINE];
    while ((read_one_line(fd, map, MAX_LINE)) > 0) {
        for (int i = 0; i < NUM_LIBS; i++) {
            if (my_strstr(map, libstocheck[i]) != NULL) {
                scan_executable_segments(map, elfSectionArr[i]);
                break;
            }
        }
    }
    my_close(fd);
}

static inline void detect_frida_threads(void) {
    DIR *dir = opendir(PROC_TASK);
    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            char filePath[MAX_LENGTH] = "";
            if (my_strcmp(entry->d_name, ".") == 0 ||
                my_strcmp(entry->d_name, "..") == 0) continue;
            snprintf(filePath, sizeof(filePath), PROC_STATUS, entry->d_name);
            int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            if (fd >= 0) {
                char buf[MAX_LENGTH] = "";
                read_one_line(fd, buf, MAX_LENGTH);
                if (my_strstr(buf, FRIDA_THREAD_GUM_JS_LOOP) ||
                    my_strstr(buf, FRIDA_THREAD_GMAIN)) {
                    my_close(fd); closedir(dir); nuke_app();
                }
                my_close(fd);
            }
        }
        closedir(dir);
    }
}

static inline void detect_frida_namedpipe(void) {
    DIR *dir = opendir(PROC_FD);
    if (dir != NULL) {
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
                    closedir(dir); nuke_app();
                }
            }
        }
    }
    closedir(dir);
}

/* ?
 * LAYER 1 -- detect_mem_reader()
 *
 * Scans every process's open file-descriptor table (/proc/<PID>/fd/).
 * If any external process has /proc/<OUR_PID>/mem OR /proc/<OUR_PID>/maps
 * open (which dump_dex_mem.py v9 and all /proc/PID/mem-based dumpers MUST
 * do), the readlink of that fd will resolve to our mem/maps path.
 * Detection -> nuke_app() immediately, before a single byte is dumped.
 * ? */

static void detect_mem_reader(void) {
    pid_t our_pid = getpid();

    /* Build the target strings we're looking for in other processes' fds. */
    char our_mem[64]  = "";
    char our_maps[64] = "";
    snprintf(our_mem,  sizeof(our_mem),  "/proc/%d/mem",  our_pid);
    snprintf(our_maps, sizeof(our_maps), "/proc/%d/maps", our_pid);

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent *pid_ent;
    while ((pid_ent = readdir(proc_dir)) != NULL) {
        /* Only numeric entries are PIDs. */
        const char *dname = pid_ent->d_name;
        if (!isdigit((unsigned char)dname[0])) continue;

        /* Skip our own process. */
        if (atoi(dname) == our_pid) continue;

        /* Open /proc/<OTHER_PID>/fd/ */
        char fd_dir_path[MAX_LENGTH] = "";
        snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%s/fd", dname);

        DIR *fd_dir = opendir(fd_dir_path);
        if (!fd_dir) continue;   /* no permission -- skip silently */

        struct dirent *fd_ent;
        while ((fd_ent = readdir(fd_dir)) != NULL) {
            if (!isdigit((unsigned char)fd_ent->d_name[0])) continue;

            char fd_link[MAX_LENGTH] = "";
            snprintf(fd_link, sizeof(fd_link),
                     "/proc/%s/fd/%s", dname, fd_ent->d_name);

            char target[MAX_LENGTH] = "";
            my_readlinkat(AT_FDCWD, fd_link, target, sizeof(target) - 1);

            if (my_strstr(target, our_mem)  != NULL ||
                my_strstr(target, our_maps) != NULL) {
                closedir(fd_dir);
                closedir(proc_dir);
                nuke_app();   /* dumper caught -- kill immediately */
            }
        }
        closedir(fd_dir);
    }
    closedir(proc_dir);
}

/* ?
 * LAYER 2b -- self_scan_and_poison_dex()
 *
 * Reads our own /proc/self/maps and finds every readable anonymous region
 * (no backing file, or [anon:dalvik-*]) that begins with the DEX magic
 * bytes (dex\n = 0x64 0x65 0x78 0x0a) AND has a valid endian_tag
 * (0x12345678) at offset 40.
 *
 * For each such region we:
 *   1. Temporarily elevate the page's protection to PROT_READ|PROT_WRITE
 *      using mprotect().
 *   2. Overwrite the first 8 bytes (magic + version string) with zeros.
 *   3. Restore the original page protection.
 *
 * This poisons the dex\n header that dump_dex_mem.py searches for,
 * making the scanner skip the region even when reading via /proc/PID/mem.
 * ART has already fully parsed the DEX at load time and does not re-read
 * the magic or version from the original buffer afterwards.
 *
 * Called from the background thread every 5 s, AFTER Layer 2a
 * (nativeWipeShard) has already zeroed the Java byte[] source.
 * ? */

static void self_scan_and_poison_dex(void) {
    int maps_fd = my_openat(AT_FDCWD, "/proc/self/maps", O_RDONLY | O_CLOEXEC, 0);
    if (maps_fd < 0) return;

    /* Open our own mem file for reading to safely check region headers. */
    int mem_fd = my_openat(AT_FDCWD, "/proc/self/mem", O_RDONLY | O_CLOEXEC, 0);
    if (mem_fd < 0) { my_close(maps_fd); return; }

    char line[MAX_LINE];
    while (read_one_line(maps_fd, line, MAX_LINE) > 0) {
        unsigned long start = 0, end = 0;
        char perm[8]        = "";
        char path[MAX_LENGTH] = "";
        char tmp[MAX_LENGTH]  = "";

        /* Parse map line: addr-addr perm offset dev inode [path] */
        int fields = sscanf(line, "%lx-%lx %4s %s %s %s %255s",
                            &start, &end, perm, tmp, tmp, tmp, path);
        if (fields < 3) continue;

        /* Must be readable. */
        if (perm[0] != 'r') continue;

        /* Skip write+execute (JIT code), and system libraries/framework. */
        if (perm[1] == 'w' && perm[2] == 'x') continue;
        if (fields >= 7) {
            if (my_strstr(path, "/system/")  != NULL) continue;
            if (my_strstr(path, "/vendor/")  != NULL) continue;
            if (my_strstr(path, "/apex/")    != NULL) continue;
            if (my_strstr(path, ".oat")      != NULL) continue;
            if (my_strstr(path, ".vdex")     != NULL) continue;
            if (my_strstr(path, ".art")      != NULL) continue;
            if (my_strstr(path, ".odex")     != NULL) continue;
            /* Only target anonymous or dalvik-labelled regions. */
            if (path[0] != '\0'
                && my_strstr(path, "dalvik") == NULL
                && my_strstr(path, "anon")   == NULL) continue;
        }

        size_t region_size = end - start;
        if (region_size < 112 || region_size > MAX_SZ) continue;

        /* Read first 44 bytes of the region safely via /proc/self/mem. */
        uint8_t hdr[44];
        my_lseek(mem_fd, (off_t)start, SEEK_SET);
        ssize_t n = my_read(mem_fd, hdr, sizeof(hdr));
        if (n < 44) continue;

        /* Check DEX magic: 'dex\n' */
        if (hdr[0] != 'd' || hdr[1] != 'e' || hdr[2] != 'x' || hdr[3] != '\n') continue;

        /* Validate endian tag at offset 40 = 0x12345678 (little-endian). */
        uint32_t endian_tag = (uint32_t)hdr[40]
                            | ((uint32_t)hdr[41] << 8)
                            | ((uint32_t)hdr[42] << 16)
                            | ((uint32_t)hdr[43] << 24);
        if (endian_tag != 0x12345678) continue;

        /* ? Found live DEX magic -- poison it. ?
         * Temporarily make the page writable, zero the magic + version
         * bytes, then restore original protection. */
        long page_size   = 4096;
        unsigned long ps = (unsigned long)page_size;
        unsigned long page_start = start & ~(ps - 1);

        /* Build original prot flags from the perm string. */
        int orig_prot = PROT_READ;
        if (perm[1] == 'w') orig_prot |= PROT_WRITE;
        if (perm[2] == 'x') orig_prot |= PROT_EXEC;

        int mp_ret = my_mprotect((void *)page_start, ps, PROT_READ | PROT_WRITE);
        if (mp_ret == 0) {
            /* Overwrite magic (dex\n) and version string (8 bytes total). */
            volatile uint8_t *ptr = (volatile uint8_t *)start;
            ptr[0] = 0x00; ptr[1] = 0x00; ptr[2] = 0x00; ptr[3] = 0x00;
            ptr[4] = 0x00; ptr[5] = 0x00; ptr[6] = 0x00; ptr[7] = 0x00;
            /* Also zero the endian_tag at offset 40 to break the validator. */
            ptr[40] = 0x00; ptr[41] = 0x00; ptr[42] = 0x00; ptr[43] = 0x00;

            /* Restore original protection. */
            my_mprotect((void *)page_start, ps, orig_prot);
        }
    }

    my_close(mem_fd);
    my_close(maps_fd);
}

/* ?
 * Background loop -- runs all layers every 5 seconds
 * ? */

static void *detect_frida_loop(void *args) {
    struct timespec timereq;
    timereq.tv_sec  = 5;
    timereq.tv_nsec = 0;
    while (1) {
        /* Original detections */
        detect_frida_threads();
        detect_frida_namedpipe();
        detect_frida_memdiskcompare();
        detect_ptrace();
        detect_frida_anonymous_memory();

        /* LAYER 1 -- catch any process that has our /proc/PID/mem open */
        detect_mem_reader();

        /* LAYER 2b -- hunt and poison any live DEX magic in our address space */
        self_scan_and_poison_dex();

        my_nanosleep(&timereq, NULL);
    }
    return NULL;
}

/* ?
 * Constructor -- runs immediately on System.load(libphantom.so)
 * ? */

__attribute__((constructor))
void detect_frida_init(void) {
    char *filePaths[NUM_LIBS] = {NULL, NULL};
    parse_proc_maps_to_fetch_path(filePaths);
    for (int i = 0; i < NUM_LIBS; i++) {
        if (filePaths[i]) {
            fetch_checksum_of_library(filePaths[i], &elfSectionArr[i]);
            free(filePaths[i]);
        }
    }
    pthread_t t;
    pthread_create(&t, NULL, detect_frida_loop, NULL);
}

/* ?
 * LAYER 2a -- nativeWipeShard()  [JNI -- called from DexProtector after load]
 *
 * Java calls this immediately after InMemoryDexClassLoader (or the file-
 * based fallback) has consumed the plaintext DEX byte[].  We zero the first
 * 8 bytes (dex\n magic + version string) and the endian_tag at offset 40
 * inside the Java byte[] so the heap copy no longer looks like a DEX to
 * any /proc/PID/mem scanner.
 *
 * ART has already fully parsed and mapped the DEX before this is called, so
 * zeroing the source byte[] does not affect class resolution.
 * ? */

JNIEXPORT void JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeWipeShard(
        JNIEnv    *env,
        jclass     clazz,
        jbyteArray j_dex)
{
    (void)clazz;
    if (!j_dex) return;
    jint len = (*env)->GetArrayLength(env, j_dex);
    if (len < 44) return;   /* need at least 44 bytes to reach the endian_tag */

    /* Zero: bytes 0-7 (magic + version) and bytes 40-43 (endian_tag). */
    static const jbyte zeros[44] = {0};

    /* Wipe magic + version (first 8 bytes). */
    (*env)->SetByteArrayRegion(env, j_dex, 0, 8, zeros);

    /* Wipe endian_tag (4 bytes at offset 40). */
    (*env)->SetByteArrayRegion(env, j_dex, 40, 4, zeros);
}

/* ?
 * SHA-256 (minimal, self-contained)
 * Hashes the package name inside native so the hash never returns to Java.
 * ? */

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

/* ?
 * ARX KDF -- byte-identical to DexSeed.arx() in Java
 * ? */

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

/* ?
 * ARX stream cipher -- port of Java DexCrypto.{exfr,FxIjsF,nDnv}
 * ? */

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

/* ?
 * zlib inflate helper
 * ? */

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

/* ?
 * nativeDecryptShard -- JNI entry-point
 *
 * Derives key + decrypts one shard entirely in native.
 * Pipeline reversal: outer inflate -> ARX XOR -> inner inflate -> plaintext DEX.
 * Key is zeroed on the stack before return; never crosses the JNI boundary.
 * ? */

JNIEXPORT jbyteArray JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard(
        JNIEnv    *env,
        jclass     clazz,
        jbyteArray j_salt,
        jbyteArray j_pkg_name_utf8,
        jbyteArray j_encrypted)
{
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

    /* 1. Derive key entirely inside native. */
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

    /* 2. Copy encrypted shard to native heap. */
    if (j_encrypted == NULL) goto cleanup;
    enc_len = (*env)->GetArrayLength(env, j_encrypted);
    if (enc_len <= 0) goto cleanup;
    enc_buf = (uint8_t *)malloc((size_t)enc_len);
    if (!enc_buf) goto cleanup;
    (*env)->GetByteArrayRegion(env, j_encrypted, 0, enc_len, (jbyte *)enc_buf);

    /* 3. Outer inflate. */
    inter_buf = inflate_alloc(enc_buf, (size_t)enc_len, &inter_len);
    free(enc_buf); enc_buf = NULL;
    if (!inter_buf) goto cleanup;

    /* 4. ARX XOR in-place. */
    { arx_ctx_t arx; arx_ctx_init(&arx, key); arx_xor(&arx, inter_buf, inter_len);
      memset(&arx, 0, sizeof(arx)); }

    /* 5. Inner inflate. */
    plain_buf = inflate_alloc(inter_buf, inter_len, &plain_len);
    if (!plain_buf) goto cleanup;

    /* 6. Return plaintext DEX bytes to Java. */
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
