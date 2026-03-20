#!/usr/bin/env python3
"""
CBE Dart Snapshot Armor
  1. Find Dart snapshot magic + features in libapp.so
  2. XOR-encrypt the features with KA_TG||KB_TG key
  3. Zero features + selectively XOR PT_DYNAMIC entries
  4. Compile libcbe_armor.so  (JNI_OnLoad + pthread runtime patcher)
  5. patchelf: add DT_NEEDED(libcbe_armor.so) to libapp.so
  6. Repack APK (strip old signature; signing done by the next step)
"""
import sys, os, struct, subprocess, zipfile, glob, shutil, re, copy

# ─── Config ──────────────────────────────────────────────────────────────────
XOR_KEY    = bytes([0x4D,0x58,0x24,0x39,0x6B,0x23,0x50,0x32,
                    0x6E,0x56,0x37,0x71,0x4C,0x35,0x72,0x54])  # KA_TG||KB_TG
SNAP_MAGIC = bytes([0xf5,0xf5,0xdc,0xdc])
FEAT_OFF   = 0x10          # features string starts at magic+16
ARMOR_LIB  = "libcbe_armor.so"
KEEP_TAGS  = {0,1,5,10}   # DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ

def xor_key(data, key, key_len=16):
    return bytes(b ^ key[i % key_len] for i,b in enumerate(data))

def vaddr_to_foff(data, va):
    e_phoff     = struct.unpack_from('<Q', data, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', data, 0x36)[0]
    e_phnum     = struct.unpack_from('<H', data, 0x38)[0]
    for i in range(e_phnum):
        off = e_phoff + i*e_phentsize
        if struct.unpack_from('<I', data, off)[0] != 1: continue   # PT_LOAD
        p_offset = struct.unpack_from('<Q', data, off+8)[0]
        p_vaddr  = struct.unpack_from('<Q', data, off+16)[0]
        p_filesz = struct.unpack_from('<Q', data, off+32)[0]
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None

def main():
    apk_path = sys.argv[1]
    print("=== CBE Snapshot Armor ===")

    # ── Extract libapp.so ─────────────────────────────────────────────────────
    with zipfile.ZipFile(apk_path,'r') as zf:
        if 'lib/arm64-v8a/libapp.so' not in zf.namelist():
            print("INFO: lib/arm64-v8a/libapp.so not in APK – not a Flutter AOT release; skipping.")
            sys.exit(0)
        libapp = bytearray(zf.read('lib/arm64-v8a/libapp.so'))
    print(f"libapp.so extracted: {len(libapp):,} bytes")

    # ── Find snapshot magic ───────────────────────────────────────────────────
    magic_off = bytes(libapp).find(SNAP_MAGIC)
    if magic_off < 0:
        print("INFO: Dart snapshot magic not found – possibly merged snapshot; skipping.")
        sys.exit(0)
    print(f"Snapshot magic @ 0x{magic_off:x}")

    # ── Read features string ──────────────────────────────────────────────────
    feat_start = magic_off + FEAT_OFF
    feat_end   = feat_start
    for i in range(feat_start, min(feat_start+512, len(libapp))):
        feat_end = i+1
        if libapp[i] == 0:
            break
    feat_bytes = bytes(libapp[feat_start:feat_end])
    feat_str   = feat_bytes[:-1].decode('ascii','replace')
    print(f"Features ({len(feat_bytes)}B): {feat_str!r}")

    # Pad to 16-byte multiple for clean XOR storage
    padded_len = (len(feat_bytes) + 15) & ~15
    feat_padded = feat_bytes + b'\x00' * (padded_len - len(feat_bytes))

    # ── XOR-encrypt features ──────────────────────────────────────────────────
    encrypted = xor_key(feat_padded, XOR_KEY)
    print(f"Encrypted payload: {padded_len} bytes")

    # ── Zero features in libapp ───────────────────────────────────────────────
    for i in range(feat_start, feat_start + padded_len):
        if i < len(libapp):
            libapp[i] = 0
    print("Features zeroed in libapp.so")

    # ── Selectively scramble PT_DYNAMIC ──────────────────────────────────────
    e_phoff     = struct.unpack_from('<Q', libapp, 0x20)[0]
    e_phentsize = struct.unpack_from('<H', libapp, 0x36)[0]
    e_phnum     = struct.unpack_from('<H', libapp, 0x38)[0]
    dyn_foff = dyn_filesz = 0
    for i in range(e_phnum):
        hdr = e_phoff + i*e_phentsize
        if struct.unpack_from('<I', libapp, hdr)[0] == 2:  # PT_DYNAMIC
            dyn_foff  = struct.unpack_from('<Q', libapp, hdr+8)[0]
            dyn_filesz= struct.unpack_from('<Q', libapp, hdr+32)[0]
            break
    scrambled = 0
    if dyn_foff and dyn_filesz:
        for j in range(dyn_filesz // 16):
            tag = struct.unpack_from('<Q', libapp, dyn_foff + j*16)[0]
            if tag not in KEEP_TAGS:
                for k in range(16):
                    idx = dyn_foff + j*16 + k
                    if idx < len(libapp):
                        libapp[idx] ^= XOR_KEY[(j*16+k) % len(XOR_KEY)]
                scrambled += 1
            if tag == 0:
                break
    print(f"PT_DYNAMIC: {scrambled} entries scrambled (DT_NEEDED/STRTAB/STRSZ/NULL preserved)")

    # ── Generate C source for armor library ───────────────────────────────────
    c_arr = ','.join(f'0x{b:02x}' for b in encrypted)
    c_src = f'''\
#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <time.h>

static const uint8_t _k[16]={{0x4D,0x58,0x24,0x39,0x6B,0x23,0x50,0x32,0x6E,0x56,0x37,0x71,0x4C,0x35,0x72,0x54}};
static const uint8_t _e[{padded_len}]={{{c_arr}}};
static const uint32_t _magic=0xdcdcf5f5U;  /* LE bytes: f5 f5 dc dc */

static void *_armor(void *a){{
    (void)a;
    struct timespec ts={{0,1000000}};  /* 1ms poll */
    for(int att=0;att<5000;att++){{
        nanosleep(&ts,NULL);
        FILE*fp=fopen("/proc/self/maps","r");
        if(!fp)continue;
        char line[512];
        int patched=0;
        while(fgets(line,sizeof(line),fp)){{
            if(!strstr(line,"libapp.so"))continue;
            unsigned long s,e; char pr[8]={{0}};
            if(sscanf(line,"%lx-%lx %4s",&s,&e,pr)!=3||pr[0]!='r')continue;
            uint8_t*base=(uint8_t*)s;
            uintptr_t sz=e-s;
            for(uintptr_t k=0;k+4<=sz;k+=4){{
                if(*(uint32_t*)(base+k)!=_magic)continue;
                uint8_t*feat=base+k+0x10;
                long pg=sysconf(_SC_PAGESIZE);
                uintptr_t ps=((uintptr_t)feat)&~(uintptr_t)(pg-1);
                if(mprotect((void*)ps,(size_t)(pg*2),PROT_READ|PROT_WRITE)!=0)break;
                for(int i=0;i<{padded_len};i++) feat[i]=_e[i]^_k[i&15];
                mprotect((void*)ps,(size_t)(pg*2),PROT_READ);
                patched=1; break;
            }}
        }}
        fclose(fp);
        if(patched)return NULL;
    }}
    return NULL;
}}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*vm,void*r){{
    (void)vm;(void)r;
    pthread_t tid;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at,PTHREAD_CREATE_DETACHED);
    pthread_create(&tid,&at,_armor,NULL);
    pthread_attr_destroy(&at);
    return JNI_VERSION_1_6;
}}
'''
    with open('/tmp/cbe_armor.c','w') as f:
        f.write(c_src)
    print("Generated /tmp/cbe_armor.c")

    # ── Find NDK clang ────────────────────────────────────────────────────────
    ndk_home = os.environ.get('ANDROID_NDK_HOME','') or os.environ.get('NDK_HOME','')
    if not ndk_home:
        for d in sorted(glob.glob('/usr/local/lib/android/sdk/ndk/*'), reverse=True):
            if os.path.isdir(d): ndk_home=d; break
    clang = None
    if ndk_home:
        clangs=[c for c in glob.glob(os.path.join(ndk_home,'toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android*-clang')) if '++' not in c]
        if clangs: clang=sorted(clangs)[-1]
    if not clang:
        print("WARNING: NDK clang not found – skipping armor compilation")
        sys.exit(0)
    print(f"NDK clang: {clang}")

    # ── Compile libcbe_armor.so ───────────────────────────────────────────────
    ret=subprocess.run([clang,'-shared','-fPIC','-O2','-fvisibility=hidden',
                        '-o',f'/tmp/{ARMOR_LIB}','/tmp/cbe_armor.c','-llog'],
                       capture_output=True,text=True)
    if ret.returncode!=0:
        print(f"Compile FAILED:\n{ret.stderr}")
        sys.exit(1)
    print(f"Compiled /tmp/{ARMOR_LIB}  ({os.path.getsize('/tmp/'+ARMOR_LIB):,} bytes)")

    # ── Save modified libapp.so ───────────────────────────────────────────────
    libapp_path='/tmp/libapp_armored.so'
    with open(libapp_path,'wb') as f:
        f.write(libapp)

    # ── Add DT_NEEDED via patchelf ────────────────────────────────────────────
    patchelf_ok=False
    pe=shutil.which('patchelf')
    if pe:
        r=subprocess.run([pe,'--add-needed',ARMOR_LIB,libapp_path],
                         capture_output=True,text=True)
        if r.returncode==0:
            patchelf_ok=True
            print(f"patchelf: DT_NEEDED({ARMOR_LIB}) added to libapp.so")
        else:
            print(f"patchelf failed: {r.stderr.strip()[:120]}")
    else:
        print("patchelf not found in PATH")
    if not patchelf_ok:
        print("WARNING: DT_NEEDED not added; armor library won't auto-load. "
              "Restoring original features to prevent crash.")
        # Restore features so app doesn't crash without patcher
        libapp_path=None   # signal to skip armor-lib injection
        with open('/tmp/libapp_armored.so','wb') as f:
            f.write(libapp)
        # Re-read original to restore features
        with zipfile.ZipFile(apk_path,'r') as zf:
            original=zf.read('lib/arm64-v8a/libapp.so')
        with open('/tmp/libapp_armored.so','wb') as f:
            f.write(original)

    # ── Repack APK ────────────────────────────────────────────────────────────
    tmp_apk=apk_path+'.armor_tmp'
    armor_bytes=None
    if libapp_path and os.path.exists(f'/tmp/{ARMOR_LIB}'):
        with open(f'/tmp/{ARMOR_LIB}','rb') as f:
            armor_bytes=f.read()
    with open('/tmp/libapp_armored.so','rb') as f:
        new_libapp=f.read()

    with zipfile.ZipFile(apk_path,'r') as zin:
        with zipfile.ZipFile(tmp_apk,'w') as zout:
            for item in zin.infolist():
                if item.filename.startswith('META-INF/'):
                    continue              # drop old signature
                data=zin.read(item.filename)
                if item.filename=='lib/arm64-v8a/libapp.so':
                    data=new_libapp
                    print(f"  ↳ replaced lib/arm64-v8a/libapp.so")
                # Preserve original ZipInfo metadata (extra, permissions, etc.)
                # Only override compress_type for .so files (must be uncompressed)
                out_info = copy.copy(item)
                if item.filename.endswith('.so'):
                    out_info.compress_type = zipfile.ZIP_STORED
                zout.writestr(out_info, data)
            if armor_bytes:
                armor_info = zipfile.ZipInfo(filename=f'lib/arm64-v8a/{ARMOR_LIB}')
                armor_info.compress_type = zipfile.ZIP_STORED
                armor_info.external_attr = 0o100644 << 16  # rw-r--r--
                zout.writestr(armor_info, armor_bytes)
                print(f"  ↳ added lib/arm64-v8a/{ARMOR_LIB}")

    os.replace(tmp_apk,apk_path)
    print(f"APK repacked → {apk_path}")
    print("Snapshot armor DONE ✓")

if __name__=='__main__':
    main()
