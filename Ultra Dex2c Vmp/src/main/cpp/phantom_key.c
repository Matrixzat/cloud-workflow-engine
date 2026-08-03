/*
 * phantom_key.c — JNI entry-point for libphantom.so
 *
 * Exports:
 *   Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeGetKey
 *
 * The per-APK DEX decryption key is derived from two inputs:
 *
 *   key = ARX_KDF(salt[16], sha256(pkg_name)[0..7])
 *
 * The same ARX_KDF is implemented on the Java/host side in PhantomKey.java.
 * Cert binding is omitted — signature tamper detection is handled by the
 * app's own tamper check.
 *
 * Build requirements:
 *   • Compile with OLLVM (see phantom/CMakeLists.txt) for control-flow
 *     flattening + bogus-control-flow passes.
 *   • Target ABIs: arm64-v8a and armeabi-v7a.
 *   • After building, AES-encrypt each .so with the blob key defined in
 *     DexCrypto.blobKey() and store as:
 *       assets/phantom/libphantom_arm64.blob
 *       assets/phantom/libphantom_arm.blob
 *
 * IMPORTANT: Do NOT compile this file on Replit.  Use the CI build in the
 * dedicated GitHub repo with OLLVM toolchain support.  See phantom/CMakeLists.txt
 * for the full build recipe.
 */

#include <jni.h>
#include <stdint.h>
#include <string.h>

/* ── SHA-256 (minimal, self-contained) ──────────────────────────────────────
 * Used to hash the package name inside the native layer so the hashed value
 * is never returned to Java.
 */

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
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i*4]<<24)|((uint32_t)data[i*4+1]<<16)
              |((uint32_t)data[i*4+2]<<8)|(uint32_t)data[i*4+3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15],7)^ROR32(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = ROR32(w[i-2],17)^ROR32(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e,6)^ROR32(e,11)^ROR32(e,25);
        uint32_t ch = (e&f)^(~e&g);
        uint32_t tmp1 = hh+S1+ch+K256[i]+w[i];
        uint32_t S0 = ROR32(a,2)^ROR32(a,13)^ROR32(a,22);
        uint32_t maj = (a&b)^(a&c)^(b&c);
        uint32_t tmp2 = S0+maj;
        hh=g; g=f; f=e; e=d+tmp1;
        d=c; c=b; b=a; a=tmp1+tmp2;
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

    while (len >= 64) {
        sha256_block(h, msg);
        msg += 64; len -= 64;
    }
    /* padding */
    memset(block, 0, 64);
    memcpy(block, msg, len);
    block[len] = 0x80;
    if (len >= 56) {
        sha256_block(h, block);
        memset(block, 0, 64);
    }
    for (i = 0; i < 8; i++)
        block[56+i] = (uint8_t)(bit_len >> (56 - i*8));
    sha256_block(h, block);

    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(h[i]>>24);
        out[i*4+1] = (uint8_t)(h[i]>>16);
        out[i*4+2] = (uint8_t)(h[i]>>8);
        out[i*4+3] = (uint8_t)(h[i]);
    }
}

/* ── ARX KDF — must stay byte-identical with PhantomKey.arx() in Java ────── */

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static inline uint32_t le32(const uint8_t *b, int off) {
    return (uint32_t)b[off]
         | ((uint32_t)b[off+1] <<  8)
         | ((uint32_t)b[off+2] << 16)
         | ((uint32_t)b[off+3] << 24);
}

static inline void put_le32(uint8_t *b, int off, uint32_t v) {
    b[off]   = (uint8_t) v;
    b[off+1] = (uint8_t)(v >>  8);
    b[off+2] = (uint8_t)(v >> 16);
    b[off+3] = (uint8_t)(v >> 24);
}

/**
 * arx_kdf — derive a 16-byte key.
 *
 * @param salt      16-byte random salt (from assets/phantom/ph_salt).
 * @param pkg_hash  32-byte SHA-256 of the package name (first 8 bytes used).
 * @param out       16-byte output key.
 */
static void arx_kdf(const uint8_t salt[16],
                    const uint8_t pkg_hash[32],
                    uint8_t out[16])
{
    uint32_t s0 = le32(salt,  0);
    uint32_t s1 = le32(salt,  4);
    uint32_t s2 = le32(salt,  8);
    uint32_t s3 = le32(salt, 12);

    /* Mix pkg hash: 8 rounds */
    int i;
    uint32_t ph0 = le32(pkg_hash, 0);
    uint32_t ph1 = le32(pkg_hash, 4);
    for (i = 0; i < 8; i++) {
        s0 = ROL32(s0 ^ ph0, 11) + s1;
        s1 = ROL32(s1 ^ ph1, 13) + s2;
        s2 = ROL32(s2 ^ ph0, 17) + s3;
        s3 = ROL32(s3 ^ ph1, 19) + s0;
    }

    put_le32(out,  0, s0);
    put_le32(out,  4, s1);
    put_le32(out,  8, s2);
    put_le32(out, 12, s3);
}

/* ── JNI entry-point ─────────────────────────────────────────────────────── */

JNIEXPORT jbyteArray JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeGetKey(
        JNIEnv *env,
        jclass  clazz,
        jbyteArray j_salt,
        jbyteArray j_pkg_name_utf8)
{
    (void)clazz;

    uint8_t salt[16]     = {0};
    uint8_t pkg_hash[32] = {0};
    uint8_t key[16]      = {0};

    /* --- salt (exactly 16 bytes) --- */
    if (j_salt == NULL || (*env)->GetArrayLength(env, j_salt) != 16) {
        goto done; /* return zeros — graceful failure */
    }
    (*env)->GetByteArrayRegion(env, j_salt, 0, 16, (jbyte *)salt);

    /* --- package name bytes → SHA-256 inside native --- */
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

done:;
    jbyteArray result = (*env)->NewByteArray(env, 16);
    if (result) (*env)->SetByteArrayRegion(env, result, 0, 16, (jbyte *)key);

    /* Zero stack secrets before returning. */
    memset(salt,     0, sizeof(salt));
    memset(pkg_hash, 0, sizeof(pkg_hash));
    memset(key,      0, sizeof(key));

    return result;
}
