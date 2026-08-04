/*
 * phantom_key.c — JNI entry-point for libphantom.so
 *
 * Exports:
 *   Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard
 *
 * Security model (mirrors 360 Jiagu's approach):
 *   The per-APK key is derived from (salt, sha256(pkg_name)) using the ARX KDF.
 *   The key NEVER crosses the JNI boundary to Java.  Instead this function
 *   performs the full pipeline in native:
 *
 *     1. Derive key = ARX_KDF(salt, sha256(pkg_name))
 *     2. Outer inflate  :  stored_bytes  → ARX_XOR(deflate(DEX))
 *     3. ARX XOR        :  ARX_XOR(deflate(DEX)) → deflate(DEX)
 *     4. Inner inflate  :  deflate(DEX) → plaintext DEX bytes
 *     5. Return the plaintext DEX as a jbyteArray
 *
 *   Java receives one decrypted DEX shard per call.  The key is zeroed
 *   on the stack before the function returns.  There is no Java-visible
 *   byte[] containing the key at any point.
 *
 * Shard storage format (written by DexPacker / DexCrypto.encrypt on host):
 *   deflate( ARX_XOR( deflate(plaintext_DEX) ) )
 *
 * Build requirements:
 *   • Compile with OLLVM (see phantom/CMakeLists.txt).
 *   • Target ABIs: arm64-v8a and armeabi-v7a.
 *   • After building, ARX-encrypt each .so with the blob key in
 *     DexCrypto.blobKey() and store as:
 *       assets/phantom/libphantom_arm64.blob
 *       assets/phantom/libphantom_arm.blob
 *
 * IMPORTANT: Do NOT compile on Replit.  Use the CI build with OLLVM toolchain.
 *            See phantom/CMakeLists.txt for the full build recipe.
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

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

/* ── ARX KDF — must stay byte-identical with DexSeed.arx() in Java ────── */

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

static void arx_kdf(const uint8_t salt[16],
                    const uint8_t pkg_hash[32],
                    uint8_t out[16])
{
    uint32_t s0 = le32(salt,  0);
    uint32_t s1 = le32(salt,  4);
    uint32_t s2 = le32(salt,  8);
    uint32_t s3 = le32(salt, 12);

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

/* ── ARX stream cipher — port of Java DexCrypto.{exfr,FxIjsF,nDnv} ─────────
 *
 * Key schedule (FxIjsF):
 *   Produces a 27-word array from the four key words {k0,k1,k2,k3}.
 *   ks[0] = k0; then for i2=0..25:
 *     t[i2%3] = (ROR8(t[i2%3]) + prev_i) ^ i2
 *     i       = ROL3(i) ^ t[i2%3]
 *     ks[i2+1] = i
 *
 * Initial keystream state (iArr2 in Java):
 *   state[0] = k0 ^ k2,  state[1] = k1 ^ k3
 *   (computed from the ORIGINAL key words, before the schedule runs)
 *
 * Each 8-byte output block is produced by nDnv:
 *   26 full rounds  : i2 = (ROR8(i2)+i)^ks[n]; i = ROL3(i)^i2;
 *    1 partial round: i2 = (ROR8(i2)+i)^ks[26];
 *   state[0] = ROL3(i)^i2;  state[1] = i2;
 *
 * Keystream bytes from 8-byte block: LE bytes of state[0] then state[1].
 */

typedef struct {
    uint32_t ks[27];   /* key schedule */
    uint32_t st[2];    /* current 8-byte keystream block */
    int      pos;      /* global byte counter (mod 8 triggers nDnv) */
} arx_ctx_t;

static void arx_ctx_init(arx_ctx_t *s, const uint8_t key[16])
{
    uint32_t k0 = le32(key, 0);
    uint32_t k1 = le32(key, 4);
    uint32_t k2 = le32(key, 8);
    uint32_t k3 = le32(key, 12);

    /* Initial keystream block — from original key words */
    s->st[0] = k0 ^ k2;
    s->st[1] = k1 ^ k3;
    s->pos   = 0;

    /* Key schedule */
    {
        int i2;
        uint32_t iv = k0;
        uint32_t t[3];
        t[0] = k1; t[1] = k2; t[2] = k3;
        s->ks[0] = iv;
        for (i2 = 0; i2 < 26; i2++) {
            t[i2 % 3] = (ROR32(t[i2 % 3], 8) + iv) ^ (uint32_t)i2;
            iv         = ROL32(iv, 3) ^ t[i2 % 3];
            s->ks[i2 + 1] = iv;
        }
    }
}

static void arx_advance_block(arx_ctx_t *s)
{
    const uint32_t *ks = s->ks;
    uint32_t i = s->st[0], i2 = s->st[1];
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
    s->st[0] = ROL32(i,3)^i2;
    s->st[1] = i2;
}

/* XOR buf[0..len) in-place with the ARX keystream.  Maintains position
 * across multiple calls so the keystream advances correctly across shards. */
static void arx_xor(arx_ctx_t *s, uint8_t *buf, size_t len)
{
    size_t n;
    for (n = 0; n < len; n++) {
        int i6    = s->pos % 8;
        int word  = (int)s->st[i6 >> 2];          /* i6/4: word 0 for 0-3, word 1 for 4-7 */
        int shift = (s->pos % 4) * 8;              /* LE byte extraction */
        if (i6 == 0) arx_advance_block(s);         /* matches Java: advance THEN read */
        word  = (int)s->st[i6 >> 2];
        buf[n] ^= (uint8_t)(word >> shift);
        s->pos++;
    }
}

/* ── zlib inflate helper ─────────────────────────────────────────────────────
 *
 * Decompresses a zlib-wrapped deflate stream (as produced by Java's
 * DeflaterOutputStream / DeflaterInputStream defaults) into a freshly
 * malloc'd buffer.  Caller must free() the result.
 * Returns NULL on error; sets *out_len on success.
 */
static uint8_t *inflate_alloc(const uint8_t *in, size_t in_len, size_t *out_len)
{
    z_stream zs;
    size_t   cap, used;
    uint8_t *buf, *tmp;
    int      ret;

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
        if (ret != Z_OK && ret != Z_BUF_ERROR) {
            free(buf); inflateEnd(&zs); return NULL;
        }
        /* Output buffer full — double it */
        used    = cap - zs.avail_out;
        cap    *= 2;
        tmp     = (uint8_t *)realloc(buf, cap);
        if (!tmp) { free(buf); inflateEnd(&zs); return NULL; }
        buf              = tmp;
        zs.next_out      = (Bytef *)(buf + used);
        zs.avail_out     = (uInt)(cap - used);
    }

    *out_len = cap - zs.avail_out;
    inflateEnd(&zs);
    return buf;
}

/* ── JNI entry-point ─────────────────────────────────────────────────────────
 *
 * Fully decrypts one encrypted DEX shard and returns the plaintext DEX bytes.
 * The derived key NEVER leaves this function — it lives only on the C stack
 * and is zeroed before return.
 *
 * Pipeline (mirrors DexCrypto.encrypt on the host packer side):
 *   stored_shard = deflate( ARX_XOR( deflate(plaintext_DEX) ) )
 *
 * Reversal here:
 *   step 1 — outer inflate  : stored_shard          → ARX_XOR(deflate(DEX))
 *   step 2 — ARX XOR        : ARX_XOR(deflate(DEX)) → deflate(DEX)
 *   step 3 — inner inflate  : deflate(DEX)           → plaintext DEX
 */
JNIEXPORT jbyteArray JNICALL
Java_com_ultra_dex2cvmp_utils_DexCrypto_nativeDecryptShard(
        JNIEnv    *env,
        jclass     clazz,
        jbyteArray j_salt,
        jbyteArray j_pkg_name_utf8,
        jbyteArray j_encrypted)
{
    jbyteArray result = NULL;

    /* Stack secrets — all zeroed before return */
    uint8_t salt[16]     = {0};
    uint8_t pkg_hash[32] = {0};
    uint8_t key[16]      = {0};

    /* Heap buffers */
    uint8_t *enc_buf   = NULL;
    uint8_t *inter_buf = NULL;   /* after outer inflate */
    uint8_t *plain_buf = NULL;   /* after inner inflate = DEX */
    size_t   inter_len = 0;
    size_t   plain_len = 0;
    jint     enc_len   = 0;

    (void)clazz;

    /* ── 1. Derive key entirely inside native ───────────────────────────── */
    if (j_salt == NULL || (*env)->GetArrayLength(env, j_salt) != 16)
        goto cleanup;
    (*env)->GetByteArrayRegion(env, j_salt, 0, 16, (jbyte *)salt);

    if (j_pkg_name_utf8 != NULL) {
        jint pkg_len = (*env)->GetArrayLength(env, j_pkg_name_utf8);
        if (pkg_len > 0 && pkg_len <= 512) {
            uint8_t pkg_buf[512];
            (*env)->GetByteArrayRegion(env, j_pkg_name_utf8, 0, pkg_len,
                                        (jbyte *)pkg_buf);
            sha256(pkg_buf, (size_t)pkg_len, pkg_hash);
            memset(pkg_buf, 0, sizeof(pkg_buf));
        }
    }
    arx_kdf(salt, pkg_hash, key);

    /* ── 2. Copy encrypted shard to native heap ─────────────────────────── */
    if (j_encrypted == NULL) goto cleanup;
    enc_len = (*env)->GetArrayLength(env, j_encrypted);
    if (enc_len <= 0) goto cleanup;

    enc_buf = (uint8_t *)malloc((size_t)enc_len);
    if (!enc_buf) goto cleanup;
    (*env)->GetByteArrayRegion(env, j_encrypted, 0, enc_len, (jbyte *)enc_buf);

    /* ── 3. Outer inflate ───────────────────────────────────────────────── */
    inter_buf = inflate_alloc(enc_buf, (size_t)enc_len, &inter_len);
    free(enc_buf); enc_buf = NULL;
    if (!inter_buf) goto cleanup;

    /* ── 4. ARX XOR in-place (key stays on native stack) ───────────────── */
    {
        arx_ctx_t arx;
        arx_ctx_init(&arx, key);
        arx_xor(&arx, inter_buf, inter_len);
        memset(&arx, 0, sizeof(arx));   /* zero keystream state */
    }

    /* ── 5. Inner inflate ───────────────────────────────────────────────── */
    plain_buf = inflate_alloc(inter_buf, inter_len, &plain_len);
    if (!plain_buf) goto cleanup;

    /* ── 6. Hand DEX bytes back to Java ─────────────────────────────────── */
    result = (*env)->NewByteArray(env, (jsize)plain_len);
    if (result)
        (*env)->SetByteArrayRegion(env, result, 0, (jsize)plain_len,
                                   (jbyte *)plain_buf);

cleanup:
    /* Zero all key material before returning */
    memset(salt,     0, sizeof(salt));
    memset(pkg_hash, 0, sizeof(pkg_hash));
    memset(key,      0, sizeof(key));
    if (enc_buf)   free(enc_buf);
    if (inter_buf) { memset(inter_buf, 0, inter_len); free(inter_buf); }
    if (plain_buf) free(plain_buf);
    return result;
}
