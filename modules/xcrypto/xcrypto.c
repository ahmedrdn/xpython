#include <string.h>
#include "py/runtime.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "xcrypto.h"

#define XCRYPTO_VERSION "1.1.0"

// ---------- Platform: random source + hardware info ----------
// ---------- Random source: different for each platform ----------
#if defined(XCRYPTO_ESP32) || defined(ESP_PLATFORM) || __has_include("esp_random.h")
#include "esp_random.h"
#include "sdkconfig.h"
#define XC_PLATFORM CONFIG_IDF_TARGET
#define XC_HW_RNG 1
#if defined(CONFIG_MBEDTLS_HARDWARE_AES)
#define XC_HW_AES 1
#endif
#if defined(CONFIG_MBEDTLS_HARDWARE_SHA)
#define XC_HW_SHA 1
#endif
#if defined(CONFIG_MBEDTLS_HARDWARE_MPI)
#define XC_HW_MPI 1
#endif
void xc_fill_random(uint8_t *buf, size_t len) {
    esp_fill_random(buf, len);              // ESP32 hardware RNG
}
#elif defined(__unix__)
#include <errno.h>
#include <sys/random.h>
#define XC_PLATFORM "unix"
#define XC_HW_RNG 0
void xc_fill_random(uint8_t *buf, size_t len) {
    size_t done = 0;
    while (done < len) {                    // Linux kernel RNG
        ssize_t n = getrandom(buf + done, len - done, 0);
        if (n < 0) {
            mp_raise_OSError(errno);
        }
        done += n;
    }
}
#else
#error "xcrypto: no random source for this port yet"
#endif

// Anything not set above means "no hardware support"
#ifndef XC_HW_AES
#define XC_HW_AES 0
#endif
#ifndef XC_HW_SHA
#define XC_HW_SHA 0
#endif
#ifndef XC_HW_MPI
#define XC_HW_MPI 0
#endif

// ---------- Helpers (C only, Python never calls these) ----------
static void check_key(size_t len) {
    if (len != 16 && len != 24 && len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("key must be 16, 24 or 32 bytes"));
    }
}

static void check_iv(size_t len) {
    if (len != 12) {
        mp_raise_ValueError(MP_ERROR_TEXT("iv must be 12 bytes"));
    }
}

// ---------- version() ----------
static mp_obj_t xcrypto_version(void) {
    return mp_obj_new_str(XCRYPTO_VERSION, strlen(XCRYPTO_VERSION));
}
static MP_DEFINE_CONST_FUN_OBJ_0(xcrypto_version_obj, xcrypto_version);

// ---------- sha256(data) -> 32 bytes ----------
static mp_obj_t xcrypto_sha256(mp_obj_t data_in) {
    mp_buffer_info_t buf;
    mp_get_buffer_raise(data_in, &buf, MP_BUFFER_READ);
    uint8_t out[32];
    if (mbedtls_sha256(buf.buf, buf.len, out, 0) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("sha256 failed"));
    }
    return mp_obj_new_bytes(out, sizeof(out));
}
static MP_DEFINE_CONST_FUN_OBJ_1(xcrypto_sha256_obj, xcrypto_sha256);

// ---------- random(n) -> n random bytes ----------
static mp_obj_t xcrypto_random(mp_obj_t n_in) {
    mp_int_t n = mp_obj_get_int(n_in);
    if (n < 0 || n > 1024) {
        mp_raise_ValueError(MP_ERROR_TEXT("n must be 0..1024"));
    }
    vstr_t out;
    vstr_init_len(&out, n);
    xc_fill_random((uint8_t *)out.buf, n);
    return mp_obj_new_bytes_from_vstr(&out);
}
static MP_DEFINE_CONST_FUN_OBJ_1(xcrypto_random_obj, xcrypto_random);

// ---------- aes_gcm_encrypt(key, iv, data[, aad]) -> (ciphertext, tag) ----------
static mp_obj_t xcrypto_aes_gcm_encrypt(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t key, iv, data, aad = {0};
    mp_get_buffer_raise(args[0], &key, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &iv, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &data, MP_BUFFER_READ);
    if (n_args > 3) {
        mp_get_buffer_raise(args[3], &aad, MP_BUFFER_READ);
    }
    check_key(key.len);
    check_iv(iv.len);

    vstr_t ct;
    vstr_init_len(&ct, data.len);
    uint8_t tag[16];

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.buf, key.len * 8);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, data.len,
            iv.buf, iv.len, aad.buf, aad.len,
            data.buf, (uint8_t *)ct.buf, sizeof(tag), tag);
    }
    mbedtls_gcm_free(&gcm);                 // also wipes the key from memory
    if (ret != 0) {
        vstr_clear(&ct);
        mp_raise_ValueError(MP_ERROR_TEXT("encryption failed"));
    }

    mp_obj_t result[2] = {
        mp_obj_new_bytes_from_vstr(&ct),
        mp_obj_new_bytes(tag, sizeof(tag)),
    };
    return mp_obj_new_tuple(2, result);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(xcrypto_aes_gcm_encrypt_obj, 3, 4, xcrypto_aes_gcm_encrypt);

// ---------- aes_gcm_decrypt(key, iv, ciphertext, tag[, aad]) -> plaintext ----------
static mp_obj_t xcrypto_aes_gcm_decrypt(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t key, iv, ct, tag, aad = {0};
    mp_get_buffer_raise(args[0], &key, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &iv, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &ct, MP_BUFFER_READ);
    mp_get_buffer_raise(args[3], &tag, MP_BUFFER_READ);
    if (n_args > 4) {
        mp_get_buffer_raise(args[4], &aad, MP_BUFFER_READ);
    }
    check_key(key.len);
    check_iv(iv.len);
    if (tag.len != 16) {
        mp_raise_ValueError(MP_ERROR_TEXT("tag must be 16 bytes"));
    }

    vstr_t pt;
    vstr_init_len(&pt, ct.len);

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.buf, key.len * 8);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, ct.len,
            iv.buf, iv.len, aad.buf, aad.len,
            tag.buf, tag.len, ct.buf, (uint8_t *)pt.buf);
    }
    mbedtls_gcm_free(&gcm);
    if (ret != 0) {
        vstr_clear(&pt);                    // never return data that failed the check
        mp_raise_ValueError(MP_ERROR_TEXT("authentication failed"));
    }
    return mp_obj_new_bytes_from_vstr(&pt);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(xcrypto_aes_gcm_decrypt_obj, 4, 5, xcrypto_aes_gcm_decrypt);

// ---------- RNG callback that mbedTLS needs for key generation and signing ----------
static int xc_rng(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    xc_fill_random(buf, len);
    return 0;
}

// ---------- hmac_sha256(key, data) -> 32 bytes ----------
static mp_obj_t xcrypto_hmac_sha256(mp_obj_t key_in, mp_obj_t data_in) {
    mp_buffer_info_t key, data;
    mp_get_buffer_raise(key_in, &key, MP_BUFFER_READ);
    mp_get_buffer_raise(data_in, &data, MP_BUFFER_READ);
    uint8_t out[32];
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (mbedtls_md_hmac(md, key.buf, key.len, data.buf, data.len, out) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("hmac failed"));
    }
    return mp_obj_new_bytes(out, sizeof(out));
}
static MP_DEFINE_CONST_FUN_OBJ_2(xcrypto_hmac_sha256_obj, xcrypto_hmac_sha256);

// ---------- hkdf_sha256(ikm, salt, info, length) -> bytes  (RFC 5869) ----------
static mp_obj_t xcrypto_hkdf_sha256(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t ikm, salt, info;
    mp_get_buffer_raise(args[0], &ikm, MP_BUFFER_READ);
    mp_get_buffer_raise(args[1], &salt, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &info, MP_BUFFER_READ);
    mp_int_t len = mp_obj_get_int(args[3]);
    if (len < 1 || len > 255 * 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("length must be 1..8160"));
    }
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    // Step 1, extract: PRK = HMAC(salt, ikm). An empty salt means 32 zero bytes.
    uint8_t zero[32] = {0}, prk[32], t[32];
    const uint8_t *s = salt.len ? salt.buf : zero;
    size_t sl = salt.len ? salt.len : sizeof(zero);
    if (mbedtls_md_hmac(md, s, sl, ikm.buf, ikm.len, prk) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("hkdf failed"));
    }

    // Step 2, expand: T(i) = HMAC(PRK, T(i-1) | info | i), joined until long enough
    vstr_t out;
    vstr_init_len(&out, len);
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    int ret = mbedtls_md_setup(&ctx, md, 1);
    size_t done = 0;
    for (uint8_t i = 1; ret == 0 && done < (size_t)len; i++) {
        ret = mbedtls_md_hmac_starts(&ctx, prk, sizeof(prk));
        if (ret == 0 && i > 1) {
            ret = mbedtls_md_hmac_update(&ctx, t, sizeof(t));
        }
        if (ret == 0) {
            ret = mbedtls_md_hmac_update(&ctx, info.buf, info.len);
        }
        if (ret == 0) {
            ret = mbedtls_md_hmac_update(&ctx, &i, 1);
        }
        if (ret == 0) {
            ret = mbedtls_md_hmac_finish(&ctx, t);
        }
        size_t n = ((size_t)len - done < 32) ? (size_t)len - done : 32;
        memcpy(out.buf + done, t, n);
        done += n;
    }
    mbedtls_md_free(&ctx);
    memset(prk, 0, sizeof(prk));             // wipe secrets from the stack
    memset(t, 0, sizeof(t));
    if (ret != 0) {
        vstr_clear(&out);
        mp_raise_ValueError(MP_ERROR_TEXT("hkdf failed"));
    }
    return mp_obj_new_bytes_from_vstr(&out);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(xcrypto_hkdf_sha256_obj, 4, 4, xcrypto_hkdf_sha256);

// ---------- ecdsa_keygen() -> (private 32 bytes, public 65 bytes), curve P-256 ----------
static mp_obj_t xcrypto_ecdsa_keygen(void) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    uint8_t priv[32], pub[65];
    size_t olen = 0;

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, xc_rng, NULL);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&d, priv, sizeof(priv));
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
            &olen, pub, sizeof(pub));
    }
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    if (ret != 0) {
        memset(priv, 0, sizeof(priv));
        mp_raise_ValueError(MP_ERROR_TEXT("keygen failed"));
    }
    mp_obj_t result[2] = {
        mp_obj_new_bytes(priv, sizeof(priv)),
        mp_obj_new_bytes(pub, sizeof(pub)),
    };
    memset(priv, 0, sizeof(priv));
    return mp_obj_new_tuple(2, result);
}
static MP_DEFINE_CONST_FUN_OBJ_0(xcrypto_ecdsa_keygen_obj, xcrypto_ecdsa_keygen);

// ---------- ecdsa_sign(private, data) -> 64-byte signature (r | s) ----------
static mp_obj_t xcrypto_ecdsa_sign(mp_obj_t priv_in, mp_obj_t data_in) {
    mp_buffer_info_t priv, data;
    mp_get_buffer_raise(priv_in, &priv, MP_BUFFER_READ);
    mp_get_buffer_raise(data_in, &data, MP_BUFFER_READ);
    if (priv.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("private key must be 32 bytes"));
    }
    uint8_t hash[32], sig[64];
    mbedtls_sha256(data.buf, data.len, hash, 0);     // sign the hash of the data

    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&d, priv.buf, 32);
    }
    if (ret == 0) {
        ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, sizeof(hash), xc_rng, NULL);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&r, sig, 32);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&s, sig + 32, 32);
    }
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    if (ret != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("sign failed"));
    }
    return mp_obj_new_bytes(sig, sizeof(sig));
}
static MP_DEFINE_CONST_FUN_OBJ_2(xcrypto_ecdsa_sign_obj, xcrypto_ecdsa_sign);

// ---------- ecdsa_verify(public, data, signature) -> True / False ----------
static mp_obj_t xcrypto_ecdsa_verify(mp_obj_t pub_in, mp_obj_t data_in, mp_obj_t sig_in) {
    mp_buffer_info_t pub, data, sig;
    mp_get_buffer_raise(pub_in, &pub, MP_BUFFER_READ);
    mp_get_buffer_raise(data_in, &data, MP_BUFFER_READ);
    mp_get_buffer_raise(sig_in, &sig, MP_BUFFER_READ);
    if (pub.len != 65) {
        mp_raise_ValueError(MP_ERROR_TEXT("public key must be 65 bytes"));
    }
    if (sig.len != 64) {
        return mp_const_false;
    }
    uint8_t hash[32];
    mbedtls_sha256(data.buf, data.len, hash, 0);

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&grp, &Q, pub.buf, pub.len);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&r, sig.buf, 32);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&s, (const uint8_t *)sig.buf + 32, 32);
    }
    if (ret == 0) {
        ret = mbedtls_ecdsa_verify(&grp, hash, sizeof(hash), &Q, &r, &s);
    }
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return mp_obj_new_bool(ret == 0);
}
static MP_DEFINE_CONST_FUN_OBJ_3(xcrypto_ecdsa_verify_obj, xcrypto_ecdsa_verify);

// ---------- capabilities() -> dict describing this build ----------
static mp_obj_t xcrypto_capabilities(void) {
    mp_obj_t algos[] = {
        MP_OBJ_NEW_QSTR(MP_QSTR_sha256),
        MP_OBJ_NEW_QSTR(MP_QSTR_hmac_sha256),
        MP_OBJ_NEW_QSTR(MP_QSTR_hkdf_sha256),
        MP_OBJ_NEW_QSTR(MP_QSTR_aes_gcm),
        MP_OBJ_NEW_QSTR(MP_QSTR_ecdsa_p256),
        MP_OBJ_NEW_QSTR(MP_QSTR_random),
    };
    mp_obj_t d = mp_obj_new_dict(6);
    mp_obj_dict_store(d, MP_OBJ_NEW_QSTR(MP_QSTR_platform),
        mp_obj_new_str(XC_PLATFORM, strlen(XC_PLATFORM)));
    mp_obj_dict_store(d, MP_OBJ_NEW_QSTR(MP_QSTR_algorithms),
        mp_obj_new_tuple(MP_ARRAY_SIZE(algos), algos));
    mp_obj_dict_store(d, MP_OBJ_NEW_QSTR(MP_QSTR_hw_rng), mp_obj_new_bool(XC_HW_RNG));
    mp_obj_dict_store(d, MP_OBJ_NEW_QSTR(MP_QSTR_hw_aes), mp_obj_new_bool(XC_HW_AES));
    mp_obj_dict_store(d, MP_OBJ_NEW_QSTR(MP_QSTR_hw_sha), mp_obj_new_bool(XC_HW_SHA));
    mp_obj_dict_store(d, MP_OBJ_NEW_QSTR(MP_QSTR_hw_mpi), mp_obj_new_bool(XC_HW_MPI));
    return d;
}
static MP_DEFINE_CONST_FUN_OBJ_0(xcrypto_capabilities_obj, xcrypto_capabilities);

// ---------- selftest() -> True if all known-answer tests pass ----------
static mp_obj_t xcrypto_selftest(void) {
    // 1. SHA-256("abc"), NIST test vector
    static const uint8_t sha_expect[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t out[32];
    mbedtls_sha256((const unsigned char *)"abc", 3, out, 0);
    if (memcmp(out, sha_expect, 32) != 0) {
        return mp_const_false;
    }

    // 2. AES-128-GCM, GCM spec test case 2: zero key, zero IV, 16 zero bytes
    static const uint8_t zeros[16] = {0};
    static const uint8_t ct_expect[16] = {
        0x03,0x88,0xda,0xce,0x60,0xb6,0xa3,0x92,0xf3,0x28,0xc2,0xb9,0x71,0xb2,0xfe,0x78};
    static const uint8_t tag_expect[16] = {
        0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf};
    uint8_t ct[16], tag[16];
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, zeros, 128);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 16,
            zeros, 12, NULL, 0, zeros, ct, 16, tag);
    }
    mbedtls_gcm_free(&gcm);
    if (ret != 0 || memcmp(ct, ct_expect, 16) != 0 || memcmp(tag, tag_expect, 16) != 0) {
        return mp_const_false;
    }
    return mp_const_true;
}
static MP_DEFINE_CONST_FUN_OBJ_0(xcrypto_selftest_obj, xcrypto_selftest);

// ---------- The module's contents, as seen from Python ----------
static const mp_rom_map_elem_t xcrypto_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__),        MP_ROM_QSTR(MP_QSTR_xcrypto) },
    { MP_ROM_QSTR(MP_QSTR_version),         MP_ROM_PTR(&xcrypto_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256),          MP_ROM_PTR(&xcrypto_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_random),          MP_ROM_PTR(&xcrypto_random_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes_gcm_encrypt), MP_ROM_PTR(&xcrypto_aes_gcm_encrypt_obj) },
    { MP_ROM_QSTR(MP_QSTR_aes_gcm_decrypt), MP_ROM_PTR(&xcrypto_aes_gcm_decrypt_obj) },
    { MP_ROM_QSTR(MP_QSTR_hmac_sha256),   MP_ROM_PTR(&xcrypto_hmac_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_hkdf_sha256),   MP_ROM_PTR(&xcrypto_hkdf_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_keygen),  MP_ROM_PTR(&xcrypto_ecdsa_keygen_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_sign),    MP_ROM_PTR(&xcrypto_ecdsa_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdsa_verify),  MP_ROM_PTR(&xcrypto_ecdsa_verify_obj) },
    { MP_ROM_QSTR(MP_QSTR_capabilities), MP_ROM_PTR(&xcrypto_capabilities_obj) },
    { MP_ROM_QSTR(MP_QSTR_selftest),        MP_ROM_PTR(&xcrypto_selftest_obj) },
};
static MP_DEFINE_CONST_DICT(xcrypto_globals, xcrypto_globals_table);

const mp_obj_module_t xcrypto_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&xcrypto_globals,
};
MP_REGISTER_MODULE(MP_QSTR_xcrypto, xcrypto_module);

// ========== C helpers for other modules (declared in xcrypto.h) ==========
int xc_ecdsa_keygen(uint8_t priv[32], uint8_t pub[65]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    size_t olen = 0;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, xc_rng, NULL);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&d, priv, 32);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, pub, 65);
    }
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ret;
}

int xc_ecdsa_sign_hash(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[64]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&d, priv, 32);
    }
    if (ret == 0) {
        ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, hash, 32, xc_rng, NULL);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&r, sig, 32);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&s, sig + 32, 32);
    }
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return ret;
}

int xc_aes_gcm(int encrypt, const uint8_t key[32], const uint8_t iv[12],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[16]) {
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        if (encrypt) {
            ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, iv, 12,
                aad, aad_len, in, out, 16, tag);
        } else {
            ret = mbedtls_gcm_auth_decrypt(&gcm, len, iv, 12, aad, aad_len, tag, 16, in, out);
        }
    }
    mbedtls_gcm_free(&gcm);
    return ret;
}
int xc_ecdsa_verify_hash(const uint8_t pub[65], const uint8_t hash[32], const uint8_t sig[64]) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi r, s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&grp, &Q, pub, 65);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_pubkey(&grp, &Q);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&r, sig, 32);
    }
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&s, sig + 32, 32);
    }
    if (ret == 0) {
        ret = mbedtls_ecdsa_verify(&grp, hash, 32, &Q, &r, &s);
    }
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return ret;
}

int xc_ecdsa_check_public(const uint8_t pub[65]) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_ecp_point_read_binary(&grp, &Q, pub, 65);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_pubkey(&grp, &Q);   // is it really a point on the curve?
    }
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return ret;
}