#include <string.h>
#include "py/runtime.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "xcrypto.h"
#include "xkeys.h"

#define XINIT_VERSION "0.3.0"

// Life-cycle states
#define ST_BLANK        0
#define ST_PERSONALIZED 1
#define ST_OPERATIONAL  2
#define ST_LOCKED       3
static const char *const state_names[] = { "BLANK", "PERSONALIZED", "OPERATIONAL", "LOCKED" };

#define PIN_MIN   6
#define PIN_MAX   16
#define PIN_TRIES 5
#define PIN_ITER  2000                  // PBKDF2 iterations: slows down guessing
#define PIN_REC   (16 + 32)             // salt + hash

// Record names in xinit's own storage
#define R_STATE "state"
#define R_PIN   "pin"
#define R_TRIES "tries"
#define R_ID    "id"
#define R_CERT  "cert"                  // 64-byte vendor signature
#define R_MAX   72                      // biggest record (an anchor: 65 bytes)
#define R_DEV   "dev"                   // 1 = development mode (REPL stays open)

// Trust anchors: Python name -> record name
static const char *const anchor_names[]   = { "vendor",   "app",   "fw"   };
static const char *const anchor_records[] = { "a_vendor", "a_app", "a_fw" };
#define N_ANCHORS 3

// Domain label for device certificates
#define CERT_LABEL     "xpy-devcert-v1"
#define CERT_LABEL_LEN 14

// ========== Storage backend: namespace "xinit" ==========
#if defined(ESP_PLATFORM) || __has_include("esp_random.h")
#include "nvs.h"
static int store_put(const char *name, const uint8_t *data, size_t len) {
    nvs_handle_t h;
    if (nvs_open("xinit", NVS_READWRITE, &h) != ESP_OK) {
        return -1;
    }
    esp_err_t e = nvs_set_blob(h, name, data, len);
    if (e == ESP_OK) {
        e = nvs_commit(h);
    }
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}
static int store_get(const char *name, uint8_t *data, size_t *len) {
    nvs_handle_t h;
    if (nvs_open("xinit", NVS_READONLY, &h) != ESP_OK) {
        return -1;
    }
    esp_err_t e = nvs_get_blob(h, name, data, len);
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}
static int store_del(const char *name) {
    nvs_handle_t h;
    if (nvs_open("xinit", NVS_READWRITE, &h) != ESP_OK) {
        return -1;
    }
    esp_err_t e = nvs_erase_key(h, name);
    if (e == ESP_OK) {
        e = nvs_commit(h);
    }
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}
#else
// PC build: RAM only, for testing
#define XI_SLOTS 12
static struct {
    char name[16];
    uint8_t data[R_MAX];
    size_t len;
} slots[XI_SLOTS];

static int find_slot(const char *name) {
    for (int i = 0; i < XI_SLOTS; i++) {
        if (slots[i].len && strcmp(slots[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}
static int store_put(const char *name, const uint8_t *data, size_t len) {
    int i = find_slot(name);
    if (i < 0) {
        for (i = 0; i < XI_SLOTS && slots[i].len; i++) {
        }
    }
    if (i >= XI_SLOTS || len > R_MAX) {
        return -1;
    }
    strcpy(slots[i].name, name);
    memcpy(slots[i].data, data, len);
    slots[i].len = len;
    return 0;
}
static int store_get(const char *name, uint8_t *data, size_t *len) {
    int i = find_slot(name);
    if (i < 0 || *len < slots[i].len) {
        return -1;
    }
    memcpy(data, slots[i].data, slots[i].len);
    *len = slots[i].len;
    return 0;
}
static int store_del(const char *name) {
    int i = find_slot(name);
    if (i < 0) {
        return -1;
    }
    memset(&slots[i], 0, sizeof(slots[i]));
    return 0;
}
#endif

// Reads a record that must have exactly `want` bytes; 0 = ok
static int load_rec(const char *name, uint8_t *buf, size_t want) {
    size_t n = want;
    return (store_get(name, buf, &n) == 0 && n == want) ? 0 : -1;
}

// ========== State and retry counter ==========
static int get_state(void) {
    uint8_t s;
    size_t n = 1;
    return store_get(R_STATE, &s, &n) == 0 ? s : ST_BLANK;
}
static void set_state(int s) {
    uint8_t b = (uint8_t)s;
    if (store_put(R_STATE, &b, 1) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("storage error"));
    }
}
static void require_state(int s, mp_rom_error_text_t msg) {
    if (get_state() != s) {
        mp_raise_ValueError(msg);
    }
}
static int get_tries(void) {
    uint8_t t;
    size_t n = 1;
    return store_get(R_TRIES, &t, &n) == 0 ? t : PIN_TRIES;
}
static void set_tries(int t) {
    uint8_t b = (uint8_t)t;
    if (store_put(R_TRIES, &b, 1) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("storage error"));
    }
}
static int has_pin(void) {
    uint8_t rec[PIN_REC];
    size_t n = sizeof(rec);
    int found = store_get(R_PIN, rec, &n) == 0;
    memset(rec, 0, sizeof(rec));
    return found;
}

// ========== PIN hashing: PBKDF2-HMAC-SHA256, one 32-byte block ==========
static int pin_hash(const uint8_t *pin, size_t pin_len, const uint8_t salt[16], uint8_t out[32]) {
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    uint8_t msg[20], u[32];
    memcpy(msg, salt, 16);
    msg[16] = 0; msg[17] = 0; msg[18] = 0; msg[19] = 1;          // salt || block number 1
    int ret = mbedtls_md_hmac(md, pin, pin_len, msg, sizeof(msg), u);   // U1
    memcpy(out, u, 32);
    for (int i = 1; ret == 0 && i < PIN_ITER; i++) {
        ret = mbedtls_md_hmac(md, pin, pin_len, u, 32, u);      // U(i) = HMAC(pin, U(i-1))
        for (int j = 0; j < 32; j++) {
            out[j] ^= u[j];                                     // result = U1 xor U2 xor ...
        }
    }
    memset(u, 0, sizeof(u));
    return ret;
}

// Compare without stopping at the first difference, so timing reveals nothing
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

static const char *get_new_pin(mp_obj_t o, size_t *n) {
    const char *pin = mp_obj_str_get_data(o, n);
    if (*n < PIN_MIN || *n > PIN_MAX) {
        mp_raise_ValueError(MP_ERROR_TEXT("PIN must be 6..16 characters"));
    }
    return pin;
}

static void store_pin(const char *pin, size_t n) {
    uint8_t rec[PIN_REC];
    xc_fill_random(rec, 16);                                    // fresh random salt
    int ret = pin_hash((const uint8_t *)pin, n, rec, rec + 16);
    if (ret == 0) {
        ret = store_put(R_PIN, rec, sizeof(rec));
    }
    memset(rec, 0, sizeof(rec));
    if (ret != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("storage error"));
    }
    set_tries(PIN_TRIES);
}

// Checks the SO PIN; raises on failure. Counts the try BEFORE checking.
static void check_pin(mp_obj_t pin_in) {
    if (get_state() == ST_LOCKED) {
        mp_raise_ValueError(MP_ERROR_TEXT("device locked"));
    }
    size_t n;
    const char *pin = mp_obj_str_get_data(pin_in, &n);
    uint8_t rec[PIN_REC];
    size_t rl = sizeof(rec);
    if (store_get(R_PIN, rec, &rl) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("no PIN set"));
    }
    int tries = get_tries() - 1;
    set_tries(tries);                                           // 1. count the attempt
    uint8_t h[32];
    int ok = pin_hash((const uint8_t *)pin, n, rec, h) == 0     // 2. then check
        && ct_equal(h, rec + 16, 32);
    memset(h, 0, sizeof(h));
    memset(rec, 0, sizeof(rec));
    if (!ok) {
        if (tries <= 0) {
            set_state(ST_LOCKED);
            mp_raise_ValueError(MP_ERROR_TEXT("wrong PIN, device locked"));
        }
        mp_raise_msg_varg(&mp_type_ValueError, MP_ERROR_TEXT("wrong PIN, %d tries left"), tries);
    }
    set_tries(PIN_TRIES);                                       // 3. correct: reset counter
}

// ========== Certificate helpers ==========
// The signed message is SHA-256("xpy-devcert-v1" || device_id || device_public_key)
static void cert_hash(const uint8_t id[16], const uint8_t pub[65], uint8_t out[32]) {
    mbedtls_sha256_context c;
    mbedtls_sha256_init(&c);
    mbedtls_sha256_starts(&c, 0);
    mbedtls_sha256_update(&c, (const uint8_t *)CERT_LABEL, CERT_LABEL_LEN);
    mbedtls_sha256_update(&c, id, 16);
    mbedtls_sha256_update(&c, pub, 65);
    mbedtls_sha256_finish(&c, out);
    mbedtls_sha256_free(&c);
}

// Python anchor name ("vendor" / "app" / "fw") -> record name; raises if unknown
static const char *anchor_record(mp_obj_t name_in) {
    const char *name = mp_obj_str_get_str(name_in);
    for (int i = 0; i < N_ANCHORS; i++) {
        if (strcmp(name, anchor_names[i]) == 0) {
            return anchor_records[i];
        }
    }
    mp_raise_ValueError(MP_ERROR_TEXT("anchor must be 'vendor', 'app' or 'fw'"));
}

// ========== Python functions ==========
static mp_obj_t xinit_version(void) {
    return mp_obj_new_str(XINIT_VERSION, strlen(XINIT_VERSION));
}
static MP_DEFINE_CONST_FUN_OBJ_0(xinit_version_obj, xinit_version);

// state() -> "BLANK" / "PERSONALIZED" / "OPERATIONAL" / "LOCKED"
static mp_obj_t xinit_state(void) {
    const char *s = state_names[get_state() & 3];
    return mp_obj_new_str(s, strlen(s));
}
static MP_DEFINE_CONST_FUN_OBJ_0(xinit_state_obj, xinit_state);

static mp_obj_t xinit_has_pin(void) {
    return mp_obj_new_bool(has_pin());
}
static MP_DEFINE_CONST_FUN_OBJ_0(xinit_has_pin_obj, xinit_has_pin);

static mp_obj_t xinit_tries_left(void) {
    return mp_obj_new_int(get_tries());
}
static MP_DEFINE_CONST_FUN_OBJ_0(xinit_tries_left_obj, xinit_tries_left);

// set_pin(pin): first PIN only. Can't replace an existing one (use change_pin).
static mp_obj_t xinit_set_pin(mp_obj_t pin_in) {
    if (has_pin()) {
        mp_raise_ValueError(MP_ERROR_TEXT("PIN already set, use change_pin"));
    }
    size_t n;
    const char *pin = get_new_pin(pin_in, &n);
    store_pin(pin, n);
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(xinit_set_pin_obj, xinit_set_pin);

// change_pin(old, new)
static mp_obj_t xinit_change_pin(mp_obj_t old_in, mp_obj_t new_in) {
    size_t n;
    const char *pin = get_new_pin(new_in, &n);
    check_pin(old_in);
    store_pin(pin, n);
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(xinit_change_pin_obj, xinit_change_pin);

// init(pin) -> (device_id 16 bytes, device public key 65 bytes)
static mp_obj_t xinit_init(mp_obj_t pin_in) {
    check_pin(pin_in);
    require_state(ST_BLANK, MP_ERROR_TEXT("not BLANK, reset first"));
    if (xk_wipe_all() != 0) {                                   // remove every old key
        mp_raise_ValueError(MP_ERROR_TEXT("key wipe failed"));
    }
    uint8_t id[16], pub[65];
    xc_fill_random(id, sizeof(id));                             // unique device ID
    if (xk_generate("device", XK_ECC_P256) != 0 || xk_public("device", pub) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("device key generation failed"));
    }
    if (store_put(R_ID, id, sizeof(id)) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("storage error"));
    }
    set_state(ST_PERSONALIZED);
    mp_obj_t result[2] = { mp_obj_new_bytes(id, 16), mp_obj_new_bytes(pub, 65) };
    return mp_obj_new_tuple(2, result);
}
static MP_DEFINE_CONST_FUN_OBJ_1(xinit_init_obj, xinit_init);

// install_anchor(pin, name, public_key): PERSONALIZED only
static mp_obj_t xinit_install_anchor(mp_obj_t pin_in, mp_obj_t name_in, mp_obj_t pub_in) {
    const char *rec = anchor_record(name_in);                   // check inputs first,
    mp_buffer_info_t pub;                                       // so mistakes don't cost a PIN try
    mp_get_buffer_raise(pub_in, &pub, MP_BUFFER_READ);
    if (pub.len != 65 || xc_ecdsa_check_public(pub.buf) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("invalid public key"));
    }
    check_pin(pin_in);
    require_state(ST_PERSONALIZED, MP_ERROR_TEXT("anchors can only be installed when PERSONALIZED"));
    if (store_put(rec, pub.buf, 65) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("storage error"));
    }
    if (strcmp(rec, "a_vendor") == 0) {
        store_del(R_CERT);                  // a new vendor key invalidates the old certificate
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_3(xinit_install_anchor_obj, xinit_install_anchor);

// anchor(name) -> 65-byte public key, or None
static mp_obj_t xinit_anchor(mp_obj_t name_in) {
    uint8_t pub[65];
    if (load_rec(anchor_record(name_in), pub, 65) != 0) {
        return mp_const_none;
    }
    return mp_obj_new_bytes(pub, 65);
}
static MP_DEFINE_CONST_FUN_OBJ_1(xinit_anchor_obj, xinit_anchor);

// set_certificate(pin, signature): accepted only if the vendor anchor verifies it
static mp_obj_t xinit_set_certificate(mp_obj_t pin_in, mp_obj_t sig_in) {
    mp_buffer_info_t sig;
    mp_get_buffer_raise(sig_in, &sig, MP_BUFFER_READ);
    if (sig.len != 64) {
        mp_raise_ValueError(MP_ERROR_TEXT("signature must be 64 bytes"));
    }
    check_pin(pin_in);
    require_state(ST_PERSONALIZED, MP_ERROR_TEXT("certificate can only be set when PERSONALIZED"));
    uint8_t vendor[65], id[16], pub[65], h[32];
    if (load_rec("a_vendor", vendor, 65) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("install the vendor anchor first"));
    }
    if (load_rec(R_ID, id, 16) != 0 || xk_public("device", pub) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("device not initialized"));
    }
    cert_hash(id, pub, h);
    if (xc_ecdsa_verify_hash(vendor, h, sig.buf) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("certificate signature invalid"));
    }
    if (store_put(R_CERT, sig.buf, 64) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("storage error"));
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(xinit_set_certificate_obj, xinit_set_certificate);

// certificate() -> (device_id, device_public_key, signature), or None
static mp_obj_t xinit_certificate(void) {
    uint8_t id[16], pub[65], sig[64];
    if (load_rec(R_ID, id, 16) != 0 || load_rec(R_CERT, sig, 64) != 0
        || xk_public("device", pub) != 0) {
        return mp_const_none;
    }
    mp_obj_t result[3] = {
        mp_obj_new_bytes(id, 16), mp_obj_new_bytes(pub, 65), mp_obj_new_bytes(sig, 64),
    };
    return mp_obj_new_tuple(3, result);
}
static MP_DEFINE_CONST_FUN_OBJ_0(xinit_certificate_obj, xinit_certificate);

// finalize(pin): PERSONALIZED -> OPERATIONAL, once all anchors and the certificate exist
static mp_obj_t xinit_finalize(mp_obj_t pin_in) {
    check_pin(pin_in);
    require_state(ST_PERSONALIZED, MP_ERROR_TEXT("device must be PERSONALIZED"));
    uint8_t buf[65];
    for (int i = 0; i < N_ANCHORS; i++) {
        if (load_rec(anchor_records[i], buf, 65) != 0) {
            mp_raise_msg_varg(&mp_type_ValueError, MP_ERROR_TEXT("missing anchor '%s'"), anchor_names[i]);
        }
    }
    if (load_rec(R_CERT, buf, 64) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("missing certificate"));
    }
    set_state(ST_OPERATIONAL);
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(xinit_finalize_obj, xinit_finalize);

// reset(pin): wipe keys, identity, anchors and certificate; back to BLANK (PIN kept)
static mp_obj_t xinit_reset(mp_obj_t pin_in) {
    check_pin(pin_in);
    if (xk_wipe_all() != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("key wipe failed"));
    }
    store_del(R_ID);
    store_del(R_CERT);
    for (int i = 0; i < N_ANCHORS; i++) {
        store_del(anchor_records[i]);
    }
    set_state(ST_BLANK);
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(xinit_reset_obj, xinit_reset);

// device_id() -> 16 bytes, or None if not initialized
static mp_obj_t xinit_device_id(void) {
    uint8_t id[16];
    if (load_rec(R_ID, id, 16) != 0) {
        return mp_const_none;
    }
    return mp_obj_new_bytes(id, 16);
}
static MP_DEFINE_CONST_FUN_OBJ_0(xinit_device_id_obj, xinit_device_id);

// dev_mode() -> True if the REPL stays open even when OPERATIONAL
static mp_obj_t xinit_dev_mode(void) {
    uint8_t d;
    size_t n = 1;
    return mp_obj_new_bool(store_get(R_DEV, &d, &n) == 0 && d == 1);
}
static MP_DEFINE_CONST_FUN_OBJ_0(xinit_dev_mode_obj, xinit_dev_mode);

// set_dev_mode(pin, on)
static mp_obj_t xinit_set_dev_mode(mp_obj_t pin_in, mp_obj_t on_in) {
    uint8_t b = mp_obj_is_true(on_in) ? 1 : 0;
    check_pin(pin_in);
    if (store_put(R_DEV, &b, 1) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("storage error"));
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(xinit_set_dev_mode_obj, xinit_set_dev_mode);

// ========== Module table ==========
static const mp_rom_map_elem_t xinit_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__),        MP_ROM_QSTR(MP_QSTR_xinit) },
    { MP_ROM_QSTR(MP_QSTR_version),         MP_ROM_PTR(&xinit_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_state),           MP_ROM_PTR(&xinit_state_obj) },
    { MP_ROM_QSTR(MP_QSTR_has_pin),         MP_ROM_PTR(&xinit_has_pin_obj) },
    { MP_ROM_QSTR(MP_QSTR_tries_left),      MP_ROM_PTR(&xinit_tries_left_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_pin),         MP_ROM_PTR(&xinit_set_pin_obj) },
    { MP_ROM_QSTR(MP_QSTR_change_pin),      MP_ROM_PTR(&xinit_change_pin_obj) },
    { MP_ROM_QSTR(MP_QSTR_init),            MP_ROM_PTR(&xinit_init_obj) },
    { MP_ROM_QSTR(MP_QSTR_install_anchor),  MP_ROM_PTR(&xinit_install_anchor_obj) },
    { MP_ROM_QSTR(MP_QSTR_anchor),          MP_ROM_PTR(&xinit_anchor_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_certificate), MP_ROM_PTR(&xinit_set_certificate_obj) },
    { MP_ROM_QSTR(MP_QSTR_certificate),     MP_ROM_PTR(&xinit_certificate_obj) },
    { MP_ROM_QSTR(MP_QSTR_finalize),        MP_ROM_PTR(&xinit_finalize_obj) },
    { MP_ROM_QSTR(MP_QSTR_reset),           MP_ROM_PTR(&xinit_reset_obj) },
    { MP_ROM_QSTR(MP_QSTR_device_id),       MP_ROM_PTR(&xinit_device_id_obj) },
    { MP_ROM_QSTR(MP_QSTR_dev_mode),        MP_ROM_PTR(&xinit_dev_mode_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_dev_mode),    MP_ROM_PTR(&xinit_set_dev_mode_obj) },
};
static MP_DEFINE_CONST_DICT(xinit_globals, xinit_globals_table);

const mp_obj_module_t xinit_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&xinit_globals,
};
MP_REGISTER_MODULE(MP_QSTR_xinit, xinit_module);