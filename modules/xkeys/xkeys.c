#include <string.h>
#include "py/runtime.h"
#include "mbedtls/sha256.h"
#include "xcrypto.h"
#include "xkeys.h"
#include "xpolicy.h"

#define XKEYS_VERSION "0.4.0"
#define XK_AES256    1
#define XK_ECC_P256  2
#define XK_LABEL_MAX 15                 // NVS name limit
#define XK_BLOB_MAX  (1 + 32 + 65)      // type byte + private key + public key

// ========== Storage backend ==========
#if defined(ESP_PLATFORM) || __has_include("esp_random.h")
#include "nvs.h"  
#include "sdkconfig.h"
#include "esp_wifi.h"
#if __has_include("bootloader_random.h")
#include "bootloader_random.h"
#define XK_HAVE_BOOT_RANDOM 1
#endif
#if defined(CONFIG_BT_ENABLED) && __has_include("esp_bt.h")
#include "esp_bt.h"
#define XK_HAVE_BT 1
#endif

// True if Wi-Fi or Bluetooth is running: their radio noise already makes the RNG truly random
static bool radio_on(void) {
    wifi_mode_t mode;
    if (esp_wifi_get_mode(&mode) == ESP_OK && mode != WIFI_MODE_NULL) {
        return true;
    }
#if XK_HAVE_BT
    if (esp_bt_controller_get_status() == ESP_BT_CONTROLLER_STATUS_ENABLED) {
        return true;
    }
#endif
    return false;
}

// Switch on the hardware noise source for key generation if no radio is running.
// Returns 1 if it was switched on, so entropy_end knows to switch it off.
static int entropy_begin(void) {
#if XK_HAVE_BOOT_RANDOM
    if (!radio_on()) {
        bootloader_random_enable();
        return 1;
    }
#endif
    return 0;
}
static void entropy_end(int enabled) {
#if XK_HAVE_BOOT_RANDOM
    if (enabled) {
        bootloader_random_disable();
    }
#endif
    (void)enabled;
}

// list of all key labels in the "xkeys" namespace
static mp_obj_t store_list(void) {
    mp_obj_t result = mp_obj_new_list(0, NULL);
    nvs_iterator_t it = NULL;
    esp_err_t e = nvs_entry_find("nvs", "xkeys", NVS_TYPE_BLOB, &it);
    while (e == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        mp_obj_list_append(result, mp_obj_new_str(info.key, strlen(info.key)));
        e = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    return result;
}                      // ESP32: flash key-value store
static int store_put(const char *label, const uint8_t *blob, size_t len) {
    nvs_handle_t h;
    if (nvs_open("xkeys", NVS_READWRITE, &h) != ESP_OK) {
        return -1;
    }
    esp_err_t e = nvs_set_blob(h, label, blob, len);
    if (e == ESP_OK) {
        e = nvs_commit(h);
    }
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}
static int store_get(const char *label, uint8_t *blob, size_t *len) {
    nvs_handle_t h;
    if (nvs_open("xkeys", NVS_READONLY, &h) != ESP_OK) {
        return -1;
    }
    esp_err_t e = nvs_get_blob(h, label, blob, len);
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}
static int store_del(const char *label) {
    nvs_handle_t h;
    if (nvs_open("xkeys", NVS_READWRITE, &h) != ESP_OK) {
        return -1;
    }
    esp_err_t e = nvs_erase_key(h, label);
    if (e == ESP_OK) {
        e = nvs_commit(h);
    }
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}

static int store_wipe(void) {
    nvs_handle_t h;
    if (nvs_open("xkeys", NVS_READWRITE, &h) != ESP_OK) {
        return -1;
    }
    esp_err_t e = nvs_erase_all(h);
    if (e == ESP_OK) {
        e = nvs_commit(h);
    }
    nvs_close(h);
    return e == ESP_OK ? 0 : -1;
}
#else
// PC build: keys in RAM only, lost when the program exits (testing only)
#define XK_SLOTS 8
static struct {
    char label[XK_LABEL_MAX + 1];
    uint8_t blob[XK_BLOB_MAX];
    size_t len;
} slots[XK_SLOTS];

static int find_slot(const char *label) {
    for (int i = 0; i < XK_SLOTS; i++) {
        if (slots[i].len && strcmp(slots[i].label, label) == 0) {
            return i;
        }
    }
    return -1;
}
static int store_put(const char *label, const uint8_t *blob, size_t len) {
    int i = find_slot(label);
    if (i < 0) {
        for (i = 0; i < XK_SLOTS && slots[i].len; i++) {
        }
    }
    if (i >= XK_SLOTS) {
        return -1;
    }
    strcpy(slots[i].label, label);
    memcpy(slots[i].blob, blob, len);
    slots[i].len = len;
    return 0;
}
static int store_get(const char *label, uint8_t *blob, size_t *len) {
    int i = find_slot(label);
    if (i < 0 || *len < slots[i].len) {
        return -1;
    }
    memcpy(blob, slots[i].blob, slots[i].len);
    *len = slots[i].len;
    return 0;
}
static int store_del(const char *label) {
    int i = find_slot(label);
    if (i < 0) {
        return -1;
    }
    memset(&slots[i], 0, sizeof(slots[i]));
    return 0;
}
static int store_wipe(void) {
    memset(slots, 0, sizeof(slots));
    return 0;
}
static int entropy_begin(void) {
    return 0;
}
static void entropy_end(int enabled) {
    (void)enabled;
}
static mp_obj_t store_list(void) {
    mp_obj_t result = mp_obj_new_list(0, NULL);
    for (int i = 0; i < XK_SLOTS; i++) {
        if (slots[i].len) {
            mp_obj_list_append(result, mp_obj_new_str(slots[i].label, strlen(slots[i].label)));
        }
    }
    return result;
}
#endif

// ========== Helpers ==========
static const char *get_label(mp_obj_t o) {
    size_t n;
    const char *s = mp_obj_str_get_data(o, &n);
    if (n == 0 || n > XK_LABEL_MAX) {
        mp_raise_ValueError(MP_ERROR_TEXT("label must be 1..15 characters"));
    }
    if (!xp_key_allowed(s)) {                                   // NEW
        mp_raise_msg_varg(&mp_type_OSError, MP_ERROR_TEXT("policy: key '%s' not allowed"), s);
    }
    return s;
}

// Loads a key record and checks its type; raises if missing or wrong type
static void load_key(const char *label, uint8_t *blob, int want_type) {
    size_t len = XK_BLOB_MAX;
    if (store_get(label, blob, &len) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("no such key"));
    }
    if (blob[0] != want_type) {
        memset(blob, 0, XK_BLOB_MAX);
        mp_raise_ValueError(MP_ERROR_TEXT("wrong key type"));
    }
}

// ========== Python functions ==========
static mp_obj_t xkeys_version(void) {
    return mp_obj_new_str(XKEYS_VERSION, strlen(XKEYS_VERSION));
}
static MP_DEFINE_CONST_FUN_OBJ_0(xkeys_version_obj, xkeys_version);

   // ---- C interface (xkeys.h) ----
   int xk_generate(const char *label, int type) {
       if (type != XK_AES256 && type != XK_ECC_P256) {
           return -2;
       }
       uint8_t blob[XK_BLOB_MAX];
       size_t len = sizeof(blob);
       if (store_get(label, blob, &len) == 0) {
           memset(blob, 0, sizeof(blob));
           return -1;
       }
       int ret = 0;
       blob[0] = (uint8_t)type;
       int ent = entropy_begin();
       if (type == XK_AES256) {
           xc_fill_random(blob + 1, 32);
           len = 1 + 32;
       } else {
           ret = xc_ecdsa_keygen(blob + 1, blob + 33);
           len = 1 + 32 + 65;
       }
       entropy_end(ent);
       if (ret == 0) {
           ret = store_put(label, blob, len);
       }
       memset(blob, 0, sizeof(blob));
       return ret == 0 ? 0 : -3;
   }

   int xk_public(const char *label, uint8_t pub[65]) {
       uint8_t blob[XK_BLOB_MAX];
       size_t len = sizeof(blob);
       int ok = store_get(label, blob, &len) == 0 && blob[0] == XK_ECC_P256;
       if (ok) {
           memcpy(pub, blob + 33, 65);
       }
       memset(blob, 0, sizeof(blob));
       return ok ? 0 : -1;
   }

   int xk_wipe_all(void) {
       return store_wipe();
   }

   // ---- Python: generate(label, type) ----
   static mp_obj_t xkeys_generate(mp_obj_t label_in, mp_obj_t type_in) {
       int r = xk_generate(get_label(label_in), mp_obj_get_int(type_in));
       if (r == -1) {
           mp_raise_ValueError(MP_ERROR_TEXT("key already exists"));
       } else if (r == -2) {
           mp_raise_ValueError(MP_ERROR_TEXT("unknown key type"));
       } else if (r != 0) {
           mp_raise_ValueError(MP_ERROR_TEXT("key generation failed"));
       }
       return mp_const_none;
   }
   static MP_DEFINE_CONST_FUN_OBJ_2(xkeys_generate_obj, xkeys_generate);
// exists(label) -> bool
static mp_obj_t xkeys_exists(mp_obj_t label_in) {
    uint8_t blob[XK_BLOB_MAX];
    size_t len = sizeof(blob);
    int found = store_get(get_label(label_in), blob, &len) == 0;
    memset(blob, 0, sizeof(blob));
    return mp_obj_new_bool(found);
}
static MP_DEFINE_CONST_FUN_OBJ_1(xkeys_exists_obj, xkeys_exists);

// delete(label)
static mp_obj_t xkeys_delete(mp_obj_t label_in) {
    if (store_del(get_label(label_in)) != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("no such key"));
    }
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(xkeys_delete_obj, xkeys_delete);

// list() -> list of key labels
static mp_obj_t xkeys_list(void) {
    return store_list();
}
static MP_DEFINE_CONST_FUN_OBJ_0(xkeys_list_obj, xkeys_list);

// public(label) -> 65-byte public key (ECC only)
static mp_obj_t xkeys_public(mp_obj_t label_in) {
    uint8_t blob[XK_BLOB_MAX];
    load_key(get_label(label_in), blob, XK_ECC_P256);
    mp_obj_t pub = mp_obj_new_bytes(blob + 33, 65);
    memset(blob, 0, sizeof(blob));
    return pub;
}
static MP_DEFINE_CONST_FUN_OBJ_1(xkeys_public_obj, xkeys_public);

// sign(label, data) -> 64-byte signature
static mp_obj_t xkeys_sign(mp_obj_t label_in, mp_obj_t data_in) {
    mp_buffer_info_t data;
    mp_get_buffer_raise(data_in, &data, MP_BUFFER_READ);
    uint8_t blob[XK_BLOB_MAX], hash[32], sig[64];
    load_key(get_label(label_in), blob, XK_ECC_P256);
    mbedtls_sha256(data.buf, data.len, hash, 0);
    int ret = xc_ecdsa_sign_hash(blob + 1, hash, sig);
    memset(blob, 0, sizeof(blob));
    if (ret != 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("sign failed"));
    }
    return mp_obj_new_bytes(sig, sizeof(sig));
}
static MP_DEFINE_CONST_FUN_OBJ_2(xkeys_sign_obj, xkeys_sign);

// encrypt(label, iv, data[, aad]) -> (ciphertext, tag)
static mp_obj_t xkeys_encrypt(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t iv, data, aad = {0};
    mp_get_buffer_raise(args[1], &iv, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &data, MP_BUFFER_READ);
    if (n_args > 3) {
        mp_get_buffer_raise(args[3], &aad, MP_BUFFER_READ);
    }
    if (iv.len != 12) {
        mp_raise_ValueError(MP_ERROR_TEXT("iv must be 12 bytes"));
    }
    uint8_t blob[XK_BLOB_MAX], tag[16];
    load_key(get_label(args[0]), blob, XK_AES256);
    vstr_t ct;
    vstr_init_len(&ct, data.len);
    int ret = xc_aes_gcm(1, blob + 1, iv.buf, aad.buf, aad.len,
        data.buf, data.len, (uint8_t *)ct.buf, tag);
    memset(blob, 0, sizeof(blob));
    if (ret != 0) {
        vstr_clear(&ct);
        mp_raise_ValueError(MP_ERROR_TEXT("encryption failed"));
    }
    mp_obj_t result[2] = { mp_obj_new_bytes_from_vstr(&ct), mp_obj_new_bytes(tag, 16) };
    return mp_obj_new_tuple(2, result);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(xkeys_encrypt_obj, 3, 4, xkeys_encrypt);

// decrypt(label, iv, ciphertext, tag[, aad]) -> plaintext
static mp_obj_t xkeys_decrypt(size_t n_args, const mp_obj_t *args) {
    mp_buffer_info_t iv, ct, tag, aad = {0};
    mp_get_buffer_raise(args[1], &iv, MP_BUFFER_READ);
    mp_get_buffer_raise(args[2], &ct, MP_BUFFER_READ);
    mp_get_buffer_raise(args[3], &tag, MP_BUFFER_READ);
    if (n_args > 4) {
        mp_get_buffer_raise(args[4], &aad, MP_BUFFER_READ);
    }
    if (iv.len != 12 || tag.len != 16) {
        mp_raise_ValueError(MP_ERROR_TEXT("iv must be 12 bytes, tag 16 bytes"));
    }
    uint8_t blob[XK_BLOB_MAX];
    load_key(get_label(args[0]), blob, XK_AES256);
    vstr_t pt;
    vstr_init_len(&pt, ct.len);
    int ret = xc_aes_gcm(0, blob + 1, iv.buf, aad.buf, aad.len,
        ct.buf, ct.len, (uint8_t *)pt.buf, tag.buf);
    memset(blob, 0, sizeof(blob));
    if (ret != 0) {
        vstr_clear(&pt);
        mp_raise_ValueError(MP_ERROR_TEXT("authentication failed"));
    }
    return mp_obj_new_bytes_from_vstr(&pt);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(xkeys_decrypt_obj, 4, 5, xkeys_decrypt);

// ========== Module table ==========
static const mp_rom_map_elem_t xkeys_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_xkeys) },
    { MP_ROM_QSTR(MP_QSTR_AES256),   MP_ROM_INT(XK_AES256) },
    { MP_ROM_QSTR(MP_QSTR_ECC_P256), MP_ROM_INT(XK_ECC_P256) },
    { MP_ROM_QSTR(MP_QSTR_version),  MP_ROM_PTR(&xkeys_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_generate), MP_ROM_PTR(&xkeys_generate_obj) },
    { MP_ROM_QSTR(MP_QSTR_exists),   MP_ROM_PTR(&xkeys_exists_obj) },
    { MP_ROM_QSTR(MP_QSTR_delete),   MP_ROM_PTR(&xkeys_delete_obj) },
    { MP_ROM_QSTR(MP_QSTR_public),   MP_ROM_PTR(&xkeys_public_obj) },
    { MP_ROM_QSTR(MP_QSTR_sign),     MP_ROM_PTR(&xkeys_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_encrypt),  MP_ROM_PTR(&xkeys_encrypt_obj) },
    { MP_ROM_QSTR(MP_QSTR_decrypt),  MP_ROM_PTR(&xkeys_decrypt_obj) },
    { MP_ROM_QSTR(MP_QSTR_list),     MP_ROM_PTR(&xkeys_list_obj) },
};
static MP_DEFINE_CONST_DICT(xkeys_globals, xkeys_globals_table);

const mp_obj_module_t xkeys_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&xkeys_globals,
};
MP_REGISTER_MODULE(MP_QSTR_xkeys, xkeys_module);