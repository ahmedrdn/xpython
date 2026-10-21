#include <string.h>
#include "py/runtime.h"
#include "mbedtls/sha256.h"

#define XCRYPTO_VERSION "0.1.0"

// xcrypto.version() -> "0.1.0"
static mp_obj_t xcrypto_version(void) {
    return mp_obj_new_str(XCRYPTO_VERSION, strlen(XCRYPTO_VERSION));
}
static MP_DEFINE_CONST_FUN_OBJ_0(xcrypto_version_obj, xcrypto_version);

// xcrypto.sha256(data) -> 32-byte digest
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

// xcrypto.selftest() -> True if the NIST test vector SHA-256("abc") matches
static mp_obj_t xcrypto_selftest(void) {
    static const uint8_t expect[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
    uint8_t out[32];
    mbedtls_sha256((const unsigned char *)"abc", 3, out, 0);
    return mp_obj_new_bool(memcmp(out, expect, 32) == 0);
}
static MP_DEFINE_CONST_FUN_OBJ_0(xcrypto_selftest_obj, xcrypto_selftest);

// The module's contents, as seen from Python
static const mp_rom_map_elem_t xcrypto_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_xcrypto) },
    { MP_ROM_QSTR(MP_QSTR_version),  MP_ROM_PTR(&xcrypto_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256),   MP_ROM_PTR(&xcrypto_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_selftest), MP_ROM_PTR(&xcrypto_selftest_obj) },
};
static MP_DEFINE_CONST_DICT(xcrypto_globals, xcrypto_globals_table);

const mp_obj_module_t xcrypto_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&xcrypto_globals,
};
MP_REGISTER_MODULE(MP_QSTR_xcrypto, xcrypto_module);