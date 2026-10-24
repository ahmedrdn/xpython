#include <string.h>
#include "py/runtime.h"
#include "py/builtin.h"
#include "extmod/vfs.h"
#include "xpolicy.h"

#define XPOLICY_VERSION "0.1.2"

// The running app's policy (a dict), or NULL when system code is running.
// Registered as a root pointer so the garbage collector keeps it alive.
MP_REGISTER_ROOT_POINTER(mp_obj_t xpolicy_active);

// Modules an app can never import, even if its manifest asks
static const char *const FORBIDDEN[] = {
    "sys", "builtins", "micropython", "uctypes", "io", "vfs", "esp", "esp32",
    "_thread", "ffi", "xinit", "xloader", "xpolicy", "xsfs", "xwatch", "xexec",
    "xnet", "network", "socket", "ssl", "tls", "ntptime", NULL
};
// Safe C modules every app may import
static const char *const DEFAULTS[] = {
    "time", "math", "json", "struct", "collections", "re", "binascii",
    "hashlib", "random", "errno", "array", "gc", "xcrypto", NULL
};

// ========== Helpers ==========
static bool active(void) {
    mp_obj_t p = MP_STATE_VM(xpolicy_active);
    return p != MP_OBJ_NULL && p != mp_const_none;
}

static mp_obj_t field(qstr name) {
    return mp_obj_dict_get(MP_STATE_VM(xpolicy_active), MP_OBJ_NEW_QSTR(name));
}

static bool in_array(const char *const *arr, const char *s) {
    for (; *arr; arr++) {
        if (strcmp(*arr, s) == 0) {
            return true;
        }
    }
    return false;
}

static bool in_list(mp_obj_t list, const char *s) {
    size_t n;
    mp_obj_t *items;
    mp_obj_get_array(list, &n, &items);
    for (size_t i = 0; i < n; i++) {
        if (strcmp(mp_obj_str_get_str(items[i]), s) == 0) {
            return true;
        }
    }
    return false;
}

// Is `path` equal to, or inside, one of the folders in `prefixes`?
static bool under(const char *path, mp_obj_t prefixes) {
    size_t n;
    mp_obj_t *items;
    mp_obj_get_array(prefixes, &n, &items);
    for (size_t i = 0; i < n; i++) {
        size_t pl;
        const char *p = mp_obj_str_get_data(items[i], &pl);
        if (pl > 0 && p[pl - 1] == '/') {
            pl--;                                   // "/logs/" is the same as "/logs"
        }
        if (strncmp(path, p, pl) == 0 && (path[pl] == '\0' || path[pl] == '/')) {
            return true;
        }
    }
    return false;
}

// Raises OSError if the running app may not access this path
static void require_path(mp_obj_t path_in, bool write) {
    if (!active()) {
        return;
    }
    const char *path = mp_obj_str_get_str(path_in);
    bool ok = path[0] == '/' && strstr(path, "..") == NULL
        && (under(path, field(MP_QSTR_write))
            || (!write && under(path, field(MP_QSTR_read))));
    if (!ok) {
        mp_raise_msg_varg(&mp_type_OSError, MP_ERROR_TEXT("policy: %s '%s' denied"),
            write ? "write" : "read", path);
    }
}

static bool module_allowed(const char *name) {
    char base[33];
    size_t i = 0;
    while (name[i] && name[i] != '.' && i < sizeof(base) - 1) {   // "a.b" -> "a"
        base[i] = name[i];
        i++;
    }
    base[i] = '\0';
    const char *plain = (base[0] == 'u') ? base + 1 : base;      // "usys" is an old name for "sys"
    if (in_array(FORBIDDEN, base) || in_array(FORBIDDEN, plain) || strcmp(plain, "os") == 0) {
        return false;
    }
    return in_array(DEFAULTS, base) || in_list(field(MP_QSTR_modules), base);
}

// C interface for xkeys
int xp_key_allowed(const char *label) {
    return !active() || in_list(field(MP_QSTR_keys), label);
}

// ========== The restricted "os" that apps get ==========
static mp_obj_t xpos_listdir(mp_obj_t p) {
    require_path(p, false);
    return mp_call_function_1(MP_OBJ_FROM_PTR(&mp_vfs_listdir_obj), p);
}
static MP_DEFINE_CONST_FUN_OBJ_1(xpos_listdir_obj, xpos_listdir);

static mp_obj_t xpos_stat(mp_obj_t p) {
    require_path(p, false);
    return mp_call_function_1(MP_OBJ_FROM_PTR(&mp_vfs_stat_obj), p);
}
static MP_DEFINE_CONST_FUN_OBJ_1(xpos_stat_obj, xpos_stat);

static mp_obj_t xpos_remove(mp_obj_t p) {
    require_path(p, true);
    return mp_call_function_1(MP_OBJ_FROM_PTR(&mp_vfs_remove_obj), p);
}
static MP_DEFINE_CONST_FUN_OBJ_1(xpos_remove_obj, xpos_remove);

static mp_obj_t xpos_mkdir(mp_obj_t p) {
    require_path(p, true);
    return mp_call_function_1(MP_OBJ_FROM_PTR(&mp_vfs_mkdir_obj), p);
}
static MP_DEFINE_CONST_FUN_OBJ_1(xpos_mkdir_obj, xpos_mkdir);

static mp_obj_t xpos_rmdir(mp_obj_t p) {
    require_path(p, true);
    return mp_call_function_1(MP_OBJ_FROM_PTR(&mp_vfs_rmdir_obj), p);
}
static MP_DEFINE_CONST_FUN_OBJ_1(xpos_rmdir_obj, xpos_rmdir);

static mp_obj_t xpos_rename(mp_obj_t a, mp_obj_t b) {
    require_path(a, true);
    require_path(b, true);
    return mp_call_function_2(MP_OBJ_FROM_PTR(&mp_vfs_rename_obj), a, b);
}
static MP_DEFINE_CONST_FUN_OBJ_2(xpos_rename_obj, xpos_rename);

static const mp_rom_map_elem_t xpos_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_os) },
    { MP_ROM_QSTR(MP_QSTR_listdir),  MP_ROM_PTR(&xpos_listdir_obj) },
    { MP_ROM_QSTR(MP_QSTR_stat),     MP_ROM_PTR(&xpos_stat_obj) },
    { MP_ROM_QSTR(MP_QSTR_remove),   MP_ROM_PTR(&xpos_remove_obj) },
    { MP_ROM_QSTR(MP_QSTR_mkdir),    MP_ROM_PTR(&xpos_mkdir_obj) },
    { MP_ROM_QSTR(MP_QSTR_rmdir),    MP_ROM_PTR(&xpos_rmdir_obj) },
    { MP_ROM_QSTR(MP_QSTR_rename),   MP_ROM_PTR(&xpos_rename_obj) },
};
static MP_DEFINE_CONST_DICT(xpos_globals, xpos_table);
static const mp_obj_module_t xpolicy_os_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&xpos_globals,
};

// ========== Python functions ==========
static mp_obj_t xpolicy_version(void) {
    return mp_obj_new_str(XPOLICY_VERSION, strlen(XPOLICY_VERSION));
}
static MP_DEFINE_CONST_FUN_OBJ_0(xpolicy_version_obj, xpolicy_version);

// activate(policy_dict): start enforcing (called by xloader)
static mp_obj_t xpolicy_activate(mp_obj_t policy) {
    if (!mp_obj_is_type(policy, &mp_type_dict)) {
        mp_raise_TypeError(MP_ERROR_TEXT("policy must be a dict"));
    }
    MP_STATE_VM(xpolicy_active) = policy;
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(xpolicy_activate_obj, xpolicy_activate);

// deactivate(): stop enforcing (system code again)
static mp_obj_t xpolicy_deactivate(void) {
    MP_STATE_VM(xpolicy_active) = MP_OBJ_NULL;
    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(xpolicy_deactivate_obj, xpolicy_deactivate);

// active() -> running app id, or None
static mp_obj_t xpolicy_active_app(void) {
    return active() ? field(MP_QSTR_app) : mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_0(xpolicy_active_app_obj, xpolicy_active_app);

// open(file, mode="r"): the policy version of the built-in open
static mp_obj_t xpolicy_open(size_t n_args, const mp_obj_t *args) {
    if (active()) {
        const char *mode = n_args > 1 ? mp_obj_str_get_str(args[1]) : "r";
        require_path(args[0], strpbrk(mode, "wax+") != NULL);
    }
    return mp_call_function_n_kw(MP_OBJ_FROM_PTR(&mp_builtin_open_obj), n_args, 0, args);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(xpolicy_open_obj, 1, 2, xpolicy_open);

// import_hook(name, ...): the policy version of the built-in __import__
static mp_obj_t xpolicy_import_hook(size_t n_args, const mp_obj_t *args) {
    if (active()) {
        const char *name = mp_obj_str_get_str(args[0]);
        if (n_args > 4 && mp_obj_get_int(args[4]) != 0) {
            mp_raise_msg(&mp_type_ImportError, MP_ERROR_TEXT("policy: relative imports not allowed"));
        }
        if (strcmp(name, "os") == 0) {
            return MP_OBJ_FROM_PTR(&xpolicy_os_module);     // the restricted os
        }
        if (!module_allowed(name)) {
            mp_raise_msg_varg(&mp_type_ImportError, MP_ERROR_TEXT("policy: module '%s' not allowed"), name);
        }
    }
    return mp_call_function_n_kw(MP_OBJ_FROM_PTR(&mp_builtin___import___obj), n_args, 0, args);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(xpolicy_import_hook_obj, 1, 5, xpolicy_import_hook);

// ========== Module table ==========
static const mp_rom_map_elem_t xpolicy_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__),    MP_ROM_QSTR(MP_QSTR_xpolicy) },
    { MP_ROM_QSTR(MP_QSTR_version),     MP_ROM_PTR(&xpolicy_version_obj) },
    { MP_ROM_QSTR(MP_QSTR_activate),    MP_ROM_PTR(&xpolicy_activate_obj) },
    { MP_ROM_QSTR(MP_QSTR_deactivate),  MP_ROM_PTR(&xpolicy_deactivate_obj) },
    { MP_ROM_QSTR(MP_QSTR_active),      MP_ROM_PTR(&xpolicy_active_app_obj) },
    { MP_ROM_QSTR(MP_QSTR_open),        MP_ROM_PTR(&xpolicy_open_obj) },
    { MP_ROM_QSTR(MP_QSTR_import_hook), MP_ROM_PTR(&xpolicy_import_hook_obj) },
};
static MP_DEFINE_CONST_DICT(xpolicy_globals, xpolicy_globals_table);

const mp_obj_module_t xpolicy_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&xpolicy_globals,
};
MP_REGISTER_MODULE(MP_QSTR_xpolicy, xpolicy_module);