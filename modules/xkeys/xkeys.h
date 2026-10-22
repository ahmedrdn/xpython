#ifndef XKEYS_H
#define XKEYS_H
#include <stdint.h>

#define XK_AES256    1
#define XK_ECC_P256  2

// C functions other xPython modules can call
int xk_generate(const char *label, int type);       // 0 ok, -1 exists, -2 bad type, -3 failed
int xk_public(const char *label, uint8_t pub[65]);  // 0 ok, -1 missing or not ECC
int xk_wipe_all(void);                              // 0 ok: deletes every key
#endif