#ifndef XCRYPTO_H
#define XCRYPTO_H
#include <stddef.h>
#include <stdint.h>

// C functions other xPython modules can call directly
void xc_fill_random(uint8_t *buf, size_t len);
int xc_ecdsa_keygen(uint8_t priv[32], uint8_t pub[65]);
int xc_ecdsa_sign_hash(const uint8_t priv[32], const uint8_t hash[32], uint8_t sig[64]);
int xc_aes_gcm(int encrypt, const uint8_t key[32], const uint8_t iv[12],
               const uint8_t *aad, size_t aad_len,
               const uint8_t *in, size_t len, uint8_t *out, uint8_t tag[16]);
int xc_ecdsa_verify_hash(const uint8_t pub[65], const uint8_t hash[32], const uint8_t sig[64]);  // 0 = valid
int xc_ecdsa_check_public(const uint8_t pub[65]);                                                  // 0 = valid point
#endif