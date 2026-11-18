# xPython benchmark

Boards: XPY_ESP32C6. Cells: mean ± standard deviation (n = repetitions). Units are in the metric name: _us microseconds per operation, _ms milliseconds, _kb kilobytes, _b bytes.

| Group | Metric | XPY_ESP32C6 |
|---|---|---|
| crypto | sha256_1k_us | 69.0 ± 0.08 (n=10) |
| crypto | sha256_16k_us | 266.1 ± 0.07 (n=10) |
| crypto | hmac_1k_us | 138.3 ± 0.66 (n=10) |
| crypto | hkdf_32_us | 197.1 ± 1.25 (n=10) |
| crypto | aesgcm_enc_1k_us | 973.9 ± 1.85 (n=10) |
| crypto | aesgcm_dec_1k_us | 987.4 ± 1.91 (n=10) |
| crypto | aesgcm_enc_4k_us | 4,600 ± 3.87 (n=10) |
| crypto | ecdsa_keygen_us | 9,222 ± 36.3 (n=10) |
| crypto | ecdsa_sign_us | 21,499 ± 54.4 (n=10) |
| crypto | ecdsa_verify_us | 41,218 ± 190.5 (n=10) |
| crypto | ecdh_us | 8,868 ± 88.3 (n=10) |
| crypto | random_32_us | 555.0 ± 0.12 (n=10) |
| keys | xkeys_sign_us | 22,200 ± 43.3 (n=10) |
| keys | xkeys_encrypt_1k_us | 1,189 ± 0.14 (n=10) |
| keys | xkeys_decrypt_1k_us | 1,197 ± 0.34 (n=10) |
| keys | xkeys_public_us | 559.7 ± 0.09 (n=10) |
| storage | plain_write_1k_us | 32,661 ± 8,570 (n=10) |
| storage | plain_read_1k_us | 4,239 ± 1,470 (n=10) |
| storage | sealed_write_1k_us | 71,773 ± 17,560 (n=10) |
| storage | sealed_read_1k_us | 8,495 ± 1,311 (n=10) |
| storage | plain_write_4k_us | 56,723 ± 7,008 (n=10) |
| storage | plain_read_4k_us | 7,505 ± 1,501 (n=10) |
| storage | sealed_write_4k_us | 118,015 ± 21,548 (n=10) |
| storage | sealed_read_4k_us | 17,639 ± 1,511 (n=10) |
| storage | plain_write_15k_us | 199,617 ± 18,672 (n=10) |
| storage | plain_read_15k_us | 19,452 ± 1,544 (n=10) |
| storage | sealed_write_15k_us | 263,859 ± 27,278 (n=10) |
| storage | sealed_read_15k_us | 40,023 ± 1,825 (n=10) |
| memory | py_heap_total_kb | 358.0 ± 0.00 (n=10) |
| memory | py_heap_free_kb | 340.0 ± 0.00 (n=10) |
| memory | idf_heap_total_kb | 415.0 ± 0.00 (n=10) |
| memory | idf_heap_free_kb | 312.0 ± 0.00 (n=10) |
| memory | idf_heap_largest_kb | 296.0 ± 0.00 (n=10) |
| memory | idf_heap_min_free_kb | 120.0 ± 0.00 (n=10) |
| memory | flash_kb | 4,096 ± 0.00 (n=10) |
| memory | slot_kb | 1,856 ± 0.00 (n=10) |
| memory | fs_total_kb | 320.0 ± 0.00 (n=10) |
| memory | fs_free_kb | 252.0 ± 0.00 (n=10) |
| memory | uptime_ms | 256,768 ± 18,977 (n=10) |

## Cost of the protection (ratio of means)

| Ratio | XPY_ESP32C6 |
|---|---|
| sealed_write_1k_us / plain_write_1k_us | 2.20× |
| sealed_read_1k_us / plain_read_1k_us | 2.00× |
| sealed_write_4k_us / plain_write_4k_us | 2.08× |
| sealed_read_4k_us / plain_read_4k_us | 2.35× |
| sealed_write_15k_us / plain_write_15k_us | 1.32× |
| sealed_read_15k_us / plain_read_15k_us | 2.06× |
| xkeys_sign_us / ecdsa_sign_us | 1.03× |
| xkeys_encrypt_1k_us / aesgcm_enc_1k_us | 1.22× |
