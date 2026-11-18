#ifndef HASHES_H
#define HASHES_H

#include <stddef.h>
#include <stdint.h>

#define TAG_H1 0x01
#define TAG_H2 0x02
#define NONCE_LEN 32

void xor_into(uint8_t *dst, const uint8_t *mask, size_t len);

/* 8 bájtos, big-endian hossz-kódolás. Nem static, mert a KEM-enkénti
 * h1 függvények (pl. frodokem_ops.c) is használják. */
void encode_len(uint8_t out[8], size_t len);

/* Közös SHAKE256 hash: tag ‖ len(pw) ‖ pw ‖ len(sid) ‖ sid ‖ r_s -> outlen bájt.
 * A H1 (KEM-enként) és a H2 is erre épül, csak más taggel és kimenethosszal. */
int hash_pw_sid(uint8_t tag,
                const uint8_t *pw, size_t pwlen,
                const uint8_t *sid, size_t sidlen,
                const uint8_t *r_s, size_t r_slen,
                uint8_t *out, size_t outlen);

/* H2: (pw, sid, s) -> NONCE_LEN bájtos maszk */
int hash_h2(uint8_t out[NONCE_LEN],
            const uint8_t *pw, size_t pwlen,
            const uint8_t *sid, size_t sidlen,
            const uint8_t *s, size_t slen);

#endif
