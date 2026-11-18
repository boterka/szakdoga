#ifndef TWO_FEISTEL_H
#define TWO_FEISTEL_H

#include <stddef.h>
#include <stdint.h>

#include "common_hashes.h"   /* NONCE_LEN */
#include "kem_operations.h"  /* kem_ops   */

/* A titkosított kimenet hossza: t (NONCE_LEN bájt) || s (pk_len bájt) */
#define FEISTEL_OUT_LEN(kem) (NONCE_LEN + (kem)->pk_len)

/* out = t || s, ahol
 *   s = pk + H1(pw, sid, r)
 *   t = r XOR H2(pw, sid, s)
 * Az r nonce-ot a hívó adja (NONCE_LEN bájt). */
int feistel2_encrypt(uint8_t *out, const uint8_t *pk,
                     const uint8_t *pw, size_t pwlen,
                     const uint8_t *sid, size_t sidlen,
                     const kem_ops *kem, const uint8_t r[NONCE_LEN]);

/* in = t || s  ->  pk_out (kem->pk_len bájt) */
int feistel2_decrypt(uint8_t *pk_out, const uint8_t *in,
                     const uint8_t *pw, size_t pwlen,
                     const uint8_t *sid, size_t sidlen,
                     const kem_ops *kem);

#endif
