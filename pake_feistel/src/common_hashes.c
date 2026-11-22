#include "common_hashes.h"

#include <oqs/oqs.h>
#include <oqs/sha3.h>   /* az OQS_SHA3_shake256_inc_* deklarációk itt vannak, az oqs.h nem húzza be */


void xor_into(uint8_t *dst, const uint8_t *mask, size_t len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] ^= mask[i];
}

void encode_len(uint8_t out[8], size_t len)
{
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)((uint64_t)len >> (8 * (7 - i)));
}


int hash_pw_sid(uint8_t tag,
                           const uint8_t *pw, size_t pwlen,
                           const uint8_t *sid, size_t sidlen,
                           const uint8_t *r_s, size_t r_slen,
                           uint8_t *out, size_t outlen)
{
    OQS_SHA3_shake256_inc_ctx ctx;
    uint8_t len_enc[8];

    OQS_SHA3_shake256_inc_init(&ctx);

    /* tag ‖ len(pw) ‖ pw ‖ len(sid) ‖ sid ‖ r vagy s */
    OQS_SHA3_shake256_inc_absorb(&ctx, &tag, 1);
    encode_len(len_enc, pwlen);
    OQS_SHA3_shake256_inc_absorb(&ctx, len_enc, sizeof len_enc);
    OQS_SHA3_shake256_inc_absorb(&ctx, pw, pwlen);

    encode_len(len_enc, sidlen);
    OQS_SHA3_shake256_inc_absorb(&ctx, len_enc, sizeof len_enc);
    OQS_SHA3_shake256_inc_absorb(&ctx, sid, sidlen);

    OQS_SHA3_shake256_inc_absorb(&ctx, r_s, r_slen);

    OQS_SHA3_shake256_inc_finalize(&ctx);
    OQS_SHA3_shake256_inc_squeeze(out, outlen, &ctx);

    OQS_SHA3_shake256_inc_ctx_release(&ctx);
    return 0;
}


int hash_h2(uint8_t out[NONCE_LEN],
            const uint8_t *pw, size_t pwlen,
            const uint8_t *sid, size_t sidlen,
            const uint8_t *s, size_t slen)
{
    return hash_pw_sid(TAG_H2, pw, pwlen, sid, sidlen, s, slen, out, NONCE_LEN);
}
