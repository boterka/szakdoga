/* src/ClassicMcEliece/mceliece_ops.c */
#include <oqs/oqs.h>
#include "kem_operations.h"
#include "common_hashes.h"

/* Classic McEliece 348864 nyilvános kulcs hossza a liboqs-ból (261 120 bájt) */
#define MCE348864_PK_LEN OQS_KEM_classic_mceliece_348864_length_public_key

static int mce348864_h1(uint8_t *out,
                        const uint8_t *pw, size_t pwlen,
                        const uint8_t *sid, size_t sidlen,
                        const uint8_t *r)
{
    /* A 348864-nél a T mátrix minden sora mt = 768 bit = 96 bájt,
     * nincs kitöltőbit, ezért minden bitminta érvényes pk:
     * a H1 kimenete egyszerűen pk_len bájt SHAKE256 kimenet. */
    return hash_pw_sid(TAG_H1, pw, pwlen, sid, sidlen,
                       r, NONCE_LEN, out, MCE348864_PK_LEN);
}

/* A csoportművelet itt is a XOR (GF(2) feletti mátrix), ami saját maga
 * inverze, ezért az add és a sub is a közös xor_into. */
const kem_ops KEM_MCE348864 = {
    .pk_len = MCE348864_PK_LEN,
    .h1     = mce348864_h1,
    .add    = xor_into,
    .sub    = xor_into,
};
