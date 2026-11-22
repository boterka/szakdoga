/* src/Bike/bike_ops.c */
#include <oqs/oqs.h>
#include "kem_operations.h"
#include "common_hashes.h"

/* BIKE-L1 (Bit Flipping Key Encapsulation, NIST 1. biztonsági szint)
 * nyilvános kulcs hossza a liboqs-ból (1541 bájt). A liboqs-ban a
 * paraméterkészletek neve bike_l1 / bike_l3 / bike_l5. */
#define BIKE_L1_PK_LEN OQS_KEM_bike_l1_length_public_key


static int bike_l1_h1(uint8_t *out,
                      const uint8_t *pw, size_t pwlen,
                      const uint8_t *sid, size_t sidlen,
                      const uint8_t *r)
{
    /* 1. lépés: pk_len bájt SHAKE256 kimenet, ugyanúgy, mint a FrodoKEM-nél. */
    int ret = hash_pw_sid(TAG_H1, pw, pwlen, sid, sidlen,
                          r, NONCE_LEN, out, BIKE_L1_PK_LEN);
    if (ret != 0) return ret;

    size_t last = BIKE_L1_PK_LEN - 1;
    out[last] &= 0x03;              /* csak a 0. és 1. bit marad: a paritásbit és a kitöltés 0 */


    //we expect the compiler to optimize this into 64 bit blocks
    uint8_t p = 0;
    for (size_t i = 0; i <= last; i++)
      p ^= out[i];

    out[last] |= (uint8_t)(__builtin_parity(p) << 2);

    return 0;
}

/* A csoportművelet itt is a XOR (GF(2) feletti polinom), ami saját maga
 * inverze, ezért az add és a sub is a közös xor_into. */
const kem_ops KEM_BIKE_L1 = {
    .pk_len = BIKE_L1_PK_LEN,
    .h1     = bike_l1_h1,
    .add    = xor_into,
    .sub    = xor_into,
};
