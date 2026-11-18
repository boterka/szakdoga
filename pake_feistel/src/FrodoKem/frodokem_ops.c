/* src/FrodoKem/frodokem_ops.c */
#include <oqs/oqs.h>
#include <oqs/sha3.h>
#include "kem_operations.h"
#include "common_hashes.h"

/* FrodoKEM-640 (SHAKE változat) nyilvános kulcs hossza a liboqs-ból */
#define FRODO640_PK_LEN OQS_KEM_frodokem_640_shake_length_public_key


static int frodo640_h1(uint8_t *out,
                       const uint8_t *pw, size_t pwlen,
                       const uint8_t *sid, size_t sidlen,
                       const uint8_t *r)
{
    /* FrodoKEM-nél a pk minden bitmintája érvényes, ezért a H1 kimenete
     * egyszerűen pk_len bájt SHAKE256 kimenet. */
    return hash_pw_sid(TAG_H1, pw, pwlen, sid, sidlen, r, NONCE_LEN,
                       out, FRODO640_PK_LEN);
}
/* A csoportművelet FrodoKEM-nél a XOR, ami saját maga inverze,
 * ezért az add és a sub is a közös xor_into. */
const kem_ops KEM_FRODO640 = {
    .pk_len = FRODO640_PK_LEN,
    .h1     = frodo640_h1,
    .add    = xor_into,
    .sub    = xor_into,
};
