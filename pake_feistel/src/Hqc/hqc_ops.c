/* src/Hqc/hqc_ops.c */
#include <oqs/oqs.h>
#include "kem_operations.h"
#include "common_hashes.h"

/* HQC-1 (Hamming Quasi-Cyclic, NIST 1. biztonsági szint) nyilvános kulcs
 * hossza a liboqs-ból (2241 bájt). A liboqs 0.16-ban a paraméterkészletek
 * neve hqc_1 / hqc_3 / hqc_5 (a régi hqc_128 / 192 / 256 helyett). */
#define HQC1_PK_LEN OQS_KEM_hqc_1_length_public_key

/* A pk felépítése (liboqs: pqc-hqc_hqc-1_ref/parsing.c, hqc_ek_pke_from_string):
 *   pk = seed_ek (32 bájt) || s (VEC_N_SIZE_BYTES = ceil(n / 8) bájt)
 * ahol n = 17669 bit. 2209 * 8 = 17672, tehát az s utolsó bájtjának
 * felső 3 bitje kitöltőbit, egy valódi kulcsban mindig 0. */
#define HQC1_SEED_LEN   32
#define HQC1_N          17669
#define HQC1_S_LEN      ((HQC1_N + 7) / 8)

static int hqc1_h1(uint8_t *out,
                   const uint8_t *pw, size_t pwlen,
                   const uint8_t *sid, size_t sidlen,
                   const uint8_t *r)
{
    /* 1. lépés: pk_len bájt SHAKE256 kimenet, ugyanúgy, mint a FrodoKEM-nél. */
    int ret = hash_pw_sid(TAG_H1, pw, pwlen, sid, sidlen,
                          r, NONCE_LEN, out, HQC1_PK_LEN);
    if (ret != 0) return ret;

    ret[HQC1_PK_LEN - 1] &= 0x1F;
    return 0;
}

const kem_ops KEM_HQC1 = {
    .pk_len = HQC1_PK_LEN,
    .h1     = hqc1_h1,
    .add    = xor_into,
    .sub    = xor_into,
};
