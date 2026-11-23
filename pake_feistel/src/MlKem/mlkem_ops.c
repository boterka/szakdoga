/* src/MlKem/mlkem_ops.c */
#include <string.h>
#include <oqs/oqs.h>
#include "kem_operations.h"
#include "common_hashes.h"
#include <oqs/sha3.h>
/* ML-KEM-512 (Module-Lattice-based Key Encapsulation Mechanism, FIPS 203,
 * NIST 1. biztonsági szint) nyilvános kulcs hossza a liboqs-ból (800 bájt).
 *
 * A pk felépítése (FIPS 203, K-PKE.KeyGen):
 *   pk = t (K * 256 együttható, mindegyik 12 biten pakolva) || rho (32 bájt seed)
 * ML-KEM-512-nél K = 2, tehát a t rész 2 * 256 * 12 / 8 = 768 bájt.
 *
 * Megjegyzés: a liboqs (és a FIPS 203) a t-t NTT (Number Theoretic Transform,
 * számelméleti transzformáció) tartományban tárolja. A maszkolásnál ez nem
 * számít: az NTT lineáris és kölcsönösen egyértelmű, így egy egyenletes mod q
 * maszk az NTT tartományban is egyenletes, és a mod q összeadás ott is
 * ugyanaz a csoportművelet. */
#define MLKEM512_PK_LEN    OQS_KEM_ml_kem_512_length_public_key

#define MLKEM_Q            3329                    /* a modulus, nem kettőhatvány */
#define MLKEM_N            256                     /* együttható polinomonként */
#define MLKEM512_K         2                       /* polinomok száma t-ben */
#define MLKEM512_COEFFS    (MLKEM512_K * MLKEM_N)  /* 512 együttható */
#define MLKEM512_T_LEN     (MLKEM512_COEFFS * 12 / 8)  /* 768 bájt */
#define MLKEM_SEED_LEN     32                      /* rho */



#define SHAKE128_RATE 168   /* egy squeeze-blokk, 3-mal osztható */



// SampleNTT (FIPS 203, Algorithm 7; Lorenzen Algorithm 5):
static void sample_ntt(const uint8_t *B, uint16_t *out)
{
  OQS_SHA3_shake128_inc_ctx ctx;
  
  OQS_SHA3_shake128_inc_init(&ctx);
  OQS_SHA3_shake128_inc_absorb(&ctx, B, 34);
  OQS_SHA3_shake128_inc_finalize(&ctx);
  uint8_t buf[3];
  uint16_t d1;
  uint16_t d2;

  unsigned int n = 0;
  while (n < MLKEM_N) {
    OQS_SHA3_shake128_inc_squeeze(buf, 3, &ctx);
    d1 = buf[0] + 256 * (buf[1] % 16);
    d2 = buf[1] / 16 + 16 * buf[2];

    if(d1 < MLKEM_Q)
      out[n++] = d1;

    if(d2 < MLKEM_Q && n < 256)
      out[n++] = d2;
  }
   
  OQS_MEM_cleanse(buf, sizeof buf);
  OQS_SHA3_shake128_inc_ctx_release(&ctx);
}

/* 12 bites pakolás (FIPS 203 ByteEncode_12): két együttható -> 3 bájt.
 *   a = a11..a0, b = b11..b0
 *   bájt0 = a alsó 8 bitje
 *   bájt1 = a felső 4 bitje | b alsó 4 bitje << 4
 *   bájt2 = b felső 8 bitje */
static void pack12(uint8_t *out, const uint16_t *c, size_t ncoeffs)
{
    for (size_t i = 0; i < ncoeffs; i += 2) {
        uint16_t a = c[i];
        uint16_t b = c[i + 1];
        out[0] = (uint8_t)(a & 0xFF);
        out[1] = (uint8_t)((a >> 8) | ((b & 0x0F) << 4));
        out[2] = (uint8_t)(b >> 4);
        out += 3;
    }
}

/* A pack12 inverze (FIPS 203 ByteDecode_12). */
static void unpack12(uint16_t *c, const uint8_t *in, size_t ncoeffs)
{
    for (size_t i = 0; i < ncoeffs; i += 2) {
        c[i]     = (uint16_t)(in[0] | ((in[1] & 0x0F) << 8));
        c[i + 1] = (uint16_t)((in[1] >> 4) | (in[2] << 4));
        in += 3;
    }
}


static int mlkem512_h1(uint8_t *out,
                       const uint8_t *pw, size_t pwlen,
                       const uint8_t *sid, size_t sidlen,
                       const uint8_t *r)
{
  uint8_t  seed[34];
  uint8_t  rho[32];
  uint16_t coeffs[MLKEM_N];
  int ret;

  ret = hash_pw_sid(0, pw, pwlen, sid, sidlen,
                      r, NONCE_LEN, seed, 32);
  if (ret != 0) goto cleanup;

  ret = hash_pw_sid(1, pw, pwlen, sid, sidlen,
                      r, NONCE_LEN, rho, 32);
  if (ret != 0) goto cleanup;

  seed[32] = 0;
  for (uint8_t i = 0; i < MLKEM512_K; i++) {
    seed[33] = i;        
    sample_ntt(seed, coeffs);
    pack12(out + i * (MLKEM_N * 12 / 8), coeffs, MLKEM_N);   /* 384 bájt / polinom */
  }
    memcpy(out + MLKEM512_T_LEN, rho, MLKEM_SEED_LEN);

cleanup:
    OQS_MEM_cleanse(seed, sizeof seed);
    OQS_MEM_cleanse(rho, sizeof rho);
    OQS_MEM_cleanse(coeffs, sizeof coeffs);
    return ret;
}

/* A csoportművelet itt NEM a XOR: a t rész együtthatónként mod q összeadás,
 * mert q = 3329 nem kettőhatvány (a XOR q fölé vihetne egy együtthatót).
 * Menete: kicsomagolás, mod q művelet, visszacsomagolás.
 * A rho rész 32 egyenletes bájt, azt XOR-ral maszkoljuk.
 * A len paramétert nem használjuk, mindig MLKEM512_PK_LEN bájttal dolgozunk.
 *
 * TODO: a visszafejtő oldalon a hálózatról jövő s-ben lehet q-nál nagyobb
 * együttható (egy valódi s-ben soha). Ezt érdemes lenne elutasítani, mint a
 * FIPS 203 modulus-ellenőrzésében. */
static void mlkem512_add(uint8_t *dst, const uint8_t *mask, size_t len)
{
    uint16_t a[MLKEM512_COEFFS];
    uint16_t m[MLKEM512_COEFFS];

    unpack12(a, dst, MLKEM512_COEFFS);
    unpack12(m, mask, MLKEM512_COEFFS);
    for (size_t i = 0; i < MLKEM512_COEFFS; i++)
        a[i] = (uint16_t)((a[i] + m[i]) % MLKEM_Q);
    pack12(dst, a, MLKEM512_COEFFS);

    xor_into(dst + MLKEM512_T_LEN, mask + MLKEM512_T_LEN, MLKEM_SEED_LEN);

    OQS_MEM_cleanse(m, sizeof m);
}

static void mlkem512_sub(uint8_t *dst, const uint8_t *mask, size_t len)
{
    uint16_t a[MLKEM512_COEFFS];
    uint16_t m[MLKEM512_COEFFS];

    unpack12(a, dst, MLKEM512_COEFFS);
    unpack12(m, mask, MLKEM512_COEFFS);
    for (size_t i = 0; i < MLKEM512_COEFFS; i++)
        a[i] = (uint16_t)((a[i] + MLKEM_Q - m[i]) % MLKEM_Q);  /* +q, hogy ne legyen negatív */
    pack12(dst, a, MLKEM512_COEFFS);

    xor_into(dst + MLKEM512_T_LEN, mask + MLKEM512_T_LEN, MLKEM_SEED_LEN);

    OQS_MEM_cleanse(m, sizeof m);
}

const kem_ops KEM_MLKEM512 = {
    .pk_len = MLKEM512_PK_LEN,
    .h1     = mlkem512_h1,
    .add    = mlkem512_add,
    .sub    = mlkem512_sub,
};
