/* Demo: mind az 5 KEM (FrodoKEM-640, HQC-1, BIKE-L1, ML-KEM-512, Classic
 * McEliece 348864) kipróbálása a 2 körös Feistel-hálóval:
 * kulcspár a liboqs-szal, titkosítás, visszafejtés, összehasonlítás.
 * Mellé egy rossz jelszavas visszafejtés is, aminek NEM szabad egyeznie. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#include <oqs/oqs.h>
#include "2feistel.h"
 
/* A liboqs kulcspár-függvényeinek közös alakja, pl. OQS_KEM_hqc_1_keypair */
typedef OQS_STATUS (*keypair_fn)(uint8_t *pk, uint8_t *sk);
 
/* Egy KEM egy körös próbája. 0 = rendben, -1 = hiba.
 * A kulcsokat malloc-kal foglaljuk, mert a McEliece pk-ja ~261 KB,
 * az már túl nagy lenne a veremre. */
static int test_kem(const char *name, const kem_ops *kem,
                    keypair_fn keypair, size_t sk_len)
{
    const uint8_t pw[]       = "correct horse battery staple";
    const uint8_t wrong_pw[] = "correct horse battery stapler";
    const uint8_t sid[]      = "session-0001";
    uint8_t r[NONCE_LEN];
    int result = -1;
 
    uint8_t *pk  = malloc(kem->pk_len);
    uint8_t *sk  = malloc(sk_len);
    uint8_t *enc = malloc(FEISTEL_OUT_LEN(kem));
    uint8_t *dec = malloc(kem->pk_len);
    if (pk == NULL || sk == NULL || enc == NULL || dec == NULL) {
        printf("%-12s malloc hiba\n", name);
        goto cleanup;
    }
 
    if (keypair(pk, sk) != OQS_SUCCESS) {
        printf("%-12s keypair hiba\n", name);
        goto cleanup;
    }
 
    OQS_randombytes(r, NONCE_LEN);
 
    if (feistel2_encrypt(enc, pk, pw, sizeof pw - 1, sid, sizeof sid - 1, kem, r) != 0) {
        printf("%-12s encrypt hiba\n", name);
        goto cleanup;
    }
 
    /* jó jelszó: vissza kell kapnunk a pk-t */
    if (feistel2_decrypt(dec, enc, pw, sizeof pw - 1, sid, sizeof sid - 1, kem) != 0) {
        printf("%-12s decrypt hiba\n", name);
        goto cleanup;
    }
    int ok = (memcmp(pk, dec, kem->pk_len) == 0);
 
    /* rossz jelszó: nem szabad visszakapnunk a pk-t */
    if (feistel2_decrypt(dec, enc, wrong_pw, sizeof wrong_pw - 1, sid, sizeof sid - 1, kem) != 0) {
        printf("%-12s decrypt hiba (rossz jelszó)\n", name);
        goto cleanup;
    }
    int wrong_differs = (memcmp(pk, dec, kem->pk_len) != 0);
 
    printf("%-12s pk = %6zu bájt | jó jelszó: %s | rossz jelszó: %s\n",
           name, kem->pk_len,
           ok ? "OK" : "MISMATCH",
           wrong_differs ? "OK (eltér)" : "HIBA (egyezik)");
 
    if (ok && wrong_differs)
        result = 0;
 
cleanup:
    if (sk != NULL)
        OQS_MEM_cleanse(sk, sk_len);
    free(pk);
    free(sk);
    free(enc);
    free(dec);
    return result;
}
 
int main(void)
{
    int failures = 0;
 
    if (test_kem("FrodoKEM-640", &KEM_FRODO640, OQS_KEM_frodokem_640_shake_keypair,
                 OQS_KEM_frodokem_640_shake_length_secret_key) != 0)
        failures++;
 
    if (test_kem("HQC-1", &KEM_HQC1, OQS_KEM_hqc_1_keypair,
                 OQS_KEM_hqc_1_length_secret_key) != 0)
        failures++;
 
    if (test_kem("BIKE-L1", &KEM_BIKE_L1, OQS_KEM_bike_l1_keypair,
                 OQS_KEM_bike_l1_length_secret_key) != 0)
        failures++;
 
    if (test_kem("ML-KEM-512", &KEM_MLKEM512, OQS_KEM_ml_kem_512_keypair,
                 OQS_KEM_ml_kem_512_length_secret_key) != 0)
        failures++;
 
    if (test_kem("McEliece", &KEM_MCE348864, OQS_KEM_classic_mceliece_348864_keypair,
                 OQS_KEM_classic_mceliece_348864_length_secret_key) != 0)
        failures++;
 
    printf("%s\n", failures == 0 ? "MINDEN RENDBEN" : "VAN HIBA");
    return failures == 0 ? 0 : 1;
}
 
