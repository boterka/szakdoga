/* Demo: FrodoKEM-640 kulcspár a liboqs-szal, a nyilvános kulcs titkosítása
 * a 2 körös Feistel-hálóval, visszafejtés, összehasonlítás. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>
#include "2feistel.h"

int main(void)
{
    const kem_ops *kem = &KEM_FRODO640;

    uint8_t pk[OQS_KEM_frodokem_640_shake_length_public_key];
    uint8_t sk[OQS_KEM_frodokem_640_shake_length_secret_key];
    uint8_t r[NONCE_LEN];
    const uint8_t pw[]  = "correct horse battery staple";
    const uint8_t sid[] = "session-0001";

    uint8_t *enc = malloc(FEISTEL_OUT_LEN(kem));
    uint8_t *dec = malloc(kem->pk_len);
    if (enc == NULL || dec == NULL) return 1;

    if (OQS_KEM_frodokem_640_shake_keypair(pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }
    printf("FrodoKEM-640 keypair OK (pk = %zu bytes)\n", kem->pk_len);

    OQS_randombytes(r, NONCE_LEN);

    if (feistel2_encrypt(enc, pk, pw, sizeof pw - 1, sid, sizeof sid - 1, kem, r) != 0) {
        fprintf(stderr, "encrypt failed\n");
        return 1;
    }
    printf("encrypt OK (out = %zu bytes)\n", (size_t)FEISTEL_OUT_LEN(kem));

    if (feistel2_decrypt(dec, enc, pw, sizeof pw - 1, sid, sizeof sid - 1, kem) != 0) {
        printf("decrypt not implemented yet (stub returns -1)\n");
    } else {
        printf("round trip: %s\n", memcmp(pk, dec, sizeof pk) == 0 ? "OK" : "MISMATCH");
    }

    OQS_MEM_cleanse(sk, sizeof sk);
    free(enc);
    free(dec);
    return 0;
}
