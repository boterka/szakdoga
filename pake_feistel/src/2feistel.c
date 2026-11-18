#include "2feistel.h"
#include "common_hashes.h"
#include "kem_operations.h"

#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>


int feistel2_encrypt(uint8_t *out, const uint8_t *pk,
                     const uint8_t *pw, size_t pwlen,
                     const uint8_t *sid, size_t sidlen,
                     const kem_ops *kem, const uint8_t r[NONCE_LEN])
{
    uint8_t *t = out;
    uint8_t *s = out + NONCE_LEN;
    uint8_t h2[NONCE_LEN];

    /* 1. kör: s = pk + H1(pw, sid, r) */
    uint8_t *mask = malloc(kem->pk_len);
    if (mask == NULL) return -1;
    if (kem->h1(mask, pw, pwlen, sid, sidlen, r) != 0) {
        free(mask);
        return -1;
    }
    memcpy(s, pk, kem->pk_len);
    kem->add(s, mask, kem->pk_len);
    OQS_MEM_cleanse(mask, kem->pk_len);
    free(mask);

    /* 2. kör: t = r XOR H2(pw, sid, s) */
    if (hash_h2(h2, pw, pwlen, sid, sidlen, s, kem->pk_len) != 0) return -1;
    memcpy(t, r, NONCE_LEN);
    xor_into(t, h2, NONCE_LEN);
    OQS_MEM_cleanse(h2, sizeof h2);

    return 0;
}

int feistel2_decrypt(uint8_t *pk_out, const uint8_t *in,
                     const uint8_t *pw, size_t pwlen,
                     const uint8_t *sid, size_t sidlen,
                     const kem_ops *kem)
{
    uint8_t *t = in;
    uint8_t *s = in + NONCE_LEN;
    uint8_t r[NONCE_LEN];
    uint8_t h2[NONCE_LEN];

    // 2. kör r = t xor H2(pw, sid, s)
    if (hash_h2(h2, pw, pwlen, sid, sidlen, s, kem->pk_len) != 0) return -1;
    memcpy(r, t, NONCE_LEN);
    xor_into(r, h2, NONCE_LEN);
    OQS_MEM_cleanse(h2, NONCE_LEN);
    
    // 1. kör pk = s - H1(pw, sid, r)
    uint8_t *mask = malloc(kem->pk_len);
    if (mask == NULL)
    {
      OQS_MEM_cleanse(r, NONCE_LEN);
      return -1;
    }
    
    if (kem->h1(mask, pw, pwlen, sid, sidlen, r) != 0)
    {
        OQS_MEM_cleanse(mask, kem->pk_len);
        free(mask);
        OQS_MEM_cleanse(r, NONCE_LEN);
        return -1;
    }
    memcpy(pk_out, s, kem->pk_len);
    kem->sub(pk_out, mask, kem->pk_len);
    OQS_MEM_cleanse(mask, kem->pk_len);
    free(mask);
    OQS_MEM_cleanse(r, NONCE_LEN);
    return 0;
    
}

