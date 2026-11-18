#ifndef KEM_OPERATIONS_H
#define KEM_OPERATIONS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t pk_len;   /* a nyilvános kulcs hossza */
    /* H1: (pw, sid, r) -> pk_len bájtos, érvényes kulcsnak látszó maszk */
    int  (*h1)(uint8_t *out,
               const uint8_t *pw, size_t pwlen,
               const uint8_t *sid, size_t sidlen,
               const uint8_t *r);
    void (*add)(uint8_t *dst, const uint8_t *mask, size_t len);
    void (*sub)(uint8_t *dst, const uint8_t *mask, size_t len);
} kem_ops;

extern const kem_ops KEM_FRODO640;
//extern const kem_ops KEM_MLKEM768;

#endif
