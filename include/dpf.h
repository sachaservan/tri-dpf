#ifndef _DPF
#define _DPF

#include <math.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define FIELDSIZE 2
#define FIELDBITS 1

#define FIELDMASK ((1L << FIELDBITS) - 1)

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

// PRG cipher context
extern EVP_CIPHER_CTX *getDPFContext(uint8_t *);
extern void destroyContext(EVP_CIPHER_CTX *);

extern void DPFGen(EVP_CIPHER_CTX *prfKey0,
                   EVP_CIPHER_CTX *prfKey1,
                   EVP_CIPHER_CTX *prfKey2,
                   int size,
                   uint64_t index,
                   unsigned char *k0,
                   unsigned char *k1);

void DPFFullDomainEval(
    EVP_CIPHER_CTX *prfKey0,
    EVP_CIPHER_CTX *prfKey1,
    EVP_CIPHER_CTX *prfKey2,
    unsigned char *k,
    int size,
    uint128_t *out);

#endif
