#ifndef _DPF
#define _DPF

#include <math.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

void innerLoop(
    EVP_CIPHER_CTX *prfKey0,
    EVP_CIPHER_CTX *prfKey1,
    EVP_CIPHER_CTX *prfKey2,
    size_t batch_size,
    size_t num_batches,
    size_t num_nodes,
    uint128_t cw0,
    uint128_t cw1,
    uint128_t cw2,
    uint128_t *parents,
    uint128_t *new_parents);

extern void DPFGen(EVP_CIPHER_CTX *prfKey0,
                   EVP_CIPHER_CTX *prfKey1,
                   EVP_CIPHER_CTX *prfKey2,
                   int size,
                   uint64_t index,
                   uint128_t msg,
                   unsigned char *k0,
                   unsigned char *k1);

extern unsigned char *DPFFullDomainEval(
    EVP_CIPHER_CTX *prfKey0,
    EVP_CIPHER_CTX *prfKey1,
    EVP_CIPHER_CTX *prfKey2,
    const uint8_t *k,
    const uint8_t size);

#endif
