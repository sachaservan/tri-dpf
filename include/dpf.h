#ifndef _DPF
#define _DPF

#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

void DPFGen(EVP_CIPHER_CTX *prfKey0,
            EVP_CIPHER_CTX *prfKey1,
            EVP_CIPHER_CTX *prfKey2,
            size_t size,
            uint64_t index,
            uint128_t msg,
            unsigned char *k0,
            unsigned char *k1);

void DPFFullDomainEval(
    EVP_CIPHER_CTX *prfKey0,
    EVP_CIPHER_CTX *prfKey1,
    EVP_CIPHER_CTX *prfKey2,
    uint128_t *cache,
    uint128_t *output,
    const uint8_t *k,
    const uint8_t size);

void FastDPFGen(EVP_CIPHER_CTX *prfKey0,
                EVP_CIPHER_CTX *prfKey1,
                EVP_CIPHER_CTX *prfKey2,
                int size,
                uint64_t index,
                uint128_t msg,
                unsigned char *k0,
                unsigned char *k1);

void FastDPFFullDomainEval(
    EVP_CIPHER_CTX *prfKey0,
    EVP_CIPHER_CTX *prfKey1,
    EVP_CIPHER_CTX *prfKey2,
    uint128_t *cache,
    uint128_t *output,
    const unsigned char *k,
    const uint8_t size);

int ExtendOutput(
    EVP_CIPHER_CTX *prfKey,
    uint128_t *output,
    uint128_t *new_output,
    const size_t output_size,
    const size_t new_output_size);

#endif
