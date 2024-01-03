#ifndef _FASTDPF
#define _FASTDPF

#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

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

#endif
