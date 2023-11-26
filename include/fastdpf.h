#ifndef _FASTDPF
#define _FASTDPF

#include <math.h>
#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

extern void FastDPFGen(EVP_CIPHER_CTX *prfKey0,
                       EVP_CIPHER_CTX *prfKey1,
                       int size,
                       uint64_t index,
                       unsigned char *k0,
                       unsigned char *k1);

extern unsigned char *FastDPFFullDomainEval(
    EVP_CIPHER_CTX *prfKey0,
    EVP_CIPHER_CTX *prfKey1,
    unsigned char *k,
    int size);

#endif
