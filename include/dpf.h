#ifndef _DPF
#define _DPF

#include <stdio.h>
#include <string.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "prf.h"

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

void DPFGen(
    struct PRFKeys *prf_keys,
    size_t size,
    uint64_t index,
    uint128_t msg,
    unsigned char *k0,
    unsigned char *k1);

void DPFFullDomainEval(
    struct PRFKeys *prf_keys,
    uint128_t *cache,
    uint128_t *output,
    const uint8_t *k,
    const uint8_t size);

void HalfDPFGen(
    struct PRFKeys *prf_keys,
    int size,
    uint64_t index,
    uint128_t msg,
    unsigned char *k0,
    unsigned char *k1);

void HalfDPFFullDomainEval(
    struct PRFKeys *prf_keys,
    uint128_t *cache,
    uint128_t *output,
    const unsigned char *k,
    const uint8_t size);

int ExtendOutput(
    struct PRFKeys *prf_keys,
    uint128_t *output,
    uint128_t *new_output,
    const size_t output_size,
    const size_t new_output_size);

#endif
