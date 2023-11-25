#ifndef _PRF
#define _PRF

#include <stdint.h>
#include <openssl/evp.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

EVP_CIPHER_CTX *PRFKeyGen(uint8_t *key);
void DestroyPRFKey(EVP_CIPHER_CTX *ctx);
void PRFEval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs);
void PRFBatchEval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs, int num_blocks);

#endif
