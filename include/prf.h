#ifndef _PRF
#define _PRF

#include <stdint.h>
#include <openssl/evp.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

struct PRFKeys
{
    EVP_CIPHER_CTX *prf_key0;
    EVP_CIPHER_CTX *prf_key1;
    EVP_CIPHER_CTX *prf_key2;
    EVP_CIPHER_CTX *prf_key_ext;
};

void PRFKeyGen(struct PRFKeys *prf_keys);
void DestroyPRFKey(struct PRFKeys *prf_keys);

// XOR with input to prevent inversion using Davies–Meyer construction
static inline void PRFEval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs)
{
    int len = 0;
    if (1 != EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16))
        printf("errors ocurred in PRF evaluation\n");

    outputs[0] ^= input[0];
}

// PRF used to expand the DPF tree. Just a call to AES-ECB.
// Note: we use ECB-mode (instead of CTR) as we want to manage each block separately.
// XOR with input to prevent inversion using Davies–Meyer construction
static inline void PRFBatchEval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs, int num_blocks)
{
    static int len = 0; // make static to avoid reallocating
    EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16 * num_blocks);

    for (size_t i = 0; i < num_blocks; i++)
        outputs[i] ^= input[i];

    // DEBUG
    // if (1 != EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16 * num_blocks))
    //     printf("errors ocurred in PRF evaluation\n");
}

#endif
