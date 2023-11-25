#include "../include/dpf.h"
#include "../include/prf.h"

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

EVP_CIPHER_CTX *PRFKeyGen(uint8_t *key)
{
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        printf("an error ocurred when creating EVP_CIPHER_CTX\n");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        printf("errors ocurred in generating new AES key\n");

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    return ctx;
}

void destroyPRFKey(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}

void PRFEval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs)
{
    int len = 0;
    if (1 != EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16))
        printf("errors ocurred in PRF evaluation\n");
}

// PRF used to expand the DPF tree. Just a call to AES-ECB.
// Note: we use ECB-mode (instead of CTR) as we want to manage each block separately.
void PRFBatchEval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs, int num_blocks)
{
    static int len = 0; // make static to avoid reallocating
    if (1 != EVP_EncryptUpdate(ctx, (uint8_t *)outputs, &len, (uint8_t *)input, 16 * num_blocks))
        printf("errors ocurred in PRF evaluation\n");
}
