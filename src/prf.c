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

void DestroyPRFKey(EVP_CIPHER_CTX *ctx)
{
    EVP_CIPHER_CTX_free(ctx);
}
