#include "dpf.h"
#include "prf.h"

#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

EVP_CIPHER_CTX *InitKey(uint8_t *key)
{
    EVP_CIPHER_CTX *ctx;

    if (!(ctx = EVP_CIPHER_CTX_new()))
        printf("an error ocurred when creating EVP_CIPHER_CTX\n");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        printf("errors ocurred in generating new AES key\n");

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    return ctx;
}

void PRFKeyGen(struct PRFKeys *prf_keys)
{
    uint8_t *key0 = malloc(sizeof(uint128_t));
    uint8_t *key1 = malloc(sizeof(uint128_t));
    uint8_t *key2 = malloc(sizeof(uint128_t));
    uint8_t *key_ext = malloc(sizeof(uint128_t));

    RAND_bytes(key0, sizeof(uint128_t));
    RAND_bytes(key1, sizeof(uint128_t));
    RAND_bytes(key2, sizeof(uint128_t));
    RAND_bytes(key_ext, sizeof(uint128_t));

    EVP_CIPHER_CTX *prf_key0 = InitKey(key0);
    EVP_CIPHER_CTX *prf_key1 = InitKey(key1);
    EVP_CIPHER_CTX *prf_key2 = InitKey(key2);
    EVP_CIPHER_CTX *prf_key_ext = InitKey(key_ext);

    prf_keys->prf_key0 = prf_key0;
    prf_keys->prf_key1 = prf_key1;
    prf_keys->prf_key2 = prf_key2;
    prf_keys->prf_key_ext = prf_key_ext;
}

void DestroyPRFKey(struct PRFKeys *prf_keys)
{
    EVP_CIPHER_CTX_free(prf_keys->prf_key0);
    EVP_CIPHER_CTX_free(prf_keys->prf_key1);
    EVP_CIPHER_CTX_free(prf_keys->prf_key2);
    EVP_CIPHER_CTX_free(prf_keys->prf_key_ext);
    free(prf_keys);
}
