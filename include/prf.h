#ifndef _PRF
#define _PRF

#include <stdint.h>
#include <openssl/evp.h>

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

static inline uint128_t flip_lsb(uint128_t input)
{
	return input ^ 1;
}

static inline uint128_t get_lsb(uint128_t input)
{
	return input & 1;
}

static inline int get_trit(uint64_t x, int size, int t)
{

	int ternary[size];
	for (int i = 0; i < size; i++)
	{
		ternary[i] = x % 3;
		x /= 3;
	}

	return ternary[t];
}

static inline int get_bit(uint128_t x, int size, int b)
{
	return ((x) >> (size - b)) & 1;
}

static void printBytes(void *p, int num)
{
	unsigned char *c = (unsigned char *)p;
	for (int i = 0; i < num; i++)
	{
		printf("%02x", c[i]);
	}
	printf("\n");
}

EVP_CIPHER_CTX *PRFKeyGen(uint8_t *key);
void destroyPRFKey(EVP_CIPHER_CTX *ctx);
void PRFEval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs);
void PRFBatchEval(EVP_CIPHER_CTX *ctx, uint128_t *input, uint128_t *outputs, int num_blocks);

#endif
