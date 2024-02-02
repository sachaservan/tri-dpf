#include "../include/dpf.h"
#include "../include/prf.h"
#include "../include/utils.h"

#include <openssl/rand.h>

#define LOG_BATCH_SIZE 6 // operate in smallish batches to maximize cache hits

// Naming conventions:
// - A,B refer to shares given to parties A and B
// - 0,1,2 refer to the branch index in the ternary tree

void DPFGen(
	EVP_CIPHER_CTX *prfKey0,
	EVP_CIPHER_CTX *prfKey1,
	EVP_CIPHER_CTX *prfKey2,
	size_t size,
	uint64_t index,
	uint128_t msg,
	unsigned char *kA,
	unsigned char *kB)
{

	// starting seeds given to each party
	uint128_t seedA;
	uint128_t seedB;

	// correction word provided to both parties
	// (one correction word per level)
	uint128_t sCW0[size];
	uint128_t sCW1[size];
	uint128_t sCW2[size]; // TODO: can we remove the need for the third CW?

	// starting seeds are random
	RAND_bytes((uint8_t *)&seedA, 16);
	RAND_bytes((uint8_t *)&seedB, 16);

	// variables for the intermediate values
	uint128_t parent, parentA, parentB, sA0, sA1, sA2, sB0, sB1, sB2;

	// current parent value (xor of the two seeds)
	parent = seedA ^ seedB;

	// control bit of the parent on the special path must always be set to 1
	// so as to apply the corresponding correction word
	if (get_lsb(parent) == 0)
		seedA = flip_lsb(seedA);

	parentA = seedA;
	parentB = seedB;

	for (size_t i = 0; i < size; i++)
	{
		// expand the starting seeds of each party
		PRFEval(prfKey0, &parentA, &sA0);
		PRFEval(prfKey1, &parentA, &sA1);
		PRFEval(prfKey2, &parentA, &sA2);

		PRFEval(prfKey0, &parentB, &sB0);
		PRFEval(prfKey1, &parentB, &sB1);
		PRFEval(prfKey2, &parentB, &sB2);

		// on-path correction word is set to random
		// so as to be indistinguishable from the real correction words
		uint128_t r;
		RAND_bytes((uint8_t *)&r, sizeof(uint128_t));

		// get the current trit (ternary bit) of the special index
		uint8_t trit = get_trit(index, size, i);

		switch (trit)
		{
		case 0:
			parent = sA0 ^ sB0 ^ r;
			if (get_lsb(parent) == 0)
				r = flip_lsb(r);

			sCW0[i] = r;
			sCW1[i] = sA1 ^ sB1;
			sCW2[i] = sA2 ^ sB2;

			if (get_lsb(parentA) == 1)
			{
				parentA = sA0 ^ r;
				parentB = sB0;
			}
			else
			{
				parentA = sA0;
				parentB = sB0 ^ r;
			}

			break;

		case 1:
			parent = sA1 ^ sB1 ^ r;
			if (get_lsb(parent) == 0)
				r = flip_lsb(r);

			sCW0[i] = sA0 ^ sB0;
			sCW1[i] = r;
			sCW2[i] = sA2 ^ sB2;

			if (get_lsb(parentA) == 1)
			{
				parentA = sA1 ^ r;
				parentB = sB1;
			}
			else
			{
				parentA = sA1;
				parentB = sB1 ^ r;
			}

			break;

		case 2:
			parent = sA2 ^ sB2 ^ r;
			if (get_lsb(parent) == 0)
				r = flip_lsb(r);

			sCW0[i] = sA0 ^ sB0;
			sCW1[i] = sA1 ^ sB1;
			sCW2[i] = r;

			if (get_lsb(parentA) == 1)
			{
				parentA = sA2 ^ r;
				parentB = sB2;
			}
			else
			{
				parentA = sA2;
				parentB = sB2 ^ r;
			}

			break;

		default:
			printf("error: not a ternary digit!\n");
			exit(0);
		}
	}

	// set the last correction word to correct the output to msg
	uint8_t last_trit = get_trit(index, size, size - 1);
	if (last_trit == 0)
		sCW0[size - 1] ^= sCW0[size - 1] ^ sA0 ^ sB0 ^ msg;
	else if (last_trit == 1)
		sCW1[size - 1] ^= sCW1[size - 1] ^ sA1 ^ sB1 ^ msg;
	else if (last_trit == 2)
		sCW2[size - 1] ^= sCW2[size - 1] ^ sA2 ^ sB2 ^ msg;

	// memcpy all the generated values into two keys
	// 16 = sizeof(uint128_t)
	memcpy(&kA[0], &seedA, 16);
	memcpy(&kA[16], &sCW0[0], size * 16);
	memcpy(&kA[16 * size + 16], &sCW1[0], size * 16);
	memcpy(&kA[16 * 2 * size + 16], &sCW2[0], size * 16);

	memcpy(&kB[0], &seedB, 16);
	memcpy(&kB[16], &sCW0[0], size * 16);
	memcpy(&kB[16 * size + 16], &sCW1[0], size * 16);
	memcpy(&kB[16 * 2 * size + 16], &sCW2[0], size * 16);
}

// evaluates the full DPF domain; much faster than
// batching the evaluation points since each level of the DPF tree
// is only expanded once.
void DPFFullDomainEval(
	EVP_CIPHER_CTX *prfKey0,
	EVP_CIPHER_CTX *prfKey1,
	EVP_CIPHER_CTX *prfKey2,
	uint128_t *cache,
	uint128_t *output,
	const uint8_t *k,
	const uint8_t size)
{

	if (size % 2 == 1)
	{
		uint128_t *tmp = cache;
		cache = output;
		output = tmp;
	}

	// full_eval_size = pow(3, size);
	const size_t num_leaves = ipow(3, size);

	memcpy(&output[0], &k[0], 16); // output[0] is the start seed
	const uint128_t *sCW0 = (uint128_t *)&k[16];
	const uint128_t *sCW1 = (uint128_t *)&k[16 * size + 16];
	const uint128_t *sCW2 = (uint128_t *)&k[16 * 2 * size + 16];

	// inner loop variables related to node expansion
	// and correction word application
	uint128_t *tmp;
	size_t idx0, idx1, idx2;
	uint8_t cb = 0;

	// batching variables related to chunking of inner loop processing
	// for the purpose of maximizing cache hits
	size_t max_batch_size = ipow(3, LOG_BATCH_SIZE);
	size_t batch, num_batches, batch_size, offset;

	size_t num_nodes = 1;
	for (uint8_t i = 0; i < size; i++)
	{
		if (i < LOG_BATCH_SIZE)
		{
			batch_size = num_nodes;
			num_batches = 1;
		}
		else
		{
			batch_size = max_batch_size;
			num_batches = num_nodes / max_batch_size;
		}

		offset = 0;
		for (batch = 0; batch < num_batches; batch++)
		{
			PRFBatchEval(prfKey0, &output[offset], &cache[offset], batch_size);
			PRFBatchEval(prfKey1, &output[offset], &cache[num_nodes + offset], batch_size);
			PRFBatchEval(prfKey2, &output[offset], &cache[(num_nodes * 2) + offset], batch_size);

			idx0 = offset;
			idx1 = num_nodes + offset;
			idx2 = (num_nodes * 2) + offset;

			while (idx0 < offset + batch_size)
			{
				cb = output[idx0] & 1; // gets the LSB of the parent
				cache[idx0] ^= (cb * sCW0[i]);
				cache[idx1] ^= (cb * sCW1[i]);
				cache[idx2] ^= (cb * sCW2[i]);

				idx0++;
				idx1++;
				idx2++;
			}

			offset += batch_size;
		}

		tmp = output;
		output = cache;
		cache = tmp;

		num_nodes *= 3;
	}
}
