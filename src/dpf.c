#include "../include/dpf.h"
#include "../include/prf.h"
#include "../include/utils.h"
#include <openssl/rand.h>

// Naming conventions:
// - A,B refer to shares given to parties A and B
// - 0,1,2 refer to the branch index in the ternary tree

void DPFGen(
	EVP_CIPHER_CTX *prfKey0,
	EVP_CIPHER_CTX *prfKey1,
	EVP_CIPHER_CTX *prfKey2,
	int size,
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

	for (int i = 0; i < size; i++)
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

void innerLoop(
	EVP_CIPHER_CTX *prfKey0,
	EVP_CIPHER_CTX *prfKey1,
	EVP_CIPHER_CTX *prfKey2,
	size_t batch_size,
	size_t num_batches,
	size_t num_nodes,
	uint128_t cw0,
	uint128_t cw1,
	uint128_t cw2,
	uint128_t *parents,
	uint128_t *new_parents)
{

	uint8_t cb;
	size_t idx0, idx1, idx2;
	size_t offset = 0;
	for (size_t b = 0; b < num_batches; b++)
	{
		PRFBatchEval(prfKey0, &parents[offset], &new_parents[offset], batch_size);
		PRFBatchEval(prfKey1, &parents[offset], &new_parents[num_nodes + offset], batch_size);
		PRFBatchEval(prfKey2, &parents[offset], &new_parents[(num_nodes * 2) + offset], batch_size);

		idx0 = offset;
		idx1 = num_nodes + offset;
		idx2 = (num_nodes * 2) + offset;

		while (idx0 < offset + batch_size)
		{
			cb = parents[idx0] & 1; // gets the LSB of the parent
			new_parents[idx0] ^= (cb * cw0);
			new_parents[idx1] ^= (cb * cw1);
			new_parents[idx2] ^= (cb * cw2);

			idx0++;
			idx1++;
			idx2++;
		}

		offset += batch_size;
	}
}

// evaluates the full DPF domain; much faster than
// batching the evaluation points since each level of the DPF tree
// is only expanded once.
unsigned char *DPFFullDomainEval(
	EVP_CIPHER_CTX *prfKey0,
	EVP_CIPHER_CTX *prfKey1,
	EVP_CIPHER_CTX *prfKey2,
	const uint8_t *k,
	const uint8_t size)
{
	// full_eval_size = pow(3, size);
	const size_t num_leaves = pow(3, size);

	uint128_t *parents = malloc(sizeof(uint128_t) * num_leaves);
	uint128_t *new_parents = malloc(sizeof(uint128_t) * num_leaves);
	uint128_t *tmp;

	memcpy(&parents[0], &k[0], 16); // parents[0] is the start seed
	const uint128_t *sCW0 = (uint128_t *)&k[16];
	const uint128_t *sCW1 = (uint128_t *)&k[16 * size + 16];
	const uint128_t *sCW2 = (uint128_t *)&k[16 * 2 * size + 16];

	size_t idx0;
	uint8_t cb = 0;

	size_t num_nodes = 1;
	size_t b, offset;
	for (uint8_t i = 0; i < size; i++)
	{

		size_t batch_size = pow(3, 5);
		size_t num_batches = num_nodes / batch_size;
		if (i < 6)
		{
			batch_size = num_nodes;
			num_batches = 1;
		}

		innerLoop(
			prfKey0,
			prfKey1,
			prfKey2,
			batch_size,
			num_batches,
			num_nodes,
			sCW0[i],
			sCW1[i],
			sCW2[i],
			parents,
			new_parents);

		tmp = parents;
		parents = new_parents;
		new_parents = tmp;

		num_nodes *= 3;
	}

	free(new_parents);
	return (unsigned char *)parents;
}
