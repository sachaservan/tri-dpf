#include "../include/fastdpf.h"
#include "../include/prf.h"
#include "../include/utils.h"
#include <openssl/rand.h>

// Naming conventions:
// - L,R refer to the left and right child nodes on the DPF/GGM tree
// - A,B refer to shares given to parties A and B
// - 0,1,2 refer to the branch index in the ternary tree

#define XOR_BATCH 4096 // has to be a power of 2

void FastDPFGen(
    EVP_CIPHER_CTX *prfKey0,
    EVP_CIPHER_CTX *prfKey1,
    int size,
    uint64_t index,
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

        PRFEval(prfKey0, &parentB, &sB0);
        PRFEval(prfKey1, &parentB, &sB1);

        // set the third seed to be the xor of the siblings and the parent
        sA2 = sA0 ^ sA1 ^ parentA;
        sB2 = sB0 ^ sB1 ^ parentB;

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
unsigned char *FastDPFFullDomainEval(
    EVP_CIPHER_CTX *prfKey0,
    EVP_CIPHER_CTX *prfKey1,
    unsigned char *k,
    int size)
{

    // uint64_t full_eval_size = pow(3, size);
    uint64_t num_leaves = pow(3, size);
    uint128_t *parents = malloc(sizeof(uint128_t) * num_leaves);
    uint128_t *new_parents = malloc(sizeof(uint128_t) * num_leaves);

    memcpy(&parents[0], &k[0], 16); // parents[0] is the start seed
    uint128_t *sCW0 = (uint128_t *)&k[16];
    uint128_t *sCW1 = (uint128_t *)&k[16 * size + 16];
    uint128_t *sCW2 = (uint128_t *)&k[16 * 2 * size + 16];

    uint64_t idx0, idx1, idx2; // indices of the left, middle, and right nodes
    uint64_t num_nodes = 1;
    uint64_t two_num_nodes = 2 * num_nodes;

    uint128_t *restrict p0;
    uint128_t *restrict p1;
    uint128_t *restrict p2;
    uint128_t *restrict np0;
    uint128_t *restrict np1;
    uint128_t *restrict np2;

    int i = 0;
    int j = 0;
    int l = 0;
    for (; i < size; i++)
    {
        PRFBatchEval(prfKey0, parents, &new_parents[0], num_nodes);
        PRFBatchEval(prfKey1, parents, &new_parents[num_nodes], num_nodes);

        if (num_nodes > XOR_BATCH)
        {
            for (j = 0; j < num_nodes - XOR_BATCH; j += XOR_BATCH)
            {
                uint128_t *restrict p1 = __builtin_assume_aligned(&new_parents[two_num_nodes + j], XOR_BATCH);
                uint128_t *restrict p2 = __builtin_assume_aligned(&new_parents[j], XOR_BATCH);
                uint128_t *restrict p3 = __builtin_assume_aligned(&parents[j], XOR_BATCH);
                uint128_t *restrict p4 = __builtin_assume_aligned(&new_parents[num_nodes + j], XOR_BATCH);

                l = 0;
                for (; l < XOR_BATCH; l++)
                    p1[l] = p2[l] ^ p3[l] ^ p4[l];
            }

            j = num_nodes - num_nodes % XOR_BATCH;
            for (; j < num_nodes; j++)
                new_parents[two_num_nodes + j] = new_parents[j] ^ parents[j] ^ new_parents[num_nodes + j];
        }
        else
        {
            for (j = 0; j < num_nodes; j++)
                new_parents[two_num_nodes + j] = new_parents[j] ^ parents[j] ^ new_parents[num_nodes + j];
        }

        idx0 = 0;
        idx1 = num_nodes;
        idx2 = two_num_nodes;

        if (num_nodes > XOR_BATCH)
        {
            for (; idx0 < num_nodes - XOR_BATCH; idx0 += XOR_BATCH)
            {
                p0 = __builtin_assume_aligned(&parents[idx0], XOR_BATCH);
                p1 = __builtin_assume_aligned(&parents[idx1], XOR_BATCH);
                p2 = __builtin_assume_aligned(&parents[idx2], XOR_BATCH);
                np0 = __builtin_assume_aligned(&new_parents[idx0], XOR_BATCH);
                np1 = __builtin_assume_aligned(&new_parents[idx1], XOR_BATCH);
                np2 = __builtin_assume_aligned(&new_parents[idx2], XOR_BATCH);

                l = 0;
                for (; l < XOR_BATCH; l++)
                {
                    uint8_t cb = p0[l] & 1; // gets the LSB of the parent
                    p0[l] = np0[l] ^ (cb * sCW0[i]);
                    p1[l] = np1[l] ^ (cb * sCW1[i]);
                    p2[l] = np2[l] ^ (cb * sCW2[i]);
                }

                idx1 += XOR_BATCH;
                idx2 += XOR_BATCH;
            }

            idx0 = num_nodes - num_nodes % XOR_BATCH;
            idx1 = idx0 + num_nodes;
            idx2 = idx1 + num_nodes;
            for (; idx0 < num_nodes; idx0++)
            {
                uint8_t cb = parents[idx0] & 1; // gets the LSB of the parent
                parents[idx0] = new_parents[idx0] ^ (cb * sCW0[i]);
                parents[idx1] = new_parents[idx1] ^ (cb * sCW1[i]);
                parents[idx2] = new_parents[idx2] ^ (cb * sCW2[i]);

                idx1++;
                idx2++;
            }
        }
        else
        {
            for (; idx0 < num_nodes; idx0++)
            {
                uint8_t cb = parents[idx0] & 1; // gets the LSB of the parent
                parents[idx0] = new_parents[idx0] ^ (cb * sCW0[i]);
                parents[idx1] = new_parents[idx1] ^ (cb * sCW1[i]);
                parents[idx2] = new_parents[idx2] ^ (cb * sCW2[i]);

                idx1++;
                idx2++;
            }
        }

        num_nodes *= 3;
        two_num_nodes = 2 * num_nodes;
    }

    free(new_parents);
    return (unsigned char *)parents;
}
