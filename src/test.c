#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "../include/prf.h"
#include "../include/dpf.h"

#define FULLEVALDOMAIN 10
#define MAXRANDINDEX 1ULL << FULLEVALDOMAIN

uint64_t randIndex()
{
    srand(time(NULL));
    return ((uint64_t)rand()) % (MAXRANDINDEX);
}

void testDPF()
{
    size_t outl = pow(3, FULLEVALDOMAIN);
    int size = FULLEVALDOMAIN; // evaluation will result in 3^size points

    uint64_t secretIndex = 0; // randIndex();
    uint8_t *key0 = malloc(sizeof(uint128_t));
    uint8_t *key1 = malloc(sizeof(uint128_t));
    uint8_t *key2 = malloc(sizeof(uint128_t));

    RAND_bytes(key0, sizeof(uint128_t));
    RAND_bytes(key1, sizeof(uint128_t));
    RAND_bytes(key2, sizeof(uint128_t));

    EVP_CIPHER_CTX *prfKey0 = PRFKeyGen(key0);
    EVP_CIPHER_CTX *prfKey1 = PRFKeyGen(key1);
    EVP_CIPHER_CTX *prfKey2 = PRFKeyGen(key2);

    unsigned char *kA = malloc(3 * size * sizeof(uint128_t) + sizeof(uint128_t));
    unsigned char *kB = malloc(3 * size * sizeof(uint128_t) + sizeof(uint128_t));

    uint128_t *shares0 = malloc(sizeof(uint128_t) * outl);
    uint128_t *shares1 = malloc(sizeof(uint128_t) * outl);

    DPFGen(prfKey0, prfKey1, prfKey2, size, secretIndex, kA, kB);

    //************************************************
    // Test full domain evaluation
    //************************************************
    printf("Testing full-domain evaluation optimization\n");
    //************************************************

    clock_t t;
    t = clock();
    DPFFullDomainEval(prfKey0, prfKey1, prfKey2, kA, size, shares0);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("DPF full-domain eval time (total) %f ms\n", time_taken);

    DPFFullDomainEval(prfKey0, prfKey1, prfKey2, kB, size, shares1);

    if ((shares0[secretIndex] ^ shares1[secretIndex]) == 0)
    {
        printf("FAIL (zero)\n");
        exit(0);
    }

    for (size_t i = 0; i < outl; i++)
    {
        if (i == secretIndex)
            continue;

        if ((shares0[i] ^ shares1[i]) != 0)
        {
            printf("FAIL (non-zero) %zu\n", i);
            printBytes(&shares0[i], 16);
            printBytes(&shares1[i], 16);

            exit(0);
        }
    }

    destroyPRFKey(prfKey0);
    destroyPRFKey(prfKey1);
    destroyPRFKey(prfKey2);

    free(kA);
    free(kB);
    free(shares0);
    free(shares1);
    printf("DONE\n\n");
}

int main(int argc, char **argv)
{

    int testTrials = 20;

    printf("******************************************\n");
    printf("Testing DPF\n");
    for (int i = 0; i < testTrials; i++)
        testDPF();
    printf("******************************************\n");
    printf("PASS\n");
    printf("******************************************\n\n");
}