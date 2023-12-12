#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "../include/prf.h"
#include "../include/dpf.h"
#include "../include/fastdpf.h"
#include "../include/utils.h"

#define FULLEVALDOMAIN 15
#define MAXRANDINDEX pow(3, FULLEVALDOMAIN)

uint64_t randIndex()
{
    srand(time(NULL));
    return ((uint64_t)rand()) % ((uint64_t)MAXRANDINDEX);
}

uint128_t randMsg()
{
    uint128_t msg;
    RAND_bytes((uint8_t *)&msg, sizeof(uint128_t));
    return msg;
}

double testDPF()
{
    size_t outl = pow(3, FULLEVALDOMAIN);
    int size = FULLEVALDOMAIN; // evaluation will result in 3^size points

    uint64_t secret_index = randIndex();
    uint128_t secret_msg = randMsg();

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

    DPFGen(prfKey0, prfKey1, prfKey2, size, secret_index, secret_msg, kA, kB);

    //************************************************
    // Test full domain evaluation
    //************************************************
    printf("Testing full-domain evaluation optimization\n");
    //************************************************

    clock_t t;
    t = clock();
    uint128_t *shares0 = (uint128_t *)DPFFullDomainEval(prfKey0, prfKey1, prfKey2, kA, size);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("DPF full-domain eval time (total) %f ms\n", time_taken);

    uint128_t *shares1 = (uint128_t *)DPFFullDomainEval(prfKey0, prfKey1, prfKey2, kB, size);

    if ((shares0[secret_index] ^ shares1[secret_index]) != secret_msg)
    {
        printf("FAIL (wrong message)\n");
        exit(0);
    }

    for (size_t i = 0; i < outl; i++)
    {
        if (i == secret_index)
            continue;

        if ((shares0[i] ^ shares1[i]) != 0)
        {
            printf("FAIL (non-zero) %zu\n", i);
            printBytes(&shares0[i], 16);
            printBytes(&shares1[i], 16);

            exit(0);
        }
    }

    DestroyPRFKey(prfKey0);
    DestroyPRFKey(prfKey1);
    DestroyPRFKey(prfKey2);

    free(kA);
    free(kB);
    free(shares0);
    free(shares1);
    printf("DONE\n\n");

    return time_taken;
}

double testFastDPF()
{
    size_t outl = pow(3, FULLEVALDOMAIN);
    int size = FULLEVALDOMAIN; // evaluation will result in 3^size points

    uint64_t secret_index = randIndex();
    uint128_t secret_msg = randMsg();

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

    FastDPFGen(prfKey0, prfKey1, prfKey2, size, secret_index, secret_msg, kA, kB);

    //************************************************
    // Test full domain evaluation
    //************************************************
    printf("Testing full-domain evaluation optimization\n");
    //************************************************

    clock_t t;
    t = clock();
    uint128_t *shares0 = (uint128_t *)FastDPFFullDomainEval(prfKey0, prfKey1, prfKey2, kA, size);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("DPF full-domain eval time (total) %f ms\n", time_taken);

    uint128_t *shares1 = (uint128_t *)FastDPFFullDomainEval(prfKey0, prfKey1, prfKey2, kB, size);

    if ((shares0[secret_index] ^ shares1[secret_index]) != secret_msg)
    {
        printf("FAIL (wrong message)\n");
        exit(0);
    }

    for (size_t i = 0; i < outl; i++)
    {
        if (i == secret_index)
            continue;

        if ((shares0[i] ^ shares1[i]) != 0)
        {
            printf("FAIL (non-zero) %zu\n", i);
            printBytes(&shares0[i], 16);
            printBytes(&shares1[i], 16);

            exit(0);
        }
    }

    DestroyPRFKey(prfKey0);
    DestroyPRFKey(prfKey1);
    DestroyPRFKey(prfKey2);

    free(kA);
    free(kB);
    free(shares0);
    free(shares1);
    printf("DONE\n\n");

    return time_taken;
}

void benchmarkAES()
{
    size_t outl = pow(3, FULLEVALDOMAIN);
    int size = FULLEVALDOMAIN;

    uint128_t key1;
    uint128_t key2;
    uint128_t key3;

    RAND_bytes((uint8_t *)&key1, sizeof(uint128_t));
    RAND_bytes((uint8_t *)&key2, sizeof(uint128_t));
    RAND_bytes((uint8_t *)&key3, sizeof(uint128_t));

    EVP_CIPHER_CTX *prfKey1 = PRFKeyGen((uint8_t *)&key1);
    EVP_CIPHER_CTX *prfKey2 = PRFKeyGen((uint8_t *)&key2);
    EVP_CIPHER_CTX *prfKey3 = PRFKeyGen((uint8_t *)&key3);

    uint128_t *data_in = malloc(sizeof(uint128_t) * outl);
    uint128_t *data_out = malloc(sizeof(uint128_t) * outl);

    // fill with unique data
    for (int i = 0; i < outl; i++)
        data_in[i] = (uint128_t)i;

    // make the input data pseudorandom for correct timing
    PRFBatchEval(prfKey1, data_in, data_out, outl);
    PRFBatchEval(prfKey2, data_out, data_in, outl);

    //************************************************
    // Benchmark AES encryption time required in DPF loop
    //************************************************

    clock_t t;
    t = clock();
    int num_blocks = 1;
    for (int i = 0; i < size; i++)
    {
        PRFBatchEval(prfKey1, data_in, data_out, num_blocks);
        PRFBatchEval(prfKey2, data_out, data_in, num_blocks);
        PRFBatchEval(prfKey3, data_in, data_out, num_blocks);
        num_blocks *= 3;
    }
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("WITHOUT half-tree optimization: time (total) %f ms\n", time_taken);

    //************************************************
    // Benchmark AES encryption time required in DPF loop
    //************************************************

    t = clock();
    num_blocks = 1;
    for (int i = 0; i < size; i++)
    {
        PRFBatchEval(prfKey1, data_out, data_in, num_blocks);
        PRFBatchEval(prfKey2, data_in, data_out, num_blocks);
        num_blocks *= 3;
    }
    t = clock() - t;
    time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("WITH half-tree optimization:    time (total) %f ms\n", time_taken);
    printf("DONE\n\n");
}

int main(int argc, char **argv)
{

    double time = 0;
    int testTrials = 3;

    printf("******************************************\n");
    printf("Testing DPF\n");
    testDPF(); // first round we throw away
    for (int i = 0; i < testTrials; i++)
        time += testDPF();
    printf("******************************************\n");
    printf("PASS\n");
    printf("Avg time: %f\n", time / testTrials);
    printf("******************************************\n\n");

    time = 0;
    printf("******************************************\n");
    printf("Testing Fast DPF\n");
    testDPF(); // first round we throw away
    for (int i = 0; i < testTrials; i++)
        time += testFastDPF();
    printf("******************************************\n");
    printf("PASS\n");
    printf("Avg time: %f\n", time / testTrials);
    printf("******************************************\n\n");

    printf("******************************************\n");
    printf("Benchmarking AES\n");
    benchmarkAES(); // first round we throw away
    for (int i = 0; i < testTrials; i++)
        benchmarkAES();
    printf("******************************************\n");
    printf("PASS\n");
    printf("******************************************\n\n");
}