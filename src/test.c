#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "prf.h"
#include "dpf.h"
#include "utils.h"

#define FULLEVALDOMAIN 14
#define OUTPUTEXT 2
#define MAXRANDINDEX ipow(3, FULLEVALDOMAIN)

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
    size_t num_leaves = ipow(3, FULLEVALDOMAIN);
    size_t size = FULLEVALDOMAIN; // evaluation will result in 3^size points

    uint64_t secret_index = randIndex();
    uint128_t secret_msg = randMsg();

    struct PRFKeys *prf_keys = malloc(sizeof(struct PRFKeys));
    PRFKeyGen(prf_keys);

    unsigned char *kA = malloc(3 * size * sizeof(uint128_t) + sizeof(uint128_t));
    unsigned char *kB = malloc(3 * size * sizeof(uint128_t) + sizeof(uint128_t));

    DPFGen(prf_keys, size, secret_index, secret_msg, kA, kB);

    uint128_t *shares0 = malloc(sizeof(uint128_t) * num_leaves);
    uint128_t *shares1 = malloc(sizeof(uint128_t) * num_leaves);
    uint128_t *ext_shares0 = malloc(sizeof(uint128_t) * num_leaves * OUTPUTEXT);
    uint128_t *ext_shares1 = malloc(sizeof(uint128_t) * num_leaves * OUTPUTEXT);
    uint128_t *cache = malloc(sizeof(uint128_t) * num_leaves);

    //************************************************
    // Test full domain evaluation
    //************************************************
    printf("Testing full-domain evaluation optimization\n");
    //************************************************

    DPFFullDomainEval(prf_keys, cache, shares0, kA, size);
    ExtendOutput(prf_keys, shares0, ext_shares0, num_leaves, num_leaves * OUTPUTEXT);

    clock_t t;
    t = clock();
    DPFFullDomainEval(prf_keys, cache, shares1, kB, size);
    ExtendOutput(prf_keys, shares1, ext_shares1, num_leaves, num_leaves * OUTPUTEXT);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("DPF full-domain eval time (total) %f ms\n", time_taken);

    if ((shares0[secret_index] ^ shares1[secret_index]) != secret_msg)
    {
        printf("FAIL (wrong message)\n");
        exit(0);
    }

    for (size_t i = 0; i < num_leaves; i++)
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

    DestroyPRFKey(prf_keys);

    free(kA);
    free(kB);
    free(shares0);
    free(shares1);
    free(cache);

    printf("DONE\n\n");

    return time_taken;
}

double testHalfDPF()
{
    size_t num_leaves = ipow(3, FULLEVALDOMAIN);
    int size = FULLEVALDOMAIN; // evaluation will result in 3^size points

    uint64_t secret_index = randIndex();
    uint128_t secret_msg = randMsg();

    struct PRFKeys *prf_keys = malloc(sizeof(struct PRFKeys));
    PRFKeyGen(prf_keys);

    unsigned char *kA = malloc(3 * size * sizeof(uint128_t) + sizeof(uint128_t));
    unsigned char *kB = malloc(3 * size * sizeof(uint128_t) + sizeof(uint128_t));

    uint128_t *shares0 = malloc(sizeof(uint128_t) * num_leaves);
    uint128_t *shares1 = malloc(sizeof(uint128_t) * num_leaves);
    uint128_t *ext_shares0 = malloc(sizeof(uint128_t) * num_leaves * OUTPUTEXT);
    uint128_t *ext_shares1 = malloc(sizeof(uint128_t) * num_leaves * OUTPUTEXT);
    uint128_t *cache = malloc(sizeof(uint128_t) * num_leaves);

    HalfDPFGen(prf_keys, size, secret_index, secret_msg, kA, kB);

    //************************************************
    // Test full domain evaluation
    //************************************************
    printf("Testing full-domain evaluation optimization\n");
    //************************************************

    HalfDPFFullDomainEval(prf_keys, cache, shares0, kA, size);
    ExtendOutput(prf_keys, shares0, ext_shares0, num_leaves, num_leaves * OUTPUTEXT);

    clock_t t;
    t = clock();
    HalfDPFFullDomainEval(prf_keys, cache, shares1, kB, size);
    ExtendOutput(prf_keys, shares1, ext_shares1, num_leaves, num_leaves * OUTPUTEXT);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("HalfDPF full-domain eval time (total) %f ms\n", time_taken);

    if ((shares0[secret_index] ^ shares1[secret_index]) != secret_msg)
    {
        printf("FAIL (wrong message)\n");
        exit(0);
    }

    for (size_t i = 0; i < num_leaves; i++)
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

    DestroyPRFKey(prf_keys);

    free(kA);
    free(kB);
    free(cache);
    free(shares0);
    free(shares1);

    printf("DONE\n\n");

    return time_taken;
}

double benchmarkGen()
{
    size_t num_leaves = ipow(3, FULLEVALDOMAIN);
    size_t size = FULLEVALDOMAIN; // evaluation will result in 3^size points

    uint64_t secret_index = randIndex();
    uint128_t secret_msg = randMsg();

    struct PRFKeys *prf_keys = malloc(sizeof(struct PRFKeys));
    PRFKeyGen(prf_keys);

    unsigned char *kA = malloc(3 * size * sizeof(uint128_t) + sizeof(uint128_t));
    unsigned char *kB = malloc(3 * size * sizeof(uint128_t) + sizeof(uint128_t));

    clock_t t;
    t = clock();
    DPFGen(prf_keys, size, secret_index, secret_msg, kA, kB);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    DestroyPRFKey(prf_keys);
    free(kA);
    free(kB);

    return time_taken;
}

double benchmarkAES()
{
    size_t num_leaves = ipow(3, FULLEVALDOMAIN);
    size_t size = FULLEVALDOMAIN;

    struct PRFKeys *prf_keys = malloc(sizeof(struct PRFKeys));
    PRFKeyGen(prf_keys);

    uint128_t *data_in = malloc(sizeof(uint128_t) * num_leaves * OUTPUTEXT);
    uint128_t *data_out = malloc(sizeof(uint128_t) * num_leaves * OUTPUTEXT);
    uint128_t *data_tmp = malloc(sizeof(uint128_t) * num_leaves * OUTPUTEXT);
    uint128_t *tmp;

    // fill with unique data
    for (size_t i = 0; i < num_leaves * OUTPUTEXT; i++)
        data_tmp[i] = (uint128_t)i;

    // make the input data pseudorandom for correct timing
    PRFBatchEval(prf_keys->prf_key0, data_tmp, data_in, num_leaves * OUTPUTEXT);

    //************************************************
    // Benchmark AES encryption time required in DPF loop
    //************************************************

    clock_t t;
    t = clock();
    size_t num_nodes = 1;
    for (size_t i = 0; i < size; i++)
    {
        PRFBatchEval(prf_keys->prf_key0, data_in, data_out, num_nodes);
        PRFBatchEval(prf_keys->prf_key1, data_in, &data_out[num_nodes], num_nodes);
        PRFBatchEval(prf_keys->prf_key2, data_in, &data_out[num_nodes * 2], num_nodes);

        tmp = data_out;
        data_out = data_in;
        data_in = tmp;

        num_nodes *= 3;
    }

    // compute AES part of output extension
    PRFBatchEval(prf_keys->prf_key0, data_in, data_out, num_nodes * OUTPUTEXT);

    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("AES: time (total) %f ms\n", time_taken);
    free(data_in);
    free(data_out);
    free(data_tmp);

    return time_taken;
}

int main(int argc, char **argv)
{

    double time = 0;
    int testTrials = 3;

    printf("******************************************\n");
    printf("Testing DPF.FullEval\n");
    testDPF(); // first round we throw away
    for (int i = 0; i < testTrials; i++)
        time += testDPF();
    printf("******************************************\n");
    printf("PASS\n");
    printf("Avg time for DPF.FullEval: %0.2f ms\n", time / testTrials);
    printf("******************************************\n\n");

    time = 0;
    printf("******************************************\n");
    printf("Testing Half DPF\n");
    testHalfDPF(); // first round we throw away
    for (int i = 0; i < testTrials; i++)
        time += testHalfDPF();
    printf("******************************************\n");
    printf("PASS\n");
    printf("Avg time for DPF.FullEval: %0.2f ms\n", time / testTrials);
    printf("******************************************\n\n");

    time = 0;
    printf("******************************************\n");
    printf("Benchmarking DPF.Gen\n");
    benchmarkGen(); // first round we throw away
    for (int i = 0; i < testTrials; i++)
        time += benchmarkGen();
    printf("******************************************\n");
    printf("PASS\n");
    printf("Avg time: %0.4f ms\n", time / testTrials);
    printf("******************************************\n\n");

    time = 0;
    printf("******************************************\n");
    printf("Benchmarking AES\n");
    benchmarkAES(); // first round we throw away
    for (int i = 0; i < testTrials; i++)
        time += benchmarkAES();
    printf("******************************************\n");
    printf("PASS\n");
    printf("Avg time: %0.2f ms\n", time / testTrials);
    printf("******************************************\n\n");
}