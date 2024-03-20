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
#define MESSAGESIZE 2
#define MAXRANDINDEX ipow(3, FULLEVALDOMAIN)

size_t randIndex()
{
    srand(time(NULL));
    return ((size_t)rand()) % ((size_t)MAXRANDINDEX);
}

uint128_t randMsg()
{
    uint128_t msg;
    RAND_bytes((uint8_t *)&msg, sizeof(uint128_t));
    return msg;
}

void testOutputCorrectness(
    uint128_t *shares0,
    uint128_t *shares1,
    size_t num_outputs,
    size_t secret_index,
    uint128_t *secret_msg,
    size_t msg_len)
{
    for (size_t i = 0; i < msg_len; i++)
    {
        uint128_t shareA = shares0[secret_index * msg_len + i];
        uint128_t shareB = shares1[secret_index * msg_len + i];
        uint128_t res = shareA ^ shareB;

        if (res != secret_msg[i])
        {
            printf("FAIL (wrong message)\n");
            exit(0);
        }
    }

    for (size_t i = 0; i < num_outputs; i++)
    {
        if (i == secret_index)
            continue;

        for (size_t j = 0; j < msg_len; j++)
        {
            uint128_t shareA = shares0[i * msg_len + j];
            uint128_t shareB = shares1[i * msg_len + j];
            uint128_t res = shareA ^ shareB;

            if (res != 0)
            {
                printf("FAIL (non-zero) %zu\n", i);
                printBytes(&shareA, 16);
                printBytes(&shareB, 16);

                exit(0);
            }
        }
    }
}

void printOutputShares(
    uint128_t *shares0,
    uint128_t *shares1,
    size_t num_outputs,
    size_t msg_len)
{
    for (size_t i = 0; i < num_outputs; i++)
    {
        for (size_t j = 0; j < msg_len; j++)
        {
            uint128_t shareA = shares0[i * msg_len + j];
            uint128_t shareB = shares1[i * msg_len + j];
            uint128_t res = shareA ^ shareB;

            printf("(%zu, %zu) %zu\n", i, j, msg_len);
            printBytes(&shareA, 16);
            printBytes(&shareB, 16);
        }
    }
}

double testDPF()
{
    const size_t size = FULLEVALDOMAIN; // evaluation will result in 3^size points
    const size_t msg_len = MESSAGESIZE;

    size_t num_leaves = ipow(3, size);

    size_t secret_index = randIndex();

    // sample a random message of size msg_len
    uint128_t *secret_msg = malloc(sizeof(uint128_t) * msg_len);
    for (size_t i = 0; i < msg_len; i++)
        secret_msg[i] = randMsg();

    struct PRFKeys *prf_keys = malloc(sizeof(struct PRFKeys));
    PRFKeyGen(prf_keys);

    struct DPFKey *kA = malloc(sizeof(struct DPFKey));
    struct DPFKey *kB = malloc(sizeof(struct DPFKey));

    DPFGen(prf_keys, size, secret_index, secret_msg, msg_len, kA, kB);

    uint128_t *shares0 = malloc(sizeof(uint128_t) * num_leaves * msg_len);
    uint128_t *shares1 = malloc(sizeof(uint128_t) * num_leaves * msg_len);
    uint128_t *cache = malloc(sizeof(uint128_t) * num_leaves * msg_len);

    //************************************************
    // Test full domain evaluation
    //************************************************

    DPFFullDomainEval(kA, cache, shares0);

    clock_t t;
    t = clock();
    DPFFullDomainEval(kB, cache, shares1);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("Time %f ms\n", time_taken);

    // printOutputShares(shares0, shares1, num_leaves, msg_len);

    testOutputCorrectness(
        shares0,
        shares1,
        num_leaves,
        secret_index,
        secret_msg,
        msg_len);

    DestroyPRFKey(prf_keys);

    free(kA);
    free(kB);
    free(shares0);
    free(shares1);
    free(cache);

    return time_taken;
}

double testHalfDPF()
{
    const size_t size = FULLEVALDOMAIN; // evaluation will result in 3^size points
    const size_t msg_len = MESSAGESIZE;

    size_t num_leaves = ipow(3, size);

    size_t secret_index = 0; // randIndex();

    // sample a random message of size msg_len
    uint128_t *secret_msg = malloc(sizeof(uint128_t) * msg_len);
    for (size_t i = 0; i < msg_len; i++)
        secret_msg[i] = randMsg();

    struct PRFKeys *prf_keys = malloc(sizeof(struct PRFKeys));
    PRFKeyGen(prf_keys);

    struct DPFKey *kA = malloc(sizeof(struct DPFKey));
    struct DPFKey *kB = malloc(sizeof(struct DPFKey));

    uint128_t *shares0 = malloc(sizeof(uint128_t) * num_leaves * msg_len);
    uint128_t *shares1 = malloc(sizeof(uint128_t) * num_leaves * msg_len);
    uint128_t *cache = malloc(sizeof(uint128_t) * num_leaves * msg_len);

    HalfDPFGen(prf_keys, size, secret_index, secret_msg, msg_len, kA, kB);

    //************************************************
    // Test full domain evaluation
    //************************************************

    HalfDPFFullDomainEval(kA, cache, shares0);

    clock_t t;
    t = clock();
    HalfDPFFullDomainEval(kB, cache, shares1);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("Time %f ms\n", time_taken);

    // printOutputShares(shares0, shares1, num_leaves, msg_len);

    testOutputCorrectness(
        shares0,
        shares1,
        num_leaves,
        secret_index,
        secret_msg,
        msg_len);

    DestroyPRFKey(prf_keys);

    free(kA);
    free(kB);
    free(cache);
    free(shares0);
    free(shares1);

    return time_taken;
}

double benchmarkGen()
{
    size_t num_leaves = ipow(3, FULLEVALDOMAIN);
    size_t size = FULLEVALDOMAIN; // evaluation will result in 3^size points

    size_t secret_index = randIndex();
    uint128_t secret_msg = randMsg();
    size_t msg_len = 1;

    struct PRFKeys *prf_keys = malloc(sizeof(struct PRFKeys));
    PRFKeyGen(prf_keys);

    struct DPFKey *kA = malloc(sizeof(struct DPFKey));
    struct DPFKey *kB = malloc(sizeof(struct DPFKey));

    clock_t t;
    t = clock();
    DPFGen(prf_keys, size, secret_index, &secret_msg, msg_len, kA, kB);
    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("Time %f ms\n", time_taken);

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

    uint128_t *data_in = malloc(sizeof(uint128_t) * num_leaves * MESSAGESIZE);
    uint128_t *data_out = malloc(sizeof(uint128_t) * num_leaves * MESSAGESIZE);
    uint128_t *data_tmp = malloc(sizeof(uint128_t) * num_leaves * MESSAGESIZE);
    uint128_t *tmp;

    // fill with unique data
    for (size_t i = 0; i < num_leaves * MESSAGESIZE; i++)
        data_tmp[i] = (uint128_t)i;

    // make the input data pseudorandom for correct timing
    PRFBatchEval(prf_keys->prf_key0, data_tmp, data_in, num_leaves * MESSAGESIZE);

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
    PRFBatchEval(prf_keys->prf_key0, data_in, data_out, num_nodes * MESSAGESIZE);

    t = clock() - t;
    double time_taken = ((double)t) / (CLOCKS_PER_SEC / 1000.0); // ms

    printf("Time %f ms\n", time_taken);
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
    for (int i = 0; i < testTrials; i++)
    {
        time += testDPF();
        printf("Done with trial %i of %i\n", i + 1, testTrials);
    }
    printf("******************************************\n");
    printf("PASS\n");
    printf("DPF.FullEval: (avg time) %0.2f ms\n", time / testTrials);
    printf("******************************************\n\n");

    time = 0;
    printf("******************************************\n");
    printf("Testing HalfDPF.FullEval\n");
    for (int i = 0; i < testTrials; i++)
    {
        time += testHalfDPF();
        printf("Done with trial %i of %i\n", i + 1, testTrials);
    }
    printf("******************************************\n");
    printf("PASS\n");
    printf("HalfDPF.FullEval: (avg time) %0.2f ms\n", time / testTrials);
    printf("******************************************\n\n");

    time = 0;
    printf("******************************************\n");
    printf("Benchmarking DPF.Gen\n");
    for (int i = 0; i < testTrials; i++)
    {
        time += benchmarkGen();
        printf("Done with trial %i of %i\n", i + 1, testTrials);
    }
    printf("******************************************\n");
    printf("Avg time: %0.4f ms\n", time / testTrials);
    printf("******************************************\n\n");

    time = 0;
    printf("******************************************\n");
    printf("Benchmarking AES\n");
    for (int i = 0; i < testTrials; i++)
    {
        time += benchmarkAES();
        printf("Done with trial %i of %i\n", i + 1, testTrials);
    }
    printf("******************************************\n");
    printf("Avg time: %0.2f ms\n", time / testTrials);
    printf("******************************************\n\n");
}