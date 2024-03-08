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

// extends the output by the provided factor using the PRG
int ExtendOutput(
    EVP_CIPHER_CTX *prfKey,
    uint128_t *output,
    uint128_t *new_output,
    const size_t output_size,
    const size_t new_output_size)
{

    if (new_output_size % output_size != 0)
    {
        printf("ERROR: new_output_size needs to be a multiple of output_size");
        return 0;
    }
    if (new_output_size < output_size)
    {
        printf("ERROR: new_output_size < output_size");
        return 0;
    }

    size_t factor = new_output_size / output_size;

    for (size_t i = 0; i < output_size; i++)
    {
        for (size_t j = 0; j < factor; j++)
            new_output[i * factor + j] = output[i] ^ j;
    }

    PRFBatchEval(prfKey, &new_output[0], &new_output[0], new_output_size);

    return 1;
}