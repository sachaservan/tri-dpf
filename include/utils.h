#ifndef _UTILS
#define _UTILS

#include <stdint.h>
#include <stdio.h>

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

static inline int ipow(int base, int exp)
{
    int result = 1;
    for (;;)
    {
        if (exp & 1)
            result *= base;
        exp >>= 1;
        if (!exp)
            break;
        base *= base;
    }

    return result;
}

#endif
