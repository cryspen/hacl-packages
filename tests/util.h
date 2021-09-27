#include <stdint.h>
#include <stdio.h>

static inline bool compare_and_print(size_t len, uint8_t *comp, uint8_t *exp)
{
    bool ok = true;
    for (size_t i = 0; i < len; i++)
    {
        ok = ok & (exp[i] == comp[i]);
    }
    if (ok)
    {
        printf("Success!\n");
    }
    else
    {
        printf("**FAILED**\n");
        printf("computed:");
        for (size_t i = 0; i < len; i++)
        {
            printf("%02x", comp[i]);
        }
        printf("\n");
        printf("expected:");
        for (size_t i = 0; i < len; i++)
        {
            printf("%02x", exp[i]);
        }
        printf("\n");
    }
    return ok;
}
