#include <stdint.h>
#include <stdio.h>

#include "utils.h"


void
printvec(const char *str, const uint8_t *vec, size_t len)
{
        int i, n;

        n = printf("%s:", str);

        for (i = MAX(3-n/8, 0); i > 0; i--)
                putchar('\t');

        if (len == 0)
                putchar('-');
        else
                for (i = 0; i < len; i++)
                        printf("%02x", vec[i]);

        putchar('\n');
}

