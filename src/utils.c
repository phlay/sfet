/*
 * utils - various helper functions for venom
 *
 * Written by Philipp Lay <philipp.lay@illunis.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version. 
 */
 
#include <sys/stat.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <err.h>

#include "defaults.h"
#include "utils.h"


void *
x_malloc(size_t size)
{
        void *rval;

        rval = malloc(size);
        if (rval == NULL)
                err(1, "can't allocate memory");
        
        return rval;
}

char *
x_strdup(const char *s)
{
        char *rval;

        rval = strdup(s);
        if (rval == NULL)
                err(1, "can't duplicate string");

        return rval;
}

int
exists(const char *path)
{
        struct stat sb;
	return (stat(path, &sb) == -1) ? 0 : 1;
}


void
burn(void *buf, size_t len)
{
	memset(buf, 0, len);
}


/*
 * XXX we need the getrandom system call
 */
int
getrandom(uint8_t *buf, size_t len)
{
        FILE *dev;

        dev = fopen(DEF_RANDDEV, "r");
        if (dev == NULL)
                return -1;

        if (fread(buf, sizeof(uint8_t), len, dev) != len) {
                fclose(dev);
                return -1;
        }

        fclose(dev);
        return 0;
}

