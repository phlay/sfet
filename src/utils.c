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
#include <unistd.h>
#include <fcntl.h>

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

#ifndef HAVE_GETRANDOM

#define GRND_NONBLOCK	1
#define GRND_RANDOM	2

/*
 * getrandom - very simple emulation of linux syscall until i get the
 * real thing.
 */
int
getrandom(void *buf, size_t buflen, unsigned int flags)
{
	const char *devname = (flags & GRND_RANDOM) ? "/dev/random" : "/dev/urandom";
	int devflag = 0;
	int dev;
	int rval;

	if (flags & GRND_NONBLOCK)
		devflag |= O_NONBLOCK;

	dev = open(devname, devflag);
	if (dev == -1)
		return -1;

	rval = read(dev, buf, buflen);

	close(dev);

	return rval;
}

#endif


int
secrand(void *buf, size_t len)
{
	uint8_t *ptr = (uint8_t *)buf;
	int n;
	int rc;

	if (len > 256)
		return -1;

	n = getrandom(ptr, len, GRND_RANDOM|GRND_NONBLOCK);
	if (n == -1)
		return -1;
	if (n == len)
		return 0;


	fprintf(stderr, "waiting for random... ");
	while (n < len) {
		rc = getrandom(ptr+n, len-n, GRND_RANDOM);
		if (rc == -1) {
			fprintf(stderr, "error\n");
			return -1;
		}

		n += rc;
	}
	fprintf(stderr, "done\n");

	return 0;
}
