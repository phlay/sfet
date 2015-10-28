/*
 * utils - various helper functions for sfet
 *
 * Written by Philipp Lay <philipp.lay@illunis.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include "utils.h"


#ifdef HAVE_GETRANDOM

#include <sys/syscall.h>
#include <linux/random.h>

#define getrandom(buf, len, flags)	syscall(SYS_getrandom, (buf), (len), (flags))

#else

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

	/* try to read all random data without blocking */
#ifdef USE_DEV_RANDOM
	n = getrandom(ptr, len, GRND_RANDOM|GRND_NONBLOCK);
#else
	n = getrandom(ptr, len, GRND_NONBLOCK);
#endif
	if (n == -1)
		return -1;
	if (n == len)
		return 0;

	/*
	 * we did'nt get everything on the first try... inform user
	 * and read more random now WITH blocking
	 */

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


int
ctiseq(const void *s1, const void *s2, size_t n)
{
	uint8_t *p1 = (uint8_t *)s1;
	uint8_t *p2 = (uint8_t *)s2;
	int mask = 0;

	while (n-- > 0)
		mask |= *p1++ ^ *p2++;

	return ((mask-1) >> 8) & 1;
}


int
exists(const char *path)
{
        struct stat sb;
	return (stat(path, &sb) == -1) ? 0 : 1;
}
