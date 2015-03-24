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

static int
direxists(const char *dir)
{
        struct stat sb;

	/* return 'no' if stat fails */
        if (stat(dir, &sb) < 0)
                return 0;

        return S_ISDIR(sb.st_mode) ? 1 : 0;
}




#ifdef HAVE_GETRANDOM
#include <linux/random.h>
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



FILE *
opentemp(char tmpfn[PATH_MAX], const char *target, int mode)
{
	char path[PATH_MAX];
	char *dir;

	FILE *rval;
	int fd;
	int rc;

	rc = snprintf(path, PATH_MAX, "%s", target);
	if (rc >= PATH_MAX)
		return NULL;

	dir = dirname(path);
	if (!direxists(dir))
		return NULL;

	fd = open(dir, O_TMPFILE | O_WRONLY, mode);
	if (fd == -1)
		return NULL;

	rc = snprintf(tmpfn, PATH_MAX, "/proc/self/fd/%d", fd);
	if (rc >= PATH_MAX)
		return NULL;

	rval = fdopen(fd, "w");

	return rval;
}
