#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>
#include <limits.h>

/* useful macros */
#define MIN(a, b)	((a) < (b)) ? (a) : (b)
#define MAX(a, b)	((a) > (b)) ? (a) : (b)


void	*x_malloc(size_t size);
char	*x_strdup(const char *s);
int	 exists(const char *path);

int	 secrand(void *, size_t);
int	 ctiseq(const void *s1, const void *s2, size_t n);

#endif
