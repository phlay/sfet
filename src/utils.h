#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

/* useful macros */
#define MIN(a, b)	((a) < (b)) ? (a) : (b)
#define MAX(a, b)	((a) > (b)) ? (a) : (b)


void	*x_malloc(size_t size);
char	*x_strdup(const char *s);
int	 exists(const char *path);


void	burn(void *, size_t);
int	secrand(void *, size_t);

#endif
