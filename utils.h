#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

#ifndef MIN
#define MIN(a, b)	((a) < (b)) ? (a) : (b)
#endif

#ifndef MAX
#define MAX(a, b)	((a) > (b)) ? (a) : (b)
#endif

int		 secrand(void *buf, size_t len);
int		 ctiseq(const void *s1, const void *s2, size_t n);
int		 exists(const char *path);

void		 store_be64(uint8_t *p, uint64_t x);
uint64_t	 load_be64(const uint8_t *p);

#endif
