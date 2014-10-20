#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

void	*x_malloc(size_t size);
char	*x_strdup(const char *s);
int	 exists(const char *path);


void	burn(void *, size_t);
int	getrandom(uint8_t *, size_t);
int	read_pass_tty(char *, size_t, const char *, const char *);

#endif
