#ifndef READPASS_H
#define READPASS_H

int	read_pass(FILE *fp, uint8_t *passwd, size_t max, const char *promptA,
		  const char *promptB);

#endif
