#ifndef BUFFER_H
#define BUFFER_H

#include <stdint.h>
#include <stddef.h>

#include "cleanup.h"

struct buffer {
	size_t	len;
	uint8_t	data[];
};

#define cu_freebuffer	do_cleanup(buffer_burnfree)


struct buffer	*buffer_alloc(size_t size);
void		 buffer_burnfree(struct buffer **bufp);


#endif
