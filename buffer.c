#include <stdlib.h>

#include "burn.h"
#include "buffer.h"

struct buffer *
buffer_alloc(size_t size)
{
	struct buffer *bufp;

	bufp = malloc(sizeof(struct buffer) + size);
	if (bufp == NULL)
		return NULL;

	bufp->len = size;
	return bufp;
}

void
buffer_burnfree(struct buffer **bufp)
{
	if (*bufp == NULL)
		return;
	burn((*bufp)->data, (*bufp)->len);
	free(*bufp);
}
