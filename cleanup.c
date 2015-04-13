#include <stdio.h>
#include <stdlib.h>

void
cleanup_free(void **ptr)
{
	free(*ptr);
}

void
cleanup_fclose(FILE **stream)
{
	if (*stream == NULL)
		return;
	fclose(*stream);
}
