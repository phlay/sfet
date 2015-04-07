#include <stdint.h>

#include "burn.h"
#include "burnstack.h"

/*
 * burnstack - cleanup our stack
 */
void
burnstack(int kb)
{
	uint8_t stack[1024];
	burn(stack, 1024);
	if (kb > 0)
		burnstack(kb-1024);
}
