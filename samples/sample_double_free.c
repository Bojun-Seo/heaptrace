/* SPDX-License-Identifier: GPL-2.0 */
#include <stdlib.h>
#include <string.h>

char *alloc_buffer(size_t size)
{
	return malloc(size);
}

void free_buffer(char *buf)
{
	free(buf);
}

int main(void)
{
	char *buf = alloc_buffer(128);

	memset(buf, 0, 128);
	free_buffer(buf);

	/* this is a double free and heaptrace --dsan reports it */
	free_buffer(buf);

	return 0;
}
