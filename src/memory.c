#include <stdlib.h>
#include <errno.h>
#include "osec.h"

void *
x_malloc(size_t size) {
	void *ptr;
	if ((ptr = malloc(size)) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "malloc");
	return ptr;
}

void *
x_realloc(void *ptr, size_t size) {
	if ((ptr = realloc(ptr, size)) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "realloc");
	return ptr;
}

void
x_free(void *ptr) {
	if (ptr != NULL)
		free(ptr);
}
