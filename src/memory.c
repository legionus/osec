#include <stdlib.h>
#include <errno.h>
#include "osec.h"

void *
xmalloc(size_t size) {
	void *ptr;
	if ((ptr = malloc(size)) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "malloc");
	return ptr;
}

void *
xrealloc(void *ptr, size_t size) {
	if ((ptr = realloc(ptr, size)) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "realloc");
	return ptr;
}

void
xfree(void *ptr) {
	if (ptr != NULL)
		free(ptr);
}
