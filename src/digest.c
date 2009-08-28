/* digest.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "osec.h"
#include "sha1.h"

extern void  *read_buf;
extern size_t read_bufsize;

void
digest(const char *fname, char *out) {
	int fd;
	ssize_t num;
	SHA_CTX ctx;

	if ((fd = open(fname, OSEC_O_FLAGS)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", fname);

	SHA1_Init(&ctx);

	/* Let the kernel know we are going to read everything in sequence. */
	(void) posix_fadvise (fd, 0, 0, POSIX_FADV_SEQUENTIAL);

	while ((num = read(fd, read_buf, read_bufsize)) > 0)
		SHA1_Update(&ctx, read_buf, (int) num);

	if (num == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: read", fname);

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", fname);

	SHA1_Final((unsigned char *) out, &ctx);
}
