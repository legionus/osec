#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <gcrypt.h>

#include "osec.h"

const char *gcry_version;

int
init_digest(void) {
	int retval = 1;
	gcry_error_t err;

	if ((gcry_version = gcry_check_version(GCRYPT_VERSION)) == NULL) {
		osec_error("WARNING: libgcrypt with version %s or above needed\n",
			GCRYPT_VERSION);
		retval = 0;
	}

	// Disable secure memory warnings
	if ((err = gcry_control(GCRYCTL_DISABLE_SECMEM_WARN)) > 0) {
		osec_error("WARNING (GCRYCTL_DISABLE_SECMEM_WARN): %s\n",
			gcry_strerror(err));
		retval = 0;
	}

	// Initialize secure memory
	if ((err = gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0)) > 0) {
		osec_error("WARNING (GCRYCTL_INIT_SECMEM): %s\n",
			gcry_strerror(err));
		retval = 0;
	}

	if ((err = gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0)) > 0) {
		osec_error("WARNING (GCRYCTL_INITIALIZATION_FINISHED): %s\n",
			gcry_strerror(err));
		retval = 0;
	}

	return retval;
}

void
digest(char *fname, struct osec_stat *st) {
	ssize_t num;
	int fd;
	unsigned char *md_string;

	void *buf;
	size_t size = 4096;

	gcry_error_t err = 0;
	gcry_md_hd_t dst = NULL;

	if ((fd = open(fname, O_RDONLY)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", fname);

	if ((err = gcry_md_open(&dst, GCRY_MD_MD5, GCRY_MD_FLAG_SECURE)) > 0)
		osec_fatal(EXIT_FAILURE, 0, "%s\n", gcry_strerror(err));

	buf = x_malloc(size);
	while ((num = read(fd, buf, size)) > 0)
		gcry_md_write(dst, buf, (size_t) num);

	if (num == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: read", fname);

	x_free(buf);
	gcry_md_final(dst);

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", fname);

	if ((md_string = gcry_md_read(dst, 0)) == NULL)
		osec_fatal(EXIT_FAILURE, 0, "%s\n", gcry_strerror(err));

	memcpy(st->digest, md_string, digest_len);
	gcry_md_close(dst);
	return;
}
