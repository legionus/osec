#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/param.h>
#include "osec.h"

void *
osec_field(const unsigned type, const void *data, const size_t dlen) {
	size_t vlen, len = 0;
	unsigned vtype;

	while (len < dlen) {
		memcpy(&vtype, (data + len), sizeof(unsigned));
		len += sizeof(unsigned);

		memcpy(&vlen, (data + len), sizeof(size_t));
		len += sizeof(size_t);

		if (vtype == type)
			return (void *) (data + len);

		len += vlen;
	}

	return NULL;
}

size_t
append_value(const unsigned type, void **dst, size_t *dlen, const void *src, const size_t slen) {

	*dst = xrealloc(*dst, (*dlen + sizeof(unsigned) + sizeof(size_t) + slen));

	memcpy(*dst + *dlen, &type, sizeof(unsigned));
	*dlen += sizeof(unsigned);

	memcpy(*dst + *dlen, &slen, sizeof(size_t));
	*dlen += sizeof(size_t);
	
	memcpy(*dst + *dlen, src, slen);
	*dlen += slen;

	return *dlen;
}

size_t
osec_state(void **val, size_t *vlen, const struct stat *st) {
	osec_stat_t ost;

	ost.dev  = st->st_dev;
	ost.ino  = st->st_ino;
	ost.uid  = st->st_uid;
	ost.gid  = st->st_gid;
	ost.mode = st->st_mode;

	return append_value(OVALUE_STAT, val, vlen, &ost, sizeof(ost));
}

size_t
osec_digest(void **val, size_t *vlen, const char *fname) {
	char fdigest[digest_len];

	digest(fname, fdigest);

	return append_value(OVALUE_CSUM, val, vlen, &fdigest, digest_len);
}

size_t
osec_symlink(void **val, size_t *vlen, const char *fname) {
	ssize_t lnklen;
	char *buf = (char *) xmalloc(MAXPATHLEN);

	if ((lnklen = readlink(fname, buf, MAXPATHLEN)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: readlink", fname);

	buf[lnklen] = '\0';

	append_value(OVALUE_LINK, val, vlen, buf, (size_t) lnklen+1);
	xfree(buf);

	return 0;
}
