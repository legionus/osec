/* dbvalue.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2009  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
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

void
append_value(const unsigned type, const void *src, const size_t slen, struct record *rec) {

	size_t sz = sizeof(unsigned) + sizeof(size_t) + slen;

	if (sz > (rec->len - rec->offset)) {
		rec->len += sz - (rec->len - rec->offset);
		rec->data = xrealloc(rec->data, rec->len);
	}

	memcpy(rec->data + rec->offset, &type, sizeof(unsigned));
	rec->offset += sizeof(unsigned);

	memcpy(rec->data + rec->offset, &slen, sizeof(size_t));
	rec->offset += sizeof(size_t);

	memcpy(rec->data + rec->offset, src, slen);
	rec->offset += slen;
}

void
osec_state(struct record *rec, const struct stat *st) {
	osec_stat_t ost;

	ost.dev   = st->st_dev;
	ost.ino   = st->st_ino;
	ost.uid   = st->st_uid;
	ost.gid   = st->st_gid;
	ost.mode  = st->st_mode;
	ost.mtime = st->st_mtime;

	append_value(OVALUE_STAT, &ost, sizeof(ost), rec);
}

void
osec_digest(struct record *rec, const char *fname) {
	char fdigest[digest_len];

	digest(fname, fdigest);

	append_value(OVALUE_CSUM, &fdigest, (size_t) digest_len, rec);
}

void
osec_symlink(struct record *rec, const char *fname) {
	ssize_t lnklen;
	char buf[MAXPATHLEN];

	if ((lnklen = readlink(fname, buf, (size_t) MAXPATHLEN)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: readlink", fname);

	buf[lnklen] = '\0';

	append_value(OVALUE_LINK, buf, (size_t) lnklen + 1, rec);
}
