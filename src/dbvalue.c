/* dbvalue.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2012  Alexey Gladkov <gladkov.alexey@gmail.com>
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
#include "config.h"
#include "osec.h"

void *
osec_field(const unsigned type, const void *data, const size_t dlen, struct field *ret) {
	size_t vlen, len = 0;
	unsigned vtype;

	while (len < dlen) {
		memcpy(&vtype, (data + len), sizeof(unsigned));
		len += sizeof(unsigned);

		memcpy(&vlen, (data + len), sizeof(size_t));
		len += sizeof(size_t);

		if (vtype == type) {
			if (ret != NULL) {
				ret->type = type;
				ret->len  = vlen;
				ret->data = (void *) (data + len);
			}
			return (void *) (data + len);
		}

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

	digest_file(fname, fdigest);

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

#ifndef HAVE_LIBATTR
void
osec_xattr(struct record *rec, const char *fname __attribute__ ((unused))) {
	const char empty = '\0';
	append_value(OVALUE_XATTR, &empty, (size_t) 1, rec);
}
#else
#include <sys/types.h>
#include <attr/xattr.h>

void
osec_xattr(struct record *rec, const char *fname) {
	const char empty = '\0';
	int is_link;
	char *xlist = NULL, *xkey = NULL, *xvalue = NULL, *res = NULL;
	size_t xlist_len = 0, xkey_len = 0, xvalue_len = 0, res_len = 0;
	size_t offset;
	ssize_t len;

	struct stat st;

	if (lstat(fname, &st) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: lstat", fname);

	is_link = ((st.st_mode & S_IFMT) == S_IFLNK);

	len = (is_link)
		? llistxattr(fname, NULL, 0)
		:  listxattr(fname, NULL, 0);

	if (len == 0)
		goto empty;

	if (len < 0 && errno == ENOTSUP) // xattr not supported
		goto empty;

	xlist_len = (size_t) len;
	xlist = xmalloc(xlist_len);

	while (1) {
		len = (is_link)
			? llistxattr(fname, xlist, xlist_len)
			:  listxattr(fname, xlist, xlist_len);

		if (len > 0) {
			xlist_len = (size_t) len;
			break;
		}

		if (errno != ERANGE) {
			osec_fatal(EXIT_FAILURE, errno, "%s: listxattr", fname);
			goto empty;
		}

		xlist_len <<= 1;

		if (!xlist_len) {
			osec_fatal(EXIT_FAILURE, 0, "%s: too many keys", fname);
			goto empty;
		}

		xlist = xrealloc(xlist, (size_t) xlist_len);
	}

	res_len = 0;
	res = NULL;

	xkey = xlist;
	offset = 0;

	while (xkey != (xlist + xlist_len)) {
		len = (is_link)
			? lgetxattr(fname, xkey, NULL, 0)
			:  getxattr(fname, xkey, NULL, 0);

		if (len == -1) {
			if (errno == ENOATTR)
				goto next;
			if (errno == ENOTSUP)
				goto empty;
		}

		if (xvalue_len < (size_t) len) {
			xvalue_len += (size_t) len - xvalue_len;
			xvalue = xrealloc(xvalue, (size_t) xvalue_len);
		}

		while (1) {
			len = (is_link)
				? lgetxattr(fname, xkey, xvalue, xvalue_len)
				:  getxattr(fname, xkey, xvalue, xvalue_len);

			if (len >= 0)
				break;

			switch (errno) {
				case ERANGE:
					xvalue_len += 20;
					if (!xvalue_len) {
						osec_fatal(EXIT_FAILURE, 0, "%s: value too long", fname);
						goto empty;
					}
					xvalue = xrealloc(xvalue, (size_t) xvalue_len);
					continue;
				case ENOATTR:
					goto next;
				case ENOTSUP:
					goto empty;
			}
		}

		/*
		 * record: <key> + '\0' + <value-len> + <value> + '\0'
		 */
		xkey_len = strlen(xkey) + 1;

		res_len += xkey_len + sizeof(size_t) + (size_t) len + 1;
		res = xrealloc(res, res_len);

		memcpy(res + offset, xkey, xkey_len);
		offset += xkey_len;

		memcpy(res + offset, &len, sizeof(size_t));
		offset += sizeof(size_t);

		memcpy(res + offset, xvalue, (size_t) len);
		offset += (size_t) len;

		res[offset] = '\0';
		offset += 1;

next:		xkey += xkey_len;
	}

	append_value(OVALUE_XATTR, res, res_len, rec);
	xfree(res);

	xfree(xlist);
	xfree(xvalue);
	return;

empty:	append_value(OVALUE_XATTR, &empty, (size_t) 1, rec);
	xfree(xlist);
	xfree(xvalue);
}
#endif
