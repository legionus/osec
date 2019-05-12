/* dbvalue.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2012  Alexey Gladkov <gladkov.alexey@gmail.com>
 * Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <gcrypt.h>

#include "osec.h"

void  *read_buf;
size_t read_bufsize;

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
osec_digest(struct record *rec, const char *fname, const hash_type_data_t *primary_type_data, const hash_type_data_t *secondary_type_data) {
	int fd;
	ssize_t num;
	gcry_error_t gcrypt_error;
	gcry_md_hd_t handle;
	unsigned char *data_ptr;

	struct record local_rec;

	local_rec.offset = 0;
	local_rec.len    = 1024;
	local_rec.data   = xmalloc(local_rec.len);

	if ((fd = open(fname, OSEC_O_FLAGS)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", fname);

	gcrypt_error = gcry_md_open(&handle, primary_type_data->gcrypt_hashtype, 0);
	if (gcry_err_code(gcrypt_error) != GPG_ERR_NO_ERROR)
		osec_fatal(EXIT_FAILURE, gcry_err_code_to_errno(gcry_err_code(gcrypt_error)), "gcry_md_open error: %s, source: %s", gcry_strerror(gcrypt_error), gcry_strsource(gcrypt_error));

	if (secondary_type_data->gcrypt_hashtype != primary_type_data->gcrypt_hashtype) {
		gcrypt_error = gcry_md_enable(handle, secondary_type_data->gcrypt_hashtype);
		if (gcry_err_code(gcrypt_error) != GPG_ERR_NO_ERROR)
			osec_fatal(EXIT_FAILURE, gcry_err_code_to_errno(gcry_err_code(gcrypt_error)), "gcry_md_enable error: %s, source: %s", gcry_strerror(gcrypt_error), gcry_strsource(gcrypt_error));
	}

	/* Let the kernel know we are going to read everything in sequence. */
	(void) posix_fadvise (fd, 0, 0, POSIX_FADV_SEQUENTIAL);

	while ((num = read(fd, read_buf, read_bufsize)) > 0) {
		gcry_md_write(handle, read_buf, (size_t) num);
	}

	if (num == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: read", fname);

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", fname);

	gcry_md_final(handle);

	data_ptr = gcry_md_read(handle, primary_type_data->gcrypt_hashtype);
	if (data_ptr == NULL)
		osec_fatal(EXIT_FAILURE, 0, "gcry_md_read returned NULL");

	osec_csum_append_value(
		primary_type_data->hashname,
		strlen(primary_type_data->hashname),
		data_ptr,
		gcry_md_get_algo_dlen(primary_type_data->gcrypt_hashtype),
		&local_rec);

	if (secondary_type_data->gcrypt_hashtype != primary_type_data->gcrypt_hashtype) {
		data_ptr = gcry_md_read(handle, secondary_type_data->gcrypt_hashtype);
		if (data_ptr == NULL)
			osec_fatal(EXIT_FAILURE, 0, "gcry_md_read returned NULL");

		osec_csum_append_value(
			secondary_type_data->hashname,
			strlen(secondary_type_data->hashname),
			data_ptr,
			gcry_md_get_algo_dlen(secondary_type_data->gcrypt_hashtype),
			&local_rec);
	}

	gcry_md_close(handle);

	append_value(OVALUE_CSUM, local_rec.data, local_rec.offset, rec);

	xfree(local_rec.data);
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
	append_value(OVALUE_XATTR, &empty, sizeof(empty), rec);
}
#else
#include <sys/types.h>
#include <sys/xattr.h>
#include <attr/attributes.h>

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

empty:	append_value(OVALUE_XATTR, &empty, sizeof(empty), rec);
	xfree(xlist);
	xfree(xvalue);
}
#endif

void *
osec_csum_field(const char *name, size_t namelen, const void *data, size_t dlen, struct csum_field *ret) {

	size_t item_namelen;
	size_t item_digestlen;

	while (dlen >= sizeof(size_t) * 2) {
		memcpy(&item_namelen, data, sizeof(size_t));
		memcpy(&item_digestlen, data + sizeof(size_t), sizeof(size_t));

		if (dlen < sizeof(size_t) * 2 + item_namelen + item_digestlen)
			break;

		if ((namelen == item_namelen)
			&& (memcmp(name, data + sizeof(size_t) * 2, namelen) == 0)) {

			if (ret) {
				ret->name_len = item_namelen;
				ret->data_len = item_digestlen;
				ret->name = data + sizeof(size_t) * 2;
				ret->data = (void*) data + sizeof(size_t) * 2 + namelen;
			}

			return (void*) data;
		}

		data += sizeof(size_t) * 2 + item_namelen + item_digestlen;
		dlen -= sizeof(size_t) * 2 + item_namelen + item_digestlen;
	}

	return NULL;
}

void *
osec_csum_field_next(const void *data, const size_t dlen, struct csum_field *ret, size_t *ret_len) {

	size_t namelen;
	size_t digestlen;

	if (dlen < sizeof(size_t) * 2)
		return NULL;

	memcpy(&namelen, data, sizeof(size_t));
	memcpy(&digestlen, data + sizeof(size_t), sizeof(size_t));

	if (dlen < sizeof(size_t) * 2 + namelen + digestlen)
		return NULL;

	if (ret) {
		ret->name_len = namelen;
		ret->data_len = digestlen;
		ret->name = data + sizeof(size_t) * 2;
		ret->data = (void*) data + sizeof(size_t) * 2 + namelen;
	}

	if (ret_len) {
		*ret_len = dlen - sizeof(size_t) * 2 - namelen - digestlen;
	}

	return (void*) data + sizeof(size_t) * 2 + namelen + digestlen;
}

void
osec_csum_append_value(const char *name, size_t namelen, const void *src, const size_t slen, struct record *rec) {

	size_t sz = sizeof(size_t) * 2 + namelen + slen;

	if (sz > (rec->len - rec->offset)) {
		rec->len += sz - (rec->len - rec->offset);
		rec->data = xrealloc(rec->data, rec->len);
	}

	memcpy(rec->data + rec->offset, &namelen, sizeof(size_t));
	rec->offset += sizeof(size_t);

	memcpy(rec->data + rec->offset, &slen, sizeof(size_t));
	rec->offset += sizeof(size_t);

	memcpy(rec->data + rec->offset, name, namelen);
	rec->offset += namelen;

	memcpy(rec->data + rec->offset, src, slen);
	rec->offset += slen;
}
