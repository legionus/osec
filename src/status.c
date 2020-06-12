/* status.c
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
#include <ctype.h>
#include <time.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>

#include "osec.h"

extern size_t pw_bufsize;
extern size_t gr_bufsize;

extern int numeric_user_group;
extern unsigned ignore;

static void printf_pwname(const char *var, uid_t uid)
{
	struct passwd pwbuf, *pw;
	char *buf = NULL;
	int rc;

	if (numeric_user_group)
		goto shownum;

	while (1) {
		buf = malloc(pw_bufsize);
		if (buf == NULL)
			goto shownum;

		rc = getpwuid_r(uid, &pwbuf, buf, pw_bufsize, &pw);

		if (rc == 0)
			break;

		if (rc == ERANGE) {
			pw_bufsize += 1024;
			xfree(buf);
			continue;
		}

		goto shownum;
	}

	if (pw == NULL)
		goto shownum;

	printf(" %s=%s", var, pw->pw_name);
	xfree(buf);
	return;
shownum:
	xfree(buf);
	printf(" %s=%ld", var, (long) uid);
	return;
}

static void printf_grname(const char *var, gid_t gid)
{
	struct group grbuf, *gr = NULL;
	char *buf = NULL;
	int rc;

	if (numeric_user_group)
		goto shownum;

	while (1) {
		buf = malloc(gr_bufsize);
		if (buf == NULL)
			goto shownum;

		rc = getgrgid_r(gid, &grbuf, buf, gr_bufsize, &gr);

		if (rc == 0)
			break;

		if (rc == ERANGE) {
			gr_bufsize += 1024;
			xfree(buf);
			continue;
		}

		goto shownum;
	}

	if (gr == NULL)
		goto shownum;

	printf(" %s=%s", var, gr->gr_name);
	xfree(buf);
	return;
shownum:
	xfree(buf);
	printf(" %s=%ld", var, (long) gid);
	return;
}

static bool is_bad(osec_stat_t *st)
{
	if (!(st->mode & (S_ISUID | S_ISGID | S_IWOTH)))
		return false;

	//skip suid or sgid directory
	if (S_ISDIR(st->mode) && !(st->mode & S_IWOTH))
		return false;

	//skip symlinks
	if (S_ISLNK(st->mode))
		return false;

	return true;
}

static void print_insecure(osec_stat_t *st)
{
	if (!is_bad(st))
		return;

	printf(" [");

	if (st->mode & S_ISUID)
		printf_pwname((char *) "suid", st->uid);

	if (st->mode & S_ISGID)
		printf_grname((char *) "sgid", st->gid);

	if (st->mode & S_IWOTH)
		printf(" ww");

	printf(" ]");
}

static void print_state(const char *mode, const char *fname, osec_stat_t *st)
{
	printf("%s\tstat\t%s\t", fname, mode);

	printf_pwname((char *) "uid", st->uid);
	printf_grname((char *) "gid", st->gid);
	printf(" mode=%lo inode=%ld", (unsigned long) st->mode, (long) st->ino);
	if (dbversion > 1) {
		printf(" mtime=%lld", st->mtime);
		if (dbversion > 4)
			/*
			 * Format the nanoseconds part.  Leave a trailing zero to
			 * discourage people from writing scripts which extract the
			 * fractional part of the timestamp by using column offsets.
			 * The reason for discouraging this is that in the future, the
			 * granularity may not be nanoseconds.
			 */
			printf(".%09lld0", st->mtime_nsec);
	}

	print_insecure(st);
	printf("\n");
}

static inline void print_digest(const char *dst, size_t len)
{
	for (size_t i = 0; i < len; i++)
		printf("%02x", (unsigned char) dst[i]);
}

static bool check_checksum(const char *fname,
		void *ndata, size_t nlen,
		void *odata, size_t olen,
		const hash_type_data_t *hashtype_data)
{
	char *old, *new;
	struct field old_data, new_data;
	struct csum_field old_csum_data, new_csum_data;

	if (ignore & OSEC_CSM)
		return true;

	old = osec_field(OVALUE_CSUM, odata, olen, &old_data);
	if (old == NULL) {
		osec_error("%s: osec_field(odata): unable to get `checksum' from database value",
				fname);
		return false;
	}

	new = osec_field(OVALUE_CSUM, ndata, nlen, &new_data);
	if (new == NULL) {
		osec_error("%s: osec_field(ndata): unable to get `checksum' from database value",
				fname);
		return false;
	}

	if (dbversion >= 4) {
		old = osec_csum_field(hashtype_data->hashname, strlen(hashtype_data->hashname),
				old, old_data.len, &old_csum_data);
		if (old == NULL) {
			osec_error("%s: osec_field(odata): checksum doesn't contain '%s' hash",
					fname, hashtype_data->hashname);
			return false;
		}
	} else {
		if (strcmp(hashtype_data->hashname, "sha1") != 0) {
			osec_error("%s: osec_field(odata): checksum doesn't contain '%s' hash",
					fname, hashtype_data->hashname);
			return false;
		}

		old_csum_data.data_len = old_data.len;
		old_csum_data.data = old;
	}

	new = osec_csum_field(hashtype_data->hashname, strlen(hashtype_data->hashname),
			new, new_data.len, &new_csum_data);
	if (new == NULL) {
		osec_error("%s: osec_field(ndata): checksum doesn't contain '%s' hash",
				fname, hashtype_data->hashname);
		return false;
	}

	if ((old_csum_data.data_len != new_csum_data.data_len) || (memcmp(old_csum_data.data, new_csum_data.data, old_csum_data.data_len) != 0)) {
		printf("%s\tchecksum\tchanged\told checksum=%s:", fname, hashtype_data->hashname);
		print_digest(old_csum_data.data, old_csum_data.data_len);

		printf("\tnew checksum=%s:", hashtype_data->hashname);
		print_digest(new_csum_data.data, new_csum_data.data_len);

		printf("\n");
	}

	return true;
}

static bool check_symlink(const char *fname,
		void *ndata, size_t nlen,
		void *odata, size_t olen)
{
	char *old, *new;

	if (ignore & OSEC_LNK)
		return true;

	old = osec_field(OVALUE_LINK, odata, olen, NULL);
	if (old == NULL) {
		osec_error("%s: osec_field(odata): unable to get `symlink' from database value",
				fname);
		return false;
	}

	new = osec_field(OVALUE_LINK, ndata, nlen, NULL);
	if (new == NULL) {
		osec_error("%s: osec_field(ndata): unable to get `symlink' from database value",
				fname);
		return false;
	}

	if (strcmp(old, new) != 0)
		printf("%s\tsymlink\tchanged\told target=%s\tnew target=%s\n",
				fname, old, new);

	return true;
}

static inline bool printable(char *data, size_t len)
{
	for (unsigned int i = 0; i < len; i++) {
		if (!isprint(data[i]) && data[i] != '\0')
			return false;
	}
	return true;
}

static void print_xattr_nonexistent(const char *msg, const char *fn,
		char *list1, size_t len1,
		char *list2, size_t len2)
{
	char *nkey, *value;
	size_t klen, vlen;

	nkey = list1;

	while (nkey != (list1 + len1)) {
		unsigned found = 0;

		klen = strlen(nkey) + 1;
		if (klen == 1)
			return;

		if (list2 && len2 > 0) {
			char *okey = list2;
			size_t olen;

			while (okey != (list2 + len2)) {
				olen = strlen(okey) + 1;
				if (olen == 1)
					break;

				if (!strcmp(nkey, okey)) {
					found = 1;
					break;
				}

				okey += olen;
				memcpy(&vlen, okey, sizeof(size_t));
				okey += sizeof(size_t) + vlen + 1;
			}
		}

		memcpy(&vlen, nkey + klen, sizeof(size_t));
		value = nkey + klen + sizeof(size_t);

		if (!found) {
			printf("%s\txattr\t%s\t%s\t%s\n",
			       fn, msg, nkey,
			       printable(value, vlen) ? value : "(binary)");
		}

		nkey += klen + sizeof(size_t) + vlen + 1;
	}
}

static void print_xattr_difference(const char *msg, const char *fn,
		char *list1, size_t len1,
		char *list2, size_t len2)
{
	char *nkey, *okey, *nvalue, *ovalue;
	size_t nvalue_len, ovalue_len;
	size_t nkey_len, okey_len;

	nkey = list1;

	while (nkey != (list1 + len1)) {
		nkey_len = strlen(nkey) + 1;
		if (nkey_len == 1)
			break;

		memcpy(&nvalue_len, nkey + nkey_len, sizeof(size_t));
		nvalue = nkey + nkey_len + sizeof(size_t);

		okey = list2;

		while (okey != (list2 + len2)) {
			okey_len = strlen(okey) + 1;
			if (okey_len == 1)
				break;

			memcpy(&ovalue_len, okey + okey_len, sizeof(size_t));
			ovalue = okey + okey_len + sizeof(size_t);

			if ((nkey_len == okey_len && !strcmp(nkey, okey)) &&
			    (nvalue_len != ovalue_len || memcmp(nvalue, ovalue, nvalue_len))) {
				printf("%s\txattr\t%s\t%s\t%s -> %s\n",
				       fn, msg, nkey,
				       printable(ovalue, ovalue_len) ? ovalue : "(binary)",
				       printable(nvalue, nvalue_len) ? nvalue : "(binary)");
				break;
			}
			okey += okey_len + sizeof(size_t) + ovalue_len + 1;
		}
		nkey += nkey_len + sizeof(size_t) + nvalue_len + 1;
	}
}

static bool check_xattr(const char *fname,
		void *ndata, size_t nlen,
		void *odata, size_t olen)
{
	struct field oattrs, nattrs;

	if (osec_field(OVALUE_XATTR, odata, olen, &oattrs) == NULL) {
		osec_error("%s: osec_field(odata): unable to get `xattr' from database value",
				fname);
		return false;
	}

	if (osec_field(OVALUE_XATTR, ndata, nlen, &nattrs) == NULL) {
		osec_error("%s: osec_field(ndata): unable to get `xattr' from database value",
				fname);
		return false;
	}

	if (nattrs.len == oattrs.len && !memcmp(nattrs.data, oattrs.data, nattrs.len))
		return true;

	print_xattr_nonexistent("new", fname, (char *) nattrs.data, nattrs.len, (char *) oattrs.data, oattrs.len);
	print_xattr_nonexistent("old", fname, (char *) oattrs.data, oattrs.len, (char *) nattrs.data, nattrs.len);
	print_xattr_difference("changed", fname, (char *) nattrs.data, nattrs.len, (char *) oattrs.data, oattrs.len);

	return true;
}

int check_difference(const char *fname,
		void *ndata, size_t nlen,
		void *odata, size_t olen,
		const hash_type_data_t *hashtype_data)
{
	osec_stat_t *new_st, *old_st;
	unsigned state = 0;

	old_st = osec_field(OVALUE_STAT, odata, olen, NULL);
	if (old_st == NULL) {
		osec_error("%s: osec_field(odata): Unable to get `stat' from database value",
				fname);
		return -1;
	}

	new_st = osec_field(OVALUE_STAT, ndata, nlen, NULL);
	if (new_st == NULL) {
		osec_error("%s: osec_field(ndata): Unable to get `stat' from database value",
				fname);
		return -1;
	}

	if (S_ISREG(new_st->mode) && S_ISREG(old_st->mode)) {
		if (!check_checksum(fname, ndata, nlen, odata, olen, hashtype_data))
			return -1;
	}
	else if (S_ISLNK(new_st->mode) && S_ISLNK(old_st->mode)) {
		if (!check_symlink(fname, ndata, nlen, odata, olen))
			return -1;
	}

	if (dbversion > 2 && !check_xattr(fname, ndata, nlen, odata, olen))
		return -1;

	// clang-format off
	if (!(ignore & OSEC_UID) && old_st->uid   != new_st->uid)    state |= OSEC_UID;
	if (!(ignore & OSEC_GID) && old_st->gid   != new_st->gid)    state |= OSEC_GID;
	if (!(ignore & OSEC_MOD) && old_st->mode  != new_st->mode)   state |= OSEC_MOD;
	if (!(ignore & OSEC_INO) && old_st->ino   != new_st->ino)    state |= OSEC_INO;
	if (dbversion > 1 && !(ignore & OSEC_MTS)) {
		if (old_st->mtime != new_st->mtime)
			state |= OSEC_MTS;
		if (dbversion > 4 && old_st->mtime_nsec != new_st->mtime_nsec)
			state |= OSEC_MTS;
	}
	// clang-format on

	if (!(state & (OSEC_UID | OSEC_GID | OSEC_MOD | OSEC_INO | OSEC_MTS)))
		return 0;

	printf("%s\tstat\tchanged\told", fname);

	/* Old state */
	if (state & OSEC_UID)
		printf_pwname((char *) "uid", old_st->uid);

	if (state & OSEC_GID)
		printf_grname((char *) "gid", old_st->gid);

	if (state & OSEC_MOD)
		printf(" mode=%lo", (unsigned long) old_st->mode);

	if (state & OSEC_INO)
		printf(" inode=%ld", (long) old_st->ino);

	if (state & OSEC_MTS)
		printf(" mtime=%lld.%09lld0", old_st->mtime, old_st->mtime_nsec);

	print_insecure(old_st);

	/* New state */
	printf("\tnew");

	if (state & OSEC_UID)
		printf_pwname((char *) "uid", new_st->uid);

	if (state & OSEC_GID)
		printf_grname((char *) "gid", new_st->gid);

	if (state & OSEC_MOD)
		printf(" mode=%lo", (unsigned long) new_st->mode);

	if (state & OSEC_INO)
		printf(" inode=%ld", (long) new_st->ino);

	if (state & OSEC_MTS)
		printf(" mtime=%lld.%09lld0", new_st->mtime, new_st->mtime_nsec);

	print_insecure(new_st);
	printf("\n");

	return 1;
}

bool check_bad_files(const char *fname, void *data, size_t len)
{
	osec_stat_t *st;

	st = osec_field(OVALUE_STAT, data, len, NULL);
	if (st == NULL) {
		osec_error("%s: osec_field: unable to get `stat' from database value",
				fname);
		return false;
	}

	if (is_bad(st))
		print_state("info", fname, st);

	return true;
}

bool check_new(const char *fname, void *data, size_t dlen,
		const hash_type_data_t *hashtype_data)
{
	struct field attrs;
	osec_stat_t *st;

	st = osec_field(OVALUE_STAT, data, dlen, NULL);
	if (st == NULL) {
		osec_error("osec_field: unable to parse `stat' field");
		return false;
	}

	if (S_ISREG(st->mode)) {
		char *csum;
		struct field csum_data;
		struct csum_field csum_field_data;

		csum = osec_field(OVALUE_CSUM, data, dlen, &csum_data);
		if (csum == NULL) {
			osec_error("osec_field: unable to parse `checksum' field");
			return false;
		}

		csum = osec_csum_field(hashtype_data->hashname, strlen(hashtype_data->hashname),
				csum, csum_data.len, &csum_field_data);
		if (csum == NULL) {
			osec_error("%s: osec_field(ndata): checksum doesn't contain `%s' hash",
					fname, hashtype_data->hashname);
			return false;
		}

		printf("%s\tchecksum\tnew\t checksum=%s:", fname, hashtype_data->hashname);
		print_digest(csum_field_data.data, csum_field_data.data_len);
		printf("\n");
	}

	print_state("new", fname, st);

	if (dbversion > 2) {
		if ((osec_field(OVALUE_XATTR, data, dlen, &attrs)) == NULL) {
			osec_error("osec_field: unable to parse `xattr' field");
			return false;
		}

		print_xattr_nonexistent("new", fname, (char *) attrs.data, attrs.len, NULL, 0);
	}

	return true;
}

bool check_removed(const char *fname, void *data, size_t len,
		const hash_type_data_t *hashtype_data)
{
	struct field attrs;
	osec_stat_t *st;

	st = osec_field(OVALUE_STAT, data, len, NULL);
	if (st == NULL) {
		osec_error("%s: osec_field: unable to get `stat' from database value",
				fname);
		return false;
	}

	if (S_ISREG(st->mode)) {
		char *csum;
		struct field csum_data;

		csum = osec_field(OVALUE_CSUM, data, len, &csum_data);
		if (csum == NULL) {
			osec_error("%s: osec_field: Unable to get `checksum' from database value",
					fname);
			return false;
		}

		if (dbversion >= 4) {
			struct csum_field csum_field_data;

			csum = osec_csum_field(hashtype_data->hashname, strlen(hashtype_data->hashname),
					csum, csum_data.len, &csum_field_data);
			if (csum == NULL) {
				osec_error("%s: osec_field: Checksum doesn't contain `%s' hash",
						fname, hashtype_data->hashname);
				return false;
			}

			printf("%s\tchecksum\tremoved\t checksum=%s:", fname, hashtype_data->hashname);
			print_digest(csum_field_data.data, csum_field_data.data_len);
			printf("\n");
		} else {
			printf("%s\tchecksum\tremoved\t checksum=sha1:", fname);
			print_digest(csum, csum_data.len);
			printf("\n");
		}
	}
	print_state((char *) "removed", fname, st);

	if (dbversion > 2) {
		if ((osec_field(OVALUE_XATTR, data, len, &attrs)) == NULL) {
			osec_error("osec_field: unable to parse `xattr' field");
			return false;
		}

		print_xattr_nonexistent("old", fname, (char *) attrs.data, attrs.len, NULL, 0);
	}

	return true;
}
