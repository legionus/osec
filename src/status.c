/* status.c
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

static void
printf_pwname(const char *var, uid_t uid) {
	struct passwd pwbuf, *pw;
	char *buf = NULL;
	int rc;

	if (numeric_user_group) {
		printf(" %s=%ld", var, (long) uid);
		return;
	}

	while (1) {
		buf = (char *) xmalloc(pw_bufsize);

		rc = getpwuid_r(uid, &pwbuf, buf, pw_bufsize, &pw);

		if (rc == 0)
			break;

		if (rc == ERANGE) {
			pw_bufsize += 1024;
			xfree(buf);
			continue;
		}

		osec_fatal(EXIT_FAILURE, rc, "getpwuid_r");
	}

	(pw != NULL)
		? printf(" %s=%s", var, pw->pw_name)
		: printf(" %s=#%ld", var, (long) uid);

	xfree(buf);
}

static void
printf_grname(const char *var, gid_t gid) {
	struct group grbuf, *gr = NULL;
	char *buf = NULL;
	int rc;

	if (numeric_user_group) {
		printf(" %s=%ld", var, (long) gid);
		return;
	}

	while (1) {
		buf = (char *) xmalloc(gr_bufsize);

		rc = getgrgid_r(gid, &grbuf, buf, gr_bufsize, &gr);

		if (rc == 0)
			break;

		if (rc == ERANGE) {
			gr_bufsize += 1024;
			xfree(buf);
			continue;
		}

		osec_fatal(EXIT_FAILURE, rc, "getgrgid_r");
	}

	(gr != NULL)
		? printf(" %s=%s", var, gr->gr_name)
		: printf(" %s=#%ld", var, (long) gid);

	xfree(buf);
}

static int
is_bad(osec_stat_t *st) {
	if (!(st->mode & (S_ISUID|S_ISGID|S_IWOTH)))
		return 0;

	//skip suid or sgid directory
	if (S_ISDIR(st->mode) && !(st->mode & S_IWOTH))
		return 0;

	//skip symlinks
	if (S_ISLNK(st->mode))
		return 0;

	return 1;
}

int
check_insecure(osec_stat_t *st) {
	if (!is_bad(st))
		return 0;

	printf(" [");

	if (st->mode & S_ISUID)
		printf_pwname((char *) "suid", st->uid);

	if (st->mode & S_ISGID)
		printf_grname((char *) "sgid", st->gid);

	if (st->mode & S_IWOTH)
		printf(" ww");

	printf(" ]");
	return 1;
}

static void
show_state(const char *mode, const char *fname, osec_stat_t *st) {
	printf("%s\tstat\t%s\t", fname, mode);

	printf_pwname((char *) "uid", st->uid);
	printf_grname((char *) "gid", st->gid);
	printf(" mode=%lo inode=%ld", (unsigned long) st->mode, (long) st->ino);
	if (dbversion > 1)
		printf(" mtime=%lld", st->mtime);

	check_insecure(st);
	printf("\n");
}

static void
show_digest(const char *dst) {
	int i = 0;
	while (i < digest_len)
		printf("%02x", (unsigned char) dst[i++]);
}


static void
check_checksum(const char *fname, void *ndata, size_t nlen, void *odata, size_t olen) {
	char *old, *new;

	if (ignore & OSEC_CSM)
		return;

	if ((old = osec_field(OVALUE_CSUM, odata, olen, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(odata): Unable to get 'checksum' from database value\n",
			fname);

	if ((new = osec_field(OVALUE_CSUM, ndata, nlen, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(ndata): Unable to get 'checksum' from database value\n",
			fname);

	if (strncmp(old, new, (size_t) digest_len) != 0) {
		printf("%s\tchecksum\tchanged\told checksum=", fname);
		show_digest(old);

		printf("\tnew checksum=");
		show_digest(new);

		printf("\n");
	}
}

static void
check_symlink(const char *fname, void *ndata, size_t nlen, void *odata, size_t olen) {
	char *old, *new;

	if (ignore & OSEC_LNK)
		return;

	if ((old = (char *) osec_field(OVALUE_LINK, odata, olen, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(odata): Unable to get 'symlink' from database value\n",
			fname);

	if ((new = (char *) osec_field(OVALUE_LINK, ndata, nlen, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(ndata): Unable to get 'symlink' from database value\n",
			fname);

	if (strcmp(old, new) != 0)
		printf("%s\tsymlink\tchanged\told target=%s\tnew target=%s\n",
			fname, old, new);
}

static int
printable(char *data, size_t len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		if (!isprint(data[i]) && data[i] != '\0')
			return 0;
	return 1;
}

static void
xattr_nonexistent(const char *msg, const char *fn, char *list1, size_t len1, char *list2, size_t len2)
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

		memcpy(&vlen, nkey + klen,  sizeof(size_t));
		value = nkey + klen + sizeof(size_t);

		if (!found) {
			printf("%s\txattr\t%s\t%s\t%s\n",
				fn, msg, nkey,
				printable(value, vlen) ? value : "(binary)");
		}

		nkey += klen + sizeof(size_t) + vlen + 1;
	}
}

static void
xattr_difference(const char *msg, const char *fn, char *list1, size_t len1, char *list2, size_t len2)
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

static void
check_xattr(const char *fname, void *ndata, size_t nlen, void *odata, size_t olen)
{
	struct field oattrs, nattrs;

	if (osec_field(OVALUE_XATTR, odata, olen, &oattrs) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(odata): Unable to get 'xattr' from database value\n",
			fname);

	if (osec_field(OVALUE_XATTR, ndata, nlen, &nattrs) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(ndata): Unable to get 'xattr' from database value\n",
			fname);

	if (nattrs.len == oattrs.len && !memcmp(nattrs.data, oattrs.data, nattrs.len))
		return;

	xattr_nonexistent("new",    fname, (char *) nattrs.data, nattrs.len, (char *) oattrs.data, oattrs.len);
	xattr_nonexistent("old",    fname, (char *) oattrs.data, oattrs.len, (char *) nattrs.data, nattrs.len);
	xattr_difference("changed", fname, (char *) nattrs.data, nattrs.len, (char *) oattrs.data, oattrs.len);
}

int
check_difference(const char *fname, void *ndata, size_t nlen, void *odata, size_t olen) {
	osec_stat_t *new_st, *old_st;
	unsigned state = 0;

	if ((old_st = osec_field(OVALUE_STAT, odata, olen, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(odata): Unable to get 'stat' from database value\n",
			fname);

	if ((new_st = osec_field(OVALUE_STAT, ndata, nlen, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field(ndata): Unable to get 'stat' from database value\n",
			fname);

	if (S_ISREG(new_st->mode) && S_ISREG(old_st->mode))
		check_checksum(fname, ndata, nlen, odata, olen);

	else if (S_ISLNK(new_st->mode) && S_ISLNK(old_st->mode))
		check_symlink(fname, ndata, nlen, odata, olen);

	if (dbversion > 2)
		check_xattr(fname, ndata, nlen, odata, olen);

	if (!(ignore & OSEC_UID) && old_st->uid   != new_st->uid)    state |= OSEC_UID;
	if (!(ignore & OSEC_GID) && old_st->gid   != new_st->gid)    state |= OSEC_GID;
	if (!(ignore & OSEC_MOD) && old_st->mode  != new_st->mode)   state |= OSEC_MOD;
	if (!(ignore & OSEC_INO) && old_st->ino   != new_st->ino)    state |= OSEC_INO;
	if (dbversion > 1 &&
	   (!(ignore & OSEC_MTS) && old_st->mtime != new_st->mtime)) state |= OSEC_MTS;

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
		printf(" mtime=%lld", old_st->mtime);

	check_insecure(old_st);

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
		printf(" mtime=%lld", new_st->mtime);

	check_insecure(new_st);
	printf("\n");
	return 1;
}


int
check_bad_files(const char *fname, void *data, size_t len) {
	osec_stat_t *st;

	if ((st = osec_field(OVALUE_STAT, data, len, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field: Unable to get 'stat' from database value\n",
			fname);

	if (!is_bad(st))
		return 0;

	show_state((char *) "info", fname, st);
	return 1;
}

void
check_new(const char *fname, void *data, size_t dlen) {
	struct field attrs;
	osec_stat_t *st;

	if ((st = osec_field(OVALUE_STAT, data, dlen, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0, "osec_field: Unable to parse field\n");

	if (S_ISREG(st->mode)) {
		char *csum;

		if ((csum = osec_field(OVALUE_CSUM, data, dlen, NULL)) == NULL)
			osec_fatal(EXIT_FAILURE, 0, "osec_field: Unable to parse field\n");

		printf("%s\tchecksum\tnew\t checksum=", fname);
		show_digest(csum);
		printf("\n");
	}
	show_state((char *) "new", fname, st);

	if (dbversion > 2) {
		if ((osec_field(OVALUE_XATTR, data, dlen, &attrs)) == NULL)
			osec_fatal(EXIT_FAILURE, 0, "osec_field: Unable to parse field\n");

			xattr_nonexistent("new", fname, (char *) attrs.data, attrs.len, NULL, 0);
	}
}

int
check_removed(const char *fname, void *data, size_t len) {
	struct field attrs;
	osec_stat_t *st;

	if ((st = osec_field(OVALUE_STAT, data, len, NULL)) == NULL)
		osec_fatal(EXIT_FAILURE, 0,
			"%s: osec_field: Unable to get 'stat' from database value\n",
			fname);

	if (S_ISREG(st->mode)) {
		char *csum;

		if ((csum = osec_field(OVALUE_CSUM, data, len, NULL)) == NULL)
			osec_fatal(EXIT_FAILURE, 0,
				"%s: osec_field: Unable to get 'checksum' from database value\n",
				fname);

		printf("%s\tchecksum\tremoved\t checksum=", fname);
		show_digest(csum);
		printf("\n");
	}
	show_state((char *) "removed", fname, st);

	if (dbversion > 2) {
		if ((osec_field(OVALUE_XATTR, data, len, &attrs)) == NULL)
			osec_fatal(EXIT_FAILURE, 0, "osec_field: Unable to parse field\n");

			xattr_nonexistent("old", fname, (char *) attrs.data, attrs.len, NULL, 0);
	}

	return 1;
}
