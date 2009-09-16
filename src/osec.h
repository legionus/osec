/* osec.h
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008-2009  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#ifndef OSEC_H
#define OSEC_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cdb.h>

#define OSEC_O_FLAGS (O_RDONLY | O_NOCTTY | O_NONBLOCK | O_NOFOLLOW)

#define OSEC_DB_VERSION 2
int dbversion;

#define OSEC_ISSET(state,mask) (((state) & mask) == mask)
#define OSEC_FMT 0037
#define OSEC_MTS 0020
#define OSEC_UID 0010
#define OSEC_GID 0004
#define OSEC_MOD 0002
#define OSEC_INO 0001

#define OVALUE_LINK 4
#define OVALUE_CSUM 2
#define OVALUE_STAT 1

typedef struct osec_stat {
	dev_t	dev;	/* ID of device containing file */
	ino_t	ino;	/* inode number */
	mode_t	mode;	/* file's permission bits */
	uid_t	uid;	/* user ID of owner */
	gid_t	gid;	/* group ID of owner */
	int64_t	mtime;	/* time of last modification */
} osec_stat_t;

#define digest_len 20 // SHA1

/* common.c */
void osec_fatal(const int exitnum, const int errnum, const char *fmt, ...);
int  osec_error(const char *fmt, ...);

/* memory.c */
void *xmempcpy(void *dest, const void *src, size_t n);
void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
void  xfree(void *ptr);

/* privs.c */
void drop_privs(char *user, char *group);

/* status.c */
void check_new(const char *fname, void *data, size_t len);

/* Return 1 if check is true. Otherwise, 0 is returned. */
int check_insecure(osec_stat_t *st);
int check_difference(const char *fname, void *ndata, size_t nlen, void *odata, size_t olen);
int check_bad_files(const char *fname, void *data, size_t len);
int check_removed(const char *fname, void *data, size_t len);

/* digest.c */
void digest(const char *fname, char *digest);

/* dbvalue.c */
void  *osec_field(const unsigned type, const void *data, const size_t dlen);
size_t append_value(const unsigned type, void **dst, size_t *dlen, const void *src, const size_t slen);
size_t osec_state(void **val, size_t *vlen, const struct stat *st);
size_t osec_digest(void **val, size_t *vlen, const char *fname);
size_t osec_symlink(void **val, size_t *vlen, const char *fname);

/* dbvalue.c */
int  compat_db_version(int fd);
void write_db_version(struct cdb_make *cdbm);

/* exclude.c */
int is_exclude(char *file);
void exclude_match_append(char *pattern);
void exclude_matches_file(char *file);

/* ignore.c */
void process_ignore(char *param);

/* path.c */
void recreate_tempdir(void);
char *validate_path(const char *path);

#endif /* OSEC_H */
