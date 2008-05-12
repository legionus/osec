#ifndef OSEC_H
#define OSEC_H

#define digest_len 16

struct osec_stat {
	mode_t	mode;
	uid_t	uid;
	gid_t	gid;
	char	digest[digest_len]; // MD5
};

/* common.c */
void osec_fatal(const int exitnum, const int errnum, const char *fmt, ...);
void osec_error(const char *fmt, ...);

/* memory.c */
void *x_malloc(size_t size);
void *x_realloc(void *ptr, size_t size);
void x_free(void *ptr);

/* privs.c */
void drop_privs(char *user, char *group);

/* status.c */
/* Return 1 if check is true. Otherwise, 0 is returned. */
int check_insecure(struct osec_stat *st);
int check_new(char *fname, struct osec_stat *st);
int check_difference(char *fname, struct osec_stat *new, struct osec_stat *old);
int check_bad_files(char *fname, struct osec_stat *st);
int check_removed(char *fname, struct osec_stat *st);

/* digest.c */
int init_digest(void);
void finalize_digest(void);
void digest(char *fname, struct osec_stat *st);

#endif /* OSEC_H */
