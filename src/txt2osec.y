/* txt2osec.y
 *
 * This file is part of Osec (lightweight integrity checker)
 *  Copyright (C) 2010-2012  Alexey Gladkov <gladkov.alexey@gmail.com>
 *  Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
%{
#define YYSTYPE long long

#include "config.h"

#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "osec.h"

extern FILE *yyin;

char str[PATH_MAX];

char *pathname = NULL;
int line_nr    = 1;

#define F_ISSET(state,mask) (((state) & (mask)) == (mask))
enum {
	FLAG_FILE  = (01 << 0),
	FLAG_CSUM  = (01 << 1),
	FLAG_LINK  = (01 << 2),
	FLAG_MODE  = (01 << 3),
	FLAG_MTIME = (01 << 4),	
	FLAG_DEV   = (01 << 5),
	FLAG_INO   = (01 << 6),
	FLAG_UID   = (01 << 7),
	FLAG_GID   = (01 << 8),
	FLAG_XATTR = (01 << 9),
};

char *fname = NULL;
char *slink = NULL;
char **chsum = NULL;
size_t chsum_count = 0;
char *xattr = NULL;
char *hashnames = NULL;

osec_stat_t ost;

struct record rec;

struct cdb_make cdbm;
long flags = 0;

void print_help(int ret);
void print_version(void);
int yyerror(const char *s);
int yylex (void);

%}

/* BISON Declarations */
%token FILENAME DEVICE INODE UID GID MTIME CHECKSUM SYMLINK MODE
%token EQUALS EOL ERROR
%token NUMBER OCTAL STRLITERAL
%token HASHNAMES
%token XATTR

/* Grammar follows */
%%
input		: /* empty string */
		| input line
 		;
line		: endline
		| fileline range endline
		| hashline hashlineend
		;
range		: range range0
		| range0
		;
range0		: devline
		| inoline
		| uidline
		| gidline
		| mtimeline
		| csumline
		| linkline
		| modeline
		| xattrline
		;
hashline	: HASHNAMES EQUALS STRLITERAL
		{
			hashnames = strdup(str);
		}
		;
fileline	: FILENAME EQUALS STRLITERAL
		{ fname = strdup(str);
		  flags |= FLAG_FILE; }
		;
csumline	: CHECKSUM EQUALS STRLITERAL
		{
		  char *delim;
		  size_t n = strlen(str);

		  delim = strchr(str, ':');
		  if (delim != NULL) {
			n = strlen(delim + 1);
		  }

		  if ((n % 2) != 0)
			osec_fatal(1, 0, "%s:%d: Checksum value invalid size: %s",
			           pathname, line_nr, str);

		  ++chsum_count;
		  chsum = xrealloc(chsum, sizeof(char*) * chsum_count);
		  chsum[chsum_count - 1] = strdup(str);
		  flags |= FLAG_CSUM; }
		;
xattrline	: XATTR EQUALS STRLITERAL
		{
		  size_t n = strlen(str);
		  if (n % 2 != 0)
			osec_fatal(1, 0, "%s:%d: Xattr value has invalid size: %s",
			           pathname, line_nr, str);
		  xattr = strdup(str);
		  flags |= FLAG_XATTR; }
		;
linkline	: SYMLINK EQUALS STRLITERAL
		{ if (strlen(str) > 0) {
			slink = strdup(str);
		  	flags |= FLAG_LINK;
		  }
		}
		;
devline		: DEVICE EQUALS NUMBER
		{ ost.dev = (dev_t) $3;
		  flags |= FLAG_DEV; }
		;
inoline		: INODE EQUALS NUMBER
		{ if ($3 > LONG_MAX)
			osec_fatal(1, 0, "%s:%d: Inode value too long: %lld",
			           pathname, line_nr, $3);
		  ost.ino = (ino_t) $3;
		  flags |= FLAG_INO; }
		;
uidline		: UID EQUALS NUMBER
		{ if ($3 > LONG_MAX)
			osec_fatal(1, 0, "%s:%d: UID value too long: %lld",
			           pathname, line_nr, $3);
		  ost.uid = (uid_t) $3;
		  flags |= FLAG_UID; }
		;
gidline		: GID EQUALS NUMBER
		{ if ($3 > LONG_MAX)
			osec_fatal(1, 0, "%s:%d: GID value too long: %lld",
			           pathname, line_nr, $3);
		  ost.gid = (gid_t) $3;
		  flags |= FLAG_GID; }
		;
mtimeline	: MTIME EQUALS NUMBER
		{ ost.mtime = (int64_t) $3;
		  flags |= FLAG_MTIME; }
		;
modeline	: MODE EQUALS OCTAL
		{ ost.mode = (mode_t) $3;
		  flags |= FLAG_MODE; }
		;
hashlineend		: EOL
		{
		}
		;
endline		: EOL
		{
			rec.offset = 0;

			if (!F_ISSET(flags, FLAG_FILE | FLAG_DEV | FLAG_INO | FLAG_UID | FLAG_GID | FLAG_MODE))
				osec_fatal(EXIT_FAILURE, 0, "%s:%d: Wrong file format",
				           pathname, line_nr);

			append_value(OVALUE_STAT, &ost, sizeof(ost), &rec);

			if (F_ISSET(flags, FLAG_XATTR)) {
				char *s = xattr;
				unsigned int h;
				size_t i;
				size_t xattr_len;
				unsigned char *xattr_str = NULL;

				xattr_len = strlen(xattr) / 2;

				xattr_str = xmalloc(xattr_len);

				for (i = 0; i < xattr_len; i++) {
					sscanf(s, "%02x", &h);
					xattr_str[i] = (unsigned char) h;
					s += 2;
				}
				append_value(OVALUE_XATTR, xattr_str, xattr_len, &rec);
				xfree(xattr);
				xfree(xattr_str);
			}
			else
			{
				/* if not xattr is found, it's probably data from database before version 3, just add empty xattr value for compatibility */
				const char empty = '\0';
				append_value(OVALUE_XATTR, &empty, sizeof(empty), &rec);
			}

			if (F_ISSET(flags, FLAG_CSUM)) {
				unsigned int h, i;
				size_t z;

				char *buffer = NULL;
				size_t buffer_size = 0;

				struct record local_rec;

				local_rec.offset = 0;
				local_rec.len    = 1024;
				local_rec.data   = xmalloc(local_rec.len);

				if (!S_ISREG(ost.mode))
					osec_fatal(EXIT_FAILURE, 0, "%s:%d: Wrong file format: checksum field for not regular file",
					           pathname, line_nr);

				for (z = 0; z < chsum_count; ++z) {
					size_t namelen;
					const char *name;
					size_t digestlen;
					const char *digest;
					char *delim;

					delim = strchr(chsum[z], ':');
					if (delim != NULL) {
						namelen = delim - chsum[z];
						name = chsum[z];
						digestlen = strlen(delim + 1) / 2;
						digest = delim + 1;
					} else {
						namelen = sizeof("sha1") - 1;
						name = "sha1";
						digestlen = strlen(chsum[z]) / 2;
						digest = chsum[z];
					}

					if (buffer_size < digestlen)
						buffer = xrealloc(buffer, digestlen);

					for (i = 0; i < digestlen; ++i) {
						sscanf(digest + i * 2, "%02x", &h);
						buffer[i] = (unsigned char) h;
					}

					osec_csum_append_value(name, namelen, buffer, digestlen, &local_rec);
				}

				append_value(OVALUE_CSUM, local_rec.data, local_rec.offset, &rec);

				for (z = 0; z < chsum_count; ++z)
					xfree(chsum[z]);
				xfree(chsum);
				chsum = NULL;
				chsum_count = 0;

				xfree(local_rec.data);
				xfree(buffer);
			}

			if (F_ISSET(flags, FLAG_LINK)) {
				if (!S_ISLNK(ost.mode))
					osec_fatal(EXIT_FAILURE, 0, "%s:%d: Wrong file format: symlink field for not symbolic link",
					           pathname, line_nr);

				append_value(OVALUE_LINK, slink, (size_t) strlen(slink)+1, &rec);
				xfree(slink);
			}

			if (cdb_make_add(&cdbm, fname, (unsigned) strlen(fname)+1, rec.data, (unsigned) rec.offset) != 0)
				osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", fname);

			xfree(fname);
			flags = 0;
		}
		;

%%

int
yyerror(const char *s)
{
	printf("txt2osec: %s:%d: %s\n", pathname, line_nr, s);
	return(0);
}

void __attribute__ ((noreturn))
print_help(int ret)
{
	printf("Usage: %s [options] <FILENAME> <DBFILE>\n"
	       "\n"
	       "Options:\n"
	       "  -V, --version   print program version and exit;\n"
	       "  -h, --help      output a brief help message.\n"
	       "\n", program_invocation_short_name);
	exit(ret);
}

void __attribute__ ((noreturn))
print_version(void)
{
	printf("%s version "PACKAGE_VERSION"\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "Modified by Aleksei Nikiforov <darktemplar@basealt.ru>\n"
	       "\n"
	       "Copyright (C) 2010-2012  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
		program_invocation_short_name);
	exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	FILE *fp;
	int c, fd;
	char *dbname;

	const hash_type_data_t *old_hash = NULL, *new_hash = NULL;

	struct option long_options[] = {
		{ "help",		no_argument,		0, 'h' },
		{ "version",		no_argument,		0, 'V' },
		{ 0, 0, 0, 0 }
	};

	while ((c = getopt_long (argc, argv, "hV", long_options, NULL)) != -1) {
		switch (c) {
			case 'V':
				print_version();
				break;
			default:
			case 'h':
				print_help(EXIT_SUCCESS);
				break;
		}
	}

	if ((argc - optind) != 2)
		print_help(EXIT_FAILURE);

	pathname = argv[optind++];
	dbname   = argv[optind];

	if ((fp = fopen(pathname, "r")) == NULL)
		osec_fatal(EXIT_FAILURE, errno, "fopen");

	if ((fd = open(dbname, O_WRONLY | O_CREAT | O_NOCTTY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: open", dbname);

	if (ftruncate(fd, 0) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: ftruncate", dbname);

	if (cdb_make_start(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_start");

	rec.data = NULL;
	rec.len  = 0;

	yyin = fp;
	yyparse();

	xfree(rec.data);
	fclose(fp);

	if (hashnames != NULL) {
		get_hashes_from_string(hashnames, strlen(hashnames), &new_hash, &old_hash);
		xfree(hashnames);
	} else {
		new_hash = get_hash_type_data_by_name("sha1", strlen("sha1"));
		old_hash = NULL;
	}

	write_db_version(&cdbm, new_hash, old_hash);

	if (cdb_make_finish(&cdbm) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_finish");

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbname);

	return EXIT_SUCCESS;
}
