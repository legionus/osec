/* txt2osec.y
 *
 * This file is part of Osec (lightweight integrity checker)
 *  Copyright (C) 2010-2012  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
%{
#define YYSTYPE long long

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

#include "config.h"
#include "osec.h"

extern FILE *yyin;

char str[PATH_MAX];

char *progname = NULL;
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
	FLAG_GID   = (01 << 8)
};

char *fname = NULL;
char *slink = NULL;
char *chsum = NULL;
osec_stat_t ost;
unsigned char csum[digest_len];

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

/* Grammar follows */
%%
input		: /* empty string */
		| input line
 		;
line		: endline
		| fileline range endline
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
		;
fileline	: FILENAME EQUALS STRLITERAL
		{ fname = strdup(str);
		  flags |= FLAG_FILE; }
		;
csumline	: CHECKSUM EQUALS STRLITERAL
		{
		  size_t n = strlen(str);
		  if (n < (digest_len * 2))
			osec_fatal(1, 0, "%s:%d: Checksum value too short: %s\n",
			           pathname, line_nr, str);
		  if (n > (digest_len * 2))
			osec_fatal(1, 0, "%s:%d: Checksum value too long: %s\n",
			           pathname, line_nr, str);
		  chsum = strdup(str);
		  flags |= FLAG_CSUM; }
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
			osec_fatal(1, 0, "%s:%d: Inode value too long: %lld\n",
			           pathname, line_nr, $3);
		  ost.ino = (ino_t) $3;
		  flags |= FLAG_INO; }
		;
uidline		: UID EQUALS NUMBER
		{ if ($3 > LONG_MAX)
			osec_fatal(1, 0, "%s:%d: UID value too long: %lld\n",
			           pathname, line_nr, $3);
		  ost.uid = (uid_t) $3;
		  flags |= FLAG_UID; }
		;
gidline		: GID EQUALS NUMBER
		{ if ($3 > LONG_MAX)
			osec_fatal(1, 0, "%s:%d: GID value too long: %lld\n",
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
endline		: EOL
		{
			rec.offset = 0;

			if (!F_ISSET(flags, FLAG_FILE | FLAG_DEV | FLAG_INO | FLAG_UID | FLAG_GID | FLAG_MODE))
				osec_fatal(EXIT_FAILURE, 0, "%s:%d: Wrong file format\n",
				           pathname, line_nr);

			append_value(OVALUE_STAT, &ost, sizeof(ost), &rec);

			if (F_ISSET(flags, FLAG_CSUM)) {
				char *s = chsum;
				unsigned int h, i;

				if (!S_ISREG(ost.mode))
					osec_fatal(EXIT_FAILURE, 0, "%s:%d: Wrong file format: checksum field for not regular file\n",
					           pathname, line_nr);

				for (i = 0; i < digest_len; i++) {
					sscanf(s, "%02x", &h);
					csum[i] = (unsigned char) h;
					s += 2;
				}
				append_value(OVALUE_CSUM, &csum, (size_t) digest_len, &rec);
				xfree(chsum);
			}

			if (F_ISSET(flags, FLAG_LINK)) {
				if (!S_ISLNK(ost.mode))
					osec_fatal(EXIT_FAILURE, 0, "%s:%d: Wrong file format: symlink field for not symbolic link\n",
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
	       "\n", progname);
	exit(ret);
}

void __attribute__ ((noreturn))
print_version(void)
{
	printf("%s version "PACKAGE_VERSION"\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "\n"
	       "Copyright (C) 2010-2012  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n",
		progname);
	exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	FILE *fp;
	int c, fd;
	char *dbname;

	struct option long_options[] = {
		{ "help",		no_argument,		0, 'h' },
		{ "version",		no_argument,		0, 'V' },
		{ 0, 0, 0, 0 }
	};

	progname = basename(argv[0]);

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

	write_db_version(&cdbm);

	if (cdb_make_finish(&cdbm) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_finish");

	if (close(fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", dbname);

	return EXIT_SUCCESS;
}
