/* osec.c
 *
 * This file is part of Osec (lightweight integrity checker)
 * Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>

#include "config.h"
#include "osec.h"

// Global variables
char *pathname;

void  *read_buf;
size_t read_bufsize;

size_t pw_bufsize;
size_t gr_bufsize;

// FIXME: use config file for this variables.
char def_db_path[] = "/tmp/osec";
char def_user[]    = "osec";
char def_group[]   = "osec";

char *exclude_matches = NULL;
size_t exclude_matches_len = 0;

char *db_path = NULL;
int read_only = 0;
int numeric_user_group = 0;
unsigned ignore = 0;

static void __attribute__ ((noreturn))
print_help(int ret)  {
	printf("Usage: "PACKAGE_NAME" [OPTIONS] [DIRECTORY...]\n"
	       "   or: "PACKAGE_NAME" [OPTIONS] --file=FILE [DIRECTORY...]\n"
	       "\n"
	       "This utility help you to see difference between\n"
	       "two states of your system.\n"
	       "\n"
	       "Options:\n"
	       "  -r, --read-only           work in read-only mode;\n"
	       "  -R, --allow-root          allow run with root priveleges;\n"
	       "  -n, --numeric-ids         dont convert uid/gid into username;\n"
	       "  -u, --user=USER           non-privelege user account name;\n"
	       "  -g, --group=GROUP         non-privelege group account name;\n"
	       "  -D, --dbpath=PATH         path to the directory with databases;\n"
	       "  -f, --file=FILE           obtain directories from file FILE;\n"
	       "  -x, --exclude=PATTERN     exclude files matching PATTERN;\n"
	       "  -X, --exclude-from=FILE   read exclude patterns from FILE;\n"
	       "  -i, --ignore=LIST         dont show changes: user, group,\n"
	       "                            mode or inode;\n"
	       "  -v, --version             print program version and exit;\n"
	       "  -h, --help                output a brief help message.\n"
	       "\n");
	exit(ret);
}

static void __attribute__ ((noreturn))
print_version(void) {
        printf(PACKAGE_NAME" version "PACKAGE_VERSION"\n"
	       "Written by Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "\n"
	       "Copyright (C) 2008  Alexey Gladkov <gladkov.alexey@gmail.com>\n"
	       "This is free software; see the source for copying conditions.  There is NO\n"
	       "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
        exit(EXIT_SUCCESS);
}

static void
gen_db_name(char *dirname, char **dbname) {
	int i = 0;
	size_t j = strlen(db_path) + 10;
	size_t len = j + strlen(dirname);

	(*dbname) = (char *) xmalloc(sizeof(char) * len);
	sprintf((*dbname), "%s/osec.cdb.", db_path);

	while (dirname[i] != '\0') {
		if ((j+3) >= len) {
			len += 32;
			(*dbname) = (char *) xrealloc((*dbname), sizeof(char) * len);
		}

		if (!isprint(dirname[i]) || (dirname[i] == '/')) {
			sprintf(((*dbname) + j), "%%%02X", (unsigned char) dirname[i]);
			j += 3;
		}
		else if (dirname[i] == '%') {
			(*dbname)[j++] = '%';
			(*dbname)[j++] = '%';
		}
		else
			(*dbname)[j++] = dirname[i];
		i++;
	}
	(*dbname)[j++] = '\0';

	if (j < len)
		(*dbname) = (char *) xrealloc((*dbname), sizeof(char) * j);
}

static int
osec_append(struct cdb_make *cdbm, char *fname) {
	DIR *d;
	void *val = NULL;
	int rc, retval = 1;
	struct dirent *dir;
	struct stat st;
	size_t len, vlen = 0;

	if (is_exclude(fname))
		return retval;

	if (lstat(fname, &st) == -1) {
		osec_error("%s: lstat: %s\n", fname, strerror(errno));
		return 0;
	}

	dirstack_push(fname);

	osec_state(&val, &vlen, &st);

	if (dirstack_get(&pathname, &len)) {
		if (cdb_make_add(cdbm, pathname, (unsigned) len, val, (unsigned) vlen) != 0)
			osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", fname);
	}
	else
		osec_fatal(EXIT_FAILURE, 0, "dirstack_get: Unable to get path");
	xfree(val);

	if ((d = opendir(fname)) == NULL) {
		if (errno == EACCES) {
			osec_error("%s: opendir: %s\n", fname, strerror(errno));
			return retval;
		}
		else
			osec_fatal(EXIT_FAILURE, errno, "%s: opendir", fname);
	}

	if (chdir(fname) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: chdir\n", fname);

	while ((dir = readdir(d)) != NULL) {
		if (!strcmp(dir->d_name, "..") || !strcmp(dir->d_name, "."))
			continue;

		if (lstat(dir->d_name, &st) == -1) {
			retval = osec_error("%s: lstat: %s\n", fname, strerror(errno));
			continue;
		}

		dirstack_push(dir->d_name);

		if (dirstack_get(&pathname, &len)) {
			val = NULL;
			vlen = 0;

			osec_state(&val, &vlen, &st);

			switch (st.st_mode & S_IFMT) {
				case S_IFREG: osec_digest(&val, &vlen, pathname);  break;
				case S_IFLNK: osec_symlink(&val, &vlen, pathname); break;
			}

			if (cdb_make_add(cdbm, pathname, (unsigned) len, val, (unsigned) vlen) != 0)
				osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", fname);

			xfree(val);
		}
		else
			osec_fatal(EXIT_FAILURE, 0, "dirstack_get: Unable to get path");

		dirstack_pop();

		if (!S_ISDIR(st.st_mode))
			continue;

		rc = osec_append(cdbm, dir->d_name);

		if (retval)
			retval = rc;
	}

	if (chdir("..") == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: chdir", fname);

	if (closedir(d) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: closedir", fname);

	dirstack_pop();

	return retval;
}

static int
create_cdb(int fd, char *dir) {
	struct cdb_make cdbm;
	int retval = 1;

	if (cdb_make_start(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_start");

	retval = (access(dir, R_OK) == 0) ?
		osec_append(&cdbm, dir) : 2;

	write_db_version(&cdbm);

	if (cdb_make_finish(&cdbm) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_finish");

	return retval;
}

static void
show_changes(struct cdb *new_cdb, struct cdb *old_cdb) {
	int rc;
	char *key;
	void *old_data, *new_data;
	unsigned cpos;
	size_t klen, old_dlen, new_dlen;

	cdb_seqinit(&cpos, new_cdb);

	while((rc = cdb_seqnext(&cpos, new_cdb)) > 0) {
		klen = (size_t) cdb_keylen(new_cdb);
		key = (char *) xmalloc(klen + 1);

		if (cdb_read(new_cdb, key, (unsigned) klen, cdb_keypos(new_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		if (key[0] != '/') {
			xfree(key);
			continue;
		}

		key[klen] = '\0';

		new_dlen = (size_t) cdb_datalen(new_cdb);
		new_data = xmalloc(new_dlen);

		if (cdb_read(new_cdb, new_data, (unsigned) new_dlen, cdb_datapos(new_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		// Search
		if (old_cdb != NULL && cdb_find(old_cdb, key, (unsigned) klen) > 0) {
			old_dlen = (size_t) cdb_datalen(old_cdb);
			old_data = xmalloc(old_dlen);

			if (cdb_read(old_cdb, old_data, (unsigned) old_dlen, cdb_datapos(old_cdb)) < 0)
				osec_fatal(EXIT_FAILURE, errno, "cdb_read");

			if (!check_difference(key, new_data, new_dlen, old_data, old_dlen))
				check_bad_files(key, new_data, new_dlen);

			xfree(old_data);
		}
		else
			check_new(key, new_data, new_dlen);

		xfree(new_data);
		xfree(key);
	}

	if (rc < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_seqnext(new_cdb)");
}

static void
show_oldfiles(struct cdb *new_cdb, struct cdb *old_cdb) {
	int rc;
	char *key;
	unsigned cpos, klen;

	cdb_seqinit(&cpos, old_cdb);

	while((rc = cdb_seqnext(&cpos, old_cdb)) > 0) {
		klen = cdb_keylen(old_cdb);
		key = (char *) xmalloc((size_t) (klen + 1));

		if (cdb_read(old_cdb, key, klen, cdb_keypos(old_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		if (key[0] != '/') {
			xfree(key);
			continue;
		}

		key[klen] = '\0';

		if (cdb_find(new_cdb, key, klen) == 0) {
			unsigned dlen = cdb_datalen(old_cdb);
			void *data = xmalloc((size_t) dlen);

			if (cdb_read(old_cdb, data, dlen, cdb_datapos(old_cdb)) < 0)
				osec_fatal(EXIT_FAILURE, errno, "cdb_read");

			check_removed(key, data, (size_t) dlen);
			xfree(data);
		}

		xfree(key);
	}

	if (rc < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_seqnext(old_cdb)");
}

static int
process(char *dirname) {
	size_t len;
	int retval = 1;
	int new_fd, old_fd;
	char *new_dbname, *old_dbname;
	struct cdb old_cdb, new_cdb;

	if (is_exclude(dirname))
		return 1;

	// Generate priv state database name
	gen_db_name(dirname, &old_dbname);

	// Open old database
	errno = 0;
	if ((old_fd = open(old_dbname, O_RDONLY|O_NOCTTY|O_NOFOLLOW)) != -1) {
		if (!compat_db_version(old_fd))
			osec_fatal(EXIT_FAILURE, 0, "%s: file not look like osec database\n", old_dbname);

		printf("Processing %s ...\n", dirname);
	}
	else if (errno == ENOENT)
		printf("Init database for %s ...\n", dirname);
	else
		osec_fatal(EXIT_FAILURE, errno, "%s: open", old_dbname);

	// Generate new state database
	len = strlen(db_path) + 21;
	new_dbname = (char *) xmalloc(sizeof(char) * len);
	sprintf(new_dbname, "%s/temp/osec.XXXXXXXXX", db_path);

	// Open new database
	if ((new_fd = mkstemp(new_dbname)) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: mkstemp", new_dbname);

	// Unlink termporary file
	if (read_only)
		remove(new_dbname);

	// Create new state
	if ((retval = create_cdb(new_fd, dirname)) == 1) {
		if (cdb_init(&new_cdb, new_fd) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_init(new_cdb)");

		if (old_fd != -1) {
			if (cdb_init(&old_cdb, old_fd) < 0)
				osec_fatal(EXIT_FAILURE, errno, "cdb_init(old_cdb)");

			show_changes(&new_cdb, &old_cdb);
			show_oldfiles(&new_cdb, &old_cdb);
		}
		else
			show_changes(&new_cdb, NULL);
	}

	if (old_fd != -1 && close(old_fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", old_dbname);

	if (close(new_fd) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: close", new_dbname);

	//replace database with new
	if (retval && !read_only)
		rename(new_dbname, old_dbname);

	xfree(old_dbname);
	xfree(new_dbname);

	return retval;
}

static void
allocate_globals(void) {
	// This variable is to display the full path.
	pathname = xmalloc(MAXPATHLEN);

	// Allocate buffer to read the files (digest.c).
	read_bufsize = (size_t) (sysconf(_SC_PAGE_SIZE) - 1);
	read_buf = xmalloc(read_bufsize);

	// (status.c)
	pw_bufsize = (size_t) sysconf(_SC_GETPW_R_SIZE_MAX);
	gr_bufsize = (size_t) sysconf(_SC_GETGR_R_SIZE_MAX);
}

int
main(int argc, char **argv) {
	int c;
	int retval = EXIT_SUCCESS;
	int allow_root = 0;
	char *dirslist_file = NULL;
	char *user = NULL, *group = NULL;

	char *path;

	struct option long_options[] = {
		{ "help",		no_argument,		0, 'h' },
		{ "version",		no_argument,		0, 'v' },
		{ "read-only",		no_argument,		0, 'r' },
		{ "allow-root",		no_argument,		0, 'R' },
		{ "numeric-ids",	no_argument,		0, 'n' },
		{ "ignore",		required_argument,	0, 'i' },
		{ "dbpath",		required_argument,	0, 'D' },
		{ "file",		required_argument,	0, 'f' },
		{ "user",		required_argument,	0, 'u' },
		{ "group",		required_argument,	0, 'g' },
		{ "exclude",		required_argument,	0, 'x' },
		{ "exclude-from",	required_argument,	0, 'X' },
		{ 0, 0, 0, 0 }
	};

	if (argc == 1)
		print_help(EXIT_SUCCESS);

	while ((c = getopt_long (argc, argv, "hvnrRi:u:g:D:f:x:X:", long_options, NULL)) != -1) {
		switch (c) {
			case 'v':
				print_version();
				break;
			case 'n':
				numeric_user_group = 1;
				break;
			case 'r':
				read_only = 1;
				break;
			case 'R':
				allow_root = 1;
				break;
			case 'u':
				user = optarg;
				break;
			case 'g':
				group = optarg;
				break;
			case 'i':
				process_ignore(optarg);
				break;
			case 'D':
				db_path = optarg;
				break;
			case 'f':
				dirslist_file = optarg;
				break;
			case 'x':
				exclude_match_append(optarg);
				break;
			case 'X':
				exclude_matches_file(optarg);
				break;
			default:
			case 'h':
				print_help(EXIT_SUCCESS);
				break;
		}
	}

	if (db_path == NULL)
		db_path = def_db_path;

	//drop program privileges if we are root
	if (!allow_root && !geteuid()) {
		drop_privs((user  != NULL ? user  : def_user),
			   (group != NULL ? group : def_group));

		if (!geteuid())
			osec_fatal(EXIT_FAILURE, 0, "cannot run from under privilege user\n");
	}

	recreate_tempdir();

	allocate_globals();

	if (dirslist_file != NULL) {
		FILE *fd;
		char *line = NULL;
		size_t len = 0;
		ssize_t n;

		if ((fd = fopen(dirslist_file, "r")) == NULL)
			osec_fatal(EXIT_FAILURE, errno, "%s: fopen", dirslist_file);

		while ((n = getline(&line, &len, fd)) != -1) {
			int i = 0;

			while(isspace(line[i]))
				i++;

			if (strlen((line + i)) == 0 || line[i] == '#')
				continue;

			if (line[n-1] == '\n')
				line[n-1] = '\0';

			if ((path = validate_path((line + i))) == NULL)
				continue;

			if (!process(path))
				retval = EXIT_FAILURE;

			xfree(path);
		}

		xfree(line);

		if (fclose(fd) != 0)
			osec_fatal(EXIT_FAILURE, errno, "%s: fclose", dirslist_file);
	}

	while (optind < argc) {
		if ((path = validate_path(argv[optind++])) == NULL)
			continue;

		if (!process(path))
			retval = EXIT_FAILURE;

		xfree(path);
	}

	xfree(pathname);
	xfree(read_buf);
	xfree(exclude_matches);

	return retval;
}
