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

// FIXME: use config file for this variables.
char def_db_path[] = "/tmp/osec";
char def_user[]    = "osec";
char def_group[]   = "osec";

char *exclude_matches = NULL;
size_t exclude_matches_len = 0;

char *db_path = NULL;
int read_only = 0;
int numeric_user_group = 0;

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

static int remove_recursive(char *fname) {
	DIR *d;
	struct dirent *dir;
	struct stat st;
	int retval = 1;

	if (lstat(fname, &st) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: lstat", fname);

	if (!S_ISDIR(st.st_mode)) {
		remove(fname);
		return retval;
	}

	if ((d = opendir(fname)) == NULL) {
		if (errno == EACCES) {
			osec_error("%s: opendir: %s\n", fname, strerror(errno));
			return 0;
		}
		else
			osec_fatal(EXIT_FAILURE, errno, "%s: opendir", fname);
	}

	if (chdir(fname) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: chdir", fname);

	while ((dir = readdir(d)) != NULL) {
		if ((!strncmp(dir->d_name, "..", (size_t) 2) || !strncmp(dir->d_name, ".", (size_t) 1)))
			continue;

		if ((retval = remove_recursive(dir->d_name)) == 0)
			break;
	}

	if (chdir("..") == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: chdir", fname);

	if (closedir(d) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: closedir", fname);

	if (retval)
		remove(fname);

	return retval;
}

static void recreate_tempdir(void) {
	struct stat st;
	char *tempdir = NULL;

	/* tempdir = db_path/temp */
	size_t len = strlen(db_path) + 6;

	tempdir = (char *) xmalloc(sizeof(char) * len);
	sprintf(tempdir, "%s/temp", db_path);

	if (lstat(tempdir, &st) == -1) {
		if (errno != ENOENT)
			osec_fatal(EXIT_FAILURE, errno, "%s: lstat", tempdir);
	}
	else if(remove_recursive(tempdir) == 0)
		osec_fatal(EXIT_FAILURE, 0, "%s: remove_recursive: Unable to remove tempdir\n", tempdir);

	if (mkdir(tempdir, 0700) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: mkdir", tempdir);

	free(tempdir);
}

static void
gen_db_name(char *dirname, char **dbname) {
	int i = 0;
	unsigned int j = strlen(db_path) + 10;
	unsigned int len = j + strlen(dirname);

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
osec_append(struct cdb_make *cdbm, char *fname, size_t flen) {
	DIR *d;
	void *val = NULL;
	size_t vlen = 0;
	int retval = 1;
	struct dirent *dir;
	struct stat st;

	if (is_exclude(fname))
		return retval;

	if (lstat(fname, &st) == -1) {
		retval = osec_error("%s: lstat: %s\n", fname, strerror(errno));
		return retval;
	}

	osec_state(&val, &vlen, &st);

	switch (st.st_mode & S_IFMT) {
		case S_IFREG: osec_digest(&val, &vlen, fname);  break;
		case S_IFLNK: osec_symlink(&val, &vlen, fname); break;
	}

	if (cdb_make_add(cdbm, fname, (unsigned) flen, val, (unsigned) vlen) != 0)
		osec_fatal(EXIT_FAILURE, errno, "%s: cdb_make_add", fname);

	xfree(val);

	if (!S_ISDIR(st.st_mode))
		return retval;

	if ((d = opendir(fname)) == NULL) {
		if (errno == EACCES) {
			osec_error("%s: opendir: %s\n", fname, strerror(errno));
			return retval;
		}
		else
			osec_fatal(EXIT_FAILURE, errno, "%s: opendir", fname);
	}

	while ((dir = readdir(d)) != NULL) {
		char *subname;
		size_t len = strlen(dir->d_name);

		if ((len <= 2) &&
		    (!strncmp(dir->d_name, "..", (size_t) 2) || !strncmp(dir->d_name, ".", (size_t) 1)))
			continue;

		len += flen + 1;

		subname = (char *) xmalloc(sizeof(char) * len);
		sprintf(subname, "%s/%s", fname, dir->d_name);

		retval = osec_append(cdbm, subname, len);
		xfree(subname);

		if (!retval)
			break;
	}

	if (closedir(d) == -1)
		osec_fatal(EXIT_FAILURE, errno, "%s: closedir", fname);

	return retval;
}

static int
create_database(int fd, char *dir, size_t len) {
	struct cdb_make cdbm;
	int retval = 1;

	if (cdb_make_start(&cdbm, fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_start");

	if (access(dir, R_OK) == 0)
		retval = osec_append(&cdbm, dir, len);
	else
		retval = 2;

	write_db_version(&cdbm);

	if (cdb_make_finish(&cdbm) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_make_finish");

	return retval;
}

static void
show_changes(int new_fd, int old_fd) {
	int rc;
	char *key;
	void *old_data, *new_data;
	unsigned cpos;
	struct cdb old_cdb, new_cdb;
	size_t klen, old_dlen, new_dlen;

	if (old_fd != -1 && cdb_init(&old_cdb, old_fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(old_cdb)");

	if (cdb_init(&new_cdb, new_fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(new_cdb)");

	cdb_seqinit(&cpos, &new_cdb);

	while((rc = cdb_seqnext(&cpos, &new_cdb)) > 0) {
		klen = (size_t) cdb_keylen(&new_cdb);
		key = (char *) xmalloc(klen + 1);

		if (cdb_read(&new_cdb, key, (unsigned) klen, cdb_keypos(&new_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		if (key[0] != '/') {
			xfree(key);
			continue;
		}

		key[klen] = '\0';

		new_dlen = (size_t) cdb_datalen(&new_cdb);
		new_data = xmalloc(new_dlen);

		if (cdb_read(&new_cdb, new_data, (unsigned) new_dlen, cdb_datapos(&new_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		// Search
		if (old_fd != -1 && cdb_find(&old_cdb, key, (unsigned) klen) > 0) {
			old_dlen = (size_t) cdb_datalen(&old_cdb);
			old_data = xmalloc(old_dlen);

			if (cdb_read(&old_cdb, old_data, (unsigned) old_dlen, cdb_datapos(&old_cdb)) < 0)
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
show_oldfiles(int new_fd, int old_fd) {
	int rc;
	char *key;
	unsigned cpos, klen;
	struct cdb old_cdb, new_cdb;

	if (old_fd == -1)
		return;

	if (cdb_init(&old_cdb, old_fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(old_cdb)");

	if (cdb_init(&new_cdb, new_fd) < 0)
		osec_fatal(EXIT_FAILURE, errno, "cdb_init(new_cdb)");

	cdb_seqinit(&cpos, &old_cdb);

	while((rc = cdb_seqnext(&cpos, &old_cdb)) > 0) {
		klen = cdb_keylen(&old_cdb);
		key = (char *) xmalloc((size_t) (klen + 1));

		if (cdb_read(&old_cdb, key, klen, cdb_keypos(&old_cdb)) < 0)
			osec_fatal(EXIT_FAILURE, errno, "cdb_read");

		if (key[0] != '/') {
			xfree(key);
			continue;
		}

		key[klen] = '\0';

		if (cdb_find(&new_cdb, key, klen) == 0) {
			unsigned dlen = cdb_datalen(&old_cdb);
			void *data = xmalloc((size_t) dlen);

			if (cdb_read(&old_cdb, data, dlen, cdb_datapos(&old_cdb)) < 0)
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
	size_t len, dlen;
	int retval = 1;
	int new_fd, old_fd;
	char *new_dbname, *old_dbname;

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
	dlen = strlen(dirname) + 1;
	if ((retval = create_database(new_fd, dirname, dlen)) == 1) {
		show_changes(new_fd, old_fd);
		show_oldfiles(new_fd, old_fd);
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

static char *
validate_path(const char *path) {
	unsigned int i, j = 0;
	char *buf = NULL;
	size_t len;

	len = strlen(path);

	if (path[0] != '/' ||
	    strstr(path, "/../") != NULL ||
	    strstr(path, "/./" ) != NULL) {
		osec_error("Canonical path required\n");
		return buf;
	}

	buf = (char *) malloc(sizeof(char) * (len+1));
	buf[j++] = '/';

	for(i = 1; i < len; i++) {
		if (path[i-1] == '/' && path[i] == '/')
			continue;
		buf[j++] = path[i];
	}
	buf[j] = '\0';

	if (buf[j-1] == '/')
		buf[j-1] = '\0';

	if (j < len)
		buf = realloc(buf, sizeof(char) * j);

	return buf;
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

	while ((c = getopt_long (argc, argv, "hvnrRu:g:D:f:x:X:", long_options, NULL)) != -1) {
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

	xfree(exclude_matches);

	return retval;
}
