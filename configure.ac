#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(osec, 1.2.7, gladkov.alexey@gmail.com)
AC_CONFIG_SRCDIR([src/osec.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE([dist-bzip2])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_MAKE_SET
AC_PROG_YACC
AM_PROG_LEX

AC_CHECK_PROG([HELP2MAN], [help2man], [yes])
if test "${HELP2MAN-}" != "yes"; then
	AC_MSG_ERROR([help2man was not found: http://www.gnu.org/software/help2man/])
fi

AC_SYS_LARGEFILE

# Checks for libraries.
AC_CHECK_LIB([cap], [cap_from_text],,
	[AC_MSG_ERROR([libcap was not found: http://sites.google.com/site/fullycapable/])])

AC_CHECK_LIB([cdb], [cdb_init],,
	[AC_MSG_ERROR([tinycdb was not found: http://www.corpit.ru/mjt/tinycdb.html])])

AC_CHECK_LIB([attr], [listxattr],,
	[AC_MSG_WARN(libattr was not found: http://savannah.nongnu.org/projects/attr)])

AC_CHECK_LIB([gcrypt],[gcry_check_version],,
	[AC_MSG_ERROR([libgcrypt was not found: https://www.gnupg.org])])

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FSEEKO
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero ftruncate memset mkdir strchr strdup strerror strstr])

AC_ARG_ENABLE(werror,
	AS_HELP_STRING(--enable-werror, [Build with -Werror option]),
	[USE_WERROR=$enableval],[USE_WERROR=no])
AM_CONDITIONAL(USE_WERROR, test "$USE_WERROR" = "yes")

AC_CONFIG_FILES([Makefile src/Makefile update/Makefile data/Makefile])
AC_OUTPUT
