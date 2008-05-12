WARNINGS = -Wall -Wextra -Werror -W -Wshadow -Wpointer-arith -Wcast-align \
	-Wwrite-strings -Wconversion -Waggregate-return -Wstrict-prototypes \
	-Wmissing-prototypes -Wmissing-declarations -Wmissing-noreturn \
	-Wmissing-format-attribute -Wredundant-decls -Wdisabled-optimization 

AM_CPPFLAGS = -g -std=c99 -D_BSD_SOURCE -D_GNU_SOURCE \
	$(WARNINGS)

AM_CPPFLAGS += $(LIBGCRYPT_CFLAGS)
LDADD        = $(LIBGCRYPT_LIBS)

bin_PROGRAMS = osec
osec_SOURCES = osec.c common.c memory.c privs.c status.c digest.c
osec_LIBS = -lcap -lcdb
