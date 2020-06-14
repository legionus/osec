/* SPDX-License-Identifier: GPL-3.0-only
 *
 * File: txt2osec.analize.l
 *
 *  Copyright (C) 2010-2020  Alexey Gladkov <gladkov.alexey@gmail.com>
 *  Copyright (C) 2019  Aleksei Nikiforov <darktemplar@basealt.ru>
 */
%option nounput
%{
#define YY_NO_INPUT 1
#define YYSTYPE long long
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "osec.h"
#include "txt2osec.h"

extern char str[PATH_MAX];
extern char *pathname;
extern int line_nr;
extern int yyerror(const char *s) __attribute__((nonnull(1)));
extern void stringovfl(void) __attribute__((noreturn));

char *p, *pmax;
%}

%option noyywrap

%x STR

Eol		\n
Continuation	\\\n
Comment		#|!
Delim		[ \t]
Equals		=
Dot		\.
Whitesp		{Delim}+
Number		[0-9]+
Octa		\\([0-7]){1,6}
Filename	file|File
Device		dev|Dev
Inode		ino|Ino
Mode		mode|Mode
Uid		uid|Uid
Gid		gid|Gid
Mtime		mtime|Mtime
Checksum	checksum|Checksum
Symlink		symlink|Symlink
Hashnames	hashnames|Hashnames
Xattr		xattr|Xattr

%%

{Whitesp}		{ /* No action and no return */ }
{Comment}.*{Eol}	{ line_nr++; }
{Continuation}		{ line_nr++; }
{Number}		{
				yylval = strtoll(yytext, NULL, 0);
				return(NUMBER);
			}
{Octa}			{
				yylval = strtoll(yytext + 1, NULL, 8);
				return(OCTAL);
			}
{Hashnames}		{ return(HASHNAMES); }
{Filename}		{ return(FILENAME); }
{Xattr}			{ return(XATTR); }
{Checksum}		{ return(CHECKSUM); }
{Symlink}		{ return(SYMLINK); }
{Device}		{ return(DEVICE); }
{Inode}			{ return(INODE); }
{Uid}			{ return(UID); }
{Gid}			{ return(GID); }
{Mtime}			{ return(MTIME); }
{Mode}			{ return(MODE); }
{Equals}		{ return(EQUALS); }
{Dot}			{ return(DOT); }
{Eol}			{
				line_nr++;
				BEGIN(0);
				return(EOL);
			}
\"			{
				p = (char *) str;
				pmax = p + sizeof(str) - 1;
				BEGIN(STR);
			}
<STR>\\\"		{
				if (p >= pmax)
					stringovfl();
				*p++='"';
			}
<STR>\\\\		{
				if (p >= pmax)
					stringovfl();
				*p++='\\';
			}
<STR>\\n		{
				if (p >= pmax)
					stringovfl();
				*p++='\n';
			}
<STR>[^\"\\]*		{
				char *ptmp = p;
				p += strlen(yytext);
				if (p >= pmax)
					stringovfl();
				strcpy(ptmp, yytext);
			}
<STR>\"			{
				*p = '\0';
				BEGIN(0);
				return(STRLITERAL);
			}
.			{
				/* report any unknown characters */
				return(ERROR);
			}

%%

void
stringovfl(void)
{
	osec_fatal(1, 0, "%s:%d: string too long", pathname, line_nr);
}
