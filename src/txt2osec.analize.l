/* txt2osec.analize.l
 *
 * This file is part of Osec (lightweight integrity checker)
 *  Copyright (C) 2010  Alexey Gladkov <gladkov.alexey@gmail.com>
 *
 * This file is covered by the GNU General Public License,
 * which should be included with osec as the file COPYING.
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
extern int yyerror(const char *s);
extern void stringovfl(void);

char *p, *pmax;
%}

%option noyywrap

%x STR

Eol		\n
Continuation	\\\n
Comment		#|!
Delim		[ \t]
Equals		=
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
Hashnames		hashnames|Hashnames

%%

{Whitesp}		{ /* No action and no return */ }
{Comment}.*{Eol}	{ line_nr++; }
{Continuation}		{ line_nr++; }
{Number}		{ yylval = strtoll(yytext,NULL,0);   return(NUMBER); }
{Octa}			{ yylval = strtoll(yytext+1,NULL,8); return(OCTAL); }
{Hashnames}		{ return(HASHNAMES); }
{Filename}		{ return(FILENAME); }
{Checksum}		{ return(CHECKSUM); }
{Symlink}		{ return(SYMLINK); }
{Device}		{ return(DEVICE); }
{Inode}			{ return(INODE); }
{Uid}			{ return(UID); }
{Gid}			{ return(GID); }
{Mtime}			{ return(MTIME); }
{Mode}			{ return(MODE); }
{Equals}                { return(EQUALS); }
{Eol}			{ line_nr++;
			  BEGIN(0);
			  return(EOL); }
\"			{ p = (char *) str;
			  pmax = p + sizeof(str) - 1;
			  BEGIN(STR); }
<STR>\\\"		{ if (p >= pmax) stringovfl();
			  *p++='"'; }
<STR>\\\\		{ if (p >= pmax) stringovfl();
			  *p++='\\'; }
<STR>\\n		{ if (p >= pmax) stringovfl();
	                  *p++='\n'; }
<STR>[^\"\\]*		{ char *ptmp = p;
			  p += strlen(yytext);
			  if (p >= pmax) stringovfl();
			  strcpy(ptmp, yytext); }
<STR>\"			{ *p = '\0';
			  BEGIN(0);
			  return(STRLITERAL); }
.			{ return(ERROR); /* report any unknown characters */}

%%

void
stringovfl(void)
{
	osec_fatal(1, 0, "%s:%d: string too long\n", pathname, line_nr);
}
