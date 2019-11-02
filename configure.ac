# Copyright (C) 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>
#
# This file is part of Distributed OpenPGP Timestamping Service (DOTS).
#
#   DOTS is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   DOTS is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with DOTS; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# (Please process this file with autoconf to produce a configure script.)

AC_REVISION([20191102])
AC_PREREQ(2.61)

AC_INIT([Distributed OpenPGP Timestamping Service], [0.0.2],
	[HeikoStamer@gmx.net], [dots], [https://savannah.nongnu.org/projects/distributed-timestamping/])

AC_LANG(C++)
AC_CONFIG_SRCDIR([src/dotsd.cc])
AC_CONFIG_HEADERS([src/dots_config.h])
AM_INIT_AUTOMAKE([subdir-objects])
AM_MAINTAINER_MODE

AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE_NAME", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$PACKAGE_VERSION", [Version of this package])

# Define some parameters and helping macros
AC_DEFINE(DOTS_MAX_N, 32, [Define the maximum number of parties/peers])
AC_DEFINE(DOTS_TIME_CONNECT, 3, [Define the timeout for TCP connect calls\
 in seconds])
AC_DEFINE(DOTS_TIME_AUTH, 30, [Define the timeout for authenticating\
 TCP connections in seconds])
AC_DEFINE(DOTS_TIME_SETUP, 180, [Define the timeout for setup the initial\
 connections in seconds])
AC_DEFINE(DOTS_TIME_POLL, 1, [Define the timeout for RBC channel polling in\
 seconds])
AC_DEFINE(DOTS_TIME_LOOP, 30, [Define number of seconds to stay inside inner\
 loop])
AC_DEFINE(DOTS_TIME_EVENT, 1800, [Define the timeout for events in seconds])
AC_DEFINE(DOTS_TIME_TERM, 1400, [Define number of seconds until a running DKGPG\
 process is terminated])
AC_DEFINE(DOTS_TIME_KILL, 1600, [Define number of seconds until a running DKGPG\
 process is killed])
AC_DEFINE(DOTS_TIME_INACTIVE, 300, [Define number of seconds without PING\
 received that turns a peer inactive])
AC_DEFINE(DOTS_TIME_UNCONFIRMED, 300, [Define number of seconds that a request\
 is hold without confirmation])
AC_DEFINE(DOTS_TIME_REMOVE, 259200, [Define number of seconds that a stamped\
 request is shown on the status page])
AC_DEFINE(DOTS_TIME_STAMP, 604800, [Define number of seconds that a timestamp\
 is hold for retrieving])
AC_DEFINE(DOTS_TIME_LOG, 86400, [Define number of seconds that a stamp-log\
 is hold for retrieving])
AC_DEFINE(DOTS_MHD_PORT, 57080, [Define listening TCP start port of the HTTP\
 daemon])
AC_DEFINE(DOTS_MAX_SIG_LENGTH, 4096, [Define the maximum number of characters\
 a submitted signature can have])

# Checks for Libtool
LT_PREREQ([2.4.2])
LT_INIT
LT_LANG([C++])

# Checks for required programs
AC_PROG_CC
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MKDIR_P

# Checks for required libraries and programs
backup_LDFLAGS="$LDFLAGS"
backup_CPPFLAGS="$CPPFLAGS"
AC_ARG_WITH(gmp, [AS_HELP_STRING([--with-gmp=<path>],
 [prefix of libgmp installation e.g. /usr/local])],
 [GMP_PREFIX="$with_gmp" LDFLAGS="-L${with_gmp}/lib $backup_LDFLAGS"\
  CPPFLAGS="-I${with_gmp}/include $backup_CPPFLAGS"],
 [AC_CHECK_LIB(gmp, __gmpz_init, [LIBS=""],
  AC_MSG_ERROR([libgmp is needed; use the --with-gmp=<path> option]))])
AC_CHECK_LIB(gmp, __gmpz_import, [LIBS=""],
 AC_MSG_ERROR([libgmp >= 4.2 is needed]))
AC_CHECK_LIB(gmp, __gmpz_export, [LIBS=""],
 AC_MSG_ERROR([libgmp >= 4.2 is needed]))
AC_CHECK_LIB(gmp, __gmpz_powm_sec,
 AC_DEFINE(HAVE_POWMSEC, , [Defined if libgmp have mpz_powm_sec() function]),
 AC_MSG_WARN([libgmp >= 5.0.3 is recommended]))
AC_CHECK_HEADERS([gmp.h], , AC_MSG_ERROR([libgmp headers are missing]))
if test "x$GMP_PREFIX" != x ; then
	LIBGMP_LIBS=" -L${GMP_PREFIX}/lib"
	LIBGMP_CFLAGS=" -I${GMP_PREFIX}/include"
else
	LIBGMP_LIBS=""
	LIBGMP_CFLAGS=""
fi
LIBGMP_LIBS="${LIBGMP_LIBS} -lgmp"
AC_SUBST(LIBGMP_LIBS)
AC_SUBST(LIBGMP_CFLAGS)
LDFLAGS="$backup_LDFLAGS"
CPPFLAGS="$backup_CPPFLAGS"

AM_PATH_LIBGCRYPT("1.8.0")
if test "x$LIBGCRYPT_LIBS" = "x"; then
	AC_MSG_ERROR([libgcrypt >= 1.8.0 is required])
fi
backup_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$LIBGCRYPT_CFLAGS $backup_CPPFLAGS"
AC_CHECK_HEADERS([gcrypt.h], , AC_MSG_ERROR([libgcrypt headers are missing]))
CPPFLAGS="$backup_CPPFLAGS"

AM_PATH_GPG_ERROR("1.27")
if test "x$GPG_ERROR_LIBS" = "x"; then
	AC_MSG_ERROR([libgpg-error >= 1.27 is required])
fi

AM_PATH_LIBTMCG("1.4.0")
if test "x$LIBTMCG_LIBS" = "x"; then
	AC_MSG_ERROR([LibTMCG >= 1.4.0 is required])
fi
AC_SUBST(LIBTMCG_LIBS)
AC_SUBST(LIBTMCG_CFLAGS)

AC_PATH_PROG(DKGPG, [dkg-timestamp])
if test "x$DKGPG" = "x"; then
	AC_MSG_ERROR([DKGPG >= 1.1.3 is required])
else
	AC_DEFINE_UNQUOTED(DOTS_PATH_DKGPG, "$DKGPG",
	 [Define path for program dkg-timestamp])
fi

backup_LDFLAGS="$LDFLAGS"
backup_CPPFLAGS="$CPPFLAGS"
AC_ARG_WITH(microhttpd, [AS_HELP_STRING([--with-microhttpd=<path>],
 [prefix of libmicrohttpd installation e.g. /usr/local])],
 [MHT_PREFIX="$with_microhttpd" LDFLAGS="-L${with_microhttpd}/lib $backup_LDFLAGS"\
  CPPFLAGS="-I${with_microhttpd}/include $backup_CPPFLAGS"],
 [AC_CHECK_LIB(microhttpd, MHD_start_daemon, [LIBS=""],
  AC_MSG_ERROR([libmicrohttpd is needed; use the --with-microhttpd=<path> option]))])
AC_CHECK_HEADERS([microhttpd.h], , AC_MSG_ERROR([libmicrohttpd header is missing]))
if test "x$MHT_PREFIX" != x ; then
	LIBMHT_LIBS=" -L${MHT_PREFIX}/lib"
	LIBMHT_CFLAGS=" -I${MHT_PREFIX}/include"
else
	LIBMHT_LIBS=""
	LIBMHT_CFLAGS=""
fi
LIBMHT_LIBS="${LIBMHT_LIBS} -lmicrohttpd"
AC_SUBST(LIBMHT_LIBS)
AC_SUBST(LIBMHT_CFLAGS)
LDFLAGS="$backup_LDFLAGS"
CPPFLAGS="$backup_CPPFLAGS"

# Checks for required header files
AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_HEADERS([algorithm assert.h cassert cstdarg cstdio cstdlib cstring\
 ctime climits errno.h fcntl.h fstream functional inttypes.h iostream\
 limits.h list map sstream stdint.h stdio.h string string.h sys/stat.h\
 sys/select.h sys/types.h time.h unistd.h vector], , 
	AC_MSG_ERROR([some headers are missing]))

# Checks for required typedefs, structures, and compiler characteristics
AC_C_CONST
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for required basic library functions
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_CHECK_FUNCS([abs chmod clock close ctime fcntl fileno fprintf memcmp\
 memcpy memmove memset mktime open perror read sscanf select sleep snprintf\
 stat strptime strrchr strtoul time write], ,
	AC_MSG_ERROR([some basic functions are missing]))

# Checks for required process and network library functions
AC_HEADER_SYS_WAIT
AC_TYPE_PID_T
AC_TYPE_SIGNAL
AC_FUNC_FORK
AC_CHECK_HEADERS([csignal unistd.h sys/types.h sys/wait.h netdb.h\
 netinet/in.h sys/socket.h termios.h], ,
	AC_MSG_ERROR([some further headers are missing]))
AC_CHECK_FUNCS([fork kill pipe pipe2 waitpid getaddrinfo getnameinfo\
 htons htonl socket setsockopt connect bind listen accept signal sigaction\
 gai_strerror freeaddrinfo tcgetattr tcsetattr], , 
	AC_MSG_ERROR([some further functions are missing]))

# Enable all compiler warnings and some more by default
CFLAGS="$CFLAGS -Wall -Wextra"
CXXFLAGS="$CXXFLAGS -Wall -Wextra"

# Define output
AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

echo "Now type 'make && make install' to build and install $PACKAGE_NAME."

