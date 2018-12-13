dnl **********************************************************************************
dnl
dnl   (c) Copyright, TekPea Inc., All rights reserved.
dnl
dnl   No duplications, whole or partial, manual or electronic, may be made
dnl   without express written permission.  Any such copies, or
dnl   revisions thereof, must display this notice unaltered.
dnl   This code contains trade secrets of TekPea, Inc.
dnl
dnl **********************************************************************************

AC_INIT(myApp, 1.0, fabriziobertocci@gmail.com)
LT_INIT
AC_CONFIG_SRCDIR([src/testauth.c])

dnl subdir-objects tells Makefile to place object files in the same dir as sources.
dnl See: https://www.gnu.org/software/automake/manual/html_node/List-of-Automake-options.html
AM_INIT_AUTOMAKE([subdir-objects])


AC_PROG_CC

AC_CONFIG_MACRO_DIRS([m4])


dnl **********************************************************************************************
dnl * Debug/Release                                                                              *
dnl **********************************************************************************************
AC_ARG_ENABLE(debug,
[  --enable-debug          enable full debugging information (and disable optimization)],
[
        CFLAGS="-g -O0 -DDEBUG"
],[
        CFLAGS="-O2 -DNDEBUG"
])


dnl **********************************************************************************************
dnl * Enable/disable compiler warnings                                                           *
dnl **********************************************************************************************
AC_ARG_ENABLE(warnings,
[  --enable-warnings       enable compiler warnings during build ],
[
        CFLAGS="$CFLAGS -Wall -Wpointer-arith -Wwrite-strings -Wconversion -Wcast-qual -W"
],[
        CFLAGS="$CFLAGS -W"
])


dnl **********************************************************************************************
dnl * MySQL-based plugin                                                                         *
dnl **********************************************************************************************
AC_ARG_ENABLE(mysql,
[  --enable-mysql          build MySQL plugin (requires libmysqlclient-dev)],
[
        CFLAGS="$CFLAGS `pkg-config --cflags mysqlclient`"
        LIBS="$LIBS `pkg-config --libs --static mysqlclient`"
        AC_MSG_RESULT(Building the MySQL plug-in)
        temp=true
],[
        AC_MSG_RESULT(NOT building the MySQL plug-in)
        temp=false
])
AM_CONDITIONAL([EPKA_BUILD_MYSQL], [test x$temp = xtrue])


AC_OUTPUT(Makefile src/Makefile)

