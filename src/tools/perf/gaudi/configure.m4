#
# Copyright (c) 2025, Habana Labs Ltd. an Intel Company. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

AC_ARG_WITH([gaudi-perftest],
            [AS_HELP_STRING([--with-gaudi-perftest], [Enable Gaudi support for performance tests (default is yes)])],
            [],
            [with_gaudi_perftest=yes])

AS_IF([test "x$with_gaudi_perftest" != "xno"],
      [
       save_CPPFLAGS="$CPPFLAGS"
       save_LDFLAGS="$LDFLAGS"
       save_LIBS="$LIBS"
       
       # Use system-provided hl-thunk
       GAUDI_CPPFLAGS="-I/usr/include/habanalabs"
       GAUDI_LIBS="-L/usr/lib/habanalabs -lhl-thunk"
       
       CPPFLAGS="$CPPFLAGS $GAUDI_CPPFLAGS"
       LDFLAGS="$LDFLAGS -L/usr/lib/habanalabs"
       
       # Check for hlthunk.h header directly
       AC_CHECK_HEADER([habanalabs/hlthunk.h],
                       [
                        # Check for hlthunk library function
                        AC_CHECK_LIB([hl-thunk], [hlthunk_open],
                                     [
                                      have_gaudi_perftest=yes
                                      ucx_perftest_modules="${ucx_perftest_modules}:gaudi"
                                      AC_DEFINE([HAVE_UCX_PERFTEST_GAUDI], [1], [Enable Gaudi for perftest])
                                     ],
                                     [have_gaudi_perftest=no])
                       ],
                       [have_gaudi_perftest=no])
       
       CPPFLAGS="$save_CPPFLAGS"
       LDFLAGS="$save_LDFLAGS"
       LIBS="$save_LIBS"
      ],
      [have_gaudi_perftest=no])

AS_IF([test "x$with_gaudi_perftest" = "xyes" -a "x$have_gaudi_perftest" != "xyes"],
      [AC_MSG_ERROR([Gaudi support for perftest requested but not found])])

AC_SUBST([GAUDI_CPPFLAGS])
AC_SUBST([GAUDI_LIBS])

AM_CONDITIONAL([HAVE_UCX_PERFTEST_GAUDI], [test "x$have_gaudi_perftest" = "xyes"])

AC_CONFIG_FILES([src/tools/perf/gaudi/Makefile])
