#
# Copyright (c) 2024, Habana Labs Ltd. an Intel Company
#

AC_DEFUN([UCX_CHECK_GAUDI],[

AS_IF([test "x$gaudi_checked" != "xyes"],
   [
    AC_ARG_WITH([gaudi],
                [AS_HELP_STRING([--with-gaudi=(DIR)], [Enable the use of GAUDI (default is yes).])],
                [], [with_gaudi=yes])

    AS_IF([test "x$with_gaudi" = "xno"],
        [
         gaudi_happy=no
        ],
        [
         save_CPPFLAGS="$CPPFLAGS"
         save_LDFLAGS="$LDFLAGS"
         save_LIBS="$LIBS"

         GAUDI_CPPFLAGS=""
         GAUDI_LDFLAGS=""
         GAUDI_LIBS=""

         AS_IF([test "x$with_gaudi" != "xno"],
               [
                AS_IF([test "x$with_gaudi" = "xguess" -o "x$with_gaudi" = "xyes"],
                      [
                       # Use system habanalabs installation
                       GAUDI_CPPFLAGS="-I/usr/include/habanalabs"
                       GAUDI_CPPFLAGS="$GAUDI_CPPFLAGS -I/usr/include/drm"
                       GAUDI_CPPFLAGS="$GAUDI_CPPFLAGS -I/usr/include/libdrm"
                       GAUDI_CPPFLAGS="$GAUDI_CPPFLAGS -DHAVE_GAUDI=1 -DHAVE_SYNAPSE_API_H=1 -DUSE_SYNAPSE_API=1"
                       GAUDI_LDFLAGS="-L/usr/lib/habanalabs"
                      ],
                      [
                       GAUDI_CPPFLAGS="-I${with_gaudi}/include/habanalabs"
                       GAUDI_CPPFLAGS="$GAUDI_CPPFLAGS -I${with_gaudi}/include/drm"
                       GAUDI_CPPFLAGS="$GAUDI_CPPFLAGS -I${with_gaudi}/include/libdrm"
                       GAUDI_CPPFLAGS="$GAUDI_CPPFLAGS -DHAVE_GAUDI=1 -DHAVE_SYNAPSE_API_H=1 -DUSE_SYNAPSE_API=1"
                       GAUDI_LDFLAGS="-L${with_gaudi}/lib/habanalabs"
                      ])
               ])

         CPPFLAGS="$CPPFLAGS $GAUDI_CPPFLAGS"
         LDFLAGS="$LDFLAGS $GAUDI_LDFLAGS"

         # Check gaudi header files - require synapse API only
         AC_CHECK_HEADERS([habanalabs/synapse_api.h],
                          [gaudi_happy="yes"], [gaudi_happy="no"])
         
         

         CPPFLAGS="$save_CPPFLAGS"
         LDFLAGS="$save_LDFLAGS"
         LIBS="$save_LIBS"

         AS_IF([test "x$gaudi_happy" = "xyes"],
               [AC_SUBST([GAUDI_CPPFLAGS], ["$GAUDI_CPPFLAGS"])
                AC_SUBST([GAUDI_LDFLAGS], ["$GAUDI_LDFLAGS"])
                AC_SUBST([GAUDI_LIBS], ["$GAUDI_LIBS"])
                AC_DEFINE([HAVE_GAUDI], 1, [Enable GAUDI support])],
               [AS_IF([test "x$with_gaudi" != "xguess"],
                      [AC_MSG_ERROR([GAUDI support is requested but gaudi packages cannot be found])],
                      [AC_MSG_WARN([GAUDI not found])])])
        ]) # "x$with_gaudi" = "xno"

        gaudi_checked=yes
        AM_CONDITIONAL([HAVE_GAUDI], [test "x$gaudi_happy" != xno])
   ]) # "x$gaudi_checked" != "xyes"

]) # UCX_CHECK_GAUDI
