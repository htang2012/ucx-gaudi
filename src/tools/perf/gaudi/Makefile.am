#
# Copyright (c) 2025, Habana Labs Ltd. an Intel Company. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

if HAVE_UCX_PERFTEST_GAUDI

module_LTLIBRARIES                  = libucx_perftest_gaudi.la
libucx_perftest_gaudi_la_CPPFLAGS   = $(BASE_CPPFLAGS) $(GAUDI_CPPFLAGS) -I/usr/include/drm -I/usr/include/libdrm
libucx_perftest_gaudi_la_CFLAGS     = $(BASE_CFLAGS) $(LT_CFLAGS)
libucx_perftest_gaudi_la_LDFLAGS    = -version-info $(SOVERSION)
libucx_perftest_gaudi_la_LIBADD     = $(GAUDI_LIBS)
libucx_perftest_gaudi_la_SOURCES    = gaudi_alloc.c

include $(top_srcdir)/config/module.am

endif
