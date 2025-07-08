#
# Copyright (c) 2024 Habana Labs, Ltd. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

if HAVE_GAUDI

module_LTLIBRARIES      = libucm_gaudi.la
libucm_gaudi_la_CPPFLAGS = $(BASE_CPPFLAGS) $(GAUDI_CPPFLAGS) -I/usr/include/drm -I/usr/include/libdrm
libucm_gaudi_la_CFLAGS   = $(BASE_CFLAGS) $(GAUDI_CFLAGS) $(LT_CFLAGS)
libucm_gaudi_la_LIBADD   = ../libucm.la $(GAUDI_LIBS)
libucm_gaudi_la_LDFLAGS  = $(UCM_MODULE_LDFLAGS) \
                           $(patsubst %, -Xlinker %, $(GAUDI_LDFLAGS)) \
                           -version-info $(SOVERSION)

noinst_HEADERS = \
	gaudimem.h

libucm_gaudi_la_SOURCES = \
	gaudimem.c

include $(top_srcdir)/config/module.am

endif
