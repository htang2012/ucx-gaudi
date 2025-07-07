#
# Copyright (c) 2024, Habana Labs Ltd. an Intel Company
#

if HAVE_GAUDI

SUBDIRS = . 

module_LTLIBRARIES      = libuct_gaudi.la
libuct_gaudi_la_CPPFLAGS = $(BASE_CPPFLAGS) $(GAUDI_CPPFLAGS)
libuct_gaudi_la_CFLAGS   = $(BASE_CFLAGS) $(GAUDI_CFLAGS) $(LT_CFLAGS)
libuct_gaudi_la_LDFLAGS  = $(GAUDI_LDFLAGS) -version-info $(SOVERSION)
libuct_gaudi_la_LIBADD   = $(top_builddir)/src/ucs/libucs.la \
                          $(top_builddir)/src/uct/libuct.la \
                          $(GAUDI_LIBS)

libuct_gaudi_la_SOURCES = \
	base/gaudi_iface.c \
	base/gaudi_md.c \
	base/gaudi_dma.c \
	copy/gaudi_copy_md.c \
	copy/gaudi_copy_iface.c \
	copy/gaudi_copy_ep.c \
	ipc/gaudi_ipc_md.c \
	ipc/gaudi_ipc_iface.c \
	ipc/gaudi_ipc_ep.c \
	ipc/gaudi_ipc_cache.c

noinst_HEADERS = \
	base/gaudi_md.h \
	base/gaudi_iface.h \
	base/gaudi_dma.h \
	copy/gaudi_copy_md.h \
	copy/gaudi_copy_iface.h \
	copy/gaudi_copy_ep.h \
	base/gaudi_md.h \
	copy/gaudi_copy.h \
	ipc/gaudi_ipc_md.h \
	ipc/gaudi_ipc_iface.h \
	ipc/gaudi_ipc_ep.h \
	ipc/gaudi_ipc_cache.h \
	ipc/gaudi_ipc.inl \
	ipc/gaudi_ipc.h

PKG_CONFIG_NAME=gaudi

include $(top_srcdir)/config/module.am
# TODO: enable pkg-config processing when module static build is enabled
# include $(top_srcdir)/config/module-pkg-config.am

endif
