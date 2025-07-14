# Gaudi Test Programs Makefile
# This makefile picks up the UCX build environment and builds Gaudi test programs

# Get the UCX root directory (3 levels up from test/gaudi)
UCX_ROOT := $(shell cd ../..; pwd)

# Detect if UCX is built (check for install directory or build artifacts)
UCX_BUILT := $(shell [ -d "$(UCX_ROOT)/install" ] || [ -f "$(UCX_ROOT)/src/uct/.libs/libuct.so" ] && echo yes)

# Compiler and flags
CC := gcc
CFLAGS := -std=gnu99 -O2 -g -Wall -Wno-unused-function
LDFLAGS := 

# UCX include paths
UCX_CPPFLAGS := -I$(UCX_ROOT)/src \
				-I$(UCX_ROOT)/src/ucs \
				-I$(UCX_ROOT)/src/uct \
				-I$(UCX_ROOT)/src/ucp \
				-I$(UCX_ROOT)

# UCX library paths - try install first, then build directories
ifeq ($(shell [ -d "$(UCX_ROOT)/install/lib" ] && echo yes),yes)
	UCX_LDFLAGS := -L$(UCX_ROOT)/install/lib
	UCX_CPPFLAGS += -I$(UCX_ROOT)/install/include
else
	UCX_LDFLAGS := -L$(UCX_ROOT)/src/ucs/.libs \
				   -L$(UCX_ROOT)/src/uct/.libs \
				   -L$(UCX_ROOT)/src/ucp/.libs
endif

# UCX libraries
UCX_LIBS := -luct -lucs -lucp -lucm -lucm -lucs -lrt -lpthread

# Habana Labs (hlthunk) flags
HLTHUNK_CPPFLAGS := -I/usr/include/habanalabs -I/usr/include/drm
HLTHUNK_LDFLAGS := -L/usr/lib/habanalabs
HLTHUNK_LIBS := -lhl-thunk

# Combined flags
ALL_CPPFLAGS := $(CFLAGS) $(UCX_CPPFLAGS) $(HLTHUNK_CPPFLAGS) -DHAVE_CONFIG_H
ALL_LDFLAGS := $(LDFLAGS) $(UCX_LDFLAGS) $(HLTHUNK_LDFLAGS)
ALL_LIBS := $(UCX_LIBS) $(HLTHUNK_LIBS)


# Test programs
PROGRAMS := basic_gaudi_test simple_gaudi_test gaudi_dmabuf_test gaudi_ib_integration_test ucx_gaudi_info gaudi_ucp_dmabuf_example test_gaudi_copy_post \
		   test_gaudi_rcache test_gaudi_memtype test_gaudi_dmabuf test_gaudi_stats test_gaudi_ipc test_gaudi_dma test_gaudi_integration \
		   test_memory_types test_memtype_detect test_refined_gaudi_dma test_simple_ucp test_ucp_gaudi_debug test_uct_gaudi_alloc test_uct_gaudi_alloc_fixed
# Generic build rule for new test programs
test_gaudi_dma: test_gaudi_dma.c ../../src/uct/gaudi/base/gaudi_dma.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $^ $(ALL_LDFLAGS) $(ALL_LIBS)

test_gaudi_integration: test_gaudi_integration.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_memory_types: test_memory_types.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_memtype_detect: test_memtype_detect.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_refined_gaudi_dma: test_refined_gaudi_dma.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_simple_ucp: test_simple_ucp.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_ucp_gaudi_debug: test_ucp_gaudi_debug.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_uct_gaudi_alloc: test_uct_gaudi_alloc.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_uct_gaudi_alloc_fixed: test_uct_gaudi_alloc_fixed.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)
# Test for uct_gaudi_copy_post_gaudi_async_copy
test_gaudi_copy_post: test_gaudi_copy_post.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $^ \
	  -L$(UCX_ROOT)/src/uct/gaudi/.libs $(ALL_LDFLAGS) $(ALL_LIBS) -luct_gaudi

# Default target
all: $(PROGRAMS)

# Basic test program for Gaudi hardware
basic_gaudi_test: basic_gaudi_test.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

# Simple test program for Gaudi basics
simple_gaudi_test: simple_gaudi_test.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

# Test program for DMA-BUF functionality
gaudi_dmabuf_test: gaudi_dmabuf_test.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

# Test program for Gaudi-IB integration
gaudi_ib_integration_test: gaudi_ib_integration_test.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

# UCX info program for Gaudi
ucx_gaudi_info: ucx_gaudi_info.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

# Gaudi UCP DMA-BUF example
gaudi_ucp_dmabuf_example: gaudi_ucp_dmabuf_example.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

# Feature test programs
test_gaudi_rcache: test_gaudi_rcache.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_gaudi_memtype: test_gaudi_memtype.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_gaudi_dmabuf: test_gaudi_dmabuf.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_gaudi_stats: test_gaudi_stats.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

test_gaudi_ipc: test_gaudi_ipc.c
	$(CC) $(ALL_CPPFLAGS) -o $@ $< $(ALL_LDFLAGS) $(ALL_LIBS)

# Clean target
clean:
	rm -f $(PROGRAMS) *.o

# Install target (optional)
install: all
	mkdir -p $(UCX_ROOT)/install/bin
	cp $(PROGRAMS) $(UCX_ROOT)/install/bin/

# Show build configuration
config:
	@echo "UCX_ROOT: $(UCX_ROOT)"
	@echo "CC: $(CC)"
	@echo "CPPFLAGS: $(ALL_CPPFLAGS)"
	@echo "LDFLAGS: $(ALL_LDFLAGS)"
	@echo "LIBS: $(ALL_LIBS)"

# Run all feature tests
test-features: test_gaudi_rcache test_gaudi_memtype test_gaudi_dmabuf test_gaudi_stats test_gaudi_ipc
	@echo "Running Gaudi feature tests..."
	@echo "================================"
	./test_gaudi_rcache -v
	@echo ""
	./test_gaudi_memtype -v
	@echo ""
	./test_gaudi_dmabuf -v
	@echo ""
	./test_gaudi_stats -v
	@echo ""
	./test_gaudi_ipc -v
	@echo ""
	@echo "All feature tests completed!"

.PHONY: all clean install config test-features
