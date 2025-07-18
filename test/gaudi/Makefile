# Gaudi Test Programs Makefile
# This makefile picks up the UCX build environment and builds Gaudi test programs

# Get the UCX root directory (3 levels up from test/gaudi)
UCX_ROOT := $(shell cd ../..; pwd)

# Detect if UCX is built (check for install directory or build artifacts)
UCX_BUILT := $(shell [ -d "$(UCX_ROOT)/install" ] || [ -f "$(UCX_ROOT)/src/uct/.libs/libuct.so" ] && echo yes)

# Compiler and flags
CC      = gcc
CFLAGS  = -O0 -g -Wall -Wno-unused-function \
          -I../../src -I../../src/ucs -I../../src/uct -I../../src/ucp -I../.. \
          -I../../install/include -I/usr/include/habanalabs -I/usr/include/drm
LDFLAGS = -L../../install/lib -L/usr/lib/habanalabs
LDLIBS  = -lucp -luct -lucs -lhlthunk

# UCX include paths
UCX_CPPFLAGS := -I$(UCX_ROOT)/src \
				-I$(UCX_ROOT)/src/ucs \
				-I$(UCX_ROOT)/src/uct \
				-I$(UCX_ROOT)/src/ucp \
				-I$(UCX_ROOT)/src/uct/api \
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


# Automatically discover all .c files and create corresponding programs
SOURCES := $(wildcard *.c)
PROGRAMS := $(SOURCES:.c=)
# Default target
all: $(PROGRAMS)

# Generic rule to build any program from its corresponding .c file
%: %.c
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

# Run all available tests
test-features: $(PROGRAMS)
	@echo "Running available Gaudi tests..."
	@echo "================================"
	@for prog in $(PROGRAMS); do \
		echo "Running $$prog..."; \
		./$$prog || echo "$$prog failed"; \
		echo ""; \
	done
	@echo "All tests completed!"

.PHONY: all clean install config test-features
