# Makefile for Gaudi tests

# Get the UCX root directory
UCX_ROOT := $(shell cd ../..; pwd)

# Compiler and flags
CC := gcc
CFLAGS := -O0 -g -Wall -Wno-unused-function \
          -I$(UCX_ROOT)/src \
          -I$(UCX_ROOT)/src/ucs \
          -I$(UCX_ROOT)/src/uct \
          -I$(UCX_ROOT)/src/ucp \
          -I$(UCX_ROOT) \
          -I$(UCX_ROOT)/install/include \
          -I/usr/include/habanalabs \
          -I/usr/include/drm \
          -I$(UCX_ROOT)/src/uct/api \
          -I$(UCX_ROOT)/src/uct/gaudi \
          -DHAVE_CONFIG_H

# Libraries
LDFLAGS := -L$(UCX_ROOT)/install/lib \
           -L/usr/lib/habanalabs \
           -luct -lucs -lucp -lucm -lrt -lpthread 

# Targets
TARGETS := ucp_dmabuf_example

.PHONY: all clean

all: $(TARGETS)

ucp_dmabuf_example: ucp_dmabuf_example.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)
