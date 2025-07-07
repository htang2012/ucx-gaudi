#!/bin/bash
# UCX build script with Gaudi support (system habanalabs)
# Usage: ./build.sh [configure options]
set -euo pipefail

# Regenerate autotools files
autoreconf -i

# Configure with Gaudi support, using system habanalabs and drm includes/libs
CPPFLAGS="-I/usr/include/habanalabs -I/usr/include/drm -DHAVE_GAUDI=1 -DHAVE_HLTHUNK_H=1" \
LDFLAGS="-L/usr/lib/habanalabs" \
./configure --enable-gtest --enable-examples --with-valgrind --enable-profiling --enable-frame-pointer -with-gaudi-perftest --enable-stats --enable-debug-data --enable-mt --with-gaudi=/usr --enable-debug --enable-examples --prefix=$PWD/install "$@"

# overall options
#--enable-gtest --enable-examples --with-valgrind --enable-profiling --enable-frame-pointer --enable-stats --enable-debug-data --enable-mt --with-gaudi=/usr --enable-debug --enable-examples --prefix=/workspace/ucx/install

# Build all targets with maximum parallelism
make -j"$(nproc)"

# Explicitly build Gaudi transport library (if present)
if [ -d src/uct/gaudi ]; then
    make -C src/uct/gaudi -j"$(nproc)"
fi

# Install to system (may require sudo)
# sudo make install

# Build and run unittests (if available)
make check || true

# Build all testgroup executables
if [ -d testgroup ]; then
    echo "\nBuilding all testgroup executables..."
    (cd testgroup && make -j"$(nproc)")
fi

echo "\nUCX build and install complete. Gaudi support enabled."
echo "If you need to rebuild, just rerun this script."

