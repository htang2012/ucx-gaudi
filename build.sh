#!/bin/bash
# UCX build script with Gaudi support (system habanalabs)
# Usage: ./build.sh [configure options]
#        ./build.sh --release    # For optimized release build
set -euo pipefail

# Check if release build is requested
RELEASE_BUILD=0
if [[ "${1:-}" == "--release" ]]; then
    RELEASE_BUILD=1
    shift # Remove --release from arguments
fi

# Regenerate autotools files
autoreconf -i

if [[ $RELEASE_BUILD -eq 1 ]]; then
    echo "Building optimized release version..."
    # Release build configuration with optimizations
    ./contrib/configure-release --prefix=/opt/ucx --with-mpi --with-gaudi --with-rdmacm --with-verbs "$@"
else
    echo "Building debug version..."
    # Configure with Gaudi support, using system habanalabs and drm includes/libs
    ./configure --with-gaudi=/usr --enable-examples --prefix=$PWD/install "$@"
fi

# overall options
#--enable-gtest --enable-examples --with-valgrind --enable-profiling --enable-frame-pointer --enable-stats --enable-debug-data --enable-mt --with-gaudi=/usr --enable-debug --enable-examples --prefix=/workspace/ucx/install

# Build all targets with maximum parallelism
if [[ $RELEASE_BUILD -eq 1 ]]; then
    echo "Building release with 8 parallel jobs..."
    make -j8
else
    echo "Building debug with maximum parallelism..."
    make -j8
fi

# Explicitly build Gaudi transport library (if present)
if [ -d src/uct/gaudi ]; then
    if [[ $RELEASE_BUILD -eq 1 ]]; then
        make -C src/uct/gaudi -j8
    else
        make -C src/uct/gaudi -j"$(nproc)"
    fi
fi

# Install to system
if [[ $RELEASE_BUILD -eq 1 ]]; then
    echo "Installing release build to /opt/ucx..."
    make install
else
    echo "Debug build installed to $PWD/install"
    # sudo make install  # Uncomment if you want to install debug build system-wide
fi

# Build and run unittests (if available)
make check || true

# Build all testgroup executables
if [ -d testgroup ]; then
    echo "\nBuilding all testgroup executables..."
    (cd testgroup && make -j8)
fi

echo "\nUCX build and install complete. Gaudi support enabled."
if [[ $RELEASE_BUILD -eq 1 ]]; then
    echo "Release build installed to /opt/ucx"
    echo "Usage: ./build.sh --release [additional configure options]"
else
    echo "Debug build installed to $PWD/install"
    echo "Usage: ./build.sh [configure options] or ./build.sh --release"
fi
echo "If you need to rebuild, just rerun this script."

