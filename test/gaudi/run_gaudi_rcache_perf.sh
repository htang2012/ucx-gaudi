#!/bin/bash

# Script to run gaudi_rcache_perf with proper library paths

# Get the UCX root directory
UCX_ROOT="$(cd ../..; pwd)"

# Set library path to include gaudi module and other UCX libraries
if [ -d "${UCX_ROOT}/install/lib" ]; then
    export LD_LIBRARY_PATH="${UCX_ROOT}/install/lib:${UCX_ROOT}/install/lib/ucx:${LD_LIBRARY_PATH}"
else
    export LD_LIBRARY_PATH="${UCX_ROOT}/src/uct/gaudi/.libs:${UCX_ROOT}/src/uct/.libs:${UCX_ROOT}/src/ucs/.libs:${UCX_ROOT}/src/ucp/.libs:${LD_LIBRARY_PATH}"
fi

echo "LD_LIBRARY_PATH: $LD_LIBRARY_PATH"
echo "Running gaudi_rcache_perf..."

./gaudi_rcache_perf


# Run the test

echo "UCT_GAUDI_COPY_ENABLE_RCACHE=yes  and Running gaudi_rcache_perf..."
UCT_GAUDI_COPY_ENABLE_RCACHE=yes ./gaudi_rcache_perf
