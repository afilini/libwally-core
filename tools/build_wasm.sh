#! /usr/bin/env bash

set -e

num_jobs=4
if [ -f /proc/cpuinfo ]; then
    num_jobs=$(grep ^processor /proc/cpuinfo | wc -l)
fi
$PWD/tools/cleanup.sh && $PWD/tools/autogen.sh
emconfigure ./configure --disable-swig-python --disable-swig-java --enable-export-all --enable-elements --enable-ecmult-static-precomputation
emmake make -j $num_jobs
emcc -O2 -s "EXTRA_EXPORTED_RUNTIME_METHODS=['getValue', 'UTF8ToString', 'ccall', 'cwrap', 'malloc']" -s LINKABLE=1 -s EXPORT_ALL=1 ./src/.libs/*.o src/secp256k1/src/*.o src/ccan/ccan/crypto/*/.libs/*.o ./src/ccan/ccan/str/hex/.libs/*.o -o wallycore.html --shell-file contrib/shell_minimal.html
