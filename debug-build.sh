#!/bin/bash
mkdir -p clang-build
pushd clang-build
cmake .. -DSTANDALONE_ASIO_DIR=/mnt/e/openSource/asio \
        -DSTDEXEC_DIR=/mnt/e/openSource/asio2exec/stdexec \
        -DUSE_BOOST=OFF \
        -DOPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/ \
        -DOPENSSL_INCLUDE_DIR=/usr/include/ \
        -DCMAKE_BUILD_TYPE=Debug \
 	-DCMAKE_C_COMPILER=clang \
	-DCMAKE_CXX_FLAGS="-stdlib=libc++ -O0 -g -fsanitize=address" \
	-DCMAKE_CXX_COMPILER=clang++
make -j8
popd
