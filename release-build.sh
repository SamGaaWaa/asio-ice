#!/bin/bash
mkdir -p clang-build
pushd clang-build

cmake .. \
        -DBoost_DIR=/root/opensource/boost_1_88_install/lib/cmake/Boost-1.88.0 \
        -DSTDEXEC_DIR=/mnt/e/openSource/asio2exec/stdexec \
        -DASIOICE_USE_BOOST_ASIO=ON \
        -DOPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/ \
        -DOPENSSL_INCLUDE_DIR=/usr/include/ \
        -DCMAKE_BUILD_TYPE=Release \
 	-DCMAKE_C_COMPILER=clang \
	-DCMAKE_CXX_FLAGS="-stdlib=libc++ -O3" \
	-DCMAKE_CXX_COMPILER=clang++
make -j8
popd
