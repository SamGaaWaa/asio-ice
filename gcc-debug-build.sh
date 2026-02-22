#!/bin/bash
mkdir -p gcc-build
pushd gcc-build

cmake .. \
        -DBoost_DIR=/home/sam/opensource/boost_install/lib/cmake/Boost-1.89.0 \
        -DSTDEXEC_DIR=/home/sam/opensource/stdexec/include \
        -DASIOICE_USE_BOOST_ASIO=ON \
        -DOPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/ \
        -DOPENSSL_INCLUDE_DIR=/usr/include/ \
        -DCMAKE_BUILD_TYPE=Debug \
 	-DCMAKE_C_COMPILER=gcc \
	-DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address" \
	-DCMAKE_CXX_COMPILER=g++
make -j8
popd
