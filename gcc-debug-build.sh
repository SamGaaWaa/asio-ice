#!/bin/bash
mkdir -p gcc-build
pushd gcc-build
cmake .. -DSTANDALONE_ASIO_DIR=/mnt/e/openSource/asio \
        -DSTDEXEC_DIR=/mnt/e/openSource/asio2exec/stdexec \
        -DUSE_BOOST=OFF \
        -DOPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu/ \
        -DOPENSSL_INCLUDE_DIR=/usr/include/ \
        -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_COMPILER=gcc \
        -DCMAKE_CXX_COMPILER=g++
make -j8
popd
