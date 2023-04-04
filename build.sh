#!/bin/bash

CURRENT_DIR=$(pwd)
BASE_BUILD_DIR=${CURRENT_DIR}/base_build/
BUILD_DIR=${CURRENT_DIR}/build/
BASE_DIR=${CURRENT_DIR}/base/
CPU_NUM=$(cat /proc/cpuinfo | grep "physical id" | wc -l)

rm -rf ${BASE_BUILD_DIR}
mkdir ${BASE_BUILD_DIR}
pushd ${BASE_BUILD_DIR}

cmake ${BASE_DIR} -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-std=c++11"
make -j${CPU_NUM}
make install
popd

rm -rf ${BUILD_DIR}
mkdir ${BUILD_DIR}
pushd ${BUILD_DIR}

cmake ${CURRENT_DIR} -DCMAKE_INCLUDE_PATH="${BASE_BUILD_DIR}install/include/"
#-DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-std=c++11"
make -j${CPU_NUM}
popd