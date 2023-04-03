#!/bin/bash

CURRENT_DIR=$(pwd)
BUILD_DIR=${CURRENT_DIR}/base_build/
BASE_DIR=${CURRENT_DIR}/base/

rm -rf ${BUILD_DIR}
mkdir ${BUILD_DIR}
pushd ${BUILD_DIR}

cmake ${BASE_DIR}
make
make install
popd