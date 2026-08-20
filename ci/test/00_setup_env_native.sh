#!/usr/bin/env bash

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
# C++26 needs GCC >= 14; ubuntu:24.04 ships gcc-13 as default and gcc-14 as a package.
export PACKAGES="g++-14 libboost-dev libsqlite3-dev libzmq3-dev"
export NO_DEPENDS=1
export GOAL="all"
export LATTICA_CONFIG="\
 -DCMAKE_C_COMPILER=gcc-14 \
 -DCMAKE_CXX_COMPILER=g++-14 \
"
