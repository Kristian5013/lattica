#!/usr/bin/env bash

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_multiprocess
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
# Multiprocess IPC build (Unix only): builds lattica-node and the Cap'n Proto
# schemas via the vendored libmultiprocess.
export PACKAGES="g++-14 libboost-dev libsqlite3-dev libzmq3-dev capnproto libcapnp-dev"
export NO_DEPENDS=1
export GOAL="all"
export LATTICA_CONFIG="\
 -DCMAKE_C_COMPILER=gcc-14 \
 -DCMAKE_CXX_COMPILER=g++-14 \
 -DENABLE_IPC=ON \
"
