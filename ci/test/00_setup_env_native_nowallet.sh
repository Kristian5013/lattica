#!/usr/bin/env bash

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_nowallet
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
# Node-only build: no wallet (no SQLite) and no ZMQ. Catches any wallet/ZMQ
# dependency leaking into the consensus or node libraries.
export PACKAGES="g++-14 libboost-dev"
export NO_DEPENDS=1
export GOAL="all"
export LATTICA_CONFIG="\
 -DCMAKE_C_COMPILER=gcc-14 \
 -DCMAKE_CXX_COMPILER=g++-14 \
 -DENABLE_WALLET=OFF \
 -DWITH_ZMQ=OFF \
"
