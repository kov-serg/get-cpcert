#!/bin/bash

function die() {
echo ERROR: $*
exit 1
}

function download() {
mkdir -p libs
wget -O libs/openssl.zip -c https://codeload.github.com/openssl/openssl/zip/OpenSSL_1_1_1-stable || die "download openssl"
wget -O libs/gost-engine.zip -c https://codeload.github.com/gost-engine/engine/zip/1b374532c2d494710c39371e83c197d08c65e8bc || die "download gost-engine"
wget -O libs/cmake-3.14.0.tar.gz -c https://github.com/Kitware/CMake/releases/download/v3.14.0/cmake-3.14.0.tar.gz || die "download cmake"
}

function prereq() {
sudo apt-get update && sudo apt-get install -y make pkg-config autoconf build-essential wget unzip
}

function unpack() {
cd libs
unzip openssl.zip          || die "unpack openssl"
unzip gost-engine.zip      || die "unpack gost-engine"
ln -s engine-1b374532c2d494710c39371e83c197d08c65e8bc engine || die "ln gost-engine"
tar xf cmake-3.14.0.tar.gz || die "unpack cmake"
cd ..
}

function mk_cmake() {
cd libs/cmake-3.14.0
./configure       || die "configure cmake"
make              || die "make cmake"
sudo make install || die "install cmake"
cd ../..
}

function mk_openssl() {
cd libs/openssl-OpenSSL_1_1_1-stable
./config          || die "config openssl"
make              || die "make openssl"
sudo make install || die "install openssl"
sudo ln -s /usr/local/lib/libssl.so.1.1 /lib/x86_64-linux-gnu/libssl.so.1.1       || die "ln libssl"
sudo ln -s /usr/local/lib/libcrypto.so.1.1 /lib/x86_64-linux-gnu/libcrypto.so.1.1 || die "ln libcrypto"
cd ../..
}

function mk_gost() {
export OPENSSL_ROOT_DIR=$(pwd)/libs/openssl-OpenSSL_1_1_1-stable
echo OPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR
cd libs/engine
mkdir build
cd build
cmake ..                            || die "cmake gost-engine"
cmake -DCMAKE_BUILD_TYPE=Release .. || die "make gost-engine"
cmake --build . --config Release    || die "build gost-engine"
sudo make install                   || die "install gost-engine"
cd ../../..
sudo cp openssl-config.txt /usr/local/ssl/openssl.cnf || die "add gost-engine to openssl"
}

prereq
download
unpack
mk_cmake
mk_openssl
mk_gost

openssl version
openssl ciphers | grep GOST2012
