#!/bin/bash

function download() {
get -O openssl.zip -c https://codeload.github.com/openssl/openssl/zip/OpenSSL_1_1_1-stable
wget -O gost-engine.zip -c https://codeload.github.com/gost-engine/engine/zip/master
wget -c https://github.com/Kitware/CMake/releases/download/v3.14.0/cmake-3.14.0.tar.gz
}

function prereq() {
sudo apt-get install make pkg-config autoconf build-essential
}

function unpack() {
unzip openssl.zip
unzip gost-engine.zip
tar xf cmake-3.14.0.tar.gz
}

function mk_cmake() {
cd cmake-3.14.0
./configure
make
sudo make install
cd ..
}

function mk_openssl() {
cd openssl-OpenSSL_1_1_1-stable
./config
make
sudo make install
sudo ln -s /usr/local/lib/libssl.so.1.1 /lib/x86_64-linux-gnu/libssl.so.1.1
sudo ln -s /usr/local/lib/libcrypto.so.1.1 /lib/x86_64-linux-gnu/libcrypto.so.1.1
cd ..
}

function mk_gost() {
export OPENSSL_ROOT_DIR=$(pwd)/openssl-OpenSSL_1_1_1-stable
echo OPENSSL_ROOT_DIR=$OPENSSL_ROOT_DIR
cd engine-master
mkdir build
cd build
cmake ..
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
sudo make install
sudo cp openssl-config.txt /usr/local/ssl/openssl.cnf
}

#prereq
download
unpack
mk_cmake
mk_openssl
mk_gost

openssl version
openssl ciphers | grep GOST2012
