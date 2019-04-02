# get-cpcert

Console utility to convert cryptopro4 certificate (gost-2001, gost-2012) into pem file for openssl 1.1.1

## usage
get-cpcert folder.000 password > certificate.pem

## build

Tested on ubuntu 14.04 LTS 64bit

prepare.sh -- download,build & install openssl 1.1.1 & gost-engine + cmake
  it takes about 530Mb disk space and 20min to build on my notebook

build.sh -- build get-cpcert

## output
get-cpcert
libgost.so

## prebuild binaries
get-cpcert-bin.tar.gz -- contains prebuild binaries for ubuntu 14.04 64bit and 3 samples for testing
  
