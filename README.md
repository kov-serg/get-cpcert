# get-cpcert

Console utility to convert cryptopro4 certificate (gost-2001, gost-2012-256) into pem file for openssl 1.1.1

## usage
get-cpcert folder.000 password > certificate.pem

## build

Tested on ubuntu 14.04 LTS 64bit

prepare.sh -- download,build & install openssl 1.1.1 & gost-engine + cmake

build.sh -- build get-cpcert

## output
get-cpcert
libgost.so
