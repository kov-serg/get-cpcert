#!/bin/sh

cp libs/engine/build/bin/gost.so libgost.so
gcc -o get-cpcert -Ilibs/engine get-cpcert.c \
  -Llibs/openssl-OpenSSL_1_1_1-stable -lssl -lcrypto \
  -Llibs/engine/build -lgost_core -L. -lgost \
  -lpthread -ldl -Xlinker '-rpath=.'
