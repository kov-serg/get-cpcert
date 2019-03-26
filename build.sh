!/bin/sh

cp engine-master/build/bin/gost.so libgost.so
gcc -o get-cpcert -Iengine-master get-cpcert.c \
  -Lopenssl-OpenSSL_1_1_1-stable -lssl -lcrypto \
  -Lengine-master/build -lgost_core -L. -lgost \
  -lpthread -ldl -Xlinker '-rpath=.'
