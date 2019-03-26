!/bin/sh

cp ../engine-master/build/bin/gost.so libgost.so
gcc -o get-cpcert -I../engine-master get-cpcert.c \
  -L.../openssl-OpenSSL_1_1_1-stable -lssl -lcrypto \
  -L../engine-master/build -lgost_core -L. -lgost \
  -lpthread -ldl -Xlinker '-rpath=.'
