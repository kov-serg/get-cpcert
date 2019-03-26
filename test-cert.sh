#!/bin/bash

cert=test-cert.pem

# openssl genpkey -algorithm gost2012_256 -pkeyopt paramset:A -out ca.key

function sign() {
  filename=$1
  sign=$filename.sig
  echo signing $filename
  openssl smime -sign -binary -noattr -in $filename -signer $cert -out $sign -outform DER
}
function show() {
  filename=$1
  sign=$filename.sig
  openssl asn1parse -inform DER -in $sign
}
function check() {
  filename=$1
  sign=$filename.sig
  echo -n "checking $filename - "
  openssl smime -verify -noverify -CAfile $cert -content $filename -in $sign -inform DER >/dev/null
}

echo test > test.txt

sign test.txt && check test.txt && show test.txt > test-cert.txt
