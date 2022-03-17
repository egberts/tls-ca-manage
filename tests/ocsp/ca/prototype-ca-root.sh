#!/bin/bash
# Title: Root CA request/sign-with-ca/verify

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

touch index.txt
echo 1000 > serial

openssl ecparam -list_curves
openssl ecparam -list_curves | grep '384\|409\|521'

# Generate Private Key for Root CA
openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out ca.cheese.key.pem

# Create a Request for Root CA
openssl req -config openssl-root.cnf \
    -new \
    -x509 \
    -sha384 \
    -extensions v3_ca \
    -key ca.cheese.key.pem \
    -out ca.cheese.crt.pem
assert_success $?

# Validate the Request for Root CA
openssl x509 -noout -text -in ca.cheese.crt.pem | grep 'Signature Algorithm:'
openssl x509 -noout -dates -in ca.cheese.crt.pem -dates -subject -issuer
openssl x509 -noout -text -in ca.cheese.crt.pem | grep 'Public-Key:'
openssl x509 -noout -text -in ca.cheese.crt.pem | grep 'NIST CURVE:'
exit

# Sign the CSR with our Intermediary Certificate Authority

openssl ca \
    -config ./openssl-intermediate-ocsp.cnf \
    -extensions ocsp \
    -days 365 \
    -notext \
    -md sha384 \
    -in ocsp.cheese.csr.pem \
    -out ocsp.cheese.crt.pem
assert_success $?

# Verify the certificate's usage is set for OCSP

openssl x509 -noout -text -in ocsp.cheese.crt.pem
assert_success $?

