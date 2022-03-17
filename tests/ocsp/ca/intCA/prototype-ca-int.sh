#!/bin/bash
# Title: Intermediate CA request/sign-with-ca/verify

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

touch index.txt
echo 1000 > serial
echo 1000 > crlnumber

openssl ecparam -list_curves
openssl ecparam -list_curves | grep '384\|409\|521'

# Generate Private Key for Intermediate CA
openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out intCA.cheese.key.pem

# Create a Request Intermediate Root CA
# openssl req -config openssl-intermediate-ocsp.cnf \
#     -new \
#     -x509 \
#     -sha384 \
#     -extensions v3_ca \
#     -key intCA.cheese.key.pem \
#     -out intCA.cheese.crt.pem

openssl req \
    -config openssl-intermediate-ocsp.cnf \
    -new \
    -newkey ec:<(openssl ecparam -name secp384r1) \
    -keyout intCA.cheese.key.pem \
    -out intCA.cheese.csr
assert_success $?


# Sign the CSR with our Intermediary Certificate Authority
cd ..    # go into Root CA $dir
openssl ca -config ./openssl-root.cnf \
    -extensions v3_intermediate_ca \
    -days 3600 \
    -md sha384 \
    -in intCA/intCA.cheese.csr \
    -out intCA/intCA.cheese.crt.pem
assert_success $?

cd intCA

# Verify the certificate's usage is set for OCSP

openssl x509 -noout -text -in intCA.cheese.crt.pem
assert_success $?

# Validate the Request for Root CA
openssl x509 -noout -text -in intCA.cheese.crt.pem | grep 'Signature Algorithm:'
openssl x509 -noout -dates -in intCA.cheese.crt.pem -dates -subject -issuer
openssl x509 -noout -text -in intCA.cheese.crt.pem | grep 'Public-Key:'
openssl x509 -noout -text -in intCA.cheese.crt.pem | grep 'NIST CURVE:'

