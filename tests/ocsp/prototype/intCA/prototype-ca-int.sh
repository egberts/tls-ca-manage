#!/bin/bash
# Title: Intermediate CA request/sign-with-ca/verify
#
echo "Create Intermediate CA (request/sign-with-root/verify)"
echo

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

cp /dev/null index.txt
echo 1000 > serial
echo 1000 > crlnumber


# to turn off password:
#   remove -aes256 from 'openssl ec'
#   add -nodes to 'openssl req'


# openssl ecparam -list_curves
# openssl ecparam -list_curves | grep '384\|409\|521'

# Generate Private Key for Intermediate CA
# openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out intCA.cheese.key.pem
echo "openssl ecparam ... | openssl ec ..."
openssl ecparam -genkey -name secp384r1 | openssl ec -out intCA.cheese.key.pem
assert_success $?
echo

# Create a Request Intermediate Root CA
echo "openssl req ..."
openssl req \
    -config openssl-intermediate.cnf \
    -new \
    -nodes \
    -newkey ec:<(openssl ecparam -name secp384r1) \
    -keyout intCA.cheese.key.pem \
    -out intCA.cheese.csr.pem
assert_success $?
echo


# Sign the CSR with our Intermediary Certificate Authority
cd ..    # go into Root CA $dir
openssl ca -config ./openssl-root.cnf \
    -extensions v3_intermediate_ca \
    -days 3600 \
    -md sha384 \
    -in intCA/intCA.cheese.csr.pem \
    -out intCA/intCA.cheese.crt.pem
assert_success $?

# go back down
cd intCA

# Verify the certificate's usage is set for OCSP

echo "openssl x509 ..."
openssl x509 -noout -text -in intCA.cheese.crt.pem
assert_success $?

# Validate the Request for Root CA
openssl x509 -noout -text -in intCA.cheese.crt.pem | grep 'Signature Algorithm:'
openssl x509 -noout -dates -in intCA.cheese.crt.pem -dates -subject -issuer
openssl x509 -noout -text -in intCA.cheese.crt.pem | grep 'Public-Key:'
openssl x509 -noout -text -in intCA.cheese.crt.pem | grep 'NIST CURVE:'
echo
echo "Done."
