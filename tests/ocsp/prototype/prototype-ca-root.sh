#!/bin/bash
# Title: Root CA request/sign-with-ca/verify

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

# See prototype-ca-root-reset.sh
# cp /dev/null index.txt
# echo 1000 > serial

OPENSSL_BIN="env OPENSSL_CONF=/dev/null openssl"

# to turn off password:
#   remove -aes256 from 'openssl ec'
#   add -nodes to 'openssl req'

# openssl ecparam -list_curves
# openssl ecparam -list_curves | grep '384\|409\|521'

# Generate Private Key for Root CA

echo "openssl genpkey -algorithm EC ..."
openssl genpkey -algorithm EC   \
    -pkeyopt ec_paramgen_curve:P-521 \
    -out ca.cheese.key.pem
assert_success $?
echo

echo "openssl pkey -check ..."
$OPENSSL_BIN pkey -inform PEM -noout -in ca.cheese.key.pem -check
assert_success $?
echo


# Create a Request for Root CA

echo "openssl req ..."
$OPENSSL_BIN req -config openssl-root.cnf \
    -new \
    -x509 \
    -nodes \
    -sha384 \
    -extensions v3_ca \
    -key ca.cheese.key.pem \
    -out ca.cheese.crt.pem
assert_success $?
echo

# Validate the Request for Root CA
echo "openssl x509 ..."
$OPENSSL_BIN x509 -noout -text -in ca.cheese.crt.pem | grep 'Signature Algorithm:'
$OPENSSL_BIN x509 -noout -dates -in ca.cheese.crt.pem -dates -subject -issuer
$OPENSSL_BIN x509 -noout -text -in ca.cheese.crt.pem | grep 'Public-Key:'
$OPENSSL_BIN x509 -noout -text -in ca.cheese.crt.pem | grep 'NIST CURVE:'
assert_success $?
echo
