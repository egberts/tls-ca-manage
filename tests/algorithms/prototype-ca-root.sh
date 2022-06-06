#!/bin/bash
# Title: Algorithm studies, Root CA request/sign-with-ca/verify

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
# openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out ca.cheese.key.pem
echo "openssl ecparam ... | openssl ec ..."
$OPENSSL_BIN ecparam -genkey -name secp384r1 | openssl ec -out ca.cheese.key.pem
assert_success $?

# -algorithm : RSA, RSA-PSS, EC, X25519, X448, ED25519 and ED448.

# no key generation options defined for the X25519, X448, ED25519 or ED448 algorithms

$OPENSSL_BIN genpkey -algorithm ED25519 -out ca.cheese.key.pem
assert_success $?
$OPENSSL_BIN genpkey -algorithm X25519 -out ca.cheese.key.pem
assert_success $?
$OPENSSL_BIN genpkey -algorithm X448 -out ca.cheese.key.pem
assert_success $?
$OPENSSL_BIN genpkey -algorithm ED448 -out ca.cheese.key.pem
assert_success $?
$OPENSSL_BIN genpkey -algorithm RSA-PSS -out ca.cheese.key.pem
assert_success $?
$OPENSSL_BIN genpkey -algorithm RSA -out ca.cheese.key.pem
assert_success $?

# 'EC' algorithm seems not to work
$OPENSSL_BIN genpkey -algorithm EC  -pkeyopt ec_paramgen_curve:P-256 -out ca.cheese.key.pem
assert_success $?
$OPENSSL_BIN genpkey -algorithm EC  -pkeyopt ec_paramgen_curve:P-384 -out ca.cheese.key.pem
assert_success $?
$OPENSSL_BIN genpkey -algorithm EC  -pkeyopt ec_paramgen_curve:P-521 -out ca.cheese.key.pem
assert_success $?
$OPENSSL_BIN genpkey -out ca.cheese.key.pem \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-192 -pkeyopt ec_param_enc:named_curve 
assert_success $?
$OPENSSL_BIN genpkey -out ca.cheese.key.pem \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve 
assert_success $?
$OPENSSL_BIN genpkey -out ca.cheese.key.pem \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-384 -pkeyopt ec_param_enc:named_curve 
assert_success $?
$OPENSSL_BIN genpkey -out ca.cheese.key.pem \
  -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-521 -pkeyopt ec_param_enc:named_curve 
assert_success $?
echo


$OPENSSL_BIN genpkey -out ca.cheese.key.pem \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537
assert_success $?

$OPENSSL_BIN genpkey -out ca.cheese.key.pem \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 -pkeyopt rsa_keygen_pubexp:65537
assert_success $?

$OPENSSL_BIN genpkey -out ca.cheese.key.pem \
  -aes-256-cbc \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:4096 -pkeyopt rsa_keygen_pubexp:65537
assert_success $?

exit

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
