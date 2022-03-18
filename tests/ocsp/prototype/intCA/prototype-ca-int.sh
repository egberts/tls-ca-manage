#!/bin/bash
# Title: Intermediate CA request/sign-with-ca/verify
#
echo "Create Intermediate CA (request/sign-with-root/verify)"
echo

OPENSSL_BIN="env OPENSSL_CONF=/dev/null openssl"

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

# See prototype-ca-int-reset.sh
# cp /dev/null index.txt
# echo 1000 > serial
# echo 1000 > crlnumber

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

echo "openssl pkey -check ..."
$OPENSSL_BIN pkey -inform PEM -noout -in intCA.cheese.key.pem -check
assert_success $?
echo

# need to make commonName unique:
#   leverage rootCA serial and append to intCA commonName
commonName="Intermediate CA S/N $(cat ../serial)"
echo "commonName: $commonName"

# Create a Request Intermediate Root CA
commonName="Intermediate CA"
printf "%s\n\n[intermediate_ca_req_distinguished_name_no_prompt]\ncommonName=$commonName s/n %s\n" \
    "$(cat openssl-intermediate.cnf)" "$(cat ../serial)" \
    > /tmp/x
echo "Using commonName=\"$commonName\""

echo "openssl req ..."
$OPENSSL_BIN req \
    -config /tmp/x \
    -new \
    -nodes \
    -newkey ec:<(openssl ecparam -name secp384r1) \
    -keyout intCA.cheese.key.pem \
    -out intCA.cheese.csr.pem
assert_success $?
echo

echo "openssl req -verify ..."
openssl req -verify -inform PEM -noout -in intCA.cheese.csr.pem 
assert_success $?
echo


# Sign the CSR with our Intermediary Certificate Authority
echo "Going up to Root CA directory"
cd ..    # go into Root CA $dir

echo "Signing this intCA with rootCA certs ..."
$OPENSSL_BIN ca -config ./openssl-root.cnf \
    -extensions v3_intermediate_ca \
    -days 3600 \
    -md sha384 \
    -in intCA/intCA.cheese.csr.pem \
    -out intCA/intCA.cheese.crt.pem
assert_success $?

# go back down
cd intCA

echo "openssl ca -verify ..."
# Not quite there yet....
# $OPENSSL_BIN req -verify -inform PEM -noout -in intCA.cheese.crt.pem 
# assert_success $?
echo

# Verify the certificate's usage is set for OCSP

echo "openssl x509 ..."
$OPENSSL_BIN x509 -noout -text -in intCA.cheese.crt.pem
assert_success $?

# Validate the Request for Root CA
$OPENSSL_BIN x509 -noout -text -in intCA.cheese.crt.pem | grep 'Signature Algorithm:'
$OPENSSL_BIN x509 -noout -dates -in intCA.cheese.crt.pem -dates -subject -issuer
$OPENSSL_BIN x509 -noout -text -in intCA.cheese.crt.pem | grep 'Public-Key:'
$OPENSSL_BIN x509 -noout -text -in intCA.cheese.crt.pem | grep 'NIST CURVE:'
echo
echo "Done."
