#!/bin/bash
# Title: CRL before OCSP sign-with-ca/verify
#
# The thing about the data entry here is that
# commonName must be MANDATORY at data entry time.
#
# Once commonName is entered, all is well.
#
# Also, OCSP server PKI cert is dependent on CRL
# and may be so for sometime.
#
# Prevailing wind is telling me that OCSP is 
# going away in favor of CRL and Google's proprietary
# "newCerts?"
#
# So, we have a working prototype here.

echo "Create CRL PKI certificate (sign-with-intermediate-ca/verify)"
echo

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

# For CRL, there is no new public key
# For CRL, there is no request
# For CRL, just create the server-type PKI cert
# For CRL, it is all about the preexisting intCA key/crt

# strace -f 
# openat(AT_FDCWD, "/usr/lib/ssl/openssl.cnf", O_RDONLY) = 3
# write(2, "Using configuration from ./opens"..., 61Using configuration from ./openssl-intermediateCA-ca-crl.cnf
# openat(AT_FDCWD, "./openssl-intermediateCA-ca-crl.cnf", O_RDONLY) = 3
# openat(AT_FDCWD, "./intCA.cheese.key.pem", O_RDONLY) = 3
# openat(AT_FDCWD, "./intCA.cheese.crt.pem", O_RDONLY) = 3
# openat(AT_FDCWD, "./index.txt", O_RDONLY) = 3
# openat(AT_FDCWD, "./index.txt.attr", O_RDONLY) = 4
# openat(AT_FDCWD, "./crlnumber", O_RDONLY) = 3
# openat(AT_FDCWD, "/etc/localtime", O_RDONLY|O_CLOEXEC) = 3
# openat(AT_FDCWD, "./crlnumber.new", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3
# openat(AT_FDCWD, "./whomovedmycheese.crl.pem", O_WRONLY|O_CREAT|O_TRUNC,


echo "openssl ca ..."
openssl ca -config ./openssl-intermediateCA-ca-crl.cnf \
    -gencrl \
    -out ./whomovedmycheese.crl.pem
assert_success $?


# Verify the CRL
echo "Simple parser of CRL ..."
openssl crl -in ./whomovedmycheese.crl.pem \
    -noout 
assert_success $?
echo

# Really verify the CRL against the CA
# Surprisenly, no chaining here.
echo "Verify CRL against CA (PEM-format)..."
openssl crl -verify \
    -CAfile ./intCA.cheese.crt.pem \
    -noout \
    -in ./whomovedmycheese.crl.pem
assert_success $?
echo

# Convert PEM to DER
echo "Making a DER format out of this CRL PEM ..."
openssl crl \
    -in ./whomovedmycheese.crl.pem \
    -out ./whomovedmycheese.crl.der \
    -outform DER
assert_success $?
echo

echo "Verify CRL against CA (DER-format)..."
openssl crl -verify \
    -CAfile ./intCA.cheese.crt.pem \
    -noout \
    -text \
    -in ./whomovedmycheese.crl.pem
assert_success $?
echo


echo "Done."
