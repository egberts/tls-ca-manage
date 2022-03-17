#!/bin/bash
# Title: CRL before OCSP request/sign-with-ca/verify
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

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

# For CRL, there is no new public key
# For CRL, there is no request
# For CRL, just create the server-type PKI cert

openssl ca -config ./openssl-intermediate.cnf \
    -gencrl \
    -out ./whomovedmycheese.crl
assert_success $?


# Verify the CRL
echo "Simple parser of CRL ..."
openssl crl -in ./whomovedmycheese.crl \
    -noout 
assert_success $?
echo

# Really verify the CRL against the CA
echo "Verify CRL against CA ..."
openssl crl -verify \
    -CAfile ./intCA.cheese.crt.pem \
    -noout \
    -in ./whomovedmycheese.crl
assert_success $?
echo


# Validate the Request for Root CA
openssl x509 -noout -text -in intCA.cheese.crt.pem | grep 'Signature Algorithm:'
openssl x509 -noout -dates -in intCA.cheese.crt.pem -dates -subject -issuer
openssl x509 -noout -text -in intCA.cheese.crt.pem | grep 'Public-Key:'
openssl x509 -noout -text -in intCA.cheese.crt.pem | grep 'NIST CURVE:'

