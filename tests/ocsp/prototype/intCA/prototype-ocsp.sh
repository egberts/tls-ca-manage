#!/bin/bash
# Title: OCSP signature request/sign-with-ca/verify
#
#  OCSP is a server-type PKI (via EKU:serverAuth)
#
#  Requires:
#    * Generate public key (elliptic curve)
#    * Create request certificate
#    * Create signed by CA certificate

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

# Generate Private Key for Intermediate CA
openssl ecparam -genkey -name secp384r1 | openssl ec -aes256 -out ocsp.cheese.key.pem
assert_success $?
echo

openssl req \
    -config ./openssl-ocsp-req.cnf \
    -extensions ocsp_req \
    -new \
    -newkey ec:<(openssl ecparam -name secp384r1) \
    -keyout ./ocsp.cheese.key.pem \
    -out ./ocsp.cheese.csr.pem
    # -reqexts ./openssl-intermediate-ocsp-req.cnf \
assert_success $?
echo


# Sign the CSR with our Intermediary Certificate Authority

openssl ca \
    -config ./openssl-intermediate-ocsp-ca.cnf \
    -extensions ocsp_ext \
    -days 365 \
    -notext \
    -md sha384 \
    -in ./ocsp.cheese.csr.pem \
    -out ./ocsp.cheese.crt.pem
assert_success $?
echo

# Display the certificate for OCSP server

openssl x509 -noout -text -in ./ocsp.cheese.crt.pem
assert_success $?
echo


# I haven't found ... what I am looking for ...
# ways to verify ... the OCSP some more ...
# I still haven't found ... what I am looking for ...
# 

# Assuming that ocsp.cheese.crt.pem is an ordinary server PKI
# adopt verification of servers but using a newly constructed chain file

# construct chain fail
cp intCA.cheese.crt.pem intCA.cheese.chain.crt.pem
cat ../ca.cheese.crt.pem >> intCA.cheese.chain.crt.pem

openssl verify -no-CApath -CAfile intCA.cheese.chain.crt.pem ocsp.cheese.crt.pem
assert_success $?
echo
echo "Done."

