#!/bin/bash
# Title: OCSP signature request/sign-with-ca/verify
#
#  OCSP is a server-type PKI (via EKU:serverAuth)
#
#  Requires:
#    * Generate public key (elliptic curve)
#    * Create request certificate
#    * Create signed by CA certificate

echo "Create TLS server authentication PKI certificate for OCSP server"
echo

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

# to turn off password:
#   remove -aes256 from 'openssl ec'
#   add -nodes to 'openssl req'


# Generate Private Key for Intermediate CA
echo "openssl genpkey -algorithm EC ..."
openssl genpkey -algorithm EC   \
    -pkeyopt ec_paramgen_curve:P-521 \
    -out ocsp.cheese.key.pem
assert_success $?
echo

# commonName="OCSP Responder"
# printf "%s\n\n[ocsp_req_distinguished_name_no_prompt]\ncommonName=$commonName s/n %s\n" \
#     "$(cat openssl-ocsp-req.cnf)" "$(cat serial)" \
#     > /tmp/x
# echo "Using commonName=\"$commonName\""



echo "openssl req ..."
openssl req \
    -config openssl-ocsp-req.cnf \
    -extensions ocsp_req \
    -sha384 \
    -nodes \
    -new \
    -key ./ocsp.cheese.key.pem \
    -out ./ocsp.cheese.csr.pem
    # -reqexts ./openssl-intermediate-ocsp-req.cnf \
assert_success $?
echo

echo "openssl x509 ..."
openssl req -noout -text -in ./ocsp.cheese.csr.pem
assert_success $?
echo


# Sign the CSR with our Intermediary Certificate Authority

echo "openssl ca ..."
echo "================================================================"
echo "If you got 'ERROR:There is already a certificate' error, you are"
echo "attempting to overwrite an existing cert."
echo "================================================================"
echo "Until we write a 'prototype-ca-int-renewal.sh', just execute:"
echo
echo "   prototype-ca-int-reset.sh"
echo
echo "And repeat this $0 command."
#    -extensions ocsp_ext \
openssl ca \
    -config ./openssl-intermediateCA-ca-ocsp.cnf \
    -extensions v3_OCSP \
    -days 365 \
    -notext \
    -md sha512 \
    -in ./ocsp.cheese.csr.pem \
    -out ./ocsp.cheese.crt.pem
assert_success $?
echo

# Display the certificate for OCSP server

echo "openssl x509 ..."
openssl x509 -noout -in ./ocsp.cheese.crt.pem
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

echo "openssl verify ..."
openssl verify -no-CApath -CAfile intCA.cheese.chain.crt.pem ocsp.cheese.crt.pem
assert_success $?
echo
echo "Done."

