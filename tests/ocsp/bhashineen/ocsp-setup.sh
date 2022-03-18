#!/bin/bash
# Exercise OCSP setup
# Reference: https://bhashineen.medium.com/create-your-own-ocsp-server-ffb212df8e63

echo "OCSP Demonstrator, by bhashineed @ Medium"
echo
echo "There are three types of certificates:"
echo
echo "  Root CA"
echo "  OCSP Server"
echo "  The end-user wishing to determine if certs are good"
echo 

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}


mkdir -p demoCA/newcerts

# Force reset across the board with each run (its a demonstrator!)
cp /dev/null demoCA/index.txt
echo "0001" > demoCA/serial
echo /dev/null > index.txt

echo "Generate Root key ..."
openssl genrsa -out rootCA.key.pem 1024
assert_success $?
echo

echo "Sign the Root CA itself (using 'openssl req') ..."
openssl req -new -x509 \
    -config openssl-root.cnf \
    -key rootCA.key.pem \
    -out rootCA.crt.pem \
    -days 3650
assert_success $?
echo



# Create another private key to be used as the end user private key.
echo "Generate RSA public key for end-user ..."
openssl genrsa -out end_user.key.pem 1024
assert_success $?
echo

# Create a self-signed end user certificate based on the generated private key.

echo "Sign end_user.key for a end_user.crt.pem ..."
openssl req -new -x509 \
    -config validation.cnf \
    -key end_user.key.pem \
    -out end_user.crt.pem \
    -days 3650
assert_success $?
echo

# Reverse generate a certificate signing request(CSR) from end-user certificate.
echo "Reverse-generate CSR from end_user .crt/.key ..."
openssl x509 -x509toreq \
    -in end_user.crt.pem \
    -signkey end_user.key.pem \
    -out end_user.csr.pem
assert_success $?
echo

# Sign the client certificate, using above created CA and include CRL URLs and OCSP URLs in the certificate

# -infiles must be the last option
# -infiles makes it possible to batch sign many end-users' cert for revocation
echo "Sign the end-user certificate using reverse-generate CSR ..."
openssl ca -batch \
    -config validation.cnf \
    -policy policy_anything_OCSP \
    -keyfile rootCA.key.pem \
    -cert rootCA.crt.pem \
    -startdate 150813080000Z \
    -enddate 250813090000Z \
    -notext \
    -out end_user.crt.pem \
    -infiles end_user.csr.pem 
assert_success $?
echo

# Creating the OCSP server
#
# In order to host an OCSP server, an OCSP signing certificate has to be generated. Run following 2 commands.

echo "Creating a ocspSigning.csr.pem request ..."
# *.cnf determines distinguish_names
# '-config openssl-root.cnf' gives us 'Root CA' (not desirable)
openssl req -new \
    -nodes \
    -config validation.cnf \
    -out ocspSigning.csr.pem \
    -keyout ocspSigning.key.pem 
assert_success $?
#    -config validation.cnf \
echo

echo "Signing the ocspSigning.crt.pem with v3_OCSP extension ..."
openssl ca \
    -config validation.cnf \
    -extensions v3_OCSP \
    -in ocspSigning.csr.pem  \
    -keyfile rootCA.key.pem  \
    -cert rootCA.crt.pem  \
    -out ocspSigning.crt.pem 
assert_success $?
echo

echo "Exited prematurely."
exit
# Start OCSP Server. Switch to a new terminal and run,

echo "Starting OCSP responder @ localhost:8080"
openssl ocsp \
    -index demoCA/index.txt \
    -rkey ocspSigning.key.pem \
    -rsigner ocspSigning.crt.pem \
    -CA rootCA.crt.pem \
    -port 8080 \
    -text \
    -out log.txt &
assert_success $?
echo

# Verify Certificate Revocation. Switch to a new terminal and run

echo "verifying Certificate revocation via OCSP protocol @ localhost:8080 ..."
openssl ocsp \
    -cert end_user.crt.pem \
    -CAfile rootCA.crt.pem \
    -issuer rootCA.crt.pem \
    -noverify \
    -resp_text \
    -url http://127.0.0.1:8080 
assert_success $?
echo


# This will show that the certificate status is good.

# Revoke a certificate

# If you want to revoke the certificate run following command

echo "Revoking certificate ..."
openssl ca \
    -revoke end_user.crt.pem \
    -cert rootCA.crt.pem \
    -keyfile rootCA.key.pem \
assert_success $?
echo

# Then restart the OCSP server.

echo "Starting OCSP responder @ localhost:8080"
openssl ocsp \
    -rsigner ocspSigning.crt.pem \
    -index demoCA/index.txt \
    -rkey ocspSigning.key.pem \
    -CA rootCA.crt.pem \
    -text \
    -port 8080 \
    -out log.txt &
assert_success $?
echo

# Verify Certificate Revocation. Switch to a new terminal and run

echo "Verifying OCSP revocation via OCSP protocol @ localhost:8080 ..."
openssl ocsp \
    -CAfile rootCA.crt.pem \
    -issuer rootCA.crt.pem \
    -cert end_user.crt.pem \
    -url http://127.0.0.1:8080 \
    -resp_text \
    -noverify
assert_success $?
echo

# This will show that the certificate status as revoked.
