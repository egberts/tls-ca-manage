#!/bin/bash -x 
#
# Create One Root CA that can sign only three other intermediate CAs
#
# Suitable for medium to large enterprise
#

assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Failed: errno $1; aborted."
    exit $1
  fi
}


OPTS="-v"

TLS_CA_MANAGE="../tls-ca-manage.sh"
TLS_CERT_MANAGE="../tls-cert-manage.sh"

# Create Root CA
echo "Creating AcmeRoot CA certificate ..."
${TLS_CA_MANAGE} $OPTS create -t root AcmeRoot
assert_success $?

#  Create intermediates CA
echo "Creating AcmeNetwork intermediate CA certificate (AcmeRoot CA)..."
${TLS_CA_MANAGE} $OPTS create -p AcmeRoot -t intermediate AcmeNetwork
assert_success $?

#  Create signing CAs
echo "Creating AcmeComponent intermediate CA certificate (AcmeNetwork intCA) ..."
${TLS_CA_MANAGE} $OPTS create -p AcmeNetwork -t intermediate AcmeComponent
assert_success $?

echo "Creating AcmeIdentity intermediate CA certificate (AcmeNetwork intCA) ..."
${TLS_CA_MANAGE} $OPTS create -p AcmeNetwork -t intermediate AcmeIdentity
assert_success $?

echo "Creating AcmeSecurity intermediate CA certificate (AcmeNetwork intCA) ..."
${TLS_CA_MANAGE} $OPTS create -p AcmeNetwork -t intermediate AcmeSecurity
assert_success $?

echo "Creating AcmeOther intermediate CA certificate (AcmeNetwork intCA) ..."
${TLS_CA_MANAGE} $OPTS create -p AcmeNetwork -t intermediate AcmeOther
assert_success $?


#  Create signing CAs under Component intermediate CA
echo "Creating tls-secured-portals server certificate (AcmeComponent intCA) ..."
${TLS_CERT_MANAGE} $OPTS create tls-secured-portals server AcmeComponent
assert_success $?

# TBD
# echo "Creating AcmeOCSP ocsp certificate (AcmeComponent intCA) ..."
# ${TLS_CERT_MANAGE} $OPTS create AcmeOCSP ocsp AcmeComponent
# assert_success $?

# TBD
# echo "Creating AcmeTimeStamping timestamping certificate (AcmeComponent intCA) ..."
# ${TLS_CERT_MANAGE} $OPTS create AcmeTimeStamping timestamping AcmeComponent
# assert_success $?

# TBD
# echo "Creating tls-secured-login client certificate (AcmeComponent intCA) ..."
# ${TLS_CERT_MANAGE} $OPTS create tls-secured-login client AcmeComponent # TLS Client
# assert_success $?

echo "Creating vpn-servers server certificate (AcmeComponent intCA) ..."
${TLS_CERT_MANAGE} $OPTS create vpn-servers server AcmeComponent
assert_success $?

# echo "Creating vpn-servers client certificate (AcmeComponent intCA) ..."
# ${TLS_CERT_MANAGE} $OPTS create vpn-clients client AcmeComponent
# assert_success $?


#  Create signing CAs under Identity intermediate CA
echo "Creating user-mail-encryption email certificate (AcmeIdentity intCA) ..."
${TLS_CERT_MANAGE} $OPTS create user-mail-encryption email AcmeIdentity
assert_success $?


# TBD
# https://blog.benjojo.co.uk/post/tls-https-server-from-a-yubikey
# echo "Creating secured-smartcardkeys smartcard certificate (AcmeIdentity intCA) ..."
# ${TLS_CERT_MANAGE} $OPTS create secured-smartcardkeys smartcard AcmeIdentity
# assert_success $?


# TBD
# echo "Creating user-mail-identity identity certificate (AcmeSecurity intCA) ..."
# TBD
# ${TLS_CERT_MANAGE} $OPTS create user-mail-identity identity AcmeIdentity
# TBD
# assert_success $?


#  Create signing CAs under Security intermediate CA
# TBD
# echo "Creating building-cardreaders identity certificate (AcmeSecurity intCA) ..."
# TBD
# ${TLS_CERT_MANAGE} $OPTS create building-cardreaders identity AcmeSecurity
# TBD
# assert_success $?

# TBD
# echo "Creating guardstations identity certificate (AcmeSecurity intCA) ..."
# TBD
# ${TLS_CERT_MANAGE} $OPTS create guardstations identity AcmeSecurity
# TBD
# assert_success $?

# TBD
# echo "Creating control identity certificate (AcmeSecurity intCA) ..."
# TBD
# ${TLS_CERT_MANAGE} $OPTS create control identity AcmeSecurity
# TBD
# assert_success $?


