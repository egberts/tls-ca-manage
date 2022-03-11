#!/bin/bash -x 
#
# Create One Root CA that can sign only three other intermediate CAs
#
# Suitable for medium to large enterprise
#

OPTS="-v"

TLS_CA_MANAGE="../tls-ca-manage.sh"
TLS_CERT_MANAGE="../tls-cert-manage.sh"

check_errno()
{
  local retsts
  retsts=$?
  if [ $retsts -ne 0 ]; then
    echo "Error no. ${retsts}; aborted."
    exit $retsts
  fi
}

# Create Root CA
${TLS_CA_MANAGE} $OPTS create -t root AcmeRoot
check_errno

#  Create intermediates CA
${TLS_CA_MANAGE} $OPTS create -p AcmeRoot -t intermediate AcmeNetwork

#  Create signing CAs
${TLS_CA_MANAGE} $OPTS create -p AcmeNetwork -t intermediate AcmeComponent
check_errno
${TLS_CA_MANAGE} $OPTS create -p AcmeNetwork -t intermediate AcmeIdentity
check_errno
${TLS_CA_MANAGE} $OPTS create -p AcmeNetwork -t intermediate AcmeSecurity
check_errno
${TLS_CA_MANAGE} $OPTS create -p AcmeNetwork -t intermediate AcmeOther
check_errno

#  Create signing CAs under Component intermediate CA
${TLS_CERT_MANAGE} $OPTS create tls-secured-portals server AcmeComponent
check_errno
${TLS_CERT_MANAGE} $OPTS create AcmeOCSP ocsp AcmeComponent
check_errno
${TLS_CERT_MANAGE} $OPTS create AcmeTimeStamping timestamping AcmeComponent
check_errno
${TLS_CERT_MANAGE} $OPTS create tls-secured-login client AcmeComponent # TLS Client
check_errno
${TLS_CERT_MANAGE} $OPTS create vpn-servers server AcmeComponent
check_errno
${TLS_CERT_MANAGE} $OPTS create vpn-clients client AcmeComponent
check_errno

#  Create signing CAs under Identity intermediate CA
${TLS_CERT_MANAGE} $OPTS create user-mail-encryption email AcmeIdentity
check_errno

# https://blog.benjojo.co.uk/post/tls-https-server-from-a-yubikey
${TLS_CERT_MANAGE} $OPTS create secured-smartcardkeys smartcard AcmeIdentity
check_errno

${TLS_CERT_MANAGE} $OPTS create user-mail-identity identity AcmeIdentity
check_errno

#  Create signing CAs under Security intermediate CA
${TLS_CERT_MANAGE} $OPTS create building-cardreaders identity AcmeSecurity
check_errno
${TLS_CERT_MANAGE} $OPTS create guardstations identity AcmeSecurity
check_errno
${TLS_CERT_MANAGE} $OPTS create control identity AcmeSecurity
check_errno

