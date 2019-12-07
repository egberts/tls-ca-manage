#!/bin/bash
#
# Create One Root CA that can sign only three other intermediate CAs
#
# Suitable for medium to large enterprise
#

# Create Root CA
tls-ca-manage.sh --intermediate-node root

#  Create intermediates CA
tls-ca-manage.sh create -i --parent-ca root network

#  Create signing CAs
tls-ca-manage.sh create -p network component
tls-ca-manage.sh create -p network identity
tls-ca-manage.sh create -p network security
tls-ca-manage.sh create -p network other

#  Create signing CAs under Component intermediate CA
tls-csr-manage.sh create -p component -t digitalSignature,keyEncipherment,serverAuth,clientAuth tls-secured-portal  # TLS Server
tls-csr-manage.sh create -p component -t digitalSignature,OCSPSigning ocsp-responder
tls-csr-manage.sh create -p component -t digitalSignature,timeStamping time-server
tls-csr-manage.sh create -p component -t digitalSignature,clientAuth tls-secured-login # TLS Client
tls-csr-manage.sh create -p component \
    -t nonRepudiation,digitalSignature,keyEncipherment,keyAgreement,serverAuth \
    vpn-servers
tls-csr-manage.sh create -p component \
    -t nonRepudiation,digitalSignature,keyEncipherment,clientAuth \
    vpn-clients

#  Create signing CAs under Identity intermediate CA
tls-csr-manage.sh -p identity -t keyEncipherment,emailProtection user-mail-encryption
# https://blog.benjojo.co.uk/post/tls-https-server-from-a-yubikey
tls-csr-manage.sh -p identity -t digitalSignature,clientAuth secured-smartcardkeys

tls-csr-manage.sh -p identity -t digitalSignature,emailProtection,clientAuth user-mail-identity

#  Create signing CAs under Security intermediate CA
tls-csr-manage.sh -p security -t identity building-cardreaders
tls-csr-manage.sh -p security -t identity guardstations
tls-csr-manage.sh -p security -t identity control

