#!/bin/bash
#
# Create One Root CA that can sign only three other intermediate CAs
#
# Suitable for medium to large enterprise
#
TLS_CA_MANAGE="../tls-ca-manage.sh"
TLS_CERT_MANAGE="../tls-cert-manage.sh"

# Create Root CA
${TLS_CA_MANAGE} create -t root AcmeRoot

#  Create intermediates CA
${TLS_CA_MANAGE} create -p AcmeRoot -t intermediate AcmeNetwork

#  Create signing CAs
${TLS_CA_MANAGE} create -p AcmeNetwork -t intermediate AcmeComponent
${TLS_CA_MANAGE} create -p AcmeNetwork -t intermediate AcmeIdentity
${TLS_CA_MANAGE} create -p AcmeNetwork -t intermediate AcmeSecurity
${TLS_CA_MANAGE} create -p AcmeNetwork -t intermediate AcmeOther

#  Create signing CAs under Component intermediate CA
${TLS_CERT_MANAGE} create -p AcmeComponent -t server tls-secured-portals
${TLS_CERT_MANAGE} create -p AcmeComponent -t ocsp AcmeOCSP
${TLS_CERT_MANAGE} create -p AcmeComponent -t timestamping AcmeTimeStamping
${TLS_CERT_MANAGE} create -p AcmeComponent -t client tls-secured-login # TLS Client
${TLS_CERT_MANAGE} create -p AcmeComponent -t server vpn-servers
${TLS_CERT_MANAGE} create -p AcmeComponent -t client vpn-clients
    vpn-clients

#  Create signing CAs under Identity intermediate CA
${TLS_CERT_MANAGE} create -p AcmeIdentity -t email user-mail-encryption

# https://blog.benjojo.co.uk/post/tls-https-server-from-a-yubikey
${TLS_CERT_MANAGE} create -p AcmeIdentity -t smartcard secured-smartcardkeys

${TLS_CERT_MANAGE} create -p AcmeIdentity -t identity user-mail-identity

#  Create signing CAs under Security intermediate CA
${TLS_CERT_MANAGE} create -p AcmeSecurity -t identity building-cardreaders
${TLS_CERT_MANAGE} create -p AcmeSecurity -t identity guardstations
${TLS_CERT_MANAGE} create -p AcmeSecurity -t identity control

