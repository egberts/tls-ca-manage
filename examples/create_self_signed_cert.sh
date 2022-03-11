#!/bin/bash
#
# Create a self-signed certificate
#
TLS_CA_MANAGE="../tls-ca-manage.sh"
TLS_CERT_MANAGE="../tls-cert-manage.sh"
#
${TLS_CA_MANAGE} create acme
${TLS_CA_MANAGE} verify acme
#
#
#  Create a self-signed using 521-bit ECDSA
${TLS_CA_MANAGE} create -a ecdsa -k 521 secured-acme
${TLS_CA_MANAGE} verify server secured-acme
