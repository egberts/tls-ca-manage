#!/bin/bash

# Sample server cert creation

echo "This is not ready yet..."
exit 123

# Hard coded for 'centralized' OFSTD_LAYOUT
#
# TODO:
#  - Transfer lots of parameter arguments from tls-ca-manage.sh
#  - Make it flexible

SSL_DIR="/etc/ssl"
SERVER_OPENSSL_CNF="$SSL_DIR/etc/server.cnf"
IA_NAME="$1"
DNS_NAMES="$2"
PARENT_IA_NAME="$3"

IA_KEY_PEM="$SSL_DIR/private/ca-$IA_NAME.key"
IA_CSR_PEM="$SSL_DIR/certs/ca-$IA_NAME.csr"
IA_CERT_PEM="$SSL_DIR/certs/$IA_NAME.crt"
PARENT_IA_OPENSSL_CNF="$SSL_DIR/etc/$PARENT_IA_NAME-ca.cnf"

if [[ ! -z "$SERVER_OPENSSL_CNF" ]]; then
    if [[ ! -f "$SERVER_OPENSSL_CNF" ]]; then
        echo """
# TLS server certificate request

[ default ]
SAN                     = DNS:example.invalid   # Default value

[ req ]
default_bits            = 4096                  # RSA key size
encrypt_key             = no                    # Protect private key
default_md              = sha256                # MD to use
utf8                    = yes                   # Input is UTF-8
string_mask             = utf8only              # Emit UTF-8 strings
prompt                  = yes                   # Prompt for DN
distinguished_name      = server_dn             # DN template
req_extensions          = server_reqext         # Desired extensions

[ server_dn ]
countryName             = "1. Country Name \(2 letters\) \(eg, US\)       "
countryName_max         = 2
stateOrProvinceName     = "2. State or Province Name   \(eg, region\)   "
localityName            = "3. Locality Name            \(eg, city\)     "
organizationName        = "4. Organization Name        \(eg, company\)  "
organizationalUnitName  = "5. Organizational Unit Name \(eg, section\)  "
commonName              = "6. Common Name              \(eg, FQDN\)     "
commonName_max          = 64

[ server_reqext ]
keyUsage                = critical,digitalSignature,keyEncipherment
extendedKeyUsage        = serverAuth,clientAuth
subjectKeyIdentifier    = hash
subjectAltName          = \$ENV::SAN

# TBA/TODO:
# certificatePolicies=
# Not Critical
# 1.3.6.1.4.1.6449.1.2.2.7:
#   Certification Practice Statement pointer:
#     https://secure.example.invalid/CPS
#
# authorityInfomationAccess=
# CA Issuers: URI: http://<name>.crt
# OCSP: URI: http://ocsp.example.invalid
# 2.23.140.1.2.1

""" > "$SERVER_OPENSSL_CNF"
    fi
fi

cd "$SSL_DIR"

SAN=DNS:www.example.invalid,DNS:example.invalid \
openssl req -new \
    -config "$SERVER_OPENSSL_CNF" \
    -out "$IA_CSR_PEM" \
    -keyout "$IA_KEY_PEM"

openssl ca \
    -config "$PARENT_IA_OPENSSL_CNF" \
    -in "$IA_CSR_PEM" \
    -out "$IA_CERT_PEM" \
    -extensions server_ext


echo "IA_KEY_PEM: $IA_KEY_PEM"
echo "IA_CSR_PEM: $IA_CSR_PEM"
echo "IA_CERT_PEM: $IA_CERT_PEM"
echo "IA_CHAIN_PEM: $IA_CHAIN_PEM"
echo "PARENT_IA_CHAIN_PEM: $PARENT_IA_CHAIN_PEM"
