#!/bin/bash

echo -n "Enter in CA type: "
read -r CA_TYPE

case "$CA_TYPE" in
  standalone)
    OPENSSL_CA_OPTIONS="-selfsign"
    ;;
  root)
    CONF_REQ_PROMPT="no"
    CONF_REQ_DISTINGUISHED_NAME="ca_dn"
    CONF_REQ_EXTENSIONS="ca_reqext"
    CONF_
authorityKeyIdentifier  = keyid:always
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
    ;;
  intermediate)
encrypt_key             = yes                   # Protect private key
prompt                  = no                    # Don't prompt for DN
distinguished_name      = ca_dn                 # DN section
req_extensions          = ca_reqext             # Desired extensions
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:0
extendedKeyUsage        = emailProtection,clientAuth,anyExtendedKeyUsage
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always

    ;;
  server)
encrypt_key             = no                    # Protect private key
prompt                  = yes                   # Prompt for DN
distinguished_name      = server_dn             # DN template
req_extensions          = server_reqext         # Desired extensions
keyUsage                = critical,digitalSignature,keyEncipherment
basicConstraints        = CA:false
extendedKeyUsage        = serverAuth,clientAuth
subjectAltName          = $ENV::SAN


    ;;
  client)
keyUsage                = critical,digitalSignature
extendedKeyUsage        = clientAuth
    ;;
  timestamping)
    ;;
  ocsp)
    ;;
  email)
prompt                  = yes                   # Prompt for DN
distinguished_name      = email_dn              # DN template
req_extensions          = email_reqext          # Desired extensions
subjectAltName          = email:move
keyUsage                = critical,digitalSignature,keyEncipherment
extendedKeyUsage        = emailProtection,clientAuth
    ;;
  identity)
encrypt_key             = yes                   # Protect private key
prompt                  = no                    # Don't prompt for DN
distinguished_name      = ca_dn                 # DN section
req_extensions          = ca_reqext             # Desired extensions
keyUsage                = critical,digitalSignature,keyEncipherment
basicConstraints        = CA:false
    ;;
  codesign)
# NO EMAIL HERE
encrypt_key             = yes                   # Protect private key
keyUsage                = critical,digitalSignature
basicConstraints        = CA:false
extendedKeyUsage        = critical,codeSigning
    ;;
esac
