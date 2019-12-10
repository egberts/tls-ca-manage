#!/bin/bash

function create_node_centric_config {
    OPENSSL_CNF_FNAME=$1
    echo """
# OpenSSL Configuration File
#
# Created by $0 utility
# Created on $CURRENT_TIMESTAMP
# Command: $0 $1 $2 $3 $4 $5 $6 $7 $8 $9

# The [default] section contains global constants that can be referred to from
# the entire configuration file. It may also hold settings pertaining to more
# than one openssl command.

# [default] is something that is always run.
# Used to be a label-less first section (no [default])
[ default ]
ca                      = root-ca               # CA name
dir                     = .                     # Top dir


# 'openssl req' command section
# It defines the CA's key pair, its DN, and the desired extensions for the CA
# certificate.
[ req ]
default_md              = sha256                # message digest to use
# OpenSSL '-extension' option == x509_extensions
# x509_extensions = section_ca_req_x509v3_extensions # <custom_section_name>
# input_password = <string>
# output_password = <string>
string_mask             = utf8only              # Emit UTF-8 strings
utf8                    = yes                   # Input is UTF-8
# OpenSSL '-reqexts' option == req_extensions
req_extensions          = $CNF_SECTION_REQ_EXT   # Desired extensions
default_bits            = 2048                  # RSA key size
# encrypt_rsa_key = no
encrypt_key             = yes                   # Protect private key
prompt                  = $CNF_REQ_PROMPT        # Don't prompt for DN
distinguished_name      = $CNF_SECTION_DN
attributes              = section_req_attributes

[ $CNF_SECTION_DN ]
0.domainComponent       = "org"
1.domainComponent       = "simple"
organizationName        = "Simple Inc"
organizationalUnitName  = "Simple Root CA"
commonName              = "Simple Root CA"

[ $CNF_SECTION_REQ_EXT ]
# These X509v3 items must match the requestor's X509v3 during 'openssl ca'
keyUsage                = $CNF_REQ_EXT_KU
basicConstraints        = $CNF_REQ_EXT_BC
subjectKeyIdentifier    = $CNF_REQ_EXT_SKI
extendedKeyUsage        = $CNF_REQ_EXT_EKU
authorityKeyIdentifer   = $CNF_REQ_EXT_AKI

# The remainder of the configuration file is used by the openssl ca command.
# The CA section defines the locations of CA assets, as well as the policies
# applying to the CA.

# 'openssl ca' command section
[ ca ]
default_ca              = section_ca_root_default       # <custom-section-name>

# Root CA default section
[ section_ca_root_default ]
# oid_file = <filespec>
# string_mask = <'utf8only'|string>
# utf8 = <'yes'|'no'>
unique_subject          = no                    # Require unique subject
database                = $dir/ca/$ca/db/$ca.db # Index file
private_key             = $dir/ca/$ca/private/$ca.key # CA private key
certificate             = $dir/ca/$ca.crt       # The CA cert
preserve                = no                    # Keep passed DN ordering
# msie_hack             = <'yes'|'no'>
name_opt                = ca_default            # Subject DN display options
cert_opt                = ca_default            # Certificate display options
copy_extensions         = none                  # Copy extensions from CSR
new_certs_dir           = $dir/ca/$ca           # Certificate archive
default_md              = sha1                  # MD to use
# default_email         =
policy                  = section_policy_match  # Default naming policy
# rand_serial           = <anychar>
serial                  = $dir/ca/$ca/db/$ca.crt.srl # Serial number file
# OpenSSL '-extension' option == x509_extensions
# OpenSSL '-extfile' option == x509_extensions
x509_extensions         = signing_ca_ext        # Default cert extensions
# default_startdate     = <'today'|[YY]YYMMDDHHMMSSZ>
# default_enddate       = <YYMMDDHHMMSSZ|YYYYMMDDHHMMSSZ>
default_days            = 3652                  # How long to certify for
crl                     = $dir/ca/crl/$ca.crl
# OpenSSL '-crlexts' option == crl_extensions
crl_extensions          = section_root_ca_crl_ext       # section CRL extensions
crlnumber               = $dir/ca/$ca/db/$ca.crl.srl # CRL number file
default_crl_days        = 365                   # How long before next CRL
default_crl_hours       = 0                     # How long before next CRL
email_in_dn             = no                    # Add email to cert DN
# default_email_in_dn   = <'no'|email-address>

# section_req_attributes is a required section
# CA Notes: PKIX●Important Notes–If you request the extension
#     in x509_extensions, but don't set a value in
#     'req_extensions', SAN will be blank (not in Subject
#     to be copied from).  No value, no section.
# [ section_req_attributes ]
# We don't want these, but the section must exist
#challengePassword              = A challenge password
#challengePassword_min          = 4
#challengePassword_max          = 20
#unstructuredName               = An optional company name

# Naming policies control which parts of a DN end up in the certificate and
# under what circumstances certification should be denied.

[ section_policy_best_match ]
domainComponent         = match                 # Must match 'simple.org'
organizationName        = match                 # Must match 'Simple Inc'
organizationalUnitName  = optional              # Included if present
commonName              = supplied              # Must be present

[ section_policy_any_match ]
domainComponent         = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

# CRL extensions exist solely to point to the CA certificate that has issued
# the CRL.
[ section_root_ca_crl_ext ]
authorityKeyIdentifier  = keyid:always
""" > ./openssl.cnf
}

# Usage: create_internode_config <section_name> \
#                                <internode_filespec> \
#                                <parent_node_filespec>
#                                <end_node_distance>
function create_internode_config
{
    SECTION_NAME=$1
    INTERNODE_CONFIG_FILESPEC=$2
    PARENT_CONFIG_FILESPEC=$3
    END_NODE_DISTANCE=$4
    if [[ $END_NODE_DISTANCE -ge 0 ]]; then
        PATHLEN_OPTION=",pathlen:$END_NODE_DISTANCE"
    else
        PATHLEN_OPTION=""
    fi
    CURRENT_TIMESTAMP=`date`
    echo """#
# File: $INTERNODE_CONFIG_FILESPEC
#
# Created: $CURRENT_TIMESTAMP
# Used with: $PARENT_CONFIG_FILESPEC
#
# X509v3 extensions
#
#   openssl ca -config $PARENT_CONFIG_FILESPEC \
#       -extfile $INTERNODE_CONFIG_FILESPEC \
#       ...
#
# Used to add x509v3 extension to a CA that is not a signing CA.
# It may be a top-level root CA or an intermediate CA.
# And not a self-signed test certificate.
#
# OpenSSL '-extfile' option == x509_extensions
# activated via 'openssl ca ... -extfile ./root_ca_extensions.cnf ...'
# or activated via '[ ca ]; x509_extension=root_ca_ext'
#
[ $SECTION_NAME ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true$PATHLEN_OPTION
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
crlDistributionPoint    = "URI:http://example.invalid/crl/ca.crl"
""" > "$INTERNODE_CONFIG_FILESPEC"
    unset SECTION_NAME
    unset PARENT_CONFIG_FILESPEC
    unset INTERNODE_CONFIG_FILESPEC
    unset END_NODE_DISTANCE
    unset PATHLEN_OPTION
    unset TIMESTAMP
}

echo -n "Enter in CA type: "
read -r CA_TYPE

case "$CA_TYPE" in
  standalone)
    # openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
    #   -keyout example.key -out example.crt -subj /CN=example.com \
    #   -addext subjectAltName=DNS:example.com,DNS:example.net,IP:10.0.0.1
    OPENSSL_CA_OPTIONS="-selfsign"
    CNF_REQ_PROMPT="yes"
    CNF_SECTION_DN="section_test_ca_req_dn"
    CNF_SECTION_REQ_EXT="section_test_ca_req_extensions"
    CNF_REQ_ENCRYPT_KEY="no"  # controls OpenSSL '-nodes' option
    CNF_REQ_EXT_SKI=""  # subjectKeyIdentifier
    CA_CERT_SAN=""  # subjectAltName, might need additional prompt here
    # CA_CERT_SAN="DNS:example.com,DNS:example.net,IP:10.0.0.1"
    # CNF_REQ_* pertains to main node's config file
    CNF_REQ_EXT_AKI=""  # authorityKeyIdentifier
    CNF_REQ_EXT_BC=""
    CNF_REQ_EXT_KU=""  # do not use for test self-signed
    CNF_REQ_EXT_EKU=""
    # CNF_CA_* pertains to inter-node's config file
    CNF_CA_EXT_KU=""  # keyUsage
    CNF_CA_EXT_BC="CA:false"  # basicConstraint
    CNF_CA_EXT_SKI="" # subjectKeyIdentifier
    CNF_CA_EXT_AKI=""  # authorityKeyIdentifier
    CNF_CA_EXT_EKU=""  # extendedKeyUsage
    ;;
  root)
    CNF_REQ_PROMPT="no"
    CNF_SECTION_DN="section_root_ca_req_dn"
    CNF_SECTION_REQ_EXT="section_root_ca_req_x509v3_extensions"
    #### CNF_REQ_ENCRYPT_KEY="yes"  # Need to confirm
    CA_CERT_SAN=
    CNF_REQ_EXT_KU="critical,keyCertSign,cRLSign"  # keyUsage
    CNF_REQ_EXT_BC="critical,CA:true"  # basicConstraint
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    CNF_REQ_EXT_AKI=""  # authorityKeyIdentifier
    CNF_REQ_EXT_EKU=""  # extendedKeyUsage
    CNF_CA_EXT_KU="critical,keyCertSign,cRLSign"  # keyUsage
    CNF_CA_EXT_BC="critical,CA:true"  # basicConstraint
    CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
    CNF_CA_EXT_AKI="keyid:always"  # authorityKeyIdentifier
    CNF_CA_EXT_EKU=""  # extendedKeyUsage
    ;;
  intermediate)
    CNF_REQ_PROMPT="no"
    CNF_SECTION_DN="section_intermediate_ca_req_dn"
    CNF_SECTION_REQ_EXT="section_intermediate_ca_req_x509v3_extensions"
    CNF_REQ_ENCRYPT_KEY="yes"
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    CA_CERT_SAN=
    CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
    CNF_REQ_EXT_BC="critical,CA:true,pathlen:0"
    CNF_REQ_EXT_KU="critical,keyCertSign,cRLSign"
    CNF_REQ_EXT_EKU="emailProtection,clientAuth,anyExtendedKeyUsage"
    create_node_centric_config root_ca
    create_end_node_ca  intermediate_ca_ext
    ;;
  server)
    CNF_REQ_PROMPT="yes"
    CNF_SECTION_DN="server_dn"
    CNF_SECTION_REQ_EXT="server_reqext"
    CNF_REQ_ENCRYPT_KEY="no"
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    CA_CERT_SAN="\$ENV::SAN"  # subjectAltName
    CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
    CNF_REQ_EXT_BC="CA:false"
    CNF_REQ_EXT_KU="critical,digitalSignature,keyEncipherment"
    CNF_REQ_EXT_EKU="serverAuth,clientAuth"
    ;;
# Not verified
  client)
    CNF_REQ_PROMPT="yes"
    CNF_SECTION_DN="client_dn"
    CNF_SECTION_REQ_EXT="client_reqext"
    CNF_REQ_ENCRYPT_KEY="no"
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    CA_CERT_SAN="\$ENV::SAN"  # subjectAltName
    CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
    CNF_REQ_EXT_BC="CA:false"
    CNF_REQ_EXT_KU="critical,digitalSignature"
    CNF_REQ_EXT_EKU="clientAuth"
    ;;
  software)
    CNF_REQ_PROMPT="no"
    CNF_SECTION_DN="ca_dn"
    CNF_SECTION_REQ_EXT="ca_reqext"
    CNF_REQ_ENCRYPT_KEY="no"
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    CA_CERT_SAN=""  # subjectAltName
    CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
    CNF_REQ_EXT_BC="CA:false"
    CNF_REQ_EXT_KU="critical,digitalSignature"
    CNF_REQ_EXT_EKU="clientAuth"
    ;;
  timestamping)
    ;;
  tls)
    CNF_REQ_PROMPT="no"
    CNF_SECTION_DN="ca_dn"
    CNF_SECTION_REQ_EXT="ca_reqext"
    CNF_REQ_ENCRYPT_KEY="yes"
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    CA_CERT_SAN=""  # subjectAltName
    CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
    CNF_REQ_EXT_BC="critical,CA:true,pathlen:0"  # basicConstraint
    CNF_REQ_EXT_KU="critical,keyCertSign,cRLSign"
    CNF_REQ_EXT_EKU="emailProtection,clientAuth"
    ;;
  ocsp)
    ;;
  email)
    CNF_REQ_PROMPT="no"
    CNF_SECTION_DN="section_email_ca_req_dn"
    CNF_SECTION_REQ_EXT="section_email_ca_req_x509v3_extensions"
    CNF_REQ_ENCRYPT_KEY="yes"
    CA_CERT_SAN=""  # subjectAltName
    CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
    CNF_REQ_EXT_BC="CA:false"  # basicConstraint
    CNF_REQ_EXT_KU="critical,digitalSignature,keyEncipherment"
    CNF_REQ_EXT_EKU="emailProtection,clientAuth"
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    ;;
  encryption)
    # Probably need to move this to tls-cert-manage
    CNF_REQ_PROMPT="yes"
    CNF_SECTION_DN="encryption_dn"
    CNF_SECTION_REQ_EXT="encryption_reqext"
    CNF_REQ_ENCRYPT_KEY="yes"
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    CA_CERT_SAN="email:move"  # subjectAltName
    CNF_REQ_EXT_AKI=""  # authorityKeyIdentifier
    CNF_REQ_EXT_BC=""  # basicConstraint
    CNF_REQ_EXT_KU="critical,digitalSignature,keyEncipherment"
    CNF_REQ_EXT_EKU="emailProtection,clientAuth"
    ;;
  identity)  # there's identity-ca and identity, this here is identity-ca
    CNF_REQ_PROMPT="no"
    CNF_SECTION_DN="ca_dn"
    CNF_SECTION_REQ_EXT="ca_reqext"
    CNF_REQ_ENCRYPT_KEY="yes"
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    CA_CERT_SAN="email:move"  # subjectAltName
    CNF_REQ_EXT_AKI=""  # authorityKeyIdentifier
    CNF_REQ_EXT_BC="CA:false"  # basicConstraint
    CNF_REQ_EXT_KU="critical,digitalSignature,keyEncipherment"
    CNF_REQ_EXT_EKU="emailProtection,clientAuth"
encrypt_key             = yes                   # Protect private key
prompt                  = no                    # Don't prompt for DN
distinguished_name      = ca_dn                 # DN section
req_extensions          = ca_reqext             # Desired extensions
keyUsage                = critical,digitalSignature,keyEncipherment
basicConstraints        = CA:false
    ;;
  codesign)
    CNF_REQ_PROMPT="yes"
    CNF_SECTION_DN="codesign_dn"
    CNF_SECTION_REQ_EXT="codesign_reqext"
    CNF_REQ_ENCRYPT_KEY="yes"
    # NO EMAIL HERE
    CA_CERT_SAN=""  # subjectAltName
    CNF_REQ_EXT_AKI=""  # authorityKeyIdentifier
    CNF_REQ_EXT_BC="CA:false"  # basicConstraint
    CNF_REQ_EXT_KU="critical,digitalSignature"
    CNF_REQ_EXT_EKU="critical,codeSigning"
    CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
    ;;
  *)
    echo "Invalid '$CA_TYPE' option"
    ;;
esac

CURRENT_TIMESTAMP="`date`"
create_node_centric_config ./openssl.cnf
