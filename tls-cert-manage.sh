#!/bin/bash
#
# NAME
#     tls-cert-manage.sh - Manage Root and Intermediate Certificate Authorities
#
# SYNOPSIS
#     tls-cert-manage.sh create <CERT-NAME> <CERT-TYPE> <CA-NAME>
#     tls-cert-manage.sh verify <CERT-NAME>
#     tls-cert-manage.sh renew <CERT-NAME> <CA-NAME>
#     tls-cert-manage.sh revoke <CERT-NAME> <CA-NAME> [REASON]
#
# DESCRIPTION
#    A front-end tool to OpenSSL that enables creation, renewal,
#    revocation, and verification of PKI certificates.
#
#    CERT-NAME
#        Specifies the certificate name.  Often Common Name such as
#        DNS, IP or email are used as this certificate name.
#        Must be a valid filename specification (file-system dependent).
#
#    CERT-TYPE
#        Mandatory option which specifies a type of certificate:
#
#          server       - TLS server: Web server, MTA, VPN, IMAP, POP3, 802.1ar
#          client       - TLS client:
#          ocsp         - OCSP
#          email        - Encryption part of SMTP body
#          identity     - Signing CA for Microsoft SmartCard identity
#          encryption   - Microsoft Encrypted File System (msEFS)
#          codesign     - Signed executable code
#          timestamping - ANSI X9.95 TimeStamping (RFC3161)
#
#        This argument is used only with 'create' command line option
#
#    CA-NAME 
#        Specifies the simple name of CA in which to sign this 
#        certificate against with. It may be the Root CA name
#        or the Intermediate CA name.  The CA name is
#        the same CA-NAME used when creating the parent CA.
#
#        This argument is not used with 'verify' command line option
#
#    REASON
#        Specifies the reason for this revocation of the certificate
#        The value must be one of the following:
#          - unspecified
#          - keyCompromise
#          - CACompromise
#          - affiliationChanged
#          - superseded
#          - cessationOfOperation
#          - certificateHold
#          - removeFromCRL (from RFC5280)
#
#        This argument is used only with 'revoke' command line option
#
#    -a, --algorithm
#        Selects the encryption algorithm.
#        Valid algorithms are: rsa, ecdsa, poly1305 OR ed25519
#        These value are case-sensitive.
#        If no algorithm specified, then RSA is used by default.
#
#    -b, --base-dir
#        The top-level directory of SSL, typically /etc/ssl
#        Useful for testing this command in non-root shell
#        or maintaining SSL certs elsewhere (other than /etc/ssl).
#
#    -c, --cipher
#        Specify the cipher method of the PEM key file in
#        which to password-protect the key with.  
#        Default is a plaintext key file with no password protection.
#
#    -f, --force-delete
#        Forces deletion of its specified certificate files
#        as pointed to by CA-NAME argument.  Only files
#        pointed to by CA-NAMe will get deleted: key, certificate,
#        and CRL.  Run a risk of unsynchronized CA database there.
#
#    -g, --group
#        Use this Unix group name for all files created or updated.
#        Default is ssl-cert group.
#
#    -h, --help
#
#    -k, --key-size
#        Specifies the number of bits in the key.  The choice of key
#        size depends on the algorithm (-a) used.
#        The key size does not need to be specified if using a default
#        algorithm.  The default key size is 4096 bits.
#
#        Key size for ed25519 algorithm gets ignored here.
#        Valid poly1305 key sizes are:
#        Valid rsa key sizes are: 4096, 2048, 1024 or 512.
#        Valid ecdsa key sizes are: 521, 384, 256, 224 or 192.
#
#    -m, --message-digest
# blake2b512        blake2s256        gost              md4
# md5               rmd160            sha1              sha224
# sha256            sha3-224          sha3-256          sha3-384
# sha3-512          sha384            sha512            sha512-224
# sha512-256        shake128          shake256          sm3
#
#    -n, --nested-ca
#        First chaining of first-level CAs are placed in subdirectory inside
#        its Root CA directory, and subsequent chaining of second-level CA
#        get nesting also in subdirectory inside its respective Intermediate
#        CA directory.  Very few organizations use this.
#
#    -T, --traditional
#        Indicates the standard OpenSSL directory layout.
#        Default is to use the new centralized directory layout.
#
#    -v, --verbose
#        Sets the debugging level.
#
# NOTES:
#
#    Enforces 'ssl-cert' group; and requires all admins to have 'ssl-cert'
#        group when using this command
#    DO NOT be giving 'ssl-cert' group to server daemons' supplemental
#        group ID (or worse, as its group ID);
#        for that, you copy the certs over to app-specific directory and use
#        THAT app's file permissions.
#    This command does not deal with distribution of certificates, just
#        creation/renewal/revokation of therein.
#    'ssl-cert' group means 'working with SSL/TLS certificates,
#        not just reading certs'.
#
#     Inspired by: https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html
#

function cmd_show_syntax_usage {
    echo """Usage:  
  $0 create [options] <cert-name> <cert-type> <ca-name>
  $0 renew [options] <cert-name> <ca-name>
  $0 revoke [options] <cert-name> <ca-name> <reason>
  $0 verify [options] <cert-name> 
  $0 help

  cert-name: A simple filename for this certificate
  cert-type: This certificate type
  ca-name: Simple name of CA in which to sign certificate against with

  options:
        [ --help|-h ] [ --verbosity|-v ] [ --force-delete|-f ]
        [ --base-dir|-b <ssl-directory-path> ]
        [ --algorithm|-a <rsa|ed25519|ecdsa|poly1305> ]
        [ --message-digest|-m <sha512|sha384|sha256|sha224|sha3-256|
                               sha3-224|sha3-512|sha1|md5> ]
        [ --keysize|-k <4096|2048|1024|521|512|384|256|224> ]
        [ --cipher < > ]
        [ --group|-g <group-name> ]  # (default: $DEFAULT_GROUP_NAME)
        [ --traditional|-T ]

<ca-type>: server, client, email, ocsp, timestamping, security, codesign

Default settings:
  Top-level SSL directory: $DEFAULT_SSL_DIR  Cipher: $DEFAULT_PEER_SIGNATURE
  Digest: $DEFAULT_MESSAGE_DIGEST Keysize: $DEFAULT_KEYSIZE_BITS
"""
  exit 1
}
# Create a top-level or intermediate certificate authority (CA)
#
# Complete with all directories and file protections
#
# LFS/FSSTD:  Single directory for all CA (or a directory for each CA depth?)
# Default values (tweakable)
# DEFAULT_CIPHER="des-ede3-cbc"
DEFAULT_CIPHER=
DEFAULT_CMD_MODE="verify"
DEFAULT_GROUP_NAME="ssl-cert"
DEFAULT_KEYSIZE_BITS=4096
DEFAULT_MESSAGE_DIGEST="sha256"
# shellcheck disable=SC2230
DEFAULT_OPENSSL=$(which openssl)
DEFAULT_PEER_SIGNATURE="rsa"
DEFAULT_SERIAL_ID_HEX=1000
DEFAULT_SSL_DIR="/etc/ssl"
DEFAULT_VERBOSITY=0
DEFAULT_DRYRUN=0
DEFAULT_USER_NAME=${USER}  # tells most IDE syntax checker to say that $USER is defined
# No DEFAULT_ROOT_CA_NAME
# DEFAULT_INT_CA_NAME="network"
# DEFAULT_SIGNING_CA_NAME="component"

DEFAULT_FILETYPE_KEY="key"   # sometimes .private
DEFAULT_FILETYPE_CSR="csr"   # sometimes .req, .request (PKCS#10)
DEFAULT_FILETYPE_CERT="crt"  # sometimes .pem, .cert, .cer  (PKCS#7)
DEFAULT_FILETYPE_CRL="crl"   # sometimes .revoke
DEFAULT_FILETYPE_PFX="pfx"   # sometimes .p12 (PKCS#12)

DEFAULT_OFSTD_LAYOUT="centralized"
DEFAULT_OFSTD_DIR_TREE_TYPE="flat"

DEFAULT_CA_X509_COUNTRY="US"
DEFAULT_CA_X509_STATE=""
DEFAULT_CA_X509_LOCALITY=""
DEFAULT_CA_X509_COMMON="ACME Internal Root CA A1"
DEFAULT_CA_X509_ORG="ACME Networks"
DEFAULT_CA_X509_OU="Trust Division"
DEFAULT_CA_X509_EMAIL="ca.example@example.invalid"
# Do not use HTTPS in X509_CRL (Catch-22)
DEFAULT_CA_X509_CRL="http://example.invalid/ca/example-crl.$DEFAULT_FILETYPE_CERT"
DEFAULT_CA_X509_URL_BASE="http://example.invalid/ca"
DEFAULT_CA_X509_URL_OCSP="http://ocsp.example.invalid:9080"

DEFAULT_INTCA_X509_COUNTRY="US"
DEFAULT_INTCA_X509_STATE=""
DEFAULT_INTCA_X509_LOCALITY=""
DEFAULT_INTCA_X509_COMMON="ACME Internal Intermediate CA B2"
DEFAULT_INTCA_X509_ORG="ACME Networks"
DEFAULT_INTCA_X509_OU="Semi-Trust Department"
DEFAULT_INTCA_X509_EMAIL="ca.subroot@example.invalid"
DEFAULT_INTCA_X509_CRL="http://example.invalid/subroot-ca.crl"
DEFAULT_INTCA_X509_URL_BASE="http://example.invalid/ca/subroot"
DEFAULT_INTCA_X509_URL_OCSP="http://ocsp.example.invalid:9080"


function input_data {
  ID_PROMPT="$1"
  ID_DEFAULT_VALUE="$2"
  echo -n "$ID_PROMPT (default: '$ID_DEFAULT_VALUE'): "
  read -r ID_INPUT_DATA
  if [[ -z "$ID_INPUT_DATA" ]]; then
    ID_INPUT_DATA="$ID_DEFAULT_VALUE"
  fi
  unset ID_PROMPT
  unset ID_DEFAULT_VALUE
}

function directory_file_layout {
    # directory_file_layout arguments:
    #   $1 - Single CA directory Layout (traditional or centralized)
    #   $2 - Multiple CA layout (flat or nested)
    #   $3 - Starting OpenSSL directory
    #   $4 - current issuing authority simplified filename
    # [ $5 - parent issuing authority simplified filename ]

    DFL_OFSTD_LAYOUT="$1"  # traditional | centralized
    DFL_OFSTD_DIR_TREE_TYPE="$2"  # hierarchy | flat
    DFL_SSL_DIR="$3"
    DFL_CERT_NAME="$4"
    DFL_PARENT_IA_NAME="$5"

    PRIVATE_DNAME="private"
    CERTS_DNAME="certs"
    CRL_DNAME="crl"
    DB_DNAME="db"
    NEWCERTS_DNAME="newcerts"

    SSL_CERTS_DIR="${DFL_SSL_DIR}/${CERTS_DNAME}"  # /etc/ssl/certs, always
    if [[ "$DFL_OFSTD_LAYOUT" == "traditional" ]]; then
        # Template filename
        DIRNAME_PREFIX="ca-"
        DIRNAME_SUFFIX=""

        FILENAME_PREFIX="ca."
        FILENAME_SUFFIX=""

        CERT_FILENAME_PREFIX=""
        CERT_FILENAME_SUFFIX=""

        X509_PREFIX="ca_"
        X509_SUFFIX=""

        CERT_X509_PREFIX=""
        CERT_X509_SUFFIX="_ca"

        PEM_FILETYPE_SUFFIX=".pem"

        SSL_SUBDIR_DNAME=""
        SSL_CA_DIR="${DFL_SSL_DIR}"

    elif [[ "$DFL_OFSTD_LAYOUT" == "centralized" ]]; then
        # Template filename
        DIRNAME_PREFIX=""
        DIRNAME_SUFFIX="-ca"

        FILENAME_PREFIX=""
        FILENAME_SUFFIX="-ca"

        CERT_FILENAME_PREFIX=""
        CERT_FILENAME_SUFFIX=""

        CERT_X509_PREFIX=""
        CERT_X509_SUFFIX="_ca"

        X509_PREFIX=""
        X509_SUFFIX="_ca"

        PEM_FILETYPE_SUFFIX=""
        SSL_SUBDIR_DNAME="ca"
        SSL_CA_DIR="${DFL_SSL_DIR}/${SSL_SUBDIR_DNAME}"
    else
        echo "Invalid parameter 1 (must be 'traditional' or 'centralized')"
        exit 2
    fi

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "DFL_PARENT_IA_NAME: $DFL_PARENT_IA_NAME"
        echo "DFL_CERT_NAME     : $DFL_CERT_NAME"
    fi

    if [[ "$OFSTD_DIR_TREE_TYPE" == "flat" ]]; then
        # Inspired by readthedocs
        echo ""
        CERT_FNAME="${CERT_FILENAME_PREFIX}${CERT_NAME}${CERT_FILENAME_SUFFIX}"
        CERT_SNAME="${CERT_X509_PREFIX}${CERT_NAME}${CERT_X509_SUFFIX}"
        CERT_PATH_FNAME="${DIRNAME_PREFIX}${CERT_NAME}${DIRNAME_SUFFIX}"

        PARENT_IA_FNAME="${FILENAME_PREFIX}${PARENT_IA_NAME}${FILENAME_SUFFIX}"
        PARENT_IA_SNAME="${X509_PREFIX}${PARENT_IA_NAME}${X509_SUFFIX}"
        PARENT_IA_PATH_FNAME="${DIRNAME_PREFIX}${PARENT_IA_NAME}${DIRNAME_SUFFIX}"

        CRT_CERTS_DIR="$SSL_DIR/$CERTS_DNAME"
        PARENT_IA_DIR="$SSL_CA_DIR/$PARENT_IA_PATH_FNAME"
    elif [[ "$OFSTD_DIR_TREE_TYPE" == "hierarchy" ]]; then
        # Inspired by traditional OpenSSL
        CERT_FNAME="${FILENAME_PREFIX}${CERT_NAME}${FILENAME_SUFFIX}"
        CERT_SNAME="${X509_PREFIX}${CERT_NAME}${X509_SUFFIX}"
        CERT_PATH_FNAME="${DIRNAME_PREFIX}${CERT_NAME}${DIRNAME_SUFFIX}"

        PARENT_IA_FNAME="${FILENAME_PREFIX}${PARENT_IA_NAME}${FILENAME_SUFFIX}"
        PARENT_IA_SNAME="${X509_PREFIX}${PARENT_IA_NAME}${X509_SUFFIX}"

        PARENT_IA_PATH_FNAME="${DIRNAME_PREFIX}${PARENT_IA_NAME}${DIRNAME_SUFFIX}"

        CRT_CERTS_DIR="$SSL_CA_DIR/$CERT_PATH_FNAME/$CERT_PATH_FNAME"
        PARENT_IA_DIR="$SSL_CA_DIR/$PARENT_IA_PATH_FNAME"
    else
        echo "Invalid parameter 2 (must be 'flat' or 'nested')"
        exit 1
    fi

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "DFL_OFSTD_LAYOUT: $DFL_OFSTD_LAYOUT"
        echo "OFSTD_DIR_TREE_TYPE: $OFSTD_DIR_TREE_TYPE"
        echo "SSL_CA_DIR: $SSL_CA_DIR"
        echo "CERT_FNAME: $CERT_FNAME"
        echo "PARENT_IA_FNAME: $PARENT_IA_FNAME"
        echo "CRT_CERTS_DIR: $CRT_CERTS_DIR"
        echo "PARENT_IA_DIR: $PARENT_IA_DIR"
    fi

    CERT_DB_DNAME="$DB_DNAME"

    # Define full dirspec paths for all the things associated with this issuing authority (IA)

    if [[ "$DFL_OFSTD_LAYOUT" == "traditional" ]]; then
        CERT_KEY_DIR="$PARENT_IA_DIR/$PRIVATE_DNAME"
        CERT_CERTS_DIR="$PARENT_IA_DIR/$CERTS_DNAME"
        CERT_CSR_DIR="$PARENT_IA_DIR"
        CERT_CRL_DIR="$PARENT_IA_DIR/$CRL_DNAME"
        CERT_CHAIN_DIR="$PARENT_IA_DIR"
        CERT_EXT_DIR="$PARENT_IA_DIR"
        CERT_NEWCERTS_ARCHIVE_DIR="$PARENT_IA_DIR/$NEWCERTS_DNAME"

        PARENT_IA_KEY_DIR="$PARENT_IA_DIR/$PRIVATE_DNAME"
        PARENT_IA_CERTS_DIR="$PARENT_IA_DIR/$CERTS_DNAME"
        PARENT_IA_EXT_DIR="$PARENT_IA_DIR"
        PARENT_IA_DB_DIR="$PARENT_IA_DIR"

        PARENT_IA_NEWCERTS_ARCHIVE_DIR="$PARENT_IA_DIR/$NEWCERTS_DNAME"
        PARENT_IA_INDEX_DB_DIR="$PARENT_IA_DB_DIR"
        PARENT_IA_SERIAL_DB_DIR="$PARENT_IA_DB_DIR"
        PARENT_IA_CRL_DB_DIR="$PARENT_IA_DB_DIR"

        CERT_OPENSSL_CNF_REQ_FILE="$CERT_EXT_DIR/certificate_request-${CERT_CA_TYPE}-${CERT_FNAME}.cnf"
        CERT_OPENSSL_CNF_REQ_EXTFILE="$CERT_EXT_DIR/certificate_request_extension-${PARENT_IA_FNAME}-${CERT_FNAME}.cnf"
        PARENT_IA_OPENSSL_CNF_CA_FILE="$PARENT_IA_EXT_DIR/${PARENT_IA_FNAME}.cnf"
        PARENT_IA_OPENSSL_CNF_CA_EXTFILE="$PARENT_IA_EXT_DIR/certificate_ca_extension-${CERT_CA_TYPE}-${CERT_FNAME}.cnf"
    else
        CERT_EXT_DIR="$DFL_SSL_DIR/etc"
        CERT_CRL_DIR="$DFL_SSL_DIR/$CRL_DNAME"
        CERT_CERTS_DIR="$SSL_DIR/$CERTS_DNAME"
        CERT_CSR_DIR="$SSL_CA_DIR"
        CERT_CHAIN_DIR="$SSL_CA_DIR"

        CERT_EXT_DIR="$DFL_SSL_DIR/etc"
        CERT_CRL_DIR="$CERT_CERTS_DIR"
        CERT_CERTS_DIR="$CERT_CERTS_DIR"
        CERT_CSR_DIR="$CERT_CERTS_DIR"

        PARENT_IA_EXT_DIR="$CERT_EXT_DIR"
        PARENT_IA_CERTS_DIR="$SSL_CA_DIR"
        PARENT_IA_KEY_DIR="$PARENT_IA_DIR/$PRIVATE_DNAME"
        PARENT_IA_DB_DIR="$PARENT_IA_DIR/$CERT_DB_DNAME"

        CERT_NEWCERTS_ARCHIVE_DIR="$PARENT_IA_DIR"  # where those 000x.pem files go
        CERT_KEY_DIR="$SSL_DIR/$CERTS_DNAME"

        PARENT_IA_NEWCERTS_ARCHIVE_DIR="$PARENT_IA_DIR"  # where those 000x.pem files go
        PARENT_IA_INDEX_DB_DIR="$PARENT_IA_DIR/$CERT_DB_DNAME"
        PARENT_IA_SERIAL_DB_DIR="$PARENT_IA_DIR/$CERT_DB_DNAME"
        PARENT_IA_CRL_DB_DIR="$PARENT_IA_DIR/$CERT_DB_DNAME"

        CERT_OPENSSL_CNF_REQ_FILE="$CERT_EXT_DIR/certificate_request-${CERT_CA_TYPE}-${CERT_FNAME}.cnf"
        CERT_OPENSSL_CNF_REQ_EXTFILE="$CERT_EXT_DIR/certificate_request_extension-${PARENT_IA_FNAME}-${CERT_FNAME}.cnf"
        PARENT_IA_OPENSSL_CNF_CA_FILE="$PARENT_IA_EXT_DIR/${PARENT_IA_FNAME}.cnf"
        PARENT_IA_OPENSSL_CNF_CA_EXTFILE="$PARENT_IA_EXT_DIR/certificate_ca_extension-${CERT_CA_TYPE}-${CERT_FNAME}.cnf"
    fi

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "CERT_KEY_DIR: $CERT_KEY_DIR"
        echo "CERT_CERTS_DIR: $CERT_CERTS_DIR"
        echo "CERT_CSR_DIR: $CERT_CSR_DIR"
        echo "CERT_CRL_DIR: $CERT_CRL_DIR"
        echo "CERT_CHAIN_DIR: $CERT_CHAIN_DIR"
        echo "CERT_EXT_DIR: $CERT_EXT_DIR"

        echo "PARENT_IA_KEY_DIR: $PARENT_IA_KEY_DIR"
        echo "PARENT_IA_CERTS_DIR: $PARENT_IA_CERTS_DIR"
        echo "PARENT_IA_DB_DIR: $PARENT_IA_DB_DIR"
        echo "CERT_NEWCERTS_ARCHIVE_DIR: $CERT_NEWCERTS_ARCHIVE_DIR"
        echo "PARENT_IA_NEWCERTS_ARCHIVE_DIR: $PARENT_IA_NEWCERTS_ARCHIVE_DIR"
        echo "CERT_OPENSSL_CNF_REQ_FILE: $CERT_OPENSSL_CNF_REQ_FILE"
        echo "CERT_OPENSSL_CNF_REQ_EXTFILE: $CERT_OPENSSL_CNF_REQ_EXTFILE"
        echo "PARENT_IA_OPENSSL_CNF_CA_FILE: $PARENT_IA_OPENSSL_CNF_CA_FILE"
        echo "PARENT_IA_OPENSSL_CNF_CA_EXTFILE: $PARENT_IA_OPENSSL_CNF_CA_EXTFILE"
    fi

    if [[ "$DFL_OFSTD_LAYOUT" == "traditional" ]]; then
        #PARENT_IA_FNAME_PREFIX="$FILENAME_PREFIX$PARENT_IA_NAME$FILENAME_SUFFIX"
        PARENT_IA_FNAME_PREFIX="cakey"  # It's in another directory
        # IA_FNAME_PREFIX="$FILENAME_PREFIX$CERT_NAME$FILENAME_SUFFIX"
        KEY_FNAME_PREFIX="cakey"
        # Traditional CSR is user-defined, we automate it here
        CSR_FNAME_PREFIX="ca-csr"
        CERT_FNAME_PREFIX="cacert"
        CERT_SERIAL_FNAME="serial"
        CERT_INDEX_FNAME="index.txt"
        CERT_CRLNUMBER_FNAME="crlnumber"
        PARENT_IA_SERIAL_FNAME="serial"
        PARENT_IA_INDEX_FNAME="index.txt"
        PARENT_IA_CRLNUMBER_FNAME="crlnumber"
        CRL_FNAME_PREFIX="crl"
        CHAIN_FILENAME_MID=".chain"
        CHAIN_FILETYPE_SUFFIX=".pem"
        # CHAIN_FNAME_PREFIX="$FILENAME_PREFIX$CERT_NAME$CHAIN_FILENAME_MID$CHAIN_FILENAME_SUFFIX"
        CHAIN_FNAME_PREFIX="$FILENAME_PREFIX$CERT_NAME$FILENAME_SUFFIX$CHAIN_FILENAME_MID"

        CERT_KEY_FNAME="${KEY_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
        PARENT_IA_KEY_FNAME="${PARENT_IA_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    else
        FFNAME_KEY="$FILENAME_SUFFIX.$DEFAULT_FILETYPE_KEY"  # '-ca.key'
        FFNAME_CSR="$FILENAME_SUFFIX.$DEFAULT_FILETYPE_CSR"  # '-ca.csr'
        FFNAME_CERT="$FILENAME_SUFFIX.$DEFAULT_FILETYPE_CERT"  # '-ca.crt'
        FFNAME_CRL="$FILENAME_SUFFIX.$DEFAULT_FILETYPE_CRL"  # '-ca.crl'

        PARENT_IA_FNAME_PREFIX="$FILENAME_PREFIX$PARENT_IA_NAME$FFNAME_KEY"
        KEY_FNAME_PREFIX="$FILENAME_PREFIX$CERT_NAME$FFNAME_KEY"

        CSR_FNAME_PREFIX="$FILENAME_PREFIX$CERT_NAME$FFNAME_CSR"
        CRL_FNAME_PREFIX="$FILENAME_PREFIX$CERT_NAME$FFNAME_CRL"

        CERT_FNAME_PREFIX="$FILENAME_PREFIX$CERT_NAME$FFNAME_CERT"
        PARENT_CERT_FNAME_PREFIX="$FILENAME_PREFIX$PARENT_IA_NAME$FFNAME_CERT"

        CERT_KEY_FNAME="${KEY_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
        CERT_SERIAL_FNAME="$FILENAME_PREFIX$CERT_NAME$FFNAME_CERT.srl"
        CERT_INDEX_FNAME="$FILENAME_PREFIX$CERT_NAME$FILENAME_SUFFIX.$DB_DNAME"
        CERT_CRLNUMBER_FNAME="$FILENAME_PREFIX$CERT_NAME$FFNAME_CRL.srl"

        CHAIN_FILENAME_MID="-chain"
        CHAIN_FILETYPE_SUFFIX=".pem"
        CHAIN_FNAME_PREFIX="$FILENAME_PREFIX$CERT_NAME$FILENAME_SUFFIX$CHAIN_FILENAME_MID"

        PARENT_IA_KEY_FNAME="${PARENT_IA_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
        PARENT_IA_SERIAL_FNAME="$FILENAME_PREFIX$PARENT_IA_NAME$FFNAME_CRL.srl"
        PARENT_IA_INDEX_FNAME="$FILENAME_PREFIX$PARENT_IA_NAME$FILENAME_SUFFIX.$DB_DNAME"
        PARENT_IA_CRLNUMBER_FNAME="$FILENAME_PREFIX$PARENT_IA_NAME$FFNAME_CRL.srl"
    fi

    CERT_CSR_FNAME="${CSR_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    CERT_CERT_FNAME="${CERT_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    PARENT_IA_CERT_FNAME="${PARENT_CERT_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    CERT_CRL_FNAME="${CRL_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    CERT_CHAIN_FNAME="${CHAIN_FNAME_PREFIX}${CHAIN_FILETYPE_SUFFIX}"

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "PARENT_IA_KEY_FNAME: $PARENT_IA_KEY_FNAME"
        echo "CERT_KEY_FNAME: $CERT_KEY_FNAME"
        echo "CERT_CSR_FNAME: $CERT_CSR_FNAME"
        echo "CERT_CERT_FNAME: $CERT_CERT_FNAME"
        echo "PARENT_IA_CERT_FNAME: $PARENT_IA_CERT_FNAME"
        echo "CERT_CRL_FNAME: $CERT_CRL_FNAME"
        echo "CERT_CHAIN_FNAME: $CERT_CHAIN_FNAME"
    fi

    CERT_KEY_PEM="$CERT_KEY_DIR/$CERT_KEY_FNAME"
    CERT_CSR_PEM="$CERT_CSR_DIR/$CERT_CSR_FNAME"
    CERT_CERT_PEM="$CERT_CERTS_DIR/$CERT_CERT_FNAME"
    CERT_CRL_PEM="$CERT_CRL_DIR/$CERT_CRL_FNAME"
    CERT_CHAIN_PEM="$CERT_CHAIN_DIR/$CERT_CHAIN_FNAME"

    PARENT_IA_CERT_PEM="$PARENT_IA_CERTS_DIR/$PARENT_IA_CERT_FNAME"
    PARENT_IA_KEY_PEM="$PARENT_IA_KEY_DIR/$PARENT_IA_KEY_FNAME"
    PARENT_IA_INDEX_DB="$PARENT_IA_INDEX_DB_DIR/$PARENT_IA_INDEX_FNAME"
    PARENT_IA_SERIAL_DB="$PARENT_IA_SERIAL_DB_DIR/$PARENT_IA_SERIAL_FNAME"
    PARENT_IA_CRL_DB="$PARENT_IA_CRL_DB_DIR/$PARENT_IA_CRLNUMBER_FNAME"

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "PARENT_IA_KEY_PEM: $PARENT_IA_KEY_PEM"
        echo "CERT_KEY_PEM: $CERT_KEY_PEM"
        echo "CERT_CSR_PEM: $CERT_CSR_PEM"
        echo "CERT_CERT_PEM: $CERT_CERT_PEM"
        echo "PARENT_IA_CERT_PEM: $PARENT_IA_CERT_PEM"
        echo "CERT_CRL_PEM: $CERT_CRL_PEM"
        echo "CERT_CHAIN_PEM: $CERT_CHAIN_PEM"
        echo "PARENT_IA_INDEX_DB: $PARENT_IA_INDEX_DB"
        echo "PARENT_IA_SERIAL_DB: $PARENT_IA_SERIAL_DB"
        echo "PARENT_IA_CRL_DB: $PARENT_IA_CRL_DB"
    fi
    unset DFL_OFSTD_LAYOUT
    unset DFL_OFSTD_DIR_TREE_TYPE

}

function change_owner_perm {
    CHOP_USER="$1"
    CHOP_GROUP="$2"
    CHOP_PERM="$3"
    CHOP_FILESPEC="$4"

    chown "$CHOP_USER:$CHOP_GROUP" "$CHOP_FILESPEC"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
      echo "Error $RETSTS setting $CHOP_USER:$CHOP_GROUP owner to $CHOP_FILESPEC; aborting..."
      exit ${RETSTS}
    fi

    chmod "$CHOP_PERM" "$CHOP_FILESPEC"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
      echo "Error $RETSTS setting $CHOP_USER:$CHOP_GROUP owner to $CHOP_FILESPEC; aborting..."
      exit ${RETSTS}
    fi
}


function touch_cert_file {
    TOUCH_THIS_FILE="$1"
    if [[ -d ${TOUCH_THIS_FILE} ]]; then
        # it does wonder to the file system by touching a directory (EXT4 corruption)
        echo "File $TOUCH_THIS_FILE is already directory "
        echo "(and untouchable); aborting..."
        exit 1
    fi
    [[ ${VERBOSITY} -gt 0 ]] && echo "touch $1"
    touch "$1"
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$1"
}

function delete_file {
    DELETE_FILE="${1:-/tmp/nope}"  # emergency undefined $1 protection
    if [[ -f "$DELETE_FILE" ]]; then
        [[ ${VERBOSITY} -gt 0 ]] && echo "rm $DELETE_FILE"
        rm "$DELETE_FILE"
    fi
}

function delete_cert_config {
    delete_file "$CERT_OPENSSL_CNF_REQ_FILE"  # loses any user-customization(s)
    delete_file "$CERT_OPENSSL_CNF_REQ_EXTFILE"  # loses any user-customization(s)
    # DO NOT DELETE PARENT_IA_OPENSSL_CNF_CA_FILE, that's the CA's own main config file
    delete_file "$PARENT_IA_OPENSSL_CNF_CA_EXTFILE"  # loses any user-customization(s)
}

function delete_cert_dirfiles {
    delete_file "$CERT_KEY_PEM"
    delete_file "$CERT_CSR_PEM"
    delete_file "$CERT_CERT_PEM"
    delete_file "$CERT_CRL_PEM"
    delete_file "$CERT_CHAIN_PEM"
    if [[ ${FORCE_DELETE_CONFIG} -eq 1 ]]; then
        delete_cert_config
    fi
}

function data_entry_generic {
    ID_INPUT_DATA=""
    input_data "Organization" "$X509_ORG"
    X509_ORG="$ID_INPUT_DATA"
    input_data "Org. Unit/Section/Division: " "$X509_OU"
    X509_OU="$ID_INPUT_DATA"
    input_data "Common Name: " "$X509_COMMON"
    X509_COMMON="$ID_INPUT_DATA"
    input_data "Country (2-char max.): " "$X509_COUNTRY"
    X509_COUNTRY="$ID_INPUT_DATA"
    input_data "State: " "$X509_STATE"
    X509_STATE="$ID_INPUT_DATA"
    input_data "Locality/City: " "$X509_LOCALITY"
    X509_LOCALITY="$ID_INPUT_DATA"
    input_data "Contact email: " "$X509_EMAIL"
    X509_EMAIL="$ID_INPUT_DATA"
    input_data "Base URL: " "$X509_URL_BASE"
    X509_URL="$ID_INPUT_DATA"
    input_data "CRL URL: " "$X509_CRL"
    X509_CRL="$ID_INPUT_DATA"
}



# Usage: get_x509v3_extension_by_cert_type <ca_type> <pathlen>
function get_x509v3_extension_by_cert_type {
  GXEBCT_CA_TYPE=$1
  GXEBCT_PATHLEN_COUNT=$2
  [[ -n ${GXEBCT_PATHLEN_COUNT} ]] || GXEBCT_PATHLEN_COUNT=-1
  if [[ ${GXEBCT_PATHLEN_COUNT} -ge 0 ]]; then
    GXEBCT_PATHLEN_OPTION=",pathlen:$GXEBCT_PATHLEN_COUNT"
  else
    GXEBCT_PATHLEN_OPTION=""
  fi
  case "$GXEBCT_CA_TYPE" in
    server)
      CNF_SECTION_REQ_EXT="section_server_req_x509v3_extension"
      CNF_REQ_EXT_KU="critical,digitalSignature,keyEncipherment"
      CNF_REQ_EXT_BC="CA:false"
      CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
      # CNF_REQ_EXT_AKI="keyid,issuer:always"  # used in 802.1ar iDevID
      # CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier (openssl ca)
      # Need to remove 'clientAuth' from server extendedKeyUsage; no citation
      # Need to remove 'nsSGC' from extendedKeyUsage, but no citation
      # Need to remove 'msSGC' from extendedKeyUsage, but no citation
      CNF_REQ_EXT_EKU="serverAuth,clientAuth"
      # CNF_REQ_EXT_SAN="\$ENV::SAN"  # subjectAltName
      CNF_REQ_EXT_SAN=""  # subjectAltName
      # CNF_REQ_EXT_AIA="@ocsp_info"
      # CNF_REQ_EXT_AIA="@issuer_info"
      CNF_REQ_EXT_AIA=""
      CNF_SECTION_CA_EXT="section_server_ca_x509v3_extension"
      CNF_CA_EXT_KU="critical,digitalSignature,keyEncipherment"
      CNF_CA_EXT_BC="CA:false"
      CNF_CA_EXT_SKI="hash"
      CNF_CA_EXT_AKI="keyid:always"
      CNF_CA_EXT_AIA="@ocsp_info"
      CNF_CA_EXT_EKU="serverAuth"  # No 'clientAuth' allowed
      # Only need serverAuth & clientAuth together if
      #   making a PEM key that combines private and public key (bad idea)
      CNF_CA_EXT_SAN=""
      ;;
    client)
      CNF_SECTION_REQ_EXT="section_client_req_x509v3_extension"
      # CNF_REQ_EXT_KU="critical,digitalSignature,keyEncipherment"  # very old
      CNF_REQ_EXT_KU="critical,digitalSignature"
      CNF_REQ_EXT_BC="CA:false"
      CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_REQ_EXT_EKU="clientAuth"
      CNF_REQ_EXT_SAN="email:move"  # subjectAltName
      CNF_REQ_EXT_AIA="@issuer_info"
      ;;
    timestamping)
      CNF_SECTION_REQ_EXT="section_timestamping_req_x509v3_extension"
      CNF_REQ_EXT_KU="critical,digitalSignature"
      CNF_REQ_EXT_BC="CA:false"
      CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_REQ_EXT_EKU="critical,timeStamping"
      CNF_REQ_EXT_SAN=""  # subjectAltName
      CNF_REQ_EXT_AIA="@issuer_info"
      ;;
    ocsp)
      CNF_SECTION_REQ_EXT="section_ocspsign_req_x509v3_extension"
      CNF_REQ_EXT_KU="critical,digitalSignature"
      CNF_REQ_EXT_BC="CA:false"
      CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_REQ_EXT_EKU="critical,OCSPSigning"
      CNF_REQ_EXT_SAN=""  # subjectAltName
      CNF_REQ_EXT_AIA="@issuer_info"
      CNF_CA_EXT_EXTRA="noCheck = null"
      ;;
    email)
      CNF_SECTION_REQ_EXT="section_email_req_x509v3_extensions"
      CNF_REQ_EXT_KU="critical,keyEncipherment"
      CNF_REQ_EXT_BC="CA:false"  # basicConstraint
      CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_REQ_EXT_EKU="emailProtection"
      CNF_REQ_EXT_SAN="email:move"  # subjectAltName
      CNF_REQ_EXT_AIA="@issuer_info"
    ;;
    encryption)
      CNF_SECTION_REQ_EXT="section_encryption_req_x509v3_extension"
      CNF_REQ_EXT_KU="critical,digitalSignature,keyEncipherment"  # keyUsage
      CNF_REQ_EXT_BC=""  # basicConstraint
      CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_REQ_EXT_AKI=""  # authorityKeyIdentifier
      # email encryption = "emailProtection,clientAuth"
      # Microsoft Encrypted File System = "emailProtection,msEFS"
      # merged plain email and MS identity encryption together
      CNF_REQ_EXT_EKU="emailProtection,clientAuth,msEFS"
      CNF_REQ_EXT_SAN="email:move"  # subjectAltName
      CNF_REQ_EXT_AIA="@issuer_info"
      ;;
    identity)  # there's identity-ca and identity, this here is identity-ca
      CNF_SECTION_REQ_EXT="section_identity_req_x509v3_extension"
      CNF_REQ_EXT_KU="critical,digitalSignature"
      CNF_REQ_EXT_BC="CA:false"  # basicConstraint
      CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      # msSmartcardLogin is implementation-dependent, but include here nonetheless
      CNF_REQ_EXT_EKU="emailProtection,clientAuth,msSmartcardLogin"
      CNF_REQ_EXT_SAN="email:move"  # subjectAltName
      CNF_REQ_EXT_AIA="@issuer_info"
      ;;
    codesign)
      CNF_SECTION_REQ_EXT="section_codesign_req_x509v3_extension"
      CNF_REQ_EXT_KU="critical,digitalSignature"
      CNF_REQ_EXT_BC="CA:false"  # basicConstraint
      CNF_REQ_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_REQ_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_REQ_EXT_EKU="critical,codeSigning"
      CNF_REQ_EXT_SAN=""  # subjectAltName
      CNF_REQ_EXT_AIA="@issuer_info"  # authorityInfoAccess
      ;;
    *)
      echo "Invalid '$GXEBCT_CA_TYPE' option"
      ;;
  esac
  unset GXEBCT_CA_TYPE
  unset GXEBCT_PATHLEN_COUNT
}

function write_line_or_no
{
    WLON_KEY_NAME=$1
    WLON_VALUE_NAME=$2
    WLON_INTERNODE_CONFIG_FILESPEC=$3
    if [[ -n "$WLON_VALUE_NAME" ]]; then
        echo "$WLON_KEY_NAME = $WLON_VALUE_NAME" >> "$WLON_INTERNODE_CONFIG_FILESPEC"
    fi
    unset WLON_KEY_NAME
    unset WLON_VALUE_NAME
    unset WLON_INTERNODE_CONFIG_FILESPEC
}

# Creates an extension file that details the
# relatioship between parent CA and its child CA
#
function create_generic_ca_extension_config_file
{
  CCEC_SECTION_NAME="$1"
  CCEC_EXTFILE="$2"
  CCEC_CURRENT_TIMESTAMP=$(date)
  echo """#
# File: $CCEC_EXTFILE
# Created on: $CCEC_CURRENT_TIMESTAMP
# Generated by: $0
#
# Description:
#    Generic CA certificate extension configuration file.
#
#    This file makes it possible to extend functionality of
#    the parent Signing CA to supporting different types of certificates
#
#    This file is used by the 'openssl ca' command.
#
#    An OpenSSL extension configuration file that contains
#    key-value pair that characterize the relationship between
#    the parent CA and itself.
#
# Usage:
#    openssl ca -config $PARENT_IA_OPENSSL_CNF_CA_FILE \\
#               -extfile $CCEC_EXTFILE \\
#               -extfension $CCEC_SECTION_NAME \\
#               ...
#
# Section Name breakdown:
#    ca: section name '[ ca ]'; used by 'openssl ca'
#    x509_extensions: Key name (to a key-value statement)
#    ${PARENT_IA_NAME}: Parent CA's config file
#    ${CERT_NAME}:    this node
#
# Section name could be a simple ${CA_TYPE} name
# But having CA_TYPE-CA_NAME makes it possible to support
# different class of the same CA-TYPE by using CA_NAMe as a unique label
[ $CCEC_SECTION_NAME ]
""" > "$CCEC_EXTFILE"
    write_line_or_no "keyUsage"               "$CNF_CA_EXT_KU" "$CCEC_EXTFILE"
    write_line_or_no "basicConstraints"       "$CNF_CA_EXT_BC" "$CCEC_EXTFILE"
    write_line_or_no "subjectKeyIdentifier"   "$CNF_CA_EXT_SKI" "$CCEC_EXTFILE"
    write_line_or_no "authorityKeyIdentifier" "$CNF_CA_EXT_AKI" "$CCEC_EXTFILE"
    write_line_or_no "extendedKeyUsage"       "$CNF_CA_EXT_EKU" "$CCEC_EXTFILE"
    write_line_or_no "subjectAltName"         "$CNF_CA_EXT_SAN" "$CCEC_EXTFILE"
    write_line_or_no "authorityInfoAccess"    "$CNF_CA_EXT_AIA" "$CCEC_EXTFILE"
    write_line_or_no "crlDistributionPoint"   "" "$CCEC_EXTFILE"
    echo "$CNF_CA_EXT_EXTRA" >> "$CCEC_EXTFILE"
    unset CCEC_SECTION_NAME
    unset CCEC_EXTFILE
    unset CCEC_TIMESTAMP
}

# Usage: create_cert_config
#                                <section_name> \
#                                <internode_filespec>
function create_generic_cert_req_config_file
{
  CGCRCF_SECTION_NAME=$1
  CGCRCF_CNFFILE=$2
  CGCRCF_CURRENT_TIMESTAMP=$(date)
  echo """#
# File: $CGCRCF_CNFFILE
# Created on: $CGCRCF_CURRENT_TIMESTAMP
# Generated by: $0
#
# Description:
#    Create generic Certificate Request main configuration file.
#
#    This file is used by the 'openssl req' command as main\
#    configuration file to create a end-user certificate.
#
#    Since we cannot know the DN in advance, the user
#    must be prompted for DN information.
#
#    An OpenSSL extension configuration file that contains
#    key-value pair that characterize the relationship between
#    the parent CA and itself.
#
# Usage:
#    openssl req -config $CGCRCF_CNFFILE \\
#                -extfile $CERT_OPENSSL_CNF_REQ_EXTFILE \\
#                ...
#
# Section Name breakdown:
#    req: section name '[ req ]'; used by 'openssl req'
#    x509_extensions: Key name (to a key-value statement)
#    ${PARENT_IA_NAME}: Parent CA's config file
#    ${CERT_NAME}:    this node
#
[ req ]
default_bits            = $KEYSIZE_BITS         # RSA key size
encrypt_key             = yes                   # Protect private key
default_md              = $MESSAGE_DIGEST       # MD to use
utf8                    = yes                   # Input is UTF-8
string_mask             = utf8only              # Emit UTF-8 strings
prompt                  = yes                   # Prompt for DN
distinguished_name      = ${CA_TYPE}_dn         # DN template
req_extensions          = $CGCRCF_SECTION_NAME     # Desired extensions

[ ${CA_TYPE}_dn ]
countryName               = Country Name (2-letter code)
countryName_default       = US
countryName_min           = 2
countryName_max           = 2

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = Some-State

localityName                    = Locality Name (eg, city)

0.organizationName              = \"Organization Name (eg, company)\"
0.organizationName_default      = \"ACME Network\"
# we can do this but it is not needed normally :-)
#1.organizationName             = Second Organization Name (eg, company)
#1.organizationName_default     = World Wide Web Pty Ltd

organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_default = \"ACME Intermediate CA B2\"

commonName                      = Common Name (e.g. server FQDN or YOUR name)
commonName_default              = \"John Doe\"
commonName_max                  = 64

emailAddress                    = Email Address
emailAddress_default            = \"jdoe@example.invalid\"
emailAddress_max                = 64

# domainComponent is not used by 'identity.conf'
0.domainComponent               = \"Top-level Domain Name (i.e., com, net, org)\"
0.domainComponent_default       = \"invalid\"
1.domainComponent               = \"The Domain Name (i.e., example, test, acme)\"\
1.domainComponent_default       = \"example\"
2.domainComponent               = \"Sub-Domain Name (i.e., www, ocsp, or 'blank')\"\
2.domainComponent_default       = \"\"

""" > "$CGCRCF_CNFFILE"  # create file, appends later on

  unset CIC_SECTION_NAME
  unset CIC_CONFIG_FILESPEC
  unset CIC_TIMESTAMP
}

# Usage: create_generic_ca_extension_config_file \
#                                <section_name> \
#                                <internode_filespec>
function create_generic_cert_req_extension_config_file
{
  CGCCF_SECTION_NAME=$2
  CGCCF_CONFIG_FILESPEC=$3
  CGCCF_CURRENT_TIMESTAMP=$(date)
  echo """#
# File: $CGCCF_CONFIG_FILESPEC
# Created: $CGCCF_CURRENT_TIMESTAMP
# Generated by: $0
#
# Description:
#    Create generic certificate request extension-only configuration file\
#
#    This file is used by the 'openssl req' command as an extension config file.
#
# Usage:
#    openssl req -config $PARENT_IA_OPENSSL_CNF_CA_FILE \\
#               -extfile $CGCCF_CONFIG_FILESPEC \\
#               -extension $CGCCF_SECTION_NAME \\
#        ...
#
# Section Name breakdown:
#    req: section name '[ req ]'; used by 'openssl req'
#    x509_extensions: Key name (to a key-value statement)
#    ${PARENT_IA_NAME}_ca: Parent CA's config file
#    ${CERT_NAME}:    this node
#
[ $CGCCF_SECTION_NAME ]
""" > "$CGCCF_CONFIG_FILESPEC"  # create file, appends later on
    write_line_or_no "keyUsage"               "$CNF_REQ_EXT_KU" "$CGCCF_CONFIG_FILESPEC"
    write_line_or_no "basicConstraints"       "$CNF_REQ_EXT_BC" "$CGCCF_CONFIG_FILESPEC"
    write_line_or_no "subjectKeyIdentifier"   "$CNF_REQ_EXT_SKI" "$CGCCF_CONFIG_FILESPEC"
    write_line_or_no "authorityKeyIdentifier" "$CNF_REQ_EXT_AKI" "$CGCCF_CONFIG_FILESPEC"
    write_line_or_no "extendedKeyUsage"       "$CNF_REQ_EXT_EKU" "$CGCCF_CONFIG_FILESPEC"
    write_line_or_no "subjectAltName"         "$CNF_REQ_EXT_SAN" "$CGCCF_CONFIG_FILESPEC"
    write_line_or_no "authorityInfoAccess"    "$CNF_REQ_EXT_AIA" "$CGCCF_CONFIG_FILESPEC"
    write_line_or_no "crlDistributionPoint"   "" "$CGCCF_CONFIG_FILESPEC"
    echo "$CNF_CA_EXT_EXTRA" >> "$CGCCF_CONFIG_FILESPEC"

    unset CGCCF_CONFIG_FILESPEC
    unset CGCCF_SECTION_NAME
    unset CGCCF_TIMESTAMP
}


#########################################################
# Create the public key for a CA node                   #
#########################################################
function cert_create_public_key
{
    # pre-privacy
    touch_cert_file "$CERT_KEY_PEM"
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$CERT_KEY_PEM"

    ${OPENSSL_GENPKEY} \
        ${OPENSSL_ALGORITHM} \
        -text \
        -outform PEM \
        -out "${CERT_KEY_PEM}"

    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl genpkey'; aborting..."
        exit ${RETSTS}
    fi
    if [[ ! -f "$CERT_KEY_PEM" ]]; then
        echo "Failed to create private key for $CERT_CA_TYPE ($CERT_KEY_PEM)"
        exit 126 # ENOKEY
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$CERT_KEY_PEM"

    if [[ ${VERBOSITY} -ne 0 ]]; then
        # View the private key in readable format
        openssl asn1parse -in "$CERT_KEY_PEM"
        openssl pkey \
            -in "$CERT_KEY_PEM" \
            -noout \
            -text
    fi
}

#########################################################
# Create the CA node's signing request certificate      #
# Usage: cert_create_csr  <section_name> \
#                                <internode_filespec> \
#                                <parent_node_name>
#########################################################
function cert_create_csr 
{
    CCC_SECTION_NAME=$1
    CCC_CERT_CONFIG_FILESPEC=$2

    ${OPENSSL} req -config "${CCC_CERT_CONFIG_FILESPEC}" \
        -new \
        -keyout "$CERT_KEY_PEM" \
        "$MESSAGE_DIGEST_CMDOPT" \
        -out "$CERT_CSR_PEM"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl req'; aborting..."
        exit ${RETSTS}
    fi
    if [[ ! -f "$CERT_CSR_PEM" ]]; then
        echo "Failed to create signing request for $CERT_CA_TYPE ($CERT_CSR_PEM)"
        exit 2 # ENOENT
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$CERT_CSR_PEM"

    if [[ ${VERBOSITY} -ne 0 ]]; then
        # View the CSR in readable format
        openssl asn1parse -in "$CERT_CSR_PEM"
        openssl req -in "$CERT_CSR_PEM" -noout -text
    fi
    unset CCC_SECTION_NAME
    unset CCC_INTERNODE_CONFIG_FILESPEC
    unset CCC_PARENT_CONFIG_FILESPEC
}

###############################################
# Parent CA accept CA node's CSR by trusting  #
###############################################
function cert_create_certificate {
    echo "Creating '$CERT_CA_TYPE'-type certificate ..."
    CCC_CERT_OPENSSL_CNF_EXTENSION="$1"
    CCC_CERT_OPENSSL_CNF_EXTFILE="$2"
    ${OPENSSL_CA} \
        -batch \
        ${IA_OPENSSL_CA_OPT} \
        -extfile "$CCC_CERT_OPENSSL_CNF_EXTFILE" \
        -extensions "$CCC_CERT_OPENSSL_CNF_EXTENSION" \
        -in "$CERT_CSR_PEM" \
        -days 3650 \
        -md "$MESSAGE_DIGEST" \
        -keyfile "$PARENT_IA_KEY_PEM" \
        -out "$CERT_CERT_PEM"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl ca'"
        exit ${RETSTS}
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$CERT_CERT_PEM"

    unset CCC_CERT_OPENSSL_CNF_EXTFILE
    unset CCC_CERT_OPENSSL_CNF_EXTENSION
}

function cert_create_revocation_list
{
    echo "Creating $CERT_CA_TYPE certificate revocation list (CRL)..."
    ${OPENSSL_CA} \
        -gencrl \
        -config "$PARENT_IA_OPENSSL_CNF_CA_FILE" \
        -out "$CERT_CRL_PEM"
}

function ca_extract_signing_request
{
    ###########################################################
    # Extract existing Root Certificate Authority Certificate #
    ###########################################################
    # We are at the mercy of CA_CERT_PEM being the latest
    # and ALSO in its index.txt file as well.
    ${OPENSSL_X509} -x509toreq \
       -in "$CERT_CERT_PEM" \
       -signkey "$CERT_KEY_PEM" \
       -out "$CERT_CSR_PEM"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl x509 -x509toreq'; aborting..."
        exit ${RETSTS}
    fi
    if [[ ! -f "$CERT_CSR_PEM" ]]; then
        echo "Failed to recreate request key from $CERT_CA_TYPE ($CERT_CSR_PEM)"
        exit 2 #ENOENT
    fi
    if [[ ${VERBOSITY} -ne 0 ]]; then
        openssl asn1parse -in "$CERT_CSR_PEM"
        openssl req -noout -text -in "$CERT_CSR_PEM"
    fi
}

###########################################################
# Request renewal of this Issuing Authority               #
###########################################################
function ca_renew_certificate
{
    CRC_CERT_OPENSSL_CNF_EXTFILE="$1"
    CRC_CERT_OPENSSL_CNF_EXTENSION="$2"
    # DO NOT USE 'openssl x509', because it lacks DB accounting
    ${OPENSSL_CA} \
        -verbose \
        ${IA_OPENSSL_CA_OPT} \
        -extfile "${CRC_CERT_OPENSSL_CNF_EXTFILE}" \
        -extensions "$CRC_CERT_OPENSSL_CNF_EXTENSION" \
        -days 1095 \
        -in "$CERT_CSR_PEM" \
        -out "$CERT_CERT_PEM"
        # -keyfile "$PARENT_IA_KEY_PEM" \
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl ca'; aborting..."
        exit ${RETSTS}
    fi
    if [[ ! -f "$CERT_CERT_PEM" ]]; then
        echo "Failed to recreate $CERT_CA_TYPE certificate ($CERT_CERT_PEM}"
        exit 2 # ENOENT
    fi
    unset CRC_CERT_OPENSSL_CNF_EXTFILE
    unset CRC_CERT_OPENSSL_CNF_EXTENSION
}

function hex_decrement
{
    HEX_VALUE=$1
    DECIMAL_VALUE=$(echo "ibase=16; $HEX_VALUE" | bc)
    ((DECIMAL_VALUE_PREV=DECIMAL_VALUE-1))
    HEX_VALUE_PREV=$(echo "obase=16; $DECIMAL_VALUE_PREV" | bc)
}


##################################################
# Display in human-readable format a certificate #
##################################################
function display_cert_certificate {
    DCC_THIS_PEM="$1"
    echo "Displaying MD5 of various CA certificates:"
    echo "$(${OPENSSL_X509} -noout -modulus -in "$DCC_THIS_PEM" | ${OPENSSL_MD5}) $DCC_THIS_PEM"

    if [[ ${VERBOSITY} -ne 0 ]]; then
        echo "Decoding $CERT_CA_TYPE certificate:"
        ${OPENSSL_X509} -in "$DCC_THIS_PEM" -noout -text
    else
        echo "To see decoded $CERT_CA_TYPE certificate, execute:"
        echo "  $OPENSSL_X509 -in $DCC_THIS_PEM -noout -text"
    fi
}

function delete_any_old_cert_files {
    # Yeah, yeah, yeah; destructive but this is a new infrastructure
    if [[ -d "$CERT_CERTS_DIR" ]]; then
        echo "DEBUG: DEBUG: CERTS_DIR: $CERT_CERTS_DIR exist..."
        echo -n "Asking again: Do you want to selectively-delete $CERT_CERTS_DIR? (N/yes): "
        read -r DELETE_CERT_DIR
        if [[ "$DELETE_CERT_DIR" =~ y|yes|Y|YES ]]; then
            delete_cert_dirfiles
        else
            echo "Exiting..."; exit 1
        fi
    else
        echo "WHOA! Directory $CERT_CERTS_DIR does not exist."
        exit 1
    fi
    [[ ${FORCE_DELETE_CONFIG} -eq 1 ]] && delete_cert_config
}


##################################################
# CLI create command                             #
##################################################
function cmd_create_cert {
    [[ ${VERBOSITY} -ne 0 ]] && echo "Creating $CERT_CA_TYPE certificate..."

    delete_any_old_cert_files

    if [[ ${VERBOSITY} -ne 0 ]]; then
        echo "$CERT_CA_TYPE subdirectory:  $(ls -1lad "$SSL_CA_DIR"/)"
    fi

    cd "$SSL_CA_DIR" || exit 65  # ENOPKG

    # Check for parent CA OpenSSL config file
    if [[ ! -f "$PARENT_IA_OPENSSL_CNF_CA_FILE" ]]; then
        echo "ERROR: PARENT_IA_OPENSSL_CNF_CA_FILE: $PARENT_IA_OPENSSL_CNF_CA_FILE does not exist"
        exit 2
    fi
    # Capture data entry for distinguished name
    if [[ ! -f "$CERT_OPENSSL_CNF_REQ_FILE" ]]; then

        # Create a new OpenSSL
        echo "$CERT_OPENSSL_CNF_REQ_FILE file is missing, recreating ..."
        data_entry_generic
    fi

    [[ ${VERBOSITY} -ne 0 ]] && echo "Creating $CERT_CA_TYPE private key ..."

    echo "DEBUG: DEBUG: CA_TYPE: $CA_TYPE"
    get_x509v3_extension_by_cert_type "$CA_TYPE" -1

    cert_create_public_key

    create_generic_cert_req_config_file "$THIS_SECTION" "$CERT_OPENSSL_CNF_REQ_FILE"

    # Create PKCS#10 (Certificate Signing Request)
    cert_create_csr "$THIS_SECTION" "$CERT_OPENSSL_CNF_REQ_FILE"

    SECTION_CA="$PARENT_IA_NAME-${CA_TYPE}"
    create_generic_ca_extension_config_file "$SECTION_CA" "${PARENT_IA_OPENSSL_CNF_CA_EXTFILE}"

    cert_create_certificate "$SECTION_CA" "$PARENT_IA_OPENSSL_CNF_CA_EXTFILE"

    cert_create_revocation_list

    # Clean up
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$PARENT_IA_INDEX_DB"
    if [[ -f "$PARENT_IA_INDEX_DB.old" ]]; then
        change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$PARENT_IA_INDEX_DB.old"
    fi
    if [[ -f "$PARENT_IA_INDEX_DB.attr" ]]; then
        change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$PARENT_IA_INDEX_DB.attr"
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$PARENT_IA_SERIAL_DB"
    if [[ -f "$PARENT_IA_SERIAL_DB.old" ]]; then
        change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$PARENT_IA_SERIAL_DB.old"
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$PARENT_IA_NEWCERTS_ARCHIVE_DIR"/"$STARTING_SERIAL_ID".pem

    display_cert_certificate "$CERT_CERT_PEM"

    echo "Created the following files:"
    echo "  $CERT_CA_TYPE cert req   : $CERT_CSR_PEM"
    echo "  $CERT_CA_TYPE certificate: $CERT_CERT_PEM"
    echo "  $CERT_CA_TYPE private key: $CERT_KEY_PEM"
    echo "  $CERT_CA_TYPE new cert   : $PARENT_IA_NEWCERTS_ARCHIVE_DIR"
    echo "  $CERT_CA_TYPE CRL        : $CERT_CRL_PEM"
}


##################################################
# CLI renew command                              #
##################################################
function cmd_renew_cert {
    [[ ${VERBOSITY} -ne 0 ]] && echo "Calling renew certificate..."
    if [[ ! -f "$PARENT_IA_SERIAL_DB" ]]; then
        echo "Serial ID ($PARENT_IA_SERIAL_DB) file is missing; aborting..."; exit 1
    fi
    if [[ ! -f "$PARENT_IA_CRL_DB" ]]; then
        echo "CRL number ($PARENT_IA_CRL_DB) file is missing; aborting..."; exit 1
    fi
    # Check Cert
    if [[ ! -e "$CERT_CERTS_DIR" ]]; then
        echo "No $CERT_CERTS_DIR directory found; run tls-create-ca-infrastructure.sh"
        exit 2 # ENOENT
    else
        if [[ ! -d "$CERT_CERTS_DIR" ]]; then
            echo "File '$CERT_CERTS_DIR' is not a directory."
            exit 2
        fi
    fi
    # Check PARENT_IA
    if [[ ! -e "$PARENT_IA_DIR" ]]; then
        echo "No $PARENT_IA_DIR directory found; run tls-create-ca-infrastructure.sh"
        exit 2 # ENOENT
    else
        if [[ ! -d "$PARENT_IA_DIR" ]]; then
            echo "File '$PARENT_IA_DIR' is not a directory."
            exit 2
        fi
    fi
    [[ ${VERBOSITY} -ne 0 ]] && echo "CA subdirectory:  $(ls -1lad "${CERT_CERTS_DIR}/")"

    for THIS_DIR in ${CERT_CERTS_DIR} ${CERT_KEY_DIR} ${CERT_NEWCERTS_ARCHIVE_DIR} ${CERT_CRL_DIR}; do
      if [[ ! -e "$THIS_DIR" ]]; then
        echo "Directory $THIS_DIR is missing; aborting..."
        exit 2 # ENOENT
      else
        if [[ ! -d "$THIS_DIR" ]]; then
          echo "File $THIS_DIR is not a directory; aborted."
          exit 2 # ENOENT
        fi
      fi
      change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0750 "$THIS_DIR"
    done

    ca_extract_signing_request

    echo "DEBUG: DEBUG: CA_TYPE: $CA_TYPE"
    get_x509v3_extension_by_cert_type "$CA_TYPE" -1

    THIS_SECTION="req_x509_extensions_${PARENT_IA_SNAME}_${CERT_SNAME}"
    create_internode_config "ca" "$THIS_SECTION" "$PARENT_IA_OPENSSL_CNF_CA_EXTFILE"

    ca_renew_certificate "$CERT_OPENSSL_CNF_REQ_EXTFILE" "$THIS_SECTION"

    cert_create_revocation_list

    display_cert_certificate "$CERT_CERT_PEM"

    echo "Created the following files:"
    echo "  $CERT_CA_TYPE cert req   : $CERT_CSR_PEM"
    echo "  $CERT_CA_TYPE certificate: $CERT_CERT_PEM"
    echo "  $CERT_CA_TYPE private key: $CERT_KEY_PEM"
    echo "  $CERT_CA_TYPE new cert   : $PARENT_IA_NPARENT_IA_NEWCERT_NEW_PEM"
    echo "  $CERT_CA_TYPE chain cert : $CERT_CHAIN_PEM"
    echo "  $CERT_CA_TYPE CRL        : $CERT_CRL_PEM"
    echo "  $CERT_CA_TYPE REQ cnf    : $CERT_OPENSSL_CNF_REQ_FILE"
    echo "  $CERT_CA_TYPE REQ cnf extension  : $CERT_OPENSSL_CNF_REQ_EXTFILE"
    echo "  $CERT_CA_TYPE CA cnf    : $PARENT_IA_OPENSSL_CNF_CA_FILE"
    echo "  $CERT_CA_TYPE CA cnf extension  : $PARENT_IA_OPENSSL_CNF_CA_EXTFILE"
}


##################################################
# CLI revoke command                             #
##################################################
function cmd_revoke_cert {
    # Obtain current serial ID
    NEXT_SERIAL_ID="$(cat $PARENT_IA_SERIAL_DB)"
    hex_decrement "$NEXT_SERIAL_ID"
    CURRENT_SERIAL_ID="$HEX_VALUE_PREV"

    # Read serialized file from $IA_CERTS_DIR (./certs)
    # -keyfile and -cert are not needed if an openssl.cnf is proper
    REVOKING_CERT_FILE="$CERT_NEWCERTS_ARCHIVE_DIR/$CURRENT_SERIAL_ID.pem"

    ${OPENSSL_X509} -noout -text \
        -in "$REVOKING_CERT_FILE"

    echo "Certificate file: $REVOKING_CERT_FILE"
    echo -n "Revoke above certificate? (y/N): "
    read -r REVOKE_THIS_ONE
    if [[ "$REVOKE_THIS_ONE" == "y" ]]; then

        # openssl ca -revoke /etc/ssl/newcerts/1013.pem #replacing the serial number
        ${OPENSSL_CA} -revoke "$REVOKING_CERT_FILE"
        RETSTS=$?
        if [[ ${RETSTS} -ne 0 ]]; then
            echo "Error $RETSTS during 'openssl ca'"
            echo "Command used: $OPENSSL_CA -revoke $REVOKING_CERT_FILE"
            exit ${RETSTS}
        fi
    fi

    cert_create_revocation_list
}

##################################################
# CLI verify command                             #
##################################################
function cmd_verify_cert {
    [[ ${VERBOSITY} -ne 0 ]] && echo "Verify certificate command..."

# You can use OpenSSL to check the consistency of a private key:
# openssl rsa -in [privatekey] -check

# For my forged keys it will tell you:
# RSA key error: n does not equal p q

# You can then compare the public key, for example by calculating the so-called SPKI SHA256 hash:
# openssl pkey -in [privatekey] -pubout -outform der | sha256sum
# openssl x509 -in [certificate] -pubkey |openssl pkey -pubin -pubout -outform der | sha256sum

    # Visual Inspection:
    # check a certificate, its expiration date and who signed it
    ${OPENSSL_X509} -noout -text -in "$CERT_CERT_PEM"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "FAIL: Unable to view certificate: $CERT_CSR_PEM"
        exit 1
    fi

    echo "Key:         $CERT_KEY_PEM"
    echo "CSR:         $CERT_KEY_PEM"
    echo "Certificate: $CERT_CERT_PEM"

    # Verify the key
    ${OPENSSL_PKEY} -noout -in "$CERT_KEY_PEM" -check
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Key $CERT_KEY_PEM: FAILED VERIFICATION"
    else
        echo "Key $CERT_KEY_PEM: verified"
    fi

    # Verify the CSR
    ${OPENSSL_REQ} -noout -verify -in "$CERT_CSR_PEM"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "CSR $CERT_CSR_PEM: FAILED VERIFICATION"
    else
        echo "CSR $CERT_CSR_PEM: verified"
    fi

    # Verify the Certificate
    ${OPENSSL_VERIFY} -no-CApath -no-CAstore \
        -CAfile "$PARENT_IA_CERT_PEM" "$CERT_CERT_PEM"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Certificate $CERT_CERT_PEM: FAILED VERIFICATION"
    else
        echo "Certificate $CERT_CERT_PEM: verified"
    fi


    TMP="$(mktemp -d)"

    ########################################
    # Check if Key and Certificate matches
    ########################################

    # Checking MD5 hash
    hashkey=$(${OPENSSL_X509} -noout -in "$CERT_CERT_PEM" | \
              ${OPENSSL_MD5} )
    hashcrt=$(${OPENSSL_PKEY} -noout -in "$CERT_KEY_PEM" | \
              ${OPENSSL_MD5} )
    if [[ "${hashkey}" = "${hashcrt}" ]]; then
        echo "MD5 hash matches"
    else
        echo "FAIL: MD5 hash does not match"
        exit 1
    fi

    # Checking SPKIsha256 hash
    hashkey=$(openssl pkey \
        -in "$CERT_KEY_PEM" \
        -pubout \
        -outform der \
        | sha256sum)
    hashcrt=$(openssl x509 \
        -in "$CERT_CERT_PEM" \
        -pubkey \
        | openssl pkey \
        -pubin \
        -pubout \
        -outform der \
        | sha256sum)
    if [[ "${hashkey}" = "${hashcrt}" ]]; then
        echo "SPKI SHA256 hash matches"
    else
        echo "SPKI SHA256 hash does not match"
        exit 1
    fi

    if [[ "$PEER_SIGNATURE" == "rsa" ]]; then
        # check test signature
        # This is only valid with '--algorithm rsa' option
        # openssl v1.1.1 hasn't finished Digital decryptor/encryptor for ecdsa...
        openssl x509 -in "$CERT_CERT_PEM" -noout -pubkey > "${TMP}/pubkey.pem"
        dd if=/dev/urandom of="${TMP}/rnd" bs=32 count=1 status=none
        openssl pkeyutl -sign \
            -inkey "$CERT_KEY_PEM" \
            -in "${TMP}/rnd" \
            -out "${TMP}/sig"
        openssl pkeyutl -verifyrecover \
            -inkey "${TMP}/pubkey.pem" \
            -in "${TMP}/sig" \
            -out "${TMP}/check"
        if cmp -s "${TMP}/check" "${TMP}/rnd"; then
            echo "PKCS PubKey Signature cross-verified"
        else
            echo "PKCS PubKey Signature cross-verify failed"
            exit 1
        fi

        rm -rf "${TMP}"

        CERT_SERIAL_ID_NEXT=$(cat "${PARENT_IA_SERIAL_DB}")
        hex_decrement "$CERT_SERIAL_ID_NEXT"

        CERT_SERIAL_ID_CURRENT="$HEX_VALUE_PREV"
        CA_NEWCERT_CURRENT_PEM="$CERT_NEWCERTS_ARCHIVE_DIR/${CERT_SERIAL_ID_CURRENT}.pem"

        next_pem="$(${OPENSSL_X509} -noout -modulus -in "$CA_NEWCERT_CURRENT_PEM" | ${OPENSSL_MD5})"
        current_pem="$(${OPENSSL_X509} -noout -modulus -in "$CERT_CERT_PEM" | ${OPENSSL_MD5})"
        if [[ "$next_pem" == "$current_pem" ]]; then
            echo "Archive matches"
        else
            echo "Archive mismatch"
            exit 1
        fi
    fi

    echo "CA-NAME $CERT_NAME verified"

}


##########################################################################
# MAIN SCRIPT begins
##########################################################################

# Call getopt to validate the provided input.
options=$(getopt -o a:b:c:fg:hk:m:nTv \
          --long algorithm:,base-dir:,cipher:,force-delete,group:,help,keysize:,message-digest:,nested-ca,traditional,verbose "$@")
RETSTS=$?
[[ ${RETSTS} -eq 0 ]] || {
    echo "Incorrect options provided"
    cmd_show_syntax_usage
    exit 1
}

# Sweep up default values
SSL_DIR="$DEFAULT_SSL_DIR"
# no default CA_NAME, always prompts (or auto-extracts)
# no default filename for the OpenSSL configuration file; always 'openssl.cnf'
SSL_GROUP_NAME="$DEFAULT_GROUP_NAME"   # cannot use bash GROUP(S) reserved word
KEYSIZE_BITS="$DEFAULT_KEYSIZE_BITS"
MESSAGE_DIGEST="$DEFAULT_MESSAGE_DIGEST"
OPENSSL="$DEFAULT_OPENSSL"
PEER_SIGNATURE="$DEFAULT_PEER_SIGNATURE"
STARTING_SERIAL_ID="$DEFAULT_SERIAL_ID_HEX"
SSL_DIR="$DEFAULT_SSL_DIR"
VERBOSITY="$DEFAULT_VERBOSITY"
OFSTD_LAYOUT="$DEFAULT_OFSTD_LAYOUT"
OFSTD_DIR_TREE_TYPE="$DEFAULT_OFSTD_DIR_TREE_TYPE"
FORCE_DELETE_CONFIG=0
CIPHER="$DEFAULT_CIPHER"

eval set -- "${options}"
while true; do
    case "$1" in
    -a|--algorithm)
        shift;
        PEER_SIGNATURE=$1
        [[ ! "$PEER_SIGNATURE" =~ ed25519|ecdsa|rsa|poly1305 ]] && {
            echo "Incorrect algorithm '$PEER_SIGNATURE' option provided"
            echo "Correct options are: rsa (default), ecdsa, ed25519, poly1305"
            exit 1
        }
        ;;
    --base-dir|-b)
        shift;  # The arg is next in position args
        SSL_DIR=$1  # deferred argument checking
        ;;
    -c|--cipher)
        shift;  # The arg is next in position args
        CIPHER=$1
        ;;
    -f|--force-delete)
        FORCE_DELETE_CONFIG=1
        ;;
    -g|--group)
        shift;
        SSL_GROUP_NAME=$1
        ;;
    -h|--help)
        cmd_show_syntax_usage
        ;;
    --keysize|-k)
        shift;
        KEYSIZE_BITS=$1
        ;;
    -m|--message-digest)
        shift;
        MESSAGE_DIGEST=$1
        ;;
    -n|-nested-ca)
        OFSTD_DIR_TREE_TYPE="hierarchy"
        ;;
    -o|--openssl)
        shift;
        OPENSSL=$1
        [[ ! -e "$OPENSSL" ]] && {
            echo "Executable $OPENSSL is not found"
            exit 1
        }
        ;;
    -p|--parent-ca)
        shift;
        ;;
    -T|--traditional)
        OFSTD_LAYOUT="traditional"
        ;;
    -v|--verbose)
        ((VERBOSITY=VERBOSITY+1))
        ;;
    --)
        shift
        break
        ;;
    esac
    shift
done

# 1st argument is always the command
CMD_MODE="${1:-${DEFAULT_CMD_MODE}}"

# 2nd argument is always the cert-name
CERT_NAME="$2"

# 3rd argument depends on the command selected
if [[ "$CMD_MODE" == "renew" ]]; then
  ARGOPT_PARENT_CA_NAME="$3"
elif [[ "$CMD_MODE" == "revoke" ]]; then
  ARGOPT_PARENT_CA_NAME="$3"
  ARGOPT_REASON="$4"
  case "$ARGOPT_REASON" in
    unspecified)
      ;;
    keyCompromise)
      ;;
    CACompromise)
      ;;
    affiliationChanged)
      ;;
    superseded)
      ;;
    cessationOfOperation)
      ;;
    certificateHold)
      ;;
    removeFromCRL)
      ;;
    *)
      cmd_show_syntax_usage
      echo "Error in REASON: '$ARGOPT_REASON' argument."
      echo "Valid options are unspecified, keyCompromise, CACompromise,"
      echo "       affiliationChanged, superseded, cessationOfOperation,"
      echo "       certificateHold, removeFromCRL."
      exit 255
      ;;
  esac
elif [[ "$CMD_MODE" == "create" ]]; then
  ARGOPT_CA_TYPE="$3"
  # root intermediate security component network standalone server client
  # ocsp email identity encryption codesign timestamping
  case "$ARGOPT_CA_TYPE" in
    server)
      CA_TYPE="server"
      ;;
    client)
      CA_TYPE="client"
      ;;
    ocsp)
      CA_TYPE="ocsp"
      ;;
    timestamping)
      CA_TYPE="timestamping"
      ;;
    email)
      CA_TYPE="email"
      ;;
    encryption)
      CA_TYPE="encryption"
      ;;
    codesign)
      CA_TYPE="codesign"
      ;;
    *)
      cmd_show_syntax_usage
      echo "Error in CA-TYPE: '$ARGOPT_CA_TYPE' argument."
      echo "Valid options are server, client, ocsp, timestamping, "
      echo "       email, encryption, codesign"
      exit 255
      ;;
  esac
  CERT_CA_TYPE="$CA_TYPE"
  ARGOPT_PARENT_CA_NAME="$4"
elif [[ "$CMD_MODE" == "verify" ]]; then
  ARGOPT_PARENT_CA_NAME="$3"
else
  cmd_show_syntax_usage
  echo "Valid 1st argument values are: create, renew, revoke, verify"
  exit 255
fi  
PARENT_IA_NAME="$ARGOPT_PARENT_CA_NAME"

# Check group
SYS_GROUP_NAME=$(getent group "${SSL_GROUP_NAME}" | awk -F: '{ print $1}')
if [[ -z "$SYS_GROUP_NAME" ]]; then
  echo "Group name '$SSL_GROUP_NAME' not found in /etc/group file."
  exit 1  # ENOGROUP
fi

SSL_USER_NAME="$DEFAULT_USER_NAME"
#
# Check for sufficient SSL-CERT group privilege
MY_GROUPS="$(groups)"
if [[ ! ("$MY_GROUPS" =~ $SSL_GROUP_NAME ) ]]; then
  echo "You are not in the '$SSL_GROUP_NAME' group;"
  echo "    get yourself ($SSL_USER_NAME) added to the '$SSL_GROUP_NAME' group"
  echo "Perhaps by using this command: "
  echo "    'usermod -a -G $SSL_GROUP_NAME $SSL_USER_NAME'"
  exit 1
fi
[[ ${VERBOSITY} -ne 0 ]] && echo "Group ID: $SSL_GROUP_NAME"

# Never create the /etc/ssl, that's someone else's job
# do not touch /etc/ssl
# We only create directories/files under /etc/ssl
if [[ ! -d "$SSL_DIR" ]]; then
  echo "Directory $SSL_DIR is not found; install openssl package?"
  exit 2 # ENOENT
fi

# ARGOPT_PARENT_CA_NAME has precedence over hidden Root CA name dotfile
if [[ -n "$ARGOPT_PARENT_CA_NAME" ]]; then
    # parent-ca argument given, use it
    # ignore hidden dotfile on current Root CA name
    CURRENT_ROOT_CA_NAME="$ARGOPT_PARENT_CA_NAME"
    PARENT_IA_NAME="$CURRENT_ROOT_CA_NAME"
###    IA_HAS_PARENT="yes"
####else
####    IA_HAS_PARENT="no"
fi

if [[ ${VERBOSITY} -ne 0 ]]; then
  echo "CA Name: $CERT_NAME"
  echo "Root CA Name: $PARENT_IA_NAME"
  echo "Main SSL directory: $SSL_DIR"
  echo "Issuing directory: $CERT_CERTS_DIR"
fi
#

#### IA_URL_BASE="$DEFAULT_CA_X509_URL_BASE"
IA_OPENSSL_CA_OPT=""
X509_COUNTRY="$DEFAULT_CA_X509_COUNTRY"
X509_STATE="$DEFAULT_CA_X509_STATE"
X509_LOCALITY="$DEFAULT_CA_X509_LOCALITY"
X509_COMMON="$DEFAULT_CA_X509_COMMON"
X509_ORG="$DEFAULT_CA_X509_ORG"
X509_OU="$DEFAULT_CA_X509_OU"
X509_EMAIL="$DEFAULT_CA_X509_EMAIL"
X509_URL_BASE="$DEFAULT_CA_X509_URL_BASE"
X509_CRL="$DEFAULT_CA_X509_CRL"

OPENSSL_GENPKEY="$OPENSSL genpkey"
# The OpenSSL options -paramfile and -algorithm are mutually exclusive.
# OPENSSL_ALGORITHM
# MESSAGE_DIGEST
# KEY_SIZE

# OpenSSH can accept private keys from one of the following file formats:
#
#   * raw RSA/PEM format,
#   * RSA/PEM with encryption,
#   * PKCS#8 with no encryption, or
#   * PKCS#8 with encryption (which can be "old-style" or PBKDF2).
#
# For password protection of the private key, against attackers who
# could steal a copy of your private key file, you really want to
# use the last option: PKCS#8 with encryption with PBKDF2.
# Unfortunately, with the openssl command-line tool, you cannot
# configure PBKDF2 much; you cannot choose the hash function
# (that's SHA-1, and that's it -- and that's not a real problem),
# and, more importantly, you cannot choose the iteration count,
# with a default of 2048 which is a bit low for comfort.
#
# You could encrypt your key with some other tool, with a higher
# PBKDF2 iteration count, but I don't know of any readily available
# tool for that. This would be a matter of some programming with
# a crypto library.
#
# A good CA operator would have his own iterator.
#
# In any case, you'd better have a strong password. 15 random
# lowercase letters (easy to type, not that hard to remember)
# will offer 70 bits of entropy, which is quite enough to
# thwart attackers, even when bad password derivation is
# used (iteration count of 1).

# If a cipher is specified then all PEM key files are encrypted with a password
case "$CIPHER" in
  aes128|aes256|"aes-256-cbc"|aes-128-cbc|des-ede3-cbc|camellia-256-cbc)
    # Never use '-pass stdin' for password inputs because it 'echos' keystrokes
    CIPHER_OPTION="-$CIPHER"
    ;;
  "")
    CIPHER_OPTION=
    ;;
  *)
    echo "Invalid ED25519 $CIPHER cipher; valid ciphers are: "
    echo "    aes-256-cbc, aes-128-cbc, des-ede3-cbc and"
    echo "    camellia-256-cbc"
    echo "  See 'openssl list -cipher-algorithms' for supported encryption."
    echo "  See 'openssl cipher -v' for supported encryption."
    exit 1
    ;;
esac

# -m [sha3-256|sha3-224|sha1|sha3-512|md5] ]
# Select algorithm for peer signatures by client/server
if [[ "$PEER_SIGNATURE" == "ed25519" ]]; then
    # MESSAGE_DIGEST max at sha384
    case "$MESSAGE_DIGEST" in
      sha512|sha384|sha256|sha224|sha1|sha3-512|sha3-256|sha3-224|md5)
        MESSAGE_DIGEST="$MESSAGE_DIGEST"
        ;;
      *)
        echo "Invalid ED25519 $MESSAGE_DIGEST digest; valid digests are: "
        echo "    sha3-512, sha3-256, sha3-224, sha1"
        echo "    sha512, sha384, sha256, sha224, md5"
        exit 1
        ;;
    esac
    OPENSSL_ALGORITHM="-algorithm ED25519"
elif [[ "$PEER_SIGNATURE" == "poly1305" ]]; then
    OPENSSL_GENPKEY="$OPENSSL chacha20"
    # OPENSSL_ALGORITHM="-algorithm poly1305"   # That genpkey isn't working yet
    OPENSSL_ALGORITHM=" -p "
    # Ignoring KEYSIZE_BITS
    case "$MESSAGE_DIGEST" in
      des3|sha512|aes128|aes256|chacha20)
        OPENSSL_ALGORITHM="$OPENSSL_ALGORITHM -$MESSAGE_DIGEST"
        ;;
      *)
        echo "Invalid Poly1305 $MESSAGE_DIGEST digest; valid digests are: "
        echo "    chacha20, sha512, aes128, aes256, des3"
        exit 1
        ;;
    esac
elif [[ "$PEER_SIGNATURE" == "rsa" ]]; then
    # MESSAGE_DIGEST max at sha3-512
    case "$MESSAGE_DIGEST" in
      md5|sha1|sha224|sha256| \
      sha3-224|sha3-256|sha3-384| \
      sha3-512|sha384|sha512| \
      sha512-224|sha512-256| \
      ssl3-md5| ssl3-sha1| \
      rsa-sha1|rsa-sha224|rsa-sha256|rsa-sha384|rsa-sha512)
        OPENSSL_ALGORITHM="$OPENSSL_ALGORITHM -$MESSAGE_DIGEST"
        ;;
      *)
        echo "Invalid RSA $MESSAGE_DIGEST digest for REQ; valid digests are: "
        echo "    sha512, sha384, sha256, sha224, sha1, md5,"
        echo "    rsa-sha1, sha3-224, sha3-256, sha3-384, sha3-512,"
        echo "    sha512-224, sha512-256, rsa-sha1, rsa-sha224, rsa-sha256,"
        echo "    rsa-sha384, rsa-sha512."
        exit 1
        ;;
    esac
    if [[ ( "$KEYSIZE_BITS" -ge 512 ) && ( "$KEYSIZE_BITS" -le 8192 ) ]]; then
        OPENSSL_ALGORITHM="-algorithm rsa -pkeyopt rsa_keygen_bits:$KEYSIZE_BITS"
    else
        echo "Invalid RSA $KEYSIZE_BITS keysize; valid size are: "
        echo "    512 thru 8192."
        exit 1
    fi
elif [[ "$PEER_SIGNATURE" == "ecdsa" ]]; then
    case "$KEYSIZE_BITS" in
      521|384|256|224|192)
        # TLDR: don't use -param_enc explicit
        OPENSSL_ALGORITHM="-algorithm EC -pkeyopt ec_paramgen_curve:P-$KEYSIZE_BITS"
        ;;
      *)
        echo "Invalid ECDSA $KEYSIZE_BITS keysize; valid size are: "
        echo "    521, 384, 256, 224 or 192."
        echo "Note: 224 and 192 are not supported by publically trusted CAs"
        exit 1
      ;;
    esac
    case "$MESSAGE_DIGEST" in
      sha1|sha224|sha256)
        MESSAGE_DIGEST="$MESSAGE_DIGEST"
        ;;
      *)
        # Can create ecdsa-des3 key, but cannot make a request certificate
        # Can create ecdsa-aes128 key, but cannot make a request certificate
        # Can create ecdsa-aes256 key, but cannot make a request certificate
        echo "Invalid ECDSA $MESSAGE_DIGEST digest; valid digests are: "
        echo "    sha1, sha224, sha256."
        exit 1
        ;;
    esac
else
  echo "Unsupported PEER_SIGNATURE '$PEER_SIGNATURE'"
  echo "Correct options are: rsa (default), aes, ecdsa, ed25519"
  exit 1
fi
OPENSSL_ALGORITHM="$OPENSSL_ALGORITHM $CIPHER_OPTION"
MESSAGE_DIGEST_CMDOPT="-$MESSAGE_DIGEST"


[[ ${VERBOSITY} -ne 0 ]] && echo "Algorithm: $OPENSSL_ALGORITHM"


directory_file_layout "$OFSTD_LAYOUT" "$OFSTD_DIR_TREE_TYPE" \
                      "$SSL_DIR" "$CERT_NAME" "$PARENT_IA_NAME"

# If parent CA specified, ALWAYS CHECK for parent CA directory
if [[ ! -f "$PARENT_IA_DIR" ]]; then
    if [[ ! -d "$PARENT_IA_DIR" ]]; then
        echo "Parent '$PARENT_IA_NAME' CA directory does not exist"
        echo "Probably forgot '-p root' command line option or something"
        exit 1
    fi
fi

# OpenSSL hardcoded two environment variables: OPENSSL_CONF and SSL_CERT_FILE.
# It's stupid that we have to export this OpenSSL configuration filespec
# If we didn't, it would 'furtively' refer to it's built-in /usr/lib/openssl/openssl.cnf if no '-config' were used as 'strace -f' has shown.
# We shall have full control over what files that OpenSSL will attempts to open.
export OPENSSL_CONF="$CERT_OPENSSL_CNF_REQ_FILE"
export SSL_CERT_FILE="/dev/null"

# Four separate configuration files are needed for a certificate creation
# Two of the files are used during 'openssl req' command:
#  1. Generalized certificate OpenSSL configuration file
#  2. Type-of-Certificate Request Extension file
CERT_OPENSSL_CNF_REQ_FILE="$CERT_EXT_DIR/${PARENT_IA_FNAME}-req-${CERT_FNAME}.cnf"
CERT_OPENSSL_CNF_REQ_EXTFILE="$CERT_EXT_DIR/${PARENT_IA_FNAME}-req-${CERT_FNAME}.extensions.cnf"

#
# Other two files are used during 'openssl ca' command:
#  1. Signing CA main config file (must match to ones created by tls-ca-manage.sh)
#  2. Type-of-Certificate CA Extension file
PARENT_IA_OPENSSL_CNF_CA_FILE="$CERT_EXT_DIR/$PARENT_IA_FNAME.cnf"
PARENT_IA_OPENSSL_CNF_CA_EXTFILE="$CERT_EXT_DIR/$PARENT_IA_FNAME-${CERT_FNAME}.extensions.cnf"
#
# We create three of those files, exactly once despite multiple execution.
# Force (-f) option will help delete those files and replace it with new ones
# This makes it possible to customize these files (until -f option gets used)
#
# We auto-custom 'section_name' between file #1 and #2 in each 'openssl req'
# and 'openssl ca' commands, to tie these two files together.
#
# In 'openssl ca', section name is a simplified parent node name
THIS_SECTION="req_x509_extensions_${PARENT_IA_SNAME}_${CERT_SNAME}"

PARENT_OPENSSL_CNF_REQ_FILE="$CERT_EXT_DIR/cert_req_${CA_TYPE}.cnf"
### CERT_OPENSSL_CNF_EXT_FILE="$CERT_EXT_DIR/${PARENT_IA_FNAME}_cert_x509_extensions_${CERT_FNAME}.cnf"

# Define all the OpenSSL commands
OPENSSL_REQ="$OPENSSL req -config ${CERT_OPENSSL_CNF_REQ_FILE}"
[[ ${VERBOSITY} -ne 0 ]] && OPENSSL_REQ="$OPENSSL_REQ -verbose"
OPENSSL_X509="$OPENSSL x509"
OPENSSL_MD5="$OPENSSL md5"
OPENSSL_CA="$OPENSSL ca -config ${PARENT_IA_OPENSSL_CNF_CA_FILE}"
[[ ${VERBOSITY} -ne 0 ]] && OPENSSL_CA="${OPENSSL_CA} -verbose"
OPENSSL_PKEY="$OPENSSL pkey"
OPENSSL_VERIFY="$OPENSSL verify"

case "$CMD_MODE" in
  verify)
    cmd_verify_cert
    ;;
  create)
    cmd_create_cert
    ;;
  help)
    cmd_show_syntax_usage
    exit 1
    ;;
  renew)
    cmd_renew_cert
    ;;
  revoke)
    cmd_revoke_cert
    ;;
  *)
    echo "Invalid command '$CMD_MODE'"
    cmd_show_syntax_usage
    ;;
esac

echo "Successfully completed; exiting..."

exit 0
