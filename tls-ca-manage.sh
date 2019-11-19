#!/bin/bash
#
# File: tls-ca-manage.sh
#
# Syntax:
#  tls-ca-manage.sh
#        [ --help|-h ]
#        [ --verbosity|-v ]
#        [ --topdir|-t <ssl-directory-path> ]  # (default: /etc/ssl)
#        [ --algorithm|-a [rsa|ed25519|ecdsa|poly1305|aes256|aes512] ]  # (default: rsa)
#        [ --message-digest|-m [sha512|sha384|sha256|sha224|sha1|md5] ]  # (default: sha256)
#        [ --keysize|-k [4096, 2048, 1024, 512, 256] ]  # (default: 2048)
#        [ --serial|-s <num> ]  # (default: 1000)
#        [ --group|-g <group-name> ]  # (default: ssl-cert)
#        [ -p | --parent-ca <parent-ca-name> ]  # (no default)
#        create | renew | revoke | help
#        <ca-name>
#
# Create a top-level or intermediate certificate authority (CA)
#
# Complete with all directories and file protections
#
# LFS/FSSTD:  Single directory for all CA (or a directory for each CA depth?)
#
# Makes one assumption: that the openssl.cnf is ALWAYS the filename (never tweaked)
#                       Just that different directory has different openssl.cnf
#
# Enforces 'ssl-cert' group; and requires all admins to have 'ssl-cert'
#    group when using this command
# DO NOT be giving 'ssl-cert' group to server daemons' supplemental
#    group ID (or worse, as its group ID);
#    for that, you copy the certs over to app-specific directory and use
#    THAT app's file permissions.
# This command does not deal with distribution of certificates, just
#    creation/renewal/revokation of therein.
# 'ssl-cert' group means 'working with SSL/TLS certificates,
#    not just reading certs'.
#
# Inspired by: https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html
#
# Components:
# Public Key Infrastructure (PKI)
#     Security architecture where trust is conveyed through the signature of a trusted CA.
# Certificate Authority (CA)
#     Entity issuing certificates and CRLs.
# Registration Authority (RA)
#     Entity handling PKI enrollment. May be identical with the CA.
# Certificate
#     Public key and ID bound by a CA signature.
# Certificate Signing Request (CSR)
#     Request for certification. Contains public key and ID to be certified.
# Certificate Revocation List (CRL)
#     List of revoked certificates. Issued by a CA at regular intervals.
# Certification Practice Statement (CPS)
#     Document describing structure and processes of a CA.
#
# CA Types:
# Root CA
#     CA at the root of a PKI hierarchy. Issues only CA certificates.
# Intermediate CA
#     CA below the root CA but not a signing CA. Issues only CA certificates.
# Signing CA
#     CA at the bottom of a PKI hierarchy. Issues only user certificates.
#
# Certificate Types:
#
# CA Certificate
#     Certificate of a CA. Used to sign certificates and CRLs.
# Root Certificate
#     Self-signed CA certificate at the root of a PKI hierarchy. Serves as the
#     PKI’s trust anchor.
# Cross Certificate
#     CA certificate issued by a CA external to the primary PKI hierarchy.
#     Used to connect two PKIs and thus usually comes in pairs.
# User Certificate
#     End-user certificate issued for one or more purposes: email-protection, server-auth,
#     client-auth, code-signing, etc. A user certificate cannot sign other certificates.
#
# File Format:
# Privacy Enhanced Mail (PEM)
#    Text format. Base-64 encoded data with header and footer lines. Preferred
#    format in OpenSSL and most software based on it (e.g. Apache mod_ssl, stunnel).
#
# Distinguished Encoding Rules (DER)
#    Binary format. Preferred format in Windows environments. Also the official
#    format for Internet download of certificates and CRLs.  (Not used here)

# Default values (tweakable)
DEFAULT_CMD_MODE="verify"
DEFAULT_GROUP_NAME="ssl-cert"
DEFAULT_KEYSIZE_BITS=4096
DEFAULT_MESSAGE_DIGEST="sha256"
# shellcheck disable=SC2230
DEFAULT_OPENSSL=$(which openssl)
DEFAULT_PEER_SIGNATURE="rsa"
DEFAULT_SERIAL_ID=1000
DEFAULT_SSL_DIR="/etc/ssl"
DEFAULT_VERBOSITY=0
DEFAULT_DRYRUN=0
DEFAULT_USER_NAME=${USER}  # tells most IDE syntax checker to say that $USER is defined
# No DEFAULT_ROOT_CA_NAME
# DEFAULT_INT_CA_NAME="network"
# DEFAULT_SIGNING_CA_NAME="component"

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
DEFAULT_CA_X509_CRL="http://example.invalid/ca/example-crl.crt"
DEFAULT_CA_X509_URL_BASE="https://example.invalid/ca"
DEFAULT_CA_X509_URL_OCSP="http://ocsp.example.invalid:9080"

DEFAULT_INTCA_X509_COUNTRY="US"
DEFAULT_INTCA_X509_STATE=""
DEFAULT_INTCA_X509_LOCALITY=""
DEFAULT_INTCA_X509_COMMON="ACME Internal Intermediate CA B2"
DEFAULT_INTCA_X509_ORG="ACME Networks"
DEFAULT_INTCA_X509_OU="Semi-Trust Department"
DEFAULT_INTCA_X509_EMAIL="ca.subroot@example.invalid"
DEFAULT_INTCA_X509_CRL="https://example.invalid/subroot-ca.crl"
DEFAULT_INTCA_X509_URL_BASE="https://example.invalid/ca/subroot"
DEFAULT_INTCA_X509_URL_OCSP="http://ocsp.example.invalid:9080"


function input_data {
  PROMPT="$1"
  DEFAULT_VALUE="$2"
  echo -n "$1 (default: '$DEFAULT_VALUE'): "
  read -r INPUT_DATA
  if [[ -z "$INPUT_DATA" ]]; then
    INPUT_DATA="$DEFAULT_VALUE"
  fi
  return
}

function directory_file_layout {
    # directory_file_layout arguments:
    #   $1 - Single CA directory Layout (traditional or centralized)
    #   $2 - Multiple CA layout (flat or nested)
    #   $3 - Starting OpenSSL directory
    #   $4 - current issuing authority simplified filename
    # [ $5 - parent issuing authority simplified filename ]

    OFSTD_LAYOUT="$1"  # traditional | centralized
    OFSTD_DIR_TREE_TYPE="$2"  # hierarchy | flat
    SSL_DIR="$3"
    IA_NAME="$4"
    PARENT_IA_NAME="$5"

    PRIVATE_DNAME="private"
    CERTS_DNAME="certs"
    CRL_DNAME="crl"
    DB_DNAME="db"
    NEWCERTS_DNAME="newcerts"

    if [[ "$OFSTD_LAYOUT" == "traditional" ]]; then
        # Template filename
        SSL_SUBDIR_DNAME=""
        DIRNAME_PREFIX="ca-"
        DIRNAME_SUFFIX=""
        FILENAME_PREFIX="ca."
        FILENAME_SUFFIX=""
        PEM_FILETYPE_SUFFIX=".pem"
        SSL_CA_DIR="${SSL_DIR}"

    elif [[ "$OFSTD_LAYOUT" == "centralized" ]]; then
        # Template filename
        SSL_SUBDIR_DNAME="ca"
        DIRNAME_PREFIX=""
        DIRNAME_SUFFIX="-ca"
        FILENAME_PREFIX=""
        FILENAME_SUFFIX="-ca"
        PEM_FILETYPE_SUFFIX=""
        SSL_CA_DIR="${SSL_DIR}/${SSL_SUBDIR_DNAME}"

    else
        echo "Invalid parameter 1 (must be 'traditional' or 'centralized')"
        exit 2
    fi

    # Can reuse 'root' as intermediate name, so we can't peg by-name here
    # Create NO_PARENT flag to track top-level CA usage
    if [[ -z ${PARENT_IA_NAME} ]]; then
        # root CA
        NO_PARENT=1
        IA_CA_TYPE="Parent CA"
        IA_OPENSSL_CNF_EXTENSION="root_ca_ext"
        PARENT_IA_NAME="$IA_NAME"
    else
        # intermediate
        NO_PARENT=0
        IA_CA_TYPE="Intermediate CA"
        IA_OPENSSL_CNF_EXTENSION="intermediate_ca_ext"
    fi

    if [[ "$VERBOSITY" -ne 0 ]]; then
        echo "IA_CA_TYPE: $IA_CA_TYPE"
        echo "PARENT_IA_NAME: $PARENT_IA_NAME"
    fi

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "PARENT_IA_NAME: $PARENT_IA_NAME"
        echo "IA_NAME: $IA_NAME"
    fi

    if [[ "$OFSTD_DIR_TREE_TYPE" == "flat" ]]; then
        # Inspired by readthedocs
        echo ""
        IA_FNAME="${FILENAME_PREFIX}${IA_NAME}${FILENAME_SUFFIX}"
        PARENT_IA_FNAME="${FILENAME_PREFIX}${PARENT_IA_NAME}${FILENAME_SUFFIX}"
        IA_PATH_FNAME="${DIRNAME_PREFIX}${IA_NAME}${DIRNAME_SUFFIX}"
        PARENT_IA_PATH_FNAME="${DIRNAME_PREFIX}${PARENT_IA_NAME}${DIRNAME_SUFFIX}"

        IA_DIR="$SSL_CA_DIR/$IA_PATH_FNAME"
        PARENT_IA_DIR="$SSL_CA_DIR/$PARENT_IA_PATH_FNAME"
    elif [[ "$OFSTD_DIR_TREE_TYPE" == "hierarchy" ]]; then
        # Inspired by traditional OpenSSL
        IA_FNAME="${FILENAME_PREFIX}${IA_NAME}${FILENAME_SUFFIX}"
        PARENT_IA_FNAME="${FILENAME_PREFIX}${PARENT_IA_NAME}${FILENAME_SUFFIX}"
        IA_PATH_FNAME="${DIRNAME_PREFIX}${IA_NAME}${DIRNAME_SUFFIX}"
        PARENT_IA_PATH_FNAME="${DIRNAME_PREFIX}${PARENT_IA_NAME}${DIRNAME_SUFFIX}"

        # If the parent and child names are the same, we'll assume
        if [[ ${NO_PARENT} -eq 1 ]]; then
            # Flatten this CA dir
            IA_DIR="$SSL_CA_DIR/$IA_PATH_FNAME"
        else
            IA_DIR="$SSL_CA_DIR/$PARENT_IA_PATH_FNAME/$IA_PATH_FNAME"
        fi
        PARENT_IA_DIR="$SSL_CA_DIR/$PARENT_IA_PATH_FNAME"
    else
        echo "Invalid parameter 2 (must be 'flat' or 'nested')"
        exit 1
    fi

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "OFSTD_LAYOUT: $OFSTD_LAYOUT"
        echo "OFSTD_DIR_TREE_TYPE: $OFSTD_DIR_TREE_TYPE"
        echo "SSL_CA_DIR: $SSL_CA_DIR"
        echo "IA_FNAME: $IA_FNAME"
        echo "PARENT_IA_FNAME: $PARENT_IA_FNAME"
        echo "IA_DIR: $IA_DIR"
        echo "PARENT_IA_DIR: $PARENT_IA_DIR"
    fi

    IA_DB_DNAME="$DB_DNAME"

    # Define full dirspec paths for all the things associated with this issuing authority (IA)

    if [[ "$OFSTD_LAYOUT" == "traditional" ]]; then
        IA_SERIAL_FNAME="serial"
        IA_INDEX_FNAME="index.txt"
        IA_CRLNUMBER_FNAME="crlnumber"

        PARENT_IA_KEY_DIR="$PARENT_IA_DIR/$PRIVATE_DNAME"
        IA_KEY_DIR="$IA_DIR/$PRIVATE_DNAME"
        IA_CERTS_DIR="$IA_DIR/$CERTS_DNAME"
        PARENT_IA_CERTS_DIR="$PARENT_IA_DIR/$CERTS_DNAME"
        IA_CSR_DIR="$IA_DIR"
        IA_CRL_DIR="$IA_DIR/$CRL_DNAME"
        IA_CHAIN_DIR="$IA_DIR"
        IA_EXT_DIR="$IA_DIR"
        PARENT_IA_EXT_DIR="$PARENT_IA_DIR"
        IA_DB_DIR="$IA_DIR"
        PARENT_IA_DB_DIR="$PARENT_IA_DIR"
        IA_NEWCERTS_ARCHIVE_DIR="$IA_DIR/$NEWCERTS_DNAME"
        PARENT_IA_NEWCERTS_ARCHIVE_DIR="$PARENT_IA_DIR/$NEWCERTS_DNAME"
        IA_INDEX_DB_DIR="$IA_DB_DIR"
        PARENT_IA_INDEX_DB_DIR="$PARENT_IA_DB_DIR"
        IA_SERIAL_DB_DIR="$IA_DB_DIR"
        PARENT_IA_SERIAL_DB_DIR="$PARENT_IA_DB_DIR"
        IA_CRL_DB_DIR="$IA_DB_DIR"
        PARENT_IA_CRL_DB_DIR="$PARENT_IA_DB_DIR"
        IA_OPENSSL_CNF_FNAME="openssl.cnf"
        PARENT_IA_OPENSSL_CNF_FNAME="$IA_OPENSSL_CNF_FNAME"
        IA_OPENSSL_CNF="$IA_EXT_DIR/$IA_OPENSSL_CNF_FNAME"
        PARENT_IA_OPENSSL_CNF="$PARENT_IA_EXT_DIR/$PARENT_IA_OPENSSL_CNF_FNAME"
    else
        PARENT_IA_KEY_DIR="$PARENT_IA_DIR/$PRIVATE_DNAME"
        IA_KEY_DIR="$IA_DIR/$PRIVATE_DNAME"
        IA_CERTS_DIR="$SSL_CA_DIR"
        PARENT_IA_CERTS_DIR="$SSL_CA_DIR"
        IA_CSR_DIR="$SSL_CA_DIR"
        IA_CRL_DIR="$SSL_DIR/$CRL_DNAME"
        IA_CHAIN_DIR="$SSL_CA_DIR"
        IA_EXT_DIR="$SSL_DIR/etc"
        PARENT_IA_EXT_DIR="$IA_EXT_DIR"
        IA_DB_DIR="$IA_DIR/$IA_DB_DNAME"
        PARENT_IA_DB_DIR="$PARENT_IA_DIR/$IA_DB_DNAME"
        IA_NEWCERTS_ARCHIVE_DIR="$IA_DIR"  # where those 000x.pem files go
        PARENT_IA_NEWCERTS_ARCHIVE_DIR="$PARENT_IA_DIR"  # where those 000x.pem files go
        IA_INDEX_DB_DIR="$IA_DIR/$IA_DB_DNAME"
        PARENT_IA_INDEX_DB_DIR="$PARENT_IA_DIR/$IA_DB_DNAME"
        IA_SERIAL_DB_DIR="$IA_DIR/$IA_DB_DNAME"
        PARENT_IA_SERIAL_DB_DIR="$PARENT_IA_DIR/$IA_DB_DNAME"
        IA_CRL_DB_DIR="$IA_DIR/$IA_DB_DNAME"
        PARENT_IA_CRL_DB_DIR="$PARENT_IA_DIR/$IA_DB_DNAME"
        IA_OPENSSL_CNF_FNAME="$IA_FNAME.cnf"
        PARENT_IA_OPENSSL_CNF_FNAME="$PARENT_IA_FNAME.cnf"
        IA_OPENSSL_CNF="$IA_EXT_DIR/$IA_OPENSSL_CNF_FNAME"
        PARENT_IA_OPENSSL_CNF="$PARENT_IA_EXT_DIR/$PARENT_IA_OPENSSL_CNF_FNAME"
    fi

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "IA_SERIAL_FNAME: $IA_SERIAL_FNAME"
        echo "IA_INDEX_FNAME: $IA_INDEX_FNAME"
        echo "IA_CRLNUMBER_FNAME: $IA_CRLNUMBER_FNAME"
        echo "NO_PARENT: $NO_PARENT"

        echo "PARENT_IA_KEY_DIR: $PARENT_IA_KEY_DIR"
        echo "IA_KEY_DIR: $IA_KEY_DIR"
        echo "IA_CERTS_DIR: $IA_CERTS_DIR"
        echo "PARENT_IA_CERTS_DIR: $PARENT_IA_CERTS_DIR"
        echo "IA_CSR_DIR: $IA_CSR_DIR"
        echo "IA_CRL_DIR: $IA_CRL_DIR"
        echo "IA_CHAIN_DIR: $IA_CHAIN_DIR"
        echo "IA_EXT_DIR: $IA_EXT_DIR"
        echo "IA_DB_DIR: $IA_DB_DIR"
        echo "PARENT_IA_DB_DIR: $IA_DB_DIR"
        echo "IA_NEWCERTS_ARCHIVE_DIR: $IA_NEWCERTS_ARCHIVE_DIR"
        echo "PARENT_IA_NEWCERTS_ARCHIVE_DIR: $PARENT_IA_NEWCERTS_ARCHIVE_DIR"
        echo "IA_INDEX_DB_DIR: $IA_INDEX_DB_DIR"
        echo "IA_SERIAL_DB_DIR: $IA_SERIAL_DB_DIR"
        echo "IA_CRL_DB_DIR: $IA_CRL_DB_DIR"
        echo "IA_OPENSSL_CNF: $IA_OPENSSL_CNF"
        echo "PARENT_IA_OPENSSL_CNF: $PARENT_IA_OPENSSL_CNF"
    fi

    if [[ "$OFSTD_LAYOUT" == "traditional" ]]; then
        #PARENT_IA_FNAME_PREFIX="$FILENAME_PREFIX$PARENT_IA_NAME$FILENAME_SUFFIX"
        PARENT_IA_FNAME_PREFIX="cakey"  # It's in another directory
        # IA_FNAME_PREFIX="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX"
        IA_FNAME_PREFIX="cakey"
        # Traditional CSR is user-defined, we automate it here
        CSR_FNAME_PREFIX="ca-csr"
        CERT_FNAME_PREFIX="cacert"
        IA_SERIAL_FNAME="serial"
        IA_INDEX_FNAME="index.txt"
        IA_CRLNUMBER_FNAME="crlnumber"
        PARENT_IA_SERIAL_FNAME="serial"
        PARENT_IA_INDEX_FNAME="index.txt"
        PARENT_IA_CRLNUMBER_FNAME="crlnumber"
        CRL_FNAME_PREFIX="crl"
        CHAIN_FILENAME_MID=".chain"
        CHAIN_FILETYPE_SUFFIX=".pem"
        # CHAIN_FNAME_PREFIX="$FILENAME_PREFIX$IA_NAME$CHAIN_FILENAME_MID$CHAIN_FILENAME_SUFFIX"
        CHAIN_FNAME_PREFIX="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX$CHAIN_FILENAME_MID"

        PARENT_IA_KEY_FNAME="${PARENT_IA_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
        IA_KEY_FNAME="${IA_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    else
        PARENT_IA_FNAME_PREFIX="$FILENAME_PREFIX$PARENT_IA_NAME$FILENAME_SUFFIX.key"
        IA_FNAME_PREFIX="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX.key"
        CSR_FNAME_PREFIX="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX.csr"
        CERT_FNAME_PREFIX="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX.crt"
        PARENT_CERT_FNAME_PREFIX="$FILENAME_PREFIX$PARENT_IA_NAME$FILENAME_SUFFIX.crt"
        IA_SERIAL_FNAME="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX.crt.srl"
        IA_INDEX_FNAME="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX.$DB_DNAME"
        IA_CRLNUMBER_FNAME="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX.crl"
        PARENT_IA_SERIAL_FNAME="$FILENAME_PREFIX$PARENT_IA_NAME$FILENAME_SUFFIX.crt.srl"
        PARENT_IA_INDEX_FNAME="$FILENAME_PREFIX$PARENT_IA_NAME$FILENAME_SUFFIX.$DB_DNAME"
        PARENT_IA_CRLNUMBER_FNAME="$FILENAME_PREFIX$PARENT_IA_NAME$FILENAME_SUFFIX.crl"

        CRL_FNAME_PREFIX="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX.crl"
        CHAIN_FILENAME_MID="-chain"
        CHAIN_FILETYPE_SUFFIX=".pem"
        CHAIN_FNAME_PREFIX="$FILENAME_PREFIX$IA_NAME$FILENAME_SUFFIX$CHAIN_FILENAME_MID"

        IA_KEY_FNAME="${IA_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
        PARENT_IA_KEY_FNAME="${PARENT_IA_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    fi

    IA_CSR_FNAME="${CSR_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    IA_CERT_FNAME="${CERT_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    PARENT_IA_CERT_FNAME="${PARENT_CERT_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    IA_CRL_FNAME="${CRL_FNAME_PREFIX}${PEM_FILETYPE_SUFFIX}"
    IA_CHAIN_FNAME="${CHAIN_FNAME_PREFIX}${CHAIN_FILETYPE_SUFFIX}"

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "PARENT_IA_KEY_FNAME: $PARENT_IA_KEY_FNAME"
        echo "IA_KEY_FNAME: $IA_KEY_FNAME"
        echo "IA_CSR_FNAME: $IA_CSR_FNAME"
        echo "IA_CERT_FNAME: $IA_CERT_FNAME"
        echo "PARENT_IA_CERT_FNAME: $PARENT_IA_CERT_FNAME"
        echo "IA_CRL_FNAME: $IA_CRL_FNAME"
        echo "IA_CHAIN_FNAME: $IA_CHAIN_FNAME"
    fi

    PARENT_IA_KEY_PEM="$PARENT_IA_KEY_DIR/$PARENT_IA_KEY_FNAME${XXX_SERIAL_ID}"
    IA_KEY_PEM="$IA_KEY_DIR/$IA_KEY_FNAME"
    IA_CSR_PEM="$IA_CSR_DIR/$IA_CSR_FNAME"
    IA_CERT_PEM="$IA_CERTS_DIR/$IA_CERT_FNAME"
    PARENT_IA_CERT_PEM="$PARENT_IA_CERTS_DIR/$PARENT_IA_CERT_FNAME"
    IA_CRL_PEM="$IA_CRL_DIR/$IA_CRL_FNAME"
    IA_CHAIN_PEM="$IA_CHAIN_DIR/$IA_CHAIN_FNAME"
    IA_INDEX_DB="$IA_INDEX_DB_DIR/$IA_INDEX_FNAME"
    PARENT_IA_INDEX_DB="$PARENT_IA_INDEX_DB_DIR/$PARENT_IA_INDEX_FNAME"
    IA_SERIAL_DB="$IA_SERIAL_DB_DIR/$IA_SERIAL_FNAME"
    PARENT_IA_SERIAL_DB="$PARENT_IA_SERIAL_DB_DIR/$PARENT_IA_SERIAL_FNAME"
    IA_CRL_DB="$IA_CRL_DB_DIR/$IA_CRLNUMBER_FNAME"
    PARENT_IA_CRL_DB="$PARENT_IA_CRL_DB_DIR/$PARENT_IA_CRLNUMBER_FNAME"

    if [[ "$VERBOSITY" -gt 1 ]]; then
        echo "PARENT_IA_KEY_PEM: $PARENT_IA_KEY_PEM"
        echo "IA_KEY_PEM: $IA_KEY_PEM"
        echo "IA_CSR_PEM: $IA_CSR_PEM"
        echo "IA_CERT_PEM: $IA_CERT_PEM"
        echo "PARENT_IA_CERT_PEM: $PARENT_IA_CERT_PEM"
        echo "IA_CRL_PEM: $IA_CRL_PEM"
        echo "IA_CHAIN_PEM: $IA_CHAIN_PEM"
        echo "IA_INDEX_DB: $IA_INDEX_DB"
        echo "PARENT_IA_INDEX_DB: $PARENT_IA_INDEX_DB"
        echo "IA_SERIAL_DB: $IA_SERIAL_DB"
        echo "PARENT_IA_SERIAL_DB: $PARENT_IA_SERIAL_DB"
        echo "IA_CRL_DB: $IA_CRL_DB"
        echo "PARENT_IA_CRL_DB: $PARENT_IA_CRL_DB"
    fi
    IA_SERIAL_DB="$IA_SERIAL_DB_DIR/$IA_SERIAL_FNAME"
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

function create_ca_directory {
    mkdir "$1"
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0750 "$1"
}

function touch_ca_file {
    TOUCH_THIS_FILE="$1"
    if [[ -d ${TOUCH_THIS_FILE} ]]; then
        # it does wonder to the file system by touching a directory (EXT4 corruption)
        echo "File $TOUCH_THIS_FILE is already directory "
        echo "(and untouchable); aborting..."
        exit 1
    fi
    touch "$1"
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$1"
}

function delete_dir {
    DELETE_DIR="${1:-/tmp/nope}"  # emergency undefined $1 protection
    if [[ -d "$DELETE_DIR" ]]; then
        rm -rf "$DELETE_DIR"
    fi
}

function delete_file {
    DELETE_FILE="${1:-/tmp/nope}"  # emergency undefined $1 protection
    if [[ -f "$DELETE_DIR" ]]; then
        rm "$DELETE_FILE"
    fi
}

function delete_ca_dirfiles {
    delete_file "$IA_KEY_PEM"
    delete_file "$IA_CSR_PEM"
    delete_file "$IA_CERT_PEM"
    delete_file "$IA_CRL_PEM"
    delete_file "$IA_CHAIN_PEM"
    delete_file "$IA_INDEX_DB"
    delete_file "$IA_SERIAL_DB"
    delete_file "$IA_CRL_DB"
    delete_file "$IA_SERIAL_DB"
    delete_file "$IA_SERIAL_DB.old"
    delete_file "$IA_INDEX_DB"
    delete_file "$IA_INDEX_DB.old"
    delete_file "$IA_INDEX_DB.attr"
    delete_file "$IA_INDEX_DB"
    delete_file "$IA_CRL_DB"
    delete_file "$IA_OPENSSL_CNF_EXT"
    delete_dir "$IA_KEY_DIR"

    # Last CA standing
    if [[ "$OFSTD_LAYOUT" == "centralized" ]]; then
        # Make sure it's our matching IA, otherwise bail.
        if [[ -d "$IA_DIR" ]]; then
            CA_COUNT=$(find "$SSL_CA_DIR" -mindepth 1 -maxdepth 1 -type d | wc -l)
            if [[ ${CA_COUNT} -lt 2 ]]; then
                delete_dir "$IA_INDEX_DB_DIR"
                delete_dir "$IA_SERIAL_DB_DIR"
                delete_dir "$IA_DB_DIR"
                delete_dir "$IA_CRL_DB_DIR"
                delete_dir "$IA_CSR_DIR"
                delete_dir "$IA_CERTS_DIR"
                delete_dir "$IA_CHAIN_DIR"
                delete_dir "$IA_EXT_DIR"
                delete_dir "$SSL_CA_DIR"
            fi
            delete_dir "$IA_DIR"
        fi
    elif [[ "$OFSTD_LAYOUT" == "traditional" ]]; then
        # delete_dir $IA_INDEX_DB_DIR
        # delete_dir $IA_SERIAL_DB_DIR
        # delete_dir $IA_DB_DIR
        # delete_dir $IA_CSR_DIR
        delete_dir $IA_CERTS_DIR
        # delete_dir $IA_CRL_DIR
        # delete_dir $IA_CHAIN_DIR
        # delete_dir $IA_CRL_DB_DIR
        delete_dir "$IA_NEWCERTS_ARCHIVE_DIR"
        delete_dir "$IA_DIR"
        # delete_dir $IA_EXT_DIR
    fi
}

function create_ca_dirfiles {
    create_ca_directory "$SSL_CA_DIR"
    create_ca_directory "$IA_DIR"
    create_ca_directory "$IA_EXT_DIR"
    create_ca_directory "$IA_KEY_DIR"
    create_ca_directory "$IA_CSR_DIR"
    create_ca_directory "$IA_CERTS_DIR"
    create_ca_directory "$IA_CRL_DIR"
    create_ca_directory "$IA_CHAIN_DIR"
    create_ca_directory "$IA_DB_DIR"
    create_ca_directory "$IA_INDEX_DB_DIR"
    create_ca_directory "$IA_SERIAL_DB_DIR"
    create_ca_directory "$IA_CRL_DB_DIR"
    create_ca_directory "$IA_NEWCERTS_ARCHIVE_DIR"
    touch_ca_file "$IA_SERIAL_DB"
    touch_ca_file "$IA_INDEX_DB"
    touch_ca_file "$IA_CRL_DB"
}

function data_entry_generic {
    INPUT_DATA=
    input_data "Organization" "$X509_ORG"
    X509_ORG="$INPUT_DATA"
    input_data "Org. Unit/Section/Division: " "$X509_OU"
    X509_OU="$INPUT_DATA"
    input_data "Common Name: " "$X509_COMMON"
    X509_COMMON="$INPUT_DATA"
    input_data "Country (2-char max.): " "$X509_COUNTRY"
    X509_COUNTRY="$INPUT_DATA"
    input_data "State: " "$X509_STATE"
    X509_STATE="$INPUT_DATA"
    input_data "Locality/City: " "$X509_LOCALITY"
    X509_LOCALITY="$INPUT_DATA"
    input_data "Contact email: " "$X509_EMAIL"
    X509_EMAIL="$INPUT_DATA"
    input_data "Base URL: " "$X509_URL_BASE"
    X509_URL="$INPUT_DATA"
    input_data "CRL URL: " "$X509_CRL"
    X509_CRL="$INPUT_DATA"
}

function cmd_show_syntax_usage {
    echo """
Usage:  $0
        [ --help|-h ]
        [ --verbosity|-v ]
        [ --base-dir|-b <ssl-directory-path> ]  # (default: $DEFAULT_SSL_DIR)
        [ --algorithm|-a [rsa|ed25519|rsa|ecdsa|poly1305|aes256|aes512] ]  # (default: $DEFAULT_PEER_SIGNATURE)
        [ --message-digest|-m [sha512|sha384|sha256|sha224|sha3-256|
                               sha3-224|sha3-512|sha1|md5] ]  # (default: sha256)
        [ --keysize|-k [4096, 2048, 1024, 512, 256] ]  # (default: $DEFAULT_KEYSIZE_BITS)
        [ --serial|-s <num> ]  # (default: $DEFAULT_SERIAL_ID)
        [ --group|-g <group-name> ]  # (default: $DEFAULT_GROUP_NAME)
        [ --openssl|-o <openssl-binary-filespec ]  # (default: $OPENSSL)
        [ --traditional|-t ]
        [ --parent-ca|-p ]
        [ --dry-run|-d ]
        create | renew | revoke | verify | help
        <ca-name>
"""
  exit 1
}

function openssl_cnf_create_root_ca
{
  echo "Creating $IA_OPENSSL_CNF file..."
  echo """
# ${IA_NAME} Intermediate TLS CA

dir                     = ${IA_DIR}             # Top dir
base_url                = ${IA_URL_BASE}        # CA base URL
aia_url                 = ${IA_URL_BASE}/${IA_CERT_FNAME}     # CA certificate URL
crl_url                 = ${IA_URL_BASE}/${IA_CRL_FNAME}     # CRL distribution point
name_opt                = multiline,-esc_msb,utf8 # Display UTF-8 characters

# openssl_conf - Special OpenSSL module (required)
openssl_conf            = openssl_init

# CA certificate request
[ req ]
default_bits            = ${KEYSIZE_BITS}       # RSA key size
encrypt_key             = yes                   # Protect private key
default_md              = ${MESSAGE_DIGEST}     # MD to use
utf8                    = yes                   # Input is UTF-8
string_mask             = utf8only              # Emit UTF-8 strings
prompt                  = no                    # Don't prompt for DN
distinguished_name      = ca_dn                 # DN section
req_extensions          = ca_reqext             # Desired extensions

[ ca_dn ]
countryName             = "${X509_COUNTRY}"
organizationName        = "${X509_ORG}"
organizationalUnitName  = "${X509_OU}"
commonName              = "${X509_COMMON}"

[ ca_reqext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash

# CA operational settings

[ ca ]
default_ca              = root_ca               # The default CA section

[ root_ca ]
certificate             = ${IA_CERT_PEM}        # The CA cert
private_key             = ${IA_KEY_PEM}         # CA private key
new_certs_dir           = ${IA_NEWCERTS_ARCHIVE_DIR} # Certificate archive
serial                  = ${IA_SERIAL_DB}       # Serial number file
crlnumber               = ${IA_CRL_DB}          # CRL number file
database                = ${IA_INDEX_DB}        # Index file
unique_subject          = no                    # Require unique subject
default_days            = 3652                  # How long to certify for
default_md              = sha256                # MD to use
policy                  = match_pol             # Default naming policy
email_in_dn             = no                    # Add email to cert DN
preserve                = no                    # Keep passed DN ordering
# name_opt                = \$name_opt             # Subject DN display options
cert_opt                = ca_default            # Certificate display options
copy_extensions         = none                  # Copy extensions from CSR
x509_extensions         = intermediate_ca_ext   # Default cert extensions
default_crl_days        = 30                    # How long before next CRL
crl_extensions          = crl_ext               # CRL extensions

[ match_pol ]
countryName             = match
stateOrProvinceName     = optional
localityName            = optional
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied

[ any_pol ]
domainComponent         = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

# Extensions

[ root_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
# DO NOT INCLUDE authorityInfoAccess in ROOT CA; causes PRQP lookup-loop

[ intermediate_ca_ext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:0
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info
crlDistributionPoints   = @crl_info

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info

[ issuer_info ]
caIssuers;URI.0         = \$aia_url

[ crl_info ]
URI.0                   = \$crl_url

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2
RSA.Certificate = server-rsa.pem
ECDSA.Certificate = server-ecdsa.pem


""" > "$IA_OPENSSL_CNF"
  echo "Created $IA_CA_TYPE $IA_OPENSSL_CNF file"
}

function openssl_cnf_create_intermediate_ca
{
  echo "Creating $IA_OPENSSL_CNF file..."
  echo """
# ${IA_NAME} Intermediate TLS CA

[ default ]
dir                     = ${IA_DIR}             # Top dir
base_url                = ${IA_URL_BASE}        # CA base URL
aia_url                 = ${IA_URL_BASE}/${IA_CHAIN_FNAME}     # CA certificate URL
crl_url                 = ${IA_URL_BASE}/${IA_CRL_FNAME}     # CRL distribution point
name_opt                = multiline,-esc_msb,utf8 # Display UTF-8 characters

# openssl_conf - Special OpenSSL module (required)
openssl_conf            = openssl_init

# CA certificate request
[ req ]
default_bits            = ${KEYSIZE_BITS}       # RSA key size
encrypt_key             = yes                   # Protect private key
default_md              = ${MESSAGE_DIGEST}     # MD to use
utf8                    = yes                   # Input is UTF-8
string_mask             = utf8only              # Emit UTF-8 strings
prompt                  = no                    # Don't prompt for DN
distinguished_name      = ca_dn                 # DN section
req_extensions          = ca_reqext             # Desired extensions

[ ca_dn ]
countryName             = "${X509_COUNTRY}"
organizationName        = "${X509_ORG}"
organizationalUnitName  = "${X509_OU}"
commonName              = "${X509_COMMON}"

[ ca_reqext ]
keyUsage                = critical,keyCertSign,cRLSign
basicConstraints        = critical,CA:true,pathlen:0
subjectKeyIdentifier    = hash

# CA operational settings

[ ca ]
default_ca              = tls_ca                # The default CA section

[ tls_ca ]
certificate             = ${IA_CERT_PEM}        # The CA cert
private_key             = ${IA_KEY_PEM}         # CA private key
new_certs_dir           = ${IA_NEWCERTS_ARCHIVE_DIR}          # Certificate archive
serial                  = ${IA_SERIAL_DB}       # Serial number file
crlnumber               = ${IA_CRL_DB}          # CRL number file
database                = ${IA_INDEX_DB}        # Index file
unique_subject          = no                    # Require unique subject
default_days            = 730                   # How long to certify for
default_md              = sha256                # MD to use
policy                  = match_pol             # Default naming policy
email_in_dn             = no                    # Add email to cert DN
preserve                = no                    # Keep passed DN ordering
name_opt                = \$name_opt             # Subject DN display options
cert_opt                = ca_default            # Certificate display options
copy_extensions         = copy                  # Copy extensions from CSR
x509_extensions         = server_ext            # Default cert extensions
default_crl_days        = 1                     # How long before next CRL
crl_extensions          = crl_ext               # CRL extensions

[ match_pol ]
countryName             = match                 # Must match 'NO'
stateOrProvinceName     = optional              # Included if present
localityName            = optional              # Included if present
organizationName        = match                 # Must match 'Green AS'
organizationalUnitName  = optional              # Included if present
commonName              = supplied              # Must be present

[ extern_pol ]
countryName             = supplied              # Must be present
stateOrProvinceName     = optional              # Included if present
localityName            = optional              # Included if present
organizationName        = supplied              # Must be present
organizationalUnitName  = optional              # Included if present
commonName              = supplied              # Must be present

[ any_pol ]
domainComponent         = optional
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = optional
emailAddress            = optional

# Extensions

[ server_ext ]
keyUsage                = critical,digitalSignature,keyEncipherment
basicConstraints        = CA:false
extendedKeyUsage        = serverAuth,clientAuth
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info
crlDistributionPoints   = @crl_info

[ client_ext ]
keyUsage                = critical,digitalSignature
basicConstraints        = CA:false
extendedKeyUsage        = clientAuth
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info
crlDistributionPoints   = @crl_info

[ crl_ext ]
authorityKeyIdentifier  = keyid:always
authorityInfoAccess     = @issuer_info

[ issuer_info ]
caIssuers;URI.0         = \$aia_url

[ crl_info ]
URI.0                   = \$crl_url

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.2
CipherString = DEFAULT@SECLEVEL=2
RSA.Certificate = server-rsa.pem
ECDSA.Certificate = server-ecdsa.pem

""" > "$IA_OPENSSL_CNF"
  echo "Created $IA_CA_TYPE $IA_OPENSSL_CNF file"
}

#########################################################
# Create the public key for a CA node                   #
#########################################################
function ca_create_public_key
{
    # pre-privacy
    touch "$IA_KEY_PEM"
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_KEY_PEM"

    ${OPENSSL_GENPKEY} \
        ${OPENSSL_ALGORITHM} \
        -outform PEM \
        -text \
        -out "${IA_KEY_PEM}"

    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl genpkey'; aborting..."
        exit ${RETSTS}
    fi
    if [[ ! -f "$IA_KEY_PEM" ]]; then
        echo "Failed to create private key for $IA_CA_TYPE ($IA_KEY_PEM)"
        exit 126 # ENOKEY
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_KEY_PEM"

    if [[ ${VERBOSITY} -ne 0 ]]; then
        # View the private key in readable format
        openssl asn1parse -in "$IA_KEY_PEM"
        openssl pkey \
            -in "$IA_KEY_PEM" \
            -noout \
            -text
    fi
}

#########################################################
# Create the CA node's signing request certificate      #
#########################################################
function ca_create_csr
{
    ${OPENSSL_REQ} -new \
        -key "$IA_KEY_PEM" \
        -"$MESSAGE_DIGEST" \
        -out "$IA_CSR_PEM"
        # -subj "/C=${X509_COUNTRY}/CN=${X509_COMMON}/O=${X509_ORG}/OU=${X509_OU}" \
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl req'; aborting..."
        exit ${RETSTS}
    fi
    if [[ ! -f "$IA_CSR_PEM" ]]; then
        echo "Failed to create signing request for $IA_CA_TYPE ($IA_CSR_PEM)"
        exit 2 # ENOENT
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_CSR_PEM"

    if [[ ${VERBOSITY} -ne 0 ]]; then
        # View the CSR in readable format
        openssl asn1parse -in "$IA_CSR_PEM"
        openssl req -in "$IA_CSR_PEM" -noout -text
    fi
}

###############################################
# Parent CA accept CA node's CSR by trusting  #
###############################################
function ca_create_certificate {
    echo "Creating $IA_CA_TYPE certificate ..."
    ${OPENSSL_CA} \
        -batch \
        ${IA_OPENSSL_CA_OPT} \
        -extensions ${IA_OPENSSL_CNF_EXTENSION} \
        -in "$IA_CSR_PEM" \
        -days 3650 \
        -md "$MESSAGE_DIGEST" \
        -key "$PARENT_IA_KEY_PEM" \
        -out "$IA_CERT_PEM"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl ca'"
        exit ${RETSTS}
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_CERT_PEM"

    # bundle chains are made only in non-root depth mode
    if [[ "$DEPTH_MODE" != "root" ]]; then
        echo "Creating $IA_CA_TYPE chain certificate ..."
        echo "cat ${IA_CERT_PEM} ${PARENT_IA_CERT_PEM} > ${IA_CHAIN_PEM}"
        cat ${IA_CERT_PEM} ${PARENT_IA_CERT_PEM} > ${IA_CHAIN_PEM}
        change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_CHAIN_PEM"
    fi
}

function ca_create_revocation_list
{
    echo "Creating $IA_CA_TYPE certificate revocation list (CRL)..."
    ${OPENSSL_CA} \
        -gencrl \
        -config "$IA_OPENSSL_CNF" \
        -out "$IA_CRL_PEM"
}

function ca_extract_signing_request
{
    ###########################################################
    # Extract existing Root Certificate Authority Certificate #
    ###########################################################
    # We are at the mercy of CA_CERT_PEM being the latest
    # and ALSO in its index.txt file as well.
    ${OPENSSL_X509} -x509toreq \
       -in "$IA_CERT_PEM" \
       -signkey "$IA_KEY_PEM" \
       -out "$IA_CSR_PEM"
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl x509 -x509toreq'; aborting..."
        exit ${RETSTS}
    fi
    if [[ ! -f "$IA_CSR_PEM" ]]; then
        echo "Failed to recreate request key from $IA_CA_TYPE ($IA_CSR_PEM)"
        exit 2 #ENOENT
    fi
    if [[ ${VERBOSITY} -ne 0 ]]; then
        openssl asn1parse -in "$IA_CSR_PEM"
        openssl req -noout -text -in "$IA_CSR_PEM"
    fi
}

###########################################################
# Request renewal of this Issuing Authority               #
###########################################################
function ca_renew_certificate
{
    RENEW_EXT_FILE="$1"
    # DO NOT USE 'openssl x509', because lack of DB accounting
    ${OPENSSL_CA} \
        -verbose \
        ${IA_OPENSSL_CA_OPT} \
        -extfile "$RENEW_EXT_FILE" \
        -extensions "$IA_OPENSSL_CNF_EXTENSION" \
        -days 1095 \
        -in "$IA_CSR_PEM" \
        -out "$IA_CERT_PEM"
        # -keyfile "$PARENT_IA_KEY_PEM" \
    RETSTS=$?
    if [[ ${RETSTS} -ne 0 ]]; then
        echo "Error $RETSTS in 'openssl ca'; aborting..."
        exit ${RETSTS}
    fi
    if [[ ! -f "$IA_CERT_PEM" ]]; then
        echo "Failed to recreate $IA_CA_TYPE certificate ($IA_CERT_PEM}"
        exit 2 # ENOENT
    fi
}

function ca_create_chain_certificate
{
    # chains are made only in non-root depth mode
    if [[ "$DEPTH_MODE" != "root" ]]; then
        echo "Creating $IA_CA_TYPE chain certificate ..."
        cat ${IA_CERT_PEM} ${PARENT_IA_CERT_PEM} > ${IA_CHAIN_PEM}
    fi
}

function ca_serialization_and_unique_filenames
{
    IA_SERIAL_ID_CURRENT=`cat ${IA_SERIAL_DB}`
    ((IA_SERIAL_ID_OLD=$IA_SERIAL_ID_CURRENT-1))
    ((IA_SERIAL_ID_NEXT=$IA_SERIAL_ID_CURRENT+1))
    CA_NEWCERT_SERIAL_NEXT_PEM="$IA_NEWCERTS_ARCHIVE_DIR/${IA_SERIAL_ID_CURRENT}.pem"
    CA_NEWCERT_SERIAL_PREV_PEM="$IA_NEWCERTS_ARCHIVE_DIR/${IA_SERIAL_ID_OLD}.pem"

    # TODO: This is where you insert serial no. into various filenames
    #       Probably want to serialize the private keys as well
    #       so you can save them.  But these oldie keys should be GONE!
    #       It's practically useless from a forensic POV to keep old keys
}

##################################################
# Display in human-readable format a certificate #
##################################################
function display_ca_certificate {
    THIS_PEM="$1"
    echo "Displaying MD5 of various CA certificates:"
    echo "$(${OPENSSL_X509} -noout -modulus -in "$THIS_PEM" | ${OPENSSL_MD5}) $THIS_PEM"

    if [[ "$VERBOSITY" -ne 0 ]]; then
        echo "Decoding $IA_CA_TYPE certificate:"
        ${OPENSSL_X509} -in "$THIS_PEM" -noout -text
    else
        echo "To see decoded $IA_CA_TYPE certificate, execute:"
        echo "  $OPENSSL_X509 -in $THIS_PEM -noout -text"
    fi
}

##################################################
# CLI create command                             #
##################################################
function cmd_create_ca {

    [[ ${VERBOSITY} -ne 0 ]] && echo "Creating $IA_CA_TYPE certificate..."
    # Yeah, yeah, yeah; destructive but this is a new infrastructure
    if [[ -d "$IA_DIR" ]]; then
        echo "WHOA! Directory $IA_DIR already exist."
        echo -n "Do you want to mass-delete $IA_DIR old-stuff? (N/yes): "
        read -r DELETE_IA_DIR
        if [[ "$DELETE_IA_DIR" =~ y|yes|Y|YES ]]; then
            echo -n "Asking again: Do you want to mass-delete $IA_DIR? (N/yes): "
            read -r DELETE_IA_DIR
            if [[ "$DELETE_IA_DIR" =~ y|yes|Y|YES ]]; then
                if [[ -d "$IA_DIR" ]]; then
                    delete_ca_dirfiles
                else
                    echo "Path '$IA_DIR' is not a directory; Exiting..."; exit 1
                fi
            else
                echo "Exiting..."; exit 1
            fi
        else
            echo "Exiting..."; exit 1
        fi
    fi

    if [[ ! -e "$SSL_CA_DIR" ]]; then
        CREATE_IA_DIR=
        echo -n "Create $SSL_CA_DIR subdirectory? (Y/n): "
        read -r CREATE_IA_DIR
        if [[ "$CREATE_IA_DIR" =~ y|yes|Y|YES ]]; then
            mkdir "$SSL_CA_DIR"
            RETSTS=$?
            [[ ${RETSTS} -ne 0 ]] && echo "Unable to create $SSL_CA_DIR subdirectory; aborting..." && exit 13  # EACCESS
            [[ ${VERBOSITY} -ne 0 ]] && echo "Created $SSL_CA_DIR directory"
        else
            echo "Exiting..."
            exit 1
        fi
    else
        if [[ ! -d "$SSL_CA_DIR" ]]; then
            echo "File '$SSL_CA_DIR' is not a directory."
            exit 1
        fi
    fi
    create_ca_dirfiles

    [[ ${VERBOSITY} -ne 0 ]] &&  echo "$IA_CA_TYPE subdirectory:  $(ls -1lad "$SSL_CA_DIR"/)"

    cd "$SSL_CA_DIR" || exit 65  # ENOPKG

    # Clone OpenSSL configuration file into CA-specific subdirectory
    if [[ ! -f "$IA_OPENSSL_CNF" ]]; then
        # Clone from default /etc/ssl/openssl.cnf
        echo "$IA_OPENSSL_CNF file is missing, recreating ..."
        data_entry_generic
        if [[ -z "$IA_CERT_PEM" ]]; then
            echo "WHOA NELLY!"
            exit 2
        fi
        if [[ "$DEPTH_MODE" == "intermediate" ]]; then
            openssl_cnf_create_intermediate_ca
        else
            openssl_cnf_create_root_ca
        fi
    fi

    # OpenSSL serial accounting
    echo "$STARTING_SERIAL_ID" > "$IA_SERIAL_DB"
    echo "$STARTING_SERIAL_ID" > "$IA_CRL_DB"

    ca_serialization_and_unique_filenames
    [[ ${VERBOSITY} -ne 0 ]] && echo "Serial ID (starting): $IA_SERIAL_ID_CURRENT"

    [[ "$VERBOSITY" -ne 0 ]] && echo "Creating $IA_CA_TYPE private key ..."

    ca_create_public_key

    ca_create_csr

    ca_create_certificate

    ca_create_revocation_list

    # Clean up
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_INDEX_DB"
    if [[ -f "$IA_INDEX_DB.old" ]]; then
        change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_INDEX_DB.old"
    fi
    if [[ -f "$IA_INDEX_DB.attr" ]]; then
        change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_INDEX_DB.attr"
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_SERIAL_DB"
    if [[ -f "$IA_SERIAL_DB.old" ]]; then
        change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$IA_SERIAL_DB.old"
    fi
    change_owner_perm "$SSL_USER_NAME" "$SSL_GROUP_NAME" 0640 "$PARENT_IA_NEWCERTS_ARCHIVE_DIR"/"$STARTING_SERIAL_ID".pem

    display_ca_certificate "$IA_CERT_PEM"

    echo "Created the following files:"
    echo "  $IA_CA_TYPE cert req   : $IA_CSR_PEM"
    echo "  $IA_CA_TYPE certificate: $IA_CERT_PEM"
    echo "  $IA_CA_TYPE private key: $IA_KEY_PEM"
    echo "  $IA_CA_TYPE new cert   : $IA_NEWCERTS_ARCHIVE_DIR/$STARTING_SERIAL_ID.pem"
    if [[ "$DEPTH_MODE" != "root" ]]; then
        echo "  $IA_CA_TYPE chain cert : $IA_CHAIN_PEM"
    fi
    echo "  $IA_CA_TYPE CRL        : $IA_CRL_PEM"
}


##################################################
# CLI renew command                              #
##################################################
function cmd_renew_ca {

    ca_serialization_and_unqiue_filenames

    [[ ${VERBOSITY} -ne 0 ]] && echo "Calling renew certificate..."
    if [[ ! -f "$PARENT_IA_SERIAL_DB" ]]; then
        echo "Serial ID ($PARENT_IA_SERIAL_DB) file is missing; aborting..."; exit 1
    fi
    if [[ ! -f "$PARENT_IA_CRL_DB" ]]; then
        echo "CRL number ($PARENT_IA_CRL_DB) file is missing; aborting..."; exit 1
    fi
    # Check IA
    if [[ ! -e "$IA_DIR" ]]; then
        echo "No $IA_DIR directory found; run tls-create-ca-infrastructure.sh"
        exit 2 # ENOENT
    else
        if [[ ! -d "$IA_DIR" ]]; then
            echo "File '$IA_DIR' is not a directory."
            exit 2
        fi
    fi
    # Check PARENT_IA
    if [[ "$NO_PARENT" -ne 1 ]]; then
        if [[ ! -e "$PARENT_IA_DIR" ]]; then
            echo "No $PARENT_IA_DIR directory found; run tls-create-ca-infrastructure.sh"
            exit 2 # ENOENT
        else
            if [[ ! -d "$PARENT_IA_DIR" ]]; then
                echo "File '$PARENT_IA_DIR' is not a directory."
                exit 2
            fi
        fi
    fi
    [[ ${VERBOSITY} -ne 0 ]] && echo "CA subdirectory:  `ls -1lad ${IA_DIR}/`"

    for THIS_DIR in ${IA_CERTS_DIR} ${IA_KEY_DIR} ${IA_NEWCERTS_ARCHIVE_DIR} ${IA_CRL_DIR}; do
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

    # OpenSSL serial accounting
    touch "$IA_INDEX_DB"

    ca_extract_signing_request

    ###########################################################
    # Create new v3_ca                                        #
    ###########################################################
    PARENT_IA_OPENSSL_CNF_EXT="$PARENT_IA_OPENSSL_CNF-ca_ext"
    echo "PARENT_IA_OPENSSL_CNF_EXT: $PARENT_IA_OPENSSL_CNF_EXT"
    echo """
    [ root_ca_ext ]
    basicConstraints= critical,CA:TRUE
    subjectKeyIdentifier= hash
    keyUsage= critical, digitalSignature, cRLSign, keyCertSign
    authorityKeyIdentifier= keyid:always,issuer:always
    # Do not create authorityInfoAccess in ROOT CA; causes PRQP lookup-loops

    [ intermediate_ca_ext ]
    basicConstraints= critical,CA:TRUE,pathlen:0
    subjectKeyIdentifier= hash
    keyUsage= critical, digitalSignature, cRLSign, keyCertSign
    # extendedKeyUsage= critical, serverAuth, oCSPSigning, ipsecIKE
    authorityKeyIdentifier= keyid:always,issuer:always
    authorityInfoAccess = caIssuers;URI:${IA_URL_BASE}/${IA_CHAIN_FNAME}.cer
    crlDistributionPoints = URI:${IA_URL_BASE}/${IA_CERT_FNAME}.crl
    issuerAltName= issuer:copy

    """ > "$PARENT_IA_OPENSSL_CNF_EXT"

    ca_renew_certificate "$PARENT_IA_OPENSSL_CNF_EXT"

    ca_create_chain_certificate

    ca_create_revocation_list

    display_ca_certificate "$IA_CERT_PEM"

    echo "Created the following files:"
    echo "  $IA_CA_TYPE cert req   : $IA_CSR_PEM"
    echo "  $IA_CA_TYPE certificate: $IA_CERT_PEM"
    echo "  $IA_CA_TYPE private key: $IA_KEY_PEM"
    echo "  $IA_CA_TYPE new cert   : $IA_NEWCERTS_ARCHIVE_DIR/$IA_SERIAL_ID_NEXT.pem"
    echo "  $IA_CA_TYPE chain cert : $IA_CHAIN_PEM"
    echo "  $IA_CA_TYPE CRL        : $IA_CRL_PEM"
    echo "  $IA_CA_TYPE extension  : $PARENT_IA_OPENSSL_CNF_EXT"
}

##################################################
# CLI verify command                             #
##################################################
function cmd_verify_ca {
  [[ ${VERBOSITY} -ne 0 ]] && echo "Calling verify certificate..."
    openssl x509 -noout -text -in "$IA_CERT_PEM"

    IA_SERIAL_ID_CURRENT=`cat ${IA_SERIAL_DB}`
    ((IA_SERIAL_ID_OLD=$IA_SERIAL_ID_CURRENT-1))
    ((IA_SERIAL_ID_NEXT=$IA_SERIAL_ID_CURRENT+1))
    CA_NEWCERT_SERIAL_PREV_PEM="$IA_NEWCERTS_ARCHIVE_DIR/${IA_SERIAL_ID_OLD}.pem"
    CA_NEWCERT_SERIAL_NEXT_PEM="$IA_NEWCERTS_ARCHIVE_DIR/${IA_SERIAL_ID_NEXT}.pem"

    ${OPENSSL_X509} -noout -modulus -in "$CA_NEWCERT_SERIAL_PREV_PEM" | ${OPENSSL_MD5}
    ${OPENSSL_X509} -noout -modulus -in "$CA_NEWCERT_SERIAL_NEXT_PEM" | ${OPENSSL_MD5}
    ${OPENSSL_X509} -noout -modulus -in "$IA_CERT_PEM" | ${OPENSSL_MD5}
    echo "$(${OPENSSL_PKEY} -in "$IA_KEY_PEM" | ${OPENSSL_MD5}) $IA_KEY_PEM"
}


##########################################################################
# MAIN SCRIPT begins
##########################################################################

# Call getopt to validate the provided input.
options=$(getopt -o p:hvb:a:m:nk:c:s:g:t \
          --long parent-ca:,help,verbosity,base-dir:,algorithm:,message-digest:,nested-ca,keysize:,config:,serial:,group:,traditional -- "$@")
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
STARTING_SERIAL_ID="$DEFAULT_SERIAL_ID"
SSL_DIR="$DEFAULT_SSL_DIR"
VERBOSITY="$DEFAULT_VERBOSITY"
OFSTD_LAYOUT="$DEFAULT_OFSTD_LAYOUT"
OFSTD_DIR_TREE_TYPE="$DEFAULT_OFSTD_DIR_TREE_TYPE"
DEPTH_MODE="root"

eval set -- ${options}
while true; do
    case "$1" in
    -h|--help)
        cmd_show_syntax_usage
        ;;
    -v|--verbosity)
        ((VERBOSITY=VERBOSITY+1))
        ;;
    --base-dir|-b)
        shift;  # The arg is next in position args
        SSL_DIR=$1  # deferred argument checking
        ;;
    --traditional|-t)
        OFSTD_LAYOUT="traditional"
        ;;
    -a|--algorithm)
        shift;
        PEER_SIGNATURE=$1
        [[ ! "$PEER_SIGNATURE" =~ aes|ed25519|ecdsa|rsa|poly1305 ]] && {
            echo "Incorrect algorithm '$PEER_SIGNATURE' option provided"
            echo "Correct options are: rsa (default), aes, ecdsa, ed25519, poly1305"
            exit 1
        }
        ;;
    -m|--message-digest)
        shift;
        MESSAGE_DIGEST=$1
        # Parital from 'openssl list -digest-algorithms'
        # Validate this later because ordering of -m option is
        ;;
    -n|-nested-ca)
        OFSTD_DIR_TREE_TYPE="hierarchy"
        ;;
    --keysize|-k)
        shift;
        KEYSIZE_BITS=$1
        ;;
    -s|--serial)
        shift;  # The arg is next in position args
        STARTING_SERIAL_ID=$1
        ;;
    -g|--group)
        shift;
        SSL_GROUP_NAME=$1
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
        ARGOPT_PARENT_CA_NAME="$1"
        ;;
    --)
        shift
        break
        ;;
    esac
    shift
done
CMD_MODE="${1:-${DEFAULT_CMD_MODE}}"
IA_NAME="${2}"
# No DEFAULT_ROOT_CA_NAME

if [[ -z "$1" || -z "$2" ]]; then
    cmd_show_syntax_usage
fi

# Check group
SYS_GROUP_NAME=$(getent group ${SSL_GROUP_NAME} | awk -F: '{ print $1}')
if [[ -z "$SYS_GROUP_NAME" ]]; then
  echo "Group name '$SSL_GROUP_NAME' not found in /etc/group file."
  exit 1  # ENOGROUP
fi

SSL_USER_NAME="$DEFAULT_USER_NAME"
#
# Check for sufficient SSL-CERT group privilege
MY_GROUPS="$(groups)"
if [[ ! ("$MY_GROUPS" =~ "$SSL_GROUP_NAME" ) ]]; then
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
if [[ ! -z "$ARGOPT_PARENT_CA_NAME" ]]; then
    # parent-ca argument given, use it
    # ignore hidden dotfile on current Root CA name
    CURRENT_ROOT_CA_NAME="$ARGOPT_PARENT_CA_NAME"
    DEPTH_MODE="intermediate"
    PARENT_IA_NAME="$CURRENT_ROOT_CA_NAME"
fi

# Check for oddball case that parent and ca have same name
if [[ ! -z "$CURRENT_ROOT_CA_NAME" ]]; then
    if [[ "$IA_NAME" == "$CURRENT_ROOT_CA_NAME" ]]; then
        DEPTH_MODE="root"
        PARENT_IA_NAME=""
    fi
fi

if [[ ${VERBOSITY} -ne 0 ]]; then
  echo "CA Name: $IA_NAME"
  echo "Root CA Name: $PARENT_IA_NAME"
  echo "Depth mode: $DEPTH_MODE"
  echo "Main SSL directory: $SSL_DIR"
  echo "Issuing directory: $IA_DIR"
fi
#
#  There's 3-sets of variables: issuing authority (IA), Root CA, and intermediate CA
#  Issuing authority is the active working set of variables

# Ok, which depth mode are we in to work on as issuing authority?
if [[ "$DEPTH_MODE" == "intermediate" ]]; then
  IA_URL_BASE="$DEFAULT_INTCA_X509_URL_BASE"
  X509_COUNTRY="$DEFAULT_INTCA_X509_COUNTRY"
  X509_STATE="$DEFAULT_INTCA_X509_STATE"
  X509_LOCALITY="$DEFAULT_INTCA_X509_LOCALITY"
  X509_COMMON="$DEFAULT_INTCA_X509_COMMON"
  X509_ORG="$DEFAULT_INTCA_X509_ORG"
  X509_OU="$DEFAULT_INTCA_X509_OU"
  X509_EMAIL="$DEFAULT_INTCA_X509_EMAIL"
  X509_URL_BASE="$DEFAULT_INTCA_X509_URL_BASE"
  X509_CRL="$DEFAULT_INTCA_X509_CRL"
else
  IA_URL_BASE="$DEFAULT_CA_X509_URL_BASE"
  IA_OPENSSL_CA_OPT="-selfsign"
  X509_COUNTRY="$DEFAULT_CA_X509_COUNTRY"
  X509_STATE="$DEFAULT_CA_X509_STATE"
  X509_LOCALITY="$DEFAULT_CA_X509_LOCALITY"
  X509_COMMON="$DEFAULT_CA_X509_COMMON"
  X509_ORG="$DEFAULT_CA_X509_ORG"
  X509_OU="$DEFAULT_CA_X509_OU"
  X509_EMAIL="$DEFAULT_CA_X509_EMAIL"
  X509_URL_BASE="$DEFAULT_CA_X509_URL_BASE"
  X509_CRL="$DEFAULT_CA_X509_CRL"
fi


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
    OPENSSL_ALGORITHM="-algorithm poly1305"
    # Ignoring KEYSIZE_BITS
    case "$MESSAGE_DIGEST" in
      des3|aes128|aes256|chacha20)
        OPENSSL_ALGORITHM="$OPENSSL_ALGORITHM -$MESSAGE_DIGEST"
        ;;
      *)
        echo "Invalid Poly1305 $MESSAGE_DIGEST digest; valid digests are: "
        echo "    chacha20, aes128, aes256, des3"
        exit 1
        ;;
    esac
elif [[ "$PEER_SIGNATURE" == "rsa" ]]; then
    # MESSAGE_DIGEST max at sha3-512
    case "$KEYSIZE_BITS" in
      512|1024|2048|4096)
        OPENSSL_ALGORITHM="-algorithm rsa -pkeyopt rsa_keygen_bits:$KEYSIZE_BITS"
        ;;
      *)
        echo "Invalid RSA $KEYSIZE_BITS keysize; valid size are: "
        echo "    4096, 2048, 1024, 512."
        exit 1
        ;;
    esac
elif [[ "$PEER_SIGNATURE" == "aes" ]]; then
    OPENSSL_ALGORITHM="-algorithm aes -pkeyopt aes_keygen_bits:$KEYSIZE_BITS"
elif [[ "$PEER_SIGNATURE" == "ecdsa" ]]; then
    case "$KEYSIZE_BITS" in
      521|384|256|224|192|128)
        OPENSSL_ALGORITHM="-algorithm EC -pkeyopt ec_paramgen_curve:P-$KEYSIZE_BITS"
        ;;
      *)
        echo "Invalid ECDSA $KEYSIZE_BITS keysize; valid size are: "
        echo "    521, 384, 256, 224, 192, 128."
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
[[ ${VERBOSITY} -ne 0 ]] && echo "Algorithm: $OPENSSL_ALGORITHM"


directory_file_layout "$OFSTD_LAYOUT" "$OFSTD_DIR_TREE_TYPE" \
                      "$SSL_DIR" "$IA_NAME" "$PARENT_IA_NAME"

# If parent CA specified, ALWAYS CHECK for parent CA directory
if [[ $NO_PARENT -ne 1 ]]; then
    if [[ ! -z "$PARENT_IA_DIR" ]]; then
        if [[ ! -d "$PARENT_IA_DIR" ]]; then
            echo "Parent '$PARENT_IA_NAME' CA directory does not exist"
            echo "Probably forgot '-p root' command line option or something"
            exit 1
        fi
    fi
fi


# It's stupid that we have to export this OpenSSL configuration filespec
# If we didn't, it would 'furtively' refer to it's built-in /usr/lib/openssl/openssl.cnf if no '-config' were used as 'strace -f' has shown.
export OPENSSL_CONF="$IA_OPENSSL_CNF"


IA_SSLCFG="-config $IA_OPENSSL_CNF"
IA_REQ_SSLCFG="$IA_SSLCFG"
IA_CA_SSLCFG="-config $PARENT_IA_OPENSSL_CNF"

# Define all the OpenSSL commands
OPENSSL_REQ="$OPENSSL req ${IA_REQ_SSLCFG}"
[[ ${VERBOSITY} -ne 0 ]] && OPENSSL_REQ="$OPENSSL_REQ -verbose"
OPENSSL_X509="$OPENSSL x509"
OPENSSL_RSA="$OPENSSL rsa"
OPENSSL_MD5="$OPENSSL md5"
OPENSSL_CA="$OPENSSL ca ${IA_CA_SSLCFG}"
[[ ${VERBOSITY} -ne 0 ]] && OPENSSL_CA="${OPENSSL_CA} -verbose"
OPENSSL_GENPKEY="$OPENSSL genpkey"
OPENSSL_PKEY="$OPENSSL pkey"

case "$CMD_MODE" in
  verify)
    cmd_verify_ca
    ;;
  create)
    cmd_create_ca
    ;;
  help)
    cmd_show_syntax_usage
    exit 1
    ;;
  renew)
    cmd_renew_ca
    ;;
  *)
    echo "Invalid command '$CMD_MODE'"
    cmd_show_syntax_usage
    ;;
esac

echo "Successfully completed; exiting..."

exit 0
