#!/bin/bash
#
# File: interca-type.sh
#
# Creates an extension file that details the
# relatioship between parent CA and its child CA

# Usage: create_internode_config <section_name> \
#                                <internode_filespec> \
#                                <parent_node_name>
function create_internode_config
{
    SECTION_NAME=$1
    INTERNODE_CONFIG_FILESPEC=$2
    PARENT_CONFIG_FILESPEC=$3
    CURRENT_TIMESTAMP=`date`
    echo """#
# File: $INTERNODE_CONFIG_FILESPEC
#
# Created: $CURRENT_TIMESTAMP
# Used with: $PARENT_CONFIG_FILESPEC
#
# X509v3 extensions
#
#   openssl ca -config $PARENT_CONFIG_FILESPEC \\
#       -extfile $INTERNODE_CONFIG_FILESPEC \\
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
crlDistributionPoint    = \"URI:http://example.invalid/crl/ca.crl\"

""" > "$INTERNODE_CONFIG_FILESPEC"
    unset SECTION_NAME
    unset INTERNODE_CONFIG_FILESPEC
    unset PARENT_CONFIG_FILESPEC
    unset TIMESTAMP
}


# Usage: get_x509v3_extension_by_ca_type <ca_type> <pathlen>
function get_x509v3_extension_by_ca_type {
  GXEBCT_CA_TYPE=$1
  GXEBCT_PATHLEN_COUNT=$2
  [[ ! -z $GXEBCT_PATHLEN_COUNT ]] || GXEBCT_PATHLEN_COUNT=-1
  if [[ $GXEBCT_PATHLEN_COUNT -ge 0 ]]; then
    GXEBCT_PATHLEN_OPTION=",pathlen:$GXEBCT_PATHLEN_COUNT"
  else
    GXEBCT_PATHLEN_OPTION=""
  fi
  case "$GXEBCT_CA_TYPE" in
    standalone)
      CNF_SECTION_REQ_EXT="section_test_ca_x509v3_extensions"
      CNF_CA_EXT_KU=""  # keyUsage
      CNF_CA_EXT_BC="CA:false"  # basicConstraint
      CNF_CA_EXT_SKI="" # subjectKeyIdentifier
      CNF_CA_EXT_AKI=""  # authorityKeyIdentifier
      CNF_CA_EXT_EKU=""  # extendedKeyUsage
      CNF_CA_EXT_SAN=""  # subjectAltName
      CNF_CA_EXT_AIA="@issuer_info"
      ;;
    root|signing|intermediate|network|software|tls)
      CNF_SECTION_REQ_EXT="section_${GXEBCT_CA_TYPE}_ca_x509v3_extensions"
      CNF_CA_EXT_KU="critical,keyCertSign,cRLSign"  # keyUsage
      CNF_CA_EXT_BC="critical,CA:true"  # basicConstraint
      CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_CA_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_CA_EXT_EKU=""  # extendedKeyUsage
      CNF_CA_EXT_SAN=""  # subjectAltName
      CNF_CA_EXT_AIA="@issuer_info"
      ;;
    server)
      CNF_SECTION_REQ_EXT="section_server_ca_x509v3_extension"
      CNF_CA_EXT_KU="critical,digitalSignature,keyEncipherment"
      CNF_CA_EXT_BC="CA:false"
      CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_CA_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_CA_EXT_EKU="serverAuth,clientAuth"
      CNF_CA_EXT_SAN="\$ENV::SAN"  # subjectAltName
      # CNF_CA_EXT_AIA="@ocsp_info"
      CNF_CA_EXT_AIA="@issuer_info"
      ;;
    client)
      CNF_SECTION_REQ_EXT="section_client_ca_x509v3_extension"
      CNF_CA_EXT_KU="critical,digitalSignature"
      CNF_CA_EXT_BC="CA:false"
      CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_CA_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_CA_EXT_EKU="clientAuth"
      CNF_CA_EXT_SAN="email:move"  # subjectAltName
      CNF_CA_EXT_AIA="@issuer_info"
      ;;
    timestamping)
      CNF_SECTION_REQ_EXT="section_timestamping_ca_x509v3_extension"
      CNF_CA_EXT_KU="critical,digitalSignature"
      CNF_CA_EXT_BC="CA:false"
      CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_CA_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_CA_EXT_EKU="critical,timeStamping"
      CNF_CA_EXT_SAN=""  # subjectAltName
      CNF_CA_EXT_AIA="@issuer_info"
      ;;
    ocsp)
      CNF_SECTION_REQ_EXT="section_ocspsign_ca_x509v3_extension"
      CNF_CA_EXT_KU="critical,digitalSignature"
      CNF_CA_EXT_BC="CA:false"
      CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_CA_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_CA_EXT_EKU="critical,OCSPSigning"
      CNF_CA_EXT_SAN=""  # subjectAltName
      CNF_CA_EXT_AIA="@issuer_info"
      CNF_CA_EXT_EXTRA="noCheck = null"
      ;;
    email)
      CNF_SECTION_REQ_EXT="section_email_ca_x509v3_extensions"
      CNF_CA_EXT_KU="critical,keyEncipherment"
      CNF_CA_EXT_BC="CA:false"  # basicConstraint
      CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_CA_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_CA_EXT_EKU="emailProtection"
      CNF_CA_EXT_SAN="email:move"  # subjectAltName
      CNF_CA_EXT_AIA="@issuer_info"
    ;;
    encryption)
      CNF_SECTION_REQ_EXT="section_encryption_ca_x509v3_extension"
      CNF_CA_EXT_KU="critical,digitalSignature,keyEncipherment"  # keyUsage
      CNF_CA_EXT_BC=""  # basicConstraint
      CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_CA_EXT_AKI=""  # authorityKeyIdentifier
      # email encryption = "emailProtection,clientAuth"
      # Microsoft Encrypted File System = "emailProtection,msEFS"
      # merged plain email and MS identity encryption together
      CNF_CA_EXT_EKU="emailProtection,clientAuth,msEFS"
      CNF_CA_EXT_SAN="email:move"  # subjectAltName
      CNF_CA_EXT_AIA="@issuer_info"
      ;;
    identity)  # there's identity-ca and identity, this here is identity-ca
      CNF_SECTION_REQ_EXT="section_identity_ca_x509v3_extension"
      CNF_CA_EXT_KU="critical,digitalSignature"
      CNF_CA_EXT_BC="CA:false"  # basicConstraint
      CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_CA_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_CA_EXT_EKU="emailProtection,clientAuth,msSmartcardLogin"
      CNF_CA_EXT_SAN=""  # subjectAltName
      CNF_CA_EXT_AIA="@issuer_info"
      ;;
    codesign)
      CNF_SECTION_REQ_EXT="section_codesign_ca_x509v3_extension"
      CNF_CA_EXT_KU="critical,digitalSignature"
      CNF_CA_EXT_BC="CA:false"  # basicConstraint
      CNF_CA_EXT_SKI="hash" # subjectKeyIdentifier
      CNF_CA_EXT_AKI="keyid:always"  # authorityKeyIdentifier
      CNF_CA_EXT_EKU="critical,codeSigning"
      CNF_CA_EXT_SAN=""  # subjectAltName
      CNF_CA_EXT_AIA="@issuer_info"  # authorityInfoAccess
      ;;
    *)
      echo "Invalid '$GXEBCT_CA_TYPE' option"
      ;;
  esac
  unset GXEBCT_CA_TYPE
  unset GXEBCT_PATHLEN_COUNT
}

CURRENT_TIMESTAMP="`date`"
echo -n "Enter in node name: "
read -r NODE_NAME
echo -n "Enter in node's CA type: "
read -r CA_TYPE
echo -n "Enter in parent name: "
read -r PARENT_NODE
# Don't think I need the parent node's CA-type.
# We're focusing on this extension file that details
# relationship between parent and current CA nodes.

get_x509v3_extension_by_ca_type $CA_TYPE -1


SECTION_NAME="section_${NODE_NAME}_ca"
THIS_NODE_FILESPEC="./extensions_${PARENT_NODE}-ca_${NODE_NAME}-ca.cnf"
PARENT_NODE_NAME="${PARENT_NODE}-ca"
create_internode_config $SECTION_NAME $THIS_NODE_FILESPEC $PARENT_NODE_NAME

