#!/bin/bash
#
# Create a self-signed certificate
#
TLS_CA_MANAGE="../tls-ca-manage.sh"
#
${TLS_CA_MANAGE} create -p myselfsignedserver myselfsignedserver
${TLS_CA_MANAGE} verify myselfsignedserver
#
echo "Self-signed certificate created."
