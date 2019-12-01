#!/bin/bash
#
#  Usage: cert-get-keyid.sh  <PEM-file>
#
PEM_FILE=$1
if [[ -z "$PEM_FILE" ]]; then
  echo -n "Enter in PEM file: "
  read -r PEM_FILE
fi
if [[ ! -f "$PEM_FILE" ]]; then
  echo "No such file: $PEM_FILE"
  exit -2
fi
echo "File: $PEM_FILE"
touch /tmp/x
export OPENSSL_CONF=/bin/false
export SSL_CERT_FILE=/bin/false
AUTHORITY_KEY_ID="$(openssl x509 -in "$PEM_FILE" -noout -text | grep -A1 "Authority Key Identifier" | tail -1 | sed -s "s/ //g")"
echo "AUTHORITY_Key ID: $AUTHORITY_KEY_ID"
SUBJECT_KEY_ID="$(openssl x509 -in "$PEM_FILE" -noout -text | grep -A1 "Subject
Key Identifier" | tail -1 | sed -s "s/ //g")"
echo "Subject Key ID: $SUBJECT_KEY_ID"
exit 0
