#!/bin/bash
# Title: Intermediate CA request/sign-with-ca/verify
#
echo "Reset database in Intermediate CA (request/sign-with-root/verify)"
echo

OPENSSL_BIN="env OPENSSL_CONF=/dev/null openssl"

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

cp /dev/null index.txt
echo 1000 > serial
echo 1000 > crlnumber

echo
echo "Resetted. Done."
