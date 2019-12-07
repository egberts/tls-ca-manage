#!/bin/bash

BITSIZE=1
while [[ "$BITSIZE" -le 8192 ]]; do
  ((BITSIZE=$BITSIZE+1))
#  /usr/local/bin/openssl genpkey -algorithm EC -pkeyopt \
#  ec_paramgen_curve:P-$BITSIZE \
#  -outform PEM -text -out /tmp/ssl/ca/root-ca/private/root-ca.key \

#   /usr/local/bin/openssl genpkey \
#        -algorithm rsa \
#        -pkeyopt rsa_keygen_bits:$BITSIZE \
#        -outform PEM -text -out /tmp/ssl/ca/root-ca/private/root-ca.key \

   /usr/local/bin/openssl genpkey \
        -algorithm poly1305 \
        -pkeyopt poly1305_keygen_bits:$BITSIZE \
        -outform PEM -text -out /tmp/ssl/ca/root-ca/private/root-ca.key \
   >/dev/null 2>&1
  RETSTS=$?
  if [[ $RETSTS -eq 0 ]]; then
    echo "Success at bit size $BITSIZE"
  fi
done


