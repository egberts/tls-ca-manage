#!/bin/bash
# Title: Reset Root CA database

function assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Errno $1; aborted."
    exit $1
  fi
}

cp /dev/null index.txt
cp /dev/null crlnumber
echo 1000 > serial
echo
echo "Root CA database reseted; Done."
