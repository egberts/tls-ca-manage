#!/bin/bash
#
# Create One Root CA that can sign others
#
assert_success() {
  if [ $1 -ne 0 ]; then
    echo "Failed; aborted here."
    exit $1
  fi
}
echo "Demostrator for a single typical self-hosted server."
echo
TCAM="../tls-ca-manage.sh"
TCEM="../tls-cert-manage.sh"

#  Create a Root CA that can support intermediate CA(s)
echo "Creating Root CA certificate ..."
${TCAM} create -t root MyCaRoot
assert_success $?
echo

echo "Creating Apache Webserver certificate ..."
${TCEM} create apache-webserver   server MyCaRoot
assert_success $?
echo

echo "Verifying MyCaRoot PEM ..."
${TCAM} -v verify MyCaRoot
assert_success $?
echo

echo "Verifying apache-webserver PEM ..."
${TCEM} -v verify  apache-webserver server MyCaRoot
assert_success $?
echo
echo
echo "Done."
