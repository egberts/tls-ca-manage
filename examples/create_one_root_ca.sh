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

OPTS="-v"


echo "Demostrator for a single typical self-hosted server."
echo
TCAM="../tls-ca-manage.sh $OPTS"
TCEM="../tls-cert-manage.sh $OPTS"

#  Create a Root CA that can support intermediate CA(s)
echo "Creating Root CA certificate ..."
${TCAM} create -t root MyCaRoot
assert_success $?
echo

echo "Creating Apache Webserver certificate ..."
${TCEM} create apache-webserver   server MyCaRoot
assert_success $?
echo

echo "Creating Postfix MTA server certificate ..."
${TCEM} create postfix-mtaserver  server MyCaRoot
assert_success $?
echo

echo "Creating Dovecot IMAP server certificate ..."
${TCEM} create dovecot-imapserver server MyCaRoot
assert_success $?
echo

echo "Creating IPSec server certificate ..."
${TCEM} create ipsec-server       server MyCaRoot
assert_success $?
echo

echo "Creating Webmin Administrator certificate ..."
${TCEM} create webmin-server      server MyCaRoot
assert_success $?
echo

echo "Verifying apache-webserver PEM ..."
${TCEM} verify  apache-webserver server  MyCaRoot
assert_success $?

echo "Verifying postfix MTA server PEM ..."
${TCEM} verify  postfix-mtaserver server  MyCaRoot
assert_success $?

echo "Verifying dovecot IMAP server PEM ..."
${TCEM} verify  dovecot-imapserver server  MyCaRoot
assert_success $?

echo "Verifying IPSec server PEM ..."
${TCEM} verify  ipsec-server server  MyCaRoot
assert_success $?

echo "Verifying Webmin server PEM ..."
${TCEM} verify  webmin-server server  MyCaRoot
assert_success $?

echo "Done."
