#!/bin/bash
#
# Create One Root CA that can sign others
#
echo "Demostrator for a single typical self-hosted server."
echo
TCAM="../tls-ca-manage.sh"
TCEM="../tls-cert-manage.sh"
#  Create a Root CA that can support intermediate CA(s)
echo "Root CA started."
${TCAM} create -t root MyCaRoot
echo "Root CA done."
echo
echo "PEM for Apache Webserver started."
${TCEM} create apache-webserver   server MyCaRoot
echo "PEM for Apache Webserver done."
echo
echo "PEM for Postfix MTA server started."
${TCEM} create postfix-mtaserver  server MyCaRoot
echo "PEM for Postfix MTA server done."
echo
echo "PEM for Dovecot IMAP server started."
${TCEM} create dovecot-imapserver server MyCaRoot
echo "PEM for Dovecot IMAP server done."
echo
echo "PEM for IPSec server started."
${TCEM} create ipsec-server       server MyCaRoot
echo "PEM for IPSec server done."
echo
echo "PEM for Webmin Administrator started."
${TCEM} create webmin-server      server MyCaRoot
echo "PEM for Webmin Administrator done."
echo

echo "Verifying apache-webserver PEM ..."
${TCEM} verify  apache-webserver server  MyCaRoot
echo
echo "Verifying postfix MTA server PEM ..."
${TCEM} verify  postfix-mtaserver server  MyCaRoot
echo
echo "Verifying dovecot IMAP server PEM ..."
${TCEM} verify  dovecot-imapserver server  MyCaRoot
echo
echo "Verifying IPSec server PEM ..."
${TCEM} verify  ipsec-server server  MyCaRoot
echo
echo "Verifying Webmin server PEM ..."
${TCEM} verify  webmin-server server  MyCaRoot
echo
echo "Done."
