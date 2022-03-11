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
retsts=$?
echo "Root CA done: Exit errno $retsts"
echo
echo "PEM for Apache Webserver started."
${TCEM} create apache-webserver   server MyCaRoot
retsts=$?
echo "PEM for Apache Webserver done: exit errno $retsts"
echo

echo "Verifying MyCaRoot PEM ..."
${TCAM} -v verify root MyCaRoot
retsts=$?
echo "MyCaRoot PEM verified: exit errno $retsts"
echo
echo "Verifying apache-webserver PEM ..."
${TCEM} -v verify  apache-webserver server MyCaRoot
retsts=$?
echo "apache-webserver PEM verified: exit errno $retsts"
echo
echo
echo "Done."
