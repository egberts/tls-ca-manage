#!/bin/bash
#
# Create One Root CA that can sign others
#
TCAM="../tls-ca-manage.sh"
TCEM="../tls-cert-manage.sh"
#  Create a Root CA that can support intermediate CA(s)
${TCAM} create -t root MyCaRoot

${TCEM} create apache-webserver   server MyCaRoot
${TCEM} create postfix-mtaserver  server MyCaRoot
${TCEM} create dovecot-imapserver server MyCaRoot
${TCEM} create ipsec-server       server MyCaRoot
${TCEM} create webmin-server      server MyCaRoot

${TCEM} verify  apache-webserver   MyCaRoot
${TCEM} verify  postfix-mtaserver   MyCaRoot
${TCEM} verify  dovecot-imapserver   MyCaRoot
${TCEM} verify  ipsec-server   MyCaRoot
${TCEM} verify  webmin-server   MyCaRoot
