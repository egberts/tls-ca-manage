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

${TCEM} verify apache-webserver   server MyCaRoot
${TCEM} verify postfix-mtaserver  server MyCaRoot
${TCEM} verify dovecot-imapserver server MyCaRoot
${TCEM} verify ipsec-server       server MyCaRoot
${TCEM} verify webmin-server      server MyCaRoot
