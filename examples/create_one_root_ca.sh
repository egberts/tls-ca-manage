#!/bin/bash
#
# Create One Root CA that can sign others
#
#  Create a Root CA that can support intermediate CA(s)
tls-ca-manage.sh -i root

tls-ca-servers.sh -p root apache-webserver
tls-ca-servers.sh -p root postfix-mtaserver
tls-ca-servers.sh -p root dovecot-imapserver
tls-ca-servers.sh -p root ipsec-server
tls-ca-servers.sh -p root webmin-server

