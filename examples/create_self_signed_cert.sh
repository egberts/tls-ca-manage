#!/bin/bash
#
# Create a self-signed certificate
#
#
tls-ca-manage.sh acme
#
#
#  Secure self-signed using 521-bit ECDSA
tls-ca-manage.sh -a ecdsa -k 521 secured-acme
