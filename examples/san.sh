#!/bin/bash
#
# File: san.sh
#
# How to handle SAN in bash file with OpenSSL

# openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
#   -keyout example.key -out example.crt -subj /CN=example.com \
#   -addext subjectAltName=DNS:example.com,DNS:example.net,IP:10.0.0.1

# Trick is to use "-addext" option with 'openssl req' command

echo -n "Enter in website hostname:"
read -r HOSTNAME
echo -n "Enter in website IP:"
read -r IP_ADDRESS



CA_SAN="-addext subjectAltName=DNS:$HOSTNAME,IP:$IP_ADDRESS"
echo "CA_SAN: $CA_SAN"
