#!/bin/bash

OPENSSL_BIN="env OPENSSL_CONF=  openssl"
export OPENSSL_BIN
${OPENSSL_BIN} version
