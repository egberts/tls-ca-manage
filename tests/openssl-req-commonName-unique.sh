#!/bin/bash

commonName="Intermediate CA serial no."

openssl ecparam -genkey -name secp384r1 | openssl ec -out intCA.cheese.key.pem

printf "%s\n\n\n[intermediate_ca_req_distinguished_name_no_prompt]\ncommonName=$commonName %s\n" "$(cat openssl-intermediate.cnf)" "$(cat ../serial)" >> /tmp/x

openssl req \
    -config /tmp/x \
    -new \
    -nodes \
    -newkey ec:<(openssl ecparam -name secp384r1) \
    -keyout intCA.cheese.key.pem \
    -out intCA.cheese.csr.pem
exit
cp openssl-intermediate.cnf /tmp/x
printf "[intermediate_ca_req_distinguished_name_no_prompt]\ncommonName=$commonName %s\n" "$(cat ../serial)" >> /tmp/x
openssl req \
    -config /tmp/x \
    -new \
    -nodes \
    -newkey ec:<(openssl ecparam -name secp384r1) \
    -keyout intCA.cheese.key.pem \
    -out intCA.cheese.csr.pem
exit

openssl req \
    -config <(printf "[intermediate_ca_req_distinguished_name_no_prompt]\ncommonName=$commonName %s\n" "$(cat ../serial)" | cat openssl-intermediate.cnf) \
    -new \
    -nodes \
    -newkey ec:<(openssl ecparam -name secp384r1) \
    -keyout intCA.cheese.key.pem \
    -out intCA.cheese.csr.pem


exit

openssl x509 \
    -req \
    -extfile <(printf "[req_distinguished_name]\ncommonName_default=$commonName\n") \
    -days 365 \
    -in intCA.cheese.csr.pem \
    -CA ../ca.cheese.crt.pem \
    -CAkey ../ca.cheese.key.pem \
    -CAcreateserial \
    -out intCA.cheese.crt.pem
