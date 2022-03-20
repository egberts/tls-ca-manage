

One aspect:
-----------

Creating Intermediate CA certificate revocation list (CRL)...
COMMAND: /usr/bin/openssl ca -config /etc/ssl/etc/NewRootCA-ca.cnf -verbose -gencrl -config /etc/ssl/etc/NewIntCA-ca.cnf -out /etc/ssl/crl/NewIntCA-ca.crl
Using configuration from /etc/ssl/etc/NewIntCA-ca.cnf


    execute ${OPENSSL_CA} \
        -gencrl \
        -config "$IA_OPENSSL_CNF" \
        ${CIPHER_ARG_PASSIN} \
        -out "$IA_CRL_PEM"



