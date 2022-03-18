A working prototype of OCSP server PKI 
for use with OCSP responder.
==============================

Subdirectory 'ca' is the original by F5 community contributor.

Subdirectory 'prototype' is the planned introduction into 'tls-ca-manage'

   - Has the split 3-way openssl.cnf files.


DEMONSTRATE
------------
How to demonstrate creation of a TLS server authentication PKI 
certificate for the OCSP server-side:


```bash
cd ca
./prototype-ca-root.sh
cd intCA
./prototype-ca-int.sh
./prototype-crl-before-ocsp.sh
./prototype-ocsp.sh


References:
=============

* [Building an OpenSSL Certificate Authority - Configuring CRL and OCSP](https://community.f5.com/t5/technical-articles/building-an-openssl-certificate-authority-configuring-crl-and/ta-p/279492)
* [Creating Your Intermediary Certificate Authority](https://community.f5.com/t5/technical-articles/building-an-openssl-certificate-authority-creating-your/ta-p/279497)
* [Creating Your Root Certificate Authority](https://community.f5.com/t5/technical-articles/building-an-openssl-certificate-authority-configuring-crl-and/ta-p/279492)
* [F5 openssl_intermediate.cnf](https://web.archive.org/web/20171125110858/https://gist.github.com/Chaseabbott/b9c6ff52ba2fcbc68e1d7ce75afc3482)
* [F5 openssl_root.cnf](https://web.archive.org/web/20171125110451/https://gist.github.com/Chaseabbott/c8c913ce848829f9906fa5e45cea1e10)
