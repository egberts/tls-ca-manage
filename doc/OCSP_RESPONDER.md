

To Start OCSP Responder Server
==============================
Execute:

```bash
openssl ocsp \
    -index ./index.txt \
    -port 8080 \
    -rsigner ocspServer.crt \
    -rkey ocspServer.key \
    -CA rootCA.crt \
    -text \
    -out log.txt &
```

Now Do The OCSP Client Side
===========================
To pretend to be a web browser and do OCSP requests

```bash
openssl ocsp \
    -CAfile rootCA.crt \
    -issuer rootCA.crt \
    -cert certificate.crt \
    -url http://127.0.0.1:8080 \
    -resp_text \
    -noverify
```

Add to openssl.cnf
------------------

```ini
[ v3_OCSP_ca_ext ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = OCSPSigning
```

```ini
[ usr_cert ]
authorityInfoAccess = OCSP;URI:http://127.0.0.1:8080
```
