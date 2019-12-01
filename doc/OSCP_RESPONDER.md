

[ v3_OCSP ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = OCSPSigning


[ usr_cert ]
authorityInfoAccess = OCSP;URI:http://127.0.0.1:8080
