
x509v3 extendedKeyUsage
OID: 1.3.6.1.4.1.311.80.1

Parent: keyUsage
Parent OID: join-iso-itu-t(2).ds(5).certificateExtension(29).keyUsage(15)

Current keyUsage supported:

   digitalSignature(0)
   nonRepudiation(1)
   keyEncipherment(2)
   dataEncipherment(3)
   keyAgreement(4)
   keyCertSign(5)
   cRLSign(6)
   encipherOnly(7)
   decipherOnly(8)


Current supporting extendedKeyUsage combinatorial:
    - serverAuth
    - clientAuth
  digitalSignature
    - codeSigning
  keyEncipherment
    - serverAuth
  dataEncipherment
    - serverAuth


Examples:
  openssl req ... \
    -addext extendedKeyUsage=1.3.6.1.4.1.311.80.1 \
    -addext keyUsage=keyEncipherment

  openssl req .. \
    -reqexts SAN \
    -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:example.com,DNS:www.example.com\nextendedKeyUsage=serverAuth,clientAuth")
