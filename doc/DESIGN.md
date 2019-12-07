# tls-ca-manage

TLS Certificate Authority (CA) Manage tool provides a
front-end wrapper to OpenSSL to simplify the task of
creating, renewing, revocating, and verifying of
certificates and CAs.

# CA Certificate Type
Types of CA certificate that tls-ca-manage can create are:

* test CA (standalone node) certificate
* Root Certificate Authority (CA)  (root node)
* Intermediate CA (intermediate node)
* Signing CA (end-node)

# Signed User Certificates
Types of signed user certificates (and its private key)
that tls-cert-manage tool can create are:

* TLS Server certificate
* TLS Client certificate
* OCSP
* TimeStamping
* Email PKCS#12 certificate (encryption)
* Identity PKCS#12 certificate (identification/authentication)
* Software CodeSign certificate

# Basic Concepts
# Manage CA Concept
Basic concept of the tls-ca-manage tool operates around:

  * Issuer CA (parent node, or Parent CA)
  * Issuing CA (this node)

If no parent node is specified, then the CA is either a
test self-signed certificate or Root CA.

Issuing CA also must declare a type of node such as:

 * standalone - test self-signed
 * root
 * intermediate - no signing certs privilege
 * (signing CA)
  * server - TLS Server certificate
  * client - TLS Client
  * ocsp - OCSP Signing
  * timestamping
  * email - Email PKCS#12 certificate (encryption)
  * identity - Identity PKCS#12 certificate (identification/authentication)
  * codesign - Software CodeSign certificate


# Manage Certificates Concept
Basic concept of the tls-cert-manage tool operates around:

  * Signing CA (parent node)
  * Signed user certificate

#
