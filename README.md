Certificate Authority Management tool, written in bash shell.
# tls-ca-managed

If you have ANY of the following:

* befuddle by myriad of OpenSSL CLI options, particularly ecryption
* a white lab or clean room
* many CA nodes needed
* have a private TLD domain name and infrastructure
* have custom CA directory layouts to maintain
* Experiment with highest-encryption CA nodes.
* On a power-trip to having your very own Root CA

Fret no more, this tool may help you.  I did all the hard work and made it easy to support the following features:

* Different multi-directory layouts:
  - centralized or OpenSSL traditional
  - Nested CA or flat
* Digest algorithms:
  * SHA512, SHA384, SHA3-256, SHA3-224, SHA1, MD5
* Cipher algorithms
  * ED25519, RSA, ECDSA, ChaCha20-Poly1305, AES
* Encryption bit size
  * 4096, 2048, 1024, 521, 512, 384, 256, 224, 192, 128
 * No root account required (enforces **`ssl-cert`** supplemental group)

# Why Did I Make This?

Bash!  Flexible!  Wrapping complex OpenSSL commands to a simple function call.

There are OpenSSL encryption options that don't play well with other digest or bitsize settings.  It started out with parameter validation and explicitly telling you what options you can used with which (none of that man pages and connecting the dots there).

## Nested CA 
File organization for nested CAs also come in two flavors:
* flat
* nested-tree

At first, I defaulted it to this nested-tree because OpenSSL team seems to like this, until a new layout came along.

## New Directory Layout
Later, I ran into an awesome [webpage](https://pki-tutorial.readthedocs.io/en/latest/expert/index.html#)  on Expert PKI (diagram and all).  But I noticed the new directory layout (diametrically different than traditional OpenSSL directory layout).  I'm  going to call it the 'centralized' directory layout.

I too incorporated the new centralized directory layout into this `tls-ca-manage.sh` tool.  It could do either approach.  I defaulted it to the new centralized ones.

# OpenSSL limitation
Even with a carefully crafted OpenSSL configuration file, it is a hair-pulling experience to use the command line (especially 6-month later when you forget all those little things).   

It is so bad that even EasyRSA has a problem staying current with the OpenSSL versions.  I wanted to avoid all that dependency of OpenSSL version (after starting with its v1.1.1, due to introduction of `openssl genpkey` command).


# Syntax
So, to make it easy, the syntax is about the CA node itself.  A simple filename for a simple CA node.  

Couple that with three basic commands:  Create, renew, and verify.

That's how simple it should be.
```
tls-ca-manage.sh
    [ --help|-h ]
    [ --verbosity|-v ]
    [ --topdir|-t <ssl-directory-path> ]  # (default: /etc/ssl)
    [ --algorithm|-a [rsa|ed25519|ecdsa|poly1305|aes256|aes512] ]  # (default: rsa)
    [ --message-digest|-m [sha512|sha384|sha256|sha224|sha1|md5] ]  # (default: sha256)
    [ --keysize|-k [4096, 2048, 1024, 512, 256] ]  # (default: 4096)
    [ --serial|-s <num> ]  # (default: 1000)
    [ --group|-g <group-name> ]  # (default: ssl-cert)
    [ -p | --parent-ca <parent-ca-name> ]  # (no default)
    create | renew | revoke | help
    <ca-name>
```
# Commands
    tls-ca-managed.sh  - Creates/Renew/Verify all CA nodes (root or intermediate)
    tls-create-server.sh - Adds all the end-CAs (TLS servers, ...)

Example test runs:

    tls-ca-managed.sh create root              # creates the Root CA under /etc/ssl
    tls-ca-managed.sh verify root              # Verifies Root CA certificates
    tls-ca-managed.sh -p root create network   # creates Network Intermediate CA
    tls-ca-managed.sh -p root verify network   # Verifies Network CA certificates
    tls-ca-managed.sh -p root create identity  # creates Identity Intermediate CA
    tls-ca-managed.sh -p root create security  # creates Security Intermediate CA
    tls-ca-managed.sh -b /tmp/etc/ssl root     # creates Root CA under /tmp/etc/ssl
    tls-ca-managed.sh -t root                  # creates Root CA in traditional


Required Out-of-Band Setup:

    sudo chown root:ssl-cert /etc/ssl
    sudo chmod g+rxw,o-rwx /etc/ssl
    sudo cp ./tls-ca-managed /usr/local/bin

No install script purposely given here; this is serious admin
effort here.  May impact other servers' improperly configured
but direct access to `/etc/ssl`.

My belief is that `/etc/ssl` was never intended for direct access by
end-servers' TLS/SSL.  Just a holding area of certificates.
I've tried to give 'ssl-cert' group access to end-server(s) but realized
that would be giving away the TLS/SSL store too much.
You create the appropriate 'private' subdirectory in each of the
end-server's /etc/<server-name>/<private-tls> and COPY their server-specific certs over to there.

# Requirements

* Active shell account be in 'ssl-cert' supplemental group
* File write-access to /etc/ssl subdirectory (preferably at 'ssl-cert' group)
* OpenSSL v1.1.1 or later (depends on 'openssl genpkey')

# Example Setup
The example setups are given in following sections:
* Creating Root CA node
* Creating Intermediate CA node
* Creating 2nd Intermediate CA node
* Renew Root CA node
* Renew Intermediate CA node
* Encrypt using ChaCha20-Poly1305
* Encrypt using Elliptic Curve

## Creating Root CA node
To create a root CA node, execute:
```
$ tls-ca-manage.sh create root
Create /etc/ssl/ca subdirectory? (Y/n): y
/etc/ssl/etc/root-ca.cnf file is missing, recreating ...
Organization (default: 'ACME Networks'): 
Org. Unit/Section/Division:  (default: 'Trust Division'): 
Common Name:  (default: 'ACME Internal Root CA A1'): 
Country (2-char max.):  (default: 'US'): 
State:  (default: ''): 
Locality/City:  (default: ''): 
Contact email:  (default: 'ca.example@example.invalid'): 
Base URL:  (default: 'https://example.invalid/ca'): 
CRL URL:  (default: 'http://example.invalid/ca/example-crl.crt'): 
Creating /etc/ssl/etc/root-ca.cnf file...
Created Parent CA /etc/ssl/etc/root-ca.cnf file
.....................................................................................................................++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
.........................................................++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Creating Parent CA certificate ...
Using configuration from /etc/ssl/etc/root-ca.cnf
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 4096 (0x1000)
        Validity
            Not Before: Nov 18 23:50:16 2019 GMT
            Not After : Nov 15 23:50:16 2029 GMT
        Subject:
            countryName               = US
            organizationName          = ACME Networks
            organizationalUnitName    = Trust Division
            commonName                = ACME Internal Root CA A1
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Subject Key Identifier: 
                58:A9:A1:9B:F0:30:03:9C:A0:7A:71:C0:EE:A7:96:C3:D6:04:EE:DA
            X509v3 Authority Key Identifier: 
                58:A9:A1:9B:F0:30:03:9C:A0:7A:71:C0:EE:A7:96:C3:D6:04:EE:DA
Certificate is to be certified until Nov 15 23:50:16 2029 GMT (3650 days)

Write out database with 1 new entries
Data Base Updated
Creating Parent CA certificate revocation list (CRL)...
Using configuration from /etc/ssl/etc/root-ca.cnf
Displaying MD5 of various CA certificates:
MD5(stdin)= ba9093a4bab91ef89406ac3e7bcee3dc /etc/ssl/ca/root-ca.crt
To see decoded Parent CA certificate, execute:
  /usr/local/bin/openssl x509 -in /etc/ssl/ca/root-ca.crt -noout -text
Created the following files:
  Parent CA cert req   : /etc/ssl/ca/root-ca.csr
  Parent CA certificate: /etc/ssl/ca/root-ca.crt
  Parent CA private key: /etc/ssl/ca/root-ca/private/root-ca.key
  Parent CA new cert   : /etc/ssl/ca/root-ca/1000.pem
  Parent CA CRL        : /etc/ssl/crl/root-ca.crl
Successfully completed; exiting...

```
## Create Intermediate CA node
To creata an intermediate CA node, execute:
```
tls-ca-manage.sh create -p root component

/etc/ssl/etc/component-ca.cnf file is missing, recreating ...
Organization (default: 'ACME Networks'): 
Org. Unit/Section/Division:  (default: 'Semi-Trust Department'): 
Common Name:  (default: 'ACME Internal Intermediate CA B2'): 
Country (2-char max.):  (default: 'US'): 
State:  (default: ''): 
Locality/City:  (default: ''): 
Contact email:  (default: 'ca.subroot@example.invalid'): 
Base URL:  (default: 'https://example.invalid/ca/subroot'): 
CRL URL:  (default: 'https://example.invalid/subroot-ca.crl'): 
Creating /etc/ssl/etc/component-ca.cnf file...
Created Intermediate CA /etc/ssl/etc/component-ca.cnf file
..................................
....................................................................................................................................................................................................++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
........................++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Creating Intermediate CA certificate ...
Using configuration from /etc/ssl/etc/root-ca.cnf
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 4097 (0x1001)
        Validity
            Not Before: Nov 18 23:51:58 2019 GMT
            Not After : Nov 15 23:51:58 2029 GMT
        Subject:
            countryName               = US
            organizationName          = ACME Networks
            organizationalUnitName    = Semi-Trust Department
            commonName                = ACME Internal Intermediate CA B2
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                21:95:BC:6F:6C:BE:2C:8E:1D:66:7A:CC:2B:B1:24:A0:91:71:21:B3
            X509v3 Authority Key Identifier: 
                58:A9:A1:9B:F0:30:03:9C:A0:7A:71:C0:EE:A7:96:C3:D6:04:EE:DA
            Authority Information Access: 
                CA Issuers - URI:https://example.invalid/ca/root-ca.crt
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://example.invalid/ca/root-ca.crl
Certificate is to be certified until Nov 15 23:51:58 2029 GMT (3650 days)

Write out database with 1 new entries
Data Base Updated
Creating Intermediate CA chain certificate ...
cat /etc/ssl/ca/component-ca.crt /etc/ssl/ca/root-ca.crt > /etc/ssl/ca/component-ca-chain.pem
Creating Intermediate CA certificate revocation list (CRL)...
Using configuration from /etc/ssl/etc/component-ca.cnf
Displaying MD5 of various CA certificates:
MD5(stdin)= 8f65f5e06738f10a3f0b2862ad3a7ca6 /etc/ssl/ca/component-ca.crt
To see decoded Intermediate CA certificate, execute:
  /usr/local/bin/openssl x509 -in /etc/ssl/ca/component-ca.crt -noout -text
Created the following files:
  Intermediate CA cert req   : /etc/ssl/ca/component-ca.csr
  Intermediate CA certificate: /etc/ssl/ca/component-ca.crt
  Intermediate CA private key: /etc/ssl/ca/component-ca/private/component-ca.key
  Intermediate CA new cert   : /etc/ssl/ca/component-ca/1000.pem
  Intermediate CA chain cert : /etc/ssl/ca/component-ca-chain.pem
  Intermediate CA CRL        : /etc/ssl/crl/component-ca.crl
Successfully completed; exiting...
```

## Adding 2nd Intermediate CA node
To add a second Intermediate CA node, execute:
```
tls-ca-manage.sh create -p root identity

/etc/ssl/etc/identity-ca.cnf file is missing, recreating ...
Organization (default: 'ACME Networks'): 
Org. Unit/Section/Division:  (default: 'Semi-Trust Department'): 
Common Name:  (default: 'ACME Internal Intermediate CA B2'): 
Country (2-char max.):  (default: 'US'): 
State:  (default: ''): 
Locality/City:  (default: ''): 
Contact email:  (default: 'ca.subroot@example.invalid'): 
Base URL:  (default: 'https://example.invalid/ca/subroot'): 
CRL URL:  (default: 'https://example.invalid/subroot-ca.crl'): 
Creating /etc/ssl/etc/identity-ca.cnf file...
Created Intermediate CA /etc/ssl/etc/identity-ca.cnf file
................................................................................................................................++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
.................................................................................................................................................................................................++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Creating Intermediate CA certificate ...
Using configuration from /etc/ssl/etc/root-ca.cnf
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 4098 (0x1002)
        Validity
            Not Before: Nov 18 23:54:33 2019 GMT
            Not After : Nov 15 23:54:33 2029 GMT
        Subject:
            countryName               = US
            organizationName          = ACME Networks
            organizationalUnitName    = Semi-Trust Department
            commonName                = ACME Internal Intermediate CA B2
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                97:18:EF:DF:20:04:9E:66:21:BB:0D:59:EB:03:2A:4D:EB:55:98:D2
            X509v3 Authority Key Identifier: 
                58:A9:A1:9B:F0:30:03:9C:A0:7A:71:C0:EE:A7:96:C3:D6:04:EE:DA
            Authority Information Access: 
                CA Issuers - URI:https://example.invalid/ca/root-ca.crt
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://example.invalid/ca/root-ca.crl
Certificate is to be certified until Nov 15 23:54:33 2029 GMT (3650 days)

Write out database with 1 new entries
Data Base Updated
Creating Intermediate CA chain certificate ...
cat /etc/ssl/ca/identity-ca.crt /etc/ssl/ca/root-ca.crt > /etc/ssl/ca/identity-ca-chain.pem
Creating Intermediate CA certificate revocation list (CRL)...
Using configuration from /etc/ssl/etc/identity-ca.cnf
Displaying MD5 of various CA certificates:
MD5(stdin)= b0e64447a857b1f1d10ca09724a9eba9 /etc/ssl/ca/identity-ca.crt
To see decoded Intermediate CA certificate, execute:
  /usr/local/bin/openssl x509 -in /etc/ssl/ca/identity-ca.crt -noout -text
Created the following files:
  Intermediate CA cert req   : /etc/ssl/ca/identity-ca.csr
  Intermediate CA certificate: /etc/ssl/ca/identity-ca.crt
  Intermediate CA private key: /etc/ssl/ca/identity-ca/private/identity-ca.key
  Intermediate CA new cert   : /etc/ssl/ca/identity-ca/1000.pem
  Intermediate CA chain cert : /etc/ssl/ca/identity-ca-chain.pem
  Intermediate CA CRL        : /etc/ssl/crl/identity-ca.crl
Successfully completed; exiting...
```

## Add 3rd Intermediate CA with Elliptic Curve

```
tls-ca-manage.sh -a ecdsa -k 521 create -p root security

/etc/ssl/etc/security-ca.cnf file is missing, recreating ...
Organization (default: 'ACME Networks'): 
Org. Unit/Section/Division:  (default: 'Semi-Trust Department'): 
Common Name:  (default: 'ACME Internal Intermediate CA B2'): 
Country (2-char max.):  (default: 'US'): 
State:  (default: ''): 
Locality/City:  (default: ''): 
Contact email:  (default: 'ca.subroot@example.invalid'): 
Base URL:  (default: 'https://example.invalid/ca/subroot'): 
CRL URL:  (default: 'https://example.invalid/subroot-ca.crl'): 
Creating /etc/ssl/etc/security-ca.cnf file...
Created Intermediate CA /etc/ssl/etc/security-ca.cnf file
Creating Intermediate CA certificate ...
Using configuration from /etc/ssl/etc/root-ca.cnf
Check that the request matches the signature
Signature ok
Certificate Details:
        Serial Number: 4099 (0x1003)
        Validity
            Not Before: Nov 18 23:59:10 2019 GMT
            Not After : Nov 15 23:59:10 2029 GMT
        Subject:
            countryName               = US
            organizationName          = ACME Networks
            organizationalUnitName    = Semi-Trust Department
            commonName                = ACME Internal Intermediate CA B2
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                EC:76:73:6E:10:EC:C9:FC:DC:00:32:90:EE:06:B9:AC:5C:49:AE:19
            X509v3 Authority Key Identifier: 
                58:A9:A1:9B:F0:30:03:9C:A0:7A:71:C0:EE:A7:96:C3:D6:04:EE:DA
            Authority Information Access: 
                CA Issuers - URI:https://example.invalid/ca/root-ca.crt
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://example.invalid/ca/root-ca.crl
Certificate is to be certified until Nov 15 23:59:10 2029 GMT (3650 days)

Write out database with 1 new entries
Data Base Updated
Creating Intermediate CA chain certificate ...
cat /etc/ssl/ca/security-ca.crt /etc/ssl/ca/root-ca.crt > /etc/ssl/ca/security-ca-chain.pem
Creating Intermediate CA certificate revocation list (CRL)...
Using configuration from /etc/ssl/etc/security-ca.cnf
Displaying MD5 of various CA certificates:
MD5(stdin)= e30fbb5ba0cecaad7a2d0cb836584c05 /etc/ssl/ca/security-ca.crt
To see decoded Intermediate CA certificate, execute:
  /usr/local/bin/openssl x509 -in /etc/ssl/ca/security-ca.crt -noout -text
Created the following files:
  Intermediate CA cert req   : /etc/ssl/ca/security-ca.csr
  Intermediate CA certificate: /etc/ssl/ca/security-ca.crt
  Intermediate CA private key: /etc/ssl/ca/security-ca/private/security-ca.key
  Intermediate CA new cert   : /etc/ssl/ca/security-ca/1000.pem
  Intermediate CA chain cert : /etc/ssl/ca/security-ca-chain.pem
  Intermediate CA CRL        : /etc/ssl/crl/security-ca.crl
Successfully completed; exiting...
```
## Verify 3rd Intermediate CA node
```
tls-ca-manage.sh verify -p root security

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4099 (0x1003)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, O = ACME Networks, OU = Trust Division, CN = ACME Internal Root CA A1
        Validity
            Not Before: Nov 18 23:59:10 2019 GMT
            Not After : Nov 15 23:59:10 2029 GMT
        Subject: C = US, O = ACME Networks, OU = Semi-Trust Department, CN = ACME Internal Intermediate CA B2
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (521 bit)
                pub:
                    04:01:71:56:64:9d:2d:a2:cf:a6:ba:9e:36:ab:9d:
                    dc:d5:8b:81:ca:eb:2f:45:78:66:da:23:91:f8:85:
                    ab:09:3b:2d:fb:c8:91:0b:0b:cd:00:4a:e2:6a:1c:
                    5c:d4:92:8d:30:64:4a:46:86:19:47:04:1c:47:56:
                    b6:c1:51:30:71:4b:ee:01:93:a8:4b:8c:5f:81:d2:
                    17:dc:04:0c:05:f6:14:38:16:ab:be:02:37:ea:02:
                    b4:c2:06:1d:7f:9c:44:71:37:55:88:7e:4e:f5:31:
                    18:40:31:bb:f9:b6:e7:89:20:92:84:d7:95:4c:01:
                    3c:fc:0d:41:23:c7:20:72:8b:c3:e3:64:ef
                ASN1 OID: secp521r1
                NIST CURVE: P-521
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                EC:76:73:6E:10:EC:C9:FC:DC:00:32:90:EE:06:B9:AC:5C:49:AE:19
            X509v3 Authority Key Identifier: 
                58:A9:A1:9B:F0:30:03:9C:A0:7A:71:C0:EE:A7:96:C3:D6:04:EE:DA
            Authority Information Access: 
                CA Issuers - URI:https://example.invalid/ca/root-ca.crt
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:https://example.invalid/ca/root-ca.crl
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        63:30:a5:b7:6c:aa:1b:2e:3d:e9:df:02:51:ee:48:62:87:6f:
        3c:b2:cb:25:0c:0a:d0:1a:f9:4b:be:6b:c7:bc:fc:e3:9c:01:
        3b:6b:05:92:60:2c:55:c3:61:ca:47:7e:b1:eb:73:0c:b6:96:
        5c:4e:5c:d3:8e:8d:fd:df:a9:eb:c8:6a:49:79:eb:f1:db:6f:
        72:ea:ad:2b:3f:0a:0f:aa:ac:f9:12:37:6d:d7:12:80:0a:5e:
        6d:89:20:7d:df:3c:8f:78:71:3b:71:81:c3:b3:16:93:99:c5:
        7e:30:69:9a:60:ea:37:ac:45:66:44:a5:4c:c9:52:81:fd:e3:
        e8:06:28:41:b3:eb:fb:67:fe:86:c9:3a:d5:6d:95:a2:ad:97:
        41:75:94:23:e8:ac:92:35:24:52:b7:58:ff:0f:65:dc:cc:12:
        8e:9b:3f:5c:11:b0:d2:00:02:4a:a8:64:4d:bd:52:d9:cd:00:
        cf:8c:7e:81:17:91:f8:45:2b:51:1f:3d:70:ea:f8:b4:23:6f:
        aa:bc:7e:35:7b:cd:e2:6b:c5:13:59:3f:f1:17:49:fe:14:fa:
        62:70:97:a3:dd:f1:c5:a8:f9:82:06:6b:67:c6:92:86:cd:ec:
        ce:cc:f1:4f:23:a3:bf:cc:d6:42:96:d9:fc:ce:75:94:b5:9f:
        cd:63:30:9d:20:ea:ab:78:d3:ee:9e:92:b3:dc:9b:27:32:76:
        0d:78:c2:d0:7a:b2:d4:1d:30:b2:c9:ca:f1:a0:83:f0:ba:a2:
        6c:f8:72:78:10:31:da:cc:87:44:48:6f:37:7a:98:2e:2e:1d:
        e7:d9:85:e4:fc:7b:a8:ac:9d:42:f4:72:0c:38:fe:08:a9:51:
        95:ff:e7:b7:20:68:0e:e4:08:58:6e:49:0b:10:82:0a:4d:ac:
        10:46:41:a9:d6:77:b3:1f:b1:0e:f5:b0:9f:0b:36:fc:ab:53:
        63:13:5a:49:0e:73:30:ee:7f:ed:e4:ef:65:57:b3:90:18:9a:
        30:38:b3:aa:7b:62:76:2e:80:55:a4:96:11:af:25:c5:bf:1b:
        3f:4f:0b:37:4b:07:62:f9:16:eb:9a:83:cc:9c:27:1c:19:6c:
        15:ee:d9:b0:46:ad:5f:c6:a2:a3:3f:2d:f3:3f:1d:cf:70:c1:
        83:ba:2d:52:c2:ad:53:b9:b9:14:8e:28:4d:c2:41:24:a3:1f:
        87:f5:42:93:31:8f:f4:8e:6d:25:57:7c:0f:09:e7:fc:04:ee:
        fe:48:cf:18:ee:02:ff:fa:f1:5f:8d:82:e4:8e:30:c6:38:86:
        73:11:21:2b:4f:32:f4:cb:19:dd:c0:e8:db:7d:9a:8e:fa:26:
        fe:70:2f:9e:b3:cf:06:7d
Can't open /etc/ssl/ca/security-ca/999.pem for reading, No such file or directory
00:11:10:91:13:7F:00:00:error:system library:BIO_new_file:No such file or directory:crypto/bio/bss_file.c:69:calling fopen(/etc/ssl/ca/security-ca/999.pem, r)
00:11:10:91:13:7F:00:00:error:BIO routines:BIO_new_file:no such file:crypto/bio/bss_file.c:77:
unable to load certificate
MD5(stdin)= d41d8cd98f00b204e9800998ecf8427e
Can't open /etc/ssl/ca/security-ca/1001.pem for reading, No such file or directory
00:11:33:7D:C2:7F:00:00:error:system library:BIO_new_file:No such file or directory:crypto/bio/bss_file.c:69:calling fopen(/etc/ssl/ca/security-ca/1001.pem, r)
00:11:33:7D:C2:7F:00:00:error:BIO routines:BIO_new_file:no such file:crypto/bio/bss_file.c:77:
unable to load certificate
MD5(stdin)= d41d8cd98f00b204e9800998ecf8427e
MD5(stdin)= e30fbb5ba0cecaad7a2d0cb836584c05
MD5(stdin)= f7b2dc8f3be7464c6a73f0290b92dcfa /etc/ssl/ca/security-ca/private/security-ca.key
Successfully completed; exiting...
```

