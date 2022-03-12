**"ROOT All The Things!"**

<img src="https://github.com/egberts/tls-ca-manage/blob/36aa744f64851b0422b86eb04b570a45e79d23c5/2204FB39-2D08-4EE9-9B0B-C879C10B8441.gif" alt="tls-ca-manage logo" width="200"/>

Makes a CA PEM file correctly in the fewest steps possible.  

* so simple, it makes self-signed certificates; 
* so flexible, it creates the widest variety of PEM files.
* so advanced, that I used it to recreate a big Internet full of secured websites in my closed-network lab.

Beats EasyRSA.  Beats all online CA providers. Definitely beats using OpenSSL directly.

That's how simple it should be to create a CA ecosystem:
```
  tls-ca-manage.sh create MyPrivateRootCA root
  tls-ca-manage.sh create -p MyPrivateRootCA my-intermediate-ca
  tls-cert-manage.sh create my-web-site server my-intermediate-ca
```

[![Lint Code Base](https://github.com/egberts/tls-ca-manage/actions/workflows/lint_code_base.yml/badge.svg)](https://github.com/egberts/tls-ca-manage/actions/workflows/lint_code_base.yml)
[![Codacy Security Scan](https://github.com/egberts/tls-ca-manage/actions/workflows/codacy.yml/badge.svg)](https://github.com/egberts/tls-ca-manage/actions/workflows/codacy.yml)

# What else can tls-ca-manage do?

Certificate Authority Management tool is witten in bash shell.  Runs on any platform that runs OpenSSL.

If you have ANY of the following:

* befuddle by myriad of OpenSSL CLI options, particularly encryption
* perplex by how to cross-set the numerous settings between sections within and between the OpenSSL configuration files.
* a white lab or clean room
* many CA nodes needed
* have a private TLD domain name and infrastructure
* have custom CA directory layouts to maintain
* Experiment with highest-encryption CA nodes.
* On a power-trip to having your very own Root CA
* Use 802.1AR to secure HW nodes on network
* Experimenting with SmartCard and PKCS#15.
* Work with PKCS#7, PKCS#8, PKCS#10, PKCS#12, PKCS#15.

Fret no more, this tool may help you.  I did all the hard work and made it easy to support the following features:

* Different multi-directory layouts:
  - centralized or OpenSSL traditional
  - Nested CA or flat
* friendly error-free data entry of all combinations of crypto settings
* Digest algorithms:
  * SHA512, SHA384, SHA256, SHA3-256, SHA3-224, SHA1, MD5
* Cipher algorithms
  * aes128, aes256, aes-256-cbc, aes-128-cbc, des-ede3-cbc, camellia-256-cbc
* Encryption algorithms
  * RSA, ECDSA, ED25519, POLY1305
* Encryption bit size
  * 4096, 2048, 1024, 521, 512, 384, 256, 224, 192, 128
 * No UNIX root account required (enforces **`ssl-cert`** supplemental group)
 * see actual commands and argument settings via verbosity level 
 * And lastly, correct generation of `openssl.cnf` file with all sections properly crossreferences to each other as well as to other CA nodes' configuration file.

# Install

    sudo chown root:ssl-cert /etc/ssl
    sudo chmod g+rxw,o-rwx /etc/ssl
    sudo cp ./tls-ca-managed /usr/local/bin

No install script purposely given here; this is serious admin effort here.  May impact other servers' improperly configured but direct access to `/etc/ssl`.

My belief is that `/etc/ssl` was never intended for a direct access by end-servers' need for TLS/SSL; just a holding area of certificates.

I've tried to give 'ssl-cert' group access to end-server(s) then I realized that would be giving away the TLS/SSL store too much.

You create the appropriate 'private' subdirectory in each of the end-server's /etc/<server-name>/<private-tls> and COPY their server-specific certs over to there.

# Example Setup
The example setups are given in following sections:

* Creating Root CA node
* Creating Intermediate CA node
* Creating 2nd Intermediate CA node
* Renew Root CA node
* Renew Intermediate CA node
* Encrypt using ChaCha20-Poly1305
* Encrypt using Elliptic Curve



# Why Did I Make This?

Bash!  Flexible!  Wrapping complex PKI trees using complex OpenSSL commands into a simple command line.

![Expert PKI](https://pki-tutorial.readthedocs.io/en/latest/_images/ExpertPKILayout.png)

There are OpenSSL encryption options that don't play well with other digest or bitsize settings.  It started out with parameter validation and explicitly telling you what options you can used with which (none of that man pages and connecting the dots there).

Wait, there's more.

## Nested CA
File organization for nested CAs also come in two flavors:
* flat
* nested-tree

At first, I defaulted it to this nested-tree because OpenSSL team seems to like this, until a new layout came along.

## New Directory Layout
Later, I ran into an awesome [webpage](https://pki-tutorial.readthedocs.io/en/latest/expert/index.html#)  on Expert PKI (diagram and all).  But I noticed the new directory layout (diametrically different than traditional OpenSSL directory layout).  I'm  going to call it the 'centralized' directory layout.  Edited: I've later learned that Sweden `.se` TLD team effort is behind this design.

I too incorporated the new centralized directory layout into this `tls-ca-manage.sh` tool.  It could do either approach.  I defaulted it to the new centralized ones.

All details regarding directory layouts are given here: [CA_DIRECTORY_LAYOUTS](https://github.com/egberts/tls-ca-manage/blob/master/doc/CA_DIRECTORY_LAYOUTS)

# OpenSSL limitation
Even with a carefully crafted OpenSSL configuration file, it is a hair-pulling experience to use the command line (especially 6-month later when you forget all those little things).

It is so bad that even EasyRSA has a problem staying current with the OpenSSL versions.  I wanted to avoid all that dependency of OpenSSL version (after starting with its v1.1.1, due to introduction of `openssl genpkey` command).

Also, tls-ca-manage/tls-cert-manage cannot mix node type to a single end-node,
for that would make its end-node too over-privileged.  Make a unique single-type
'endnode' for each cert type.

This doesn't work:

    tls-ca-manage.sh create -p root -t root root
    tls-ca-manage.sh create -p root -t endnode mycompany_intca
    # splitting a CA into multiple functions (bad)
    tls-cert-manage.sh create mycompany_servers server mycompany_intca
    tls-cert-manage.sh create mycompany_emails server mycompany_intca

This works best:

    tls-ca-manage.sh create -p root -t root root
    # making an endnode CA into a unique function (good)
    tls-ca-manage.sh create -p root -t email mycompany_emails
    tls-ca-manage.sh create -p root -t server mycompany_servers
    # each cert type has its own CA (good)
    tls-cert-manage.sh create fred_flintsone email mycompany_emails


# Syntax
So, to make it easy, the syntax is about the CA node itself;  A simple filename for a simple CA node.

Coupled that with three basic commands:  Create, renew, and verify.

 
Full syntax is:
```
Usage:  ./tls-ca-manage.sh
        [ --help|-h ] [ --verbosity|-v ] [ --force-delete|-f ]
        [ --base-dir|-b <ssl-directory-path> ]
        [ --algorithm|-a [rsa|ed25519|ecdsa|poly1305] ]
        [ --message-digest|-m [sha512|sha384|sha256|sha224|sha3-256|
                               sha3-224|sha3-512|sha1|md5] ]
        [ --keysize|-k [4096, 2048, 1024, 512, 256] ]
        [ --serial|-s <num> ]  # (default: 1000)
        [ --group|-g <group-name> ]  # (default: ssl-cert)
        [ --openssl|-o <openssl-binary-filespec ]  # (default: /usr/local/bin/openssl)
        [ --parent-ca|-p ] [-t|--ca-type <ca-type>] [ --traditional|-T ]
        < create | renew | revoke | verify | help >
        <ca-name>

<ca-type>: standalone, root, intermediate, network, identity, component,
           server, client, email, ocsp, timestamping, security, codesign
Default settings:
  Top-level SSL directory: /etc/ssl  Cipher: rsa
  Digest: sha256 Keysize: 4096

```
# Command Line Options
A front-end tool to OpenSSL that enables creation, renewal, revocation, and verification of Certificate Authorities (CA).

CA can be Root CA or Intermediate CA.

Mandatory  arguments  to  long  options are mandatory for short options too.

    -a, --algorithm
      Selects the cipher algorithm.
      Valid algorithms are: rsa, ecdsa, poly1305 OR ed25519
      These value are case-sensitive.
      If no algorithm specified, then RSA is used by default.

    -b, --base-dir
        The top-level directory of SSL, typically /etc/ssl
        Useful for testing this command in non-root shell
        or maintaining SSL certs elsewhere (other than /etc/ssl).

    -c, --cipher
        Specify the encryption method of the PEM key file in
        which to protect the key with.  Default is plaintext file.

    -f, --force-delete
        Forces deletion of its specified CA's configuration file
        as pointed to by CA-NAME argument.

    -g, --group
        Use this Unix group name for all files created or updated.
        Default is ssl-cert group.

    -h, --help

    -i, --intermediate-node
        Makes this CA the intermediate node where additional CA(s)
        can be branched from this CA.  Root CA is also an intermediate
        node but top-level, self-signed intermediate node.

        Not specifying --intermediate-node option means that this CA
        cannot borne any additional CA branches and can only sign
        other certificates.

        Dictacts the presence of 'pathlen=0' in basicConstraints
        during the CA Certificate Request stage.

        Not specifying --parent-ca and not specifying --intermediate-node
        means this certificate is a self-signed standalone
        test certificate which cannot sign any other certificate.

        If --intermediate-node and no --parent-ca, creates your Root CA.

    -k, --key-size
        Specifies the number of bits in the key.  The choice of key
        size depends on the algorithm (-a) used.
        The key size does not need to be specified if using a default
        algorithm.  The default key size is 4096 bits.

        Key size for ed25519 algorithm gets ignored here.
        Valid poly1305 key sizes are:
        Valid rsa key sizes are: 4096, 2048, 1024 or 512.
        Valid ecdsa key sizes are: 521, 384, 256, 224 or 192.

    -m, --message-digest
     blake2b512        blake2s256        gost              md4
     md5               rmd160            sha1              sha224
     sha256            sha3-224          sha3-256          sha3-384
     sha3-512          sha384            sha512            sha512-224
     sha512-256        shake128          shake256          sm3

    -n, --nested-ca
        First chaining of first-level CAs are placed in subdirectory inside
        its Root CA directory, and subsequent chaining of second-level CA
        get nesting also in subdirectory inside its respective Intermediate
        CA directory.  Very few organizations use this.

    -p, --parent-ca
        Specifies the Parent CA name.  It may often be the Root CA name
        or sometimes the Intermediate CA name.  The Parent CA name is
        the same CA-NAME used when creating the parent CA.

    -r, --reason
        Specifies the reason for the revocation.
        The value can be one of the following: unspecified,
        keyCompromise, CACompromise, affiliationChanged,
        superseded, cessationOfOperation, certificateHold,
        and removeFromCRL. (from RFC5280)
        Used only with 'revoke' command

    -s, --serial
        Specifies the starting serial ID number to use in the certificate.
        The default serial ID is 1000 HEXI-decimal.  Format of number are
        stored and handled in hexidecimal format of even number length.

    -t, --ca-type
        Specifies the type of CA node that this is going to be:

          root         - Top-most Root node of CA tree
          intermediate - Middle node of CA tree
          security     - Signing CA for security plant
          component    - Generic signing CA for network
          network      - Generic signing CA for network
        End-nodes are:
          standalone   - self-signed test certificate
          server       - TLS server: Web server, MTA, VPN, IMAP, POP3, 802.1ar
          client       - TLS client:
          ocsp         - OCSP
          email        - Encryption part of SMTP body
          identity     - Signing CA for Microsoft SmartCard identity
          encryption   - Microsoft Encrypted File System (msEFS)
          codesign     - Signed executable code
          timestamping - ANSI X9.95 TimeStamping (RFC3161)

    -T, --traditional
        Indicates the standard OpenSSL directory layout.
        Default is to use the new centralized directory layout.

    -v, --verbosity
        Sets the debugging level.

Makes one assumption: that the openssl.cnf is ALWAYS the filename (never tweaked)
Just that different directory has different openssl.cnf

Enforces 'ssl-cert' group; and requires all admins to have 'ssl-cert'  group when using this command

DO NOT be giving 'ssl-cert' group to server daemons' supplemental group ID (or worse, as its group ID); for that, you copy the certs over to app-specific directory and use THAT app's file permissions.

This command does not deal with distribution of certificates, just creation/renewal/revokation of therein.

'ssl-cert' group means 'working with SSL/TLS certificates, not just reading certs'.

Inspired by: https://jamielinux.com/docs/openssl-certificate-authority/create-the-root-pair.html



# Commands

    tls-ca-managed.sh  - Creates/Renew/Verify all CA nodes (root or intermediate)
    tls-create-server.sh - Adds all the end-CAs (TLS servers, ...)

Example test runs:

    tls-ca-managed.sh create -t root root                # creates the Root CA under /etc/ssl
    tls-ca-managed.sh verify root                        # Verifies Root CA certificates
    tls-ca-managed.sh create -p root -t server network   # creates Network Intermediate CA
    tls-ca-managed.sh verify network                     # Verifies Network CA certificates
    tls-ca-managed.sh create -p root -t identity company_id  # creates Identity Intermediate CA
    tls-ca-managed.sh create -p root -t security ActiveCardKeysCA  # creates Security Intermediate CA
    tls-ca-managed.sh create -b /tmp/etc/ssl root        # creates Root CA under /tmp/etc/ssl
    tls-ca-managed.sh -T  root                           # creates Root CA in traditional OpenSSL directory layout




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

# Definitions
## Components:

* Public Key Infrastructure (PKI) - Security architecture where trust is conveyed through the signature of a trusted CA.
* Certificate Authority (CA) - Entity issuing certificates and CRLs.
* Registration Authority (RA) - Entity handling PKI enrollment. May be identical with the CA.
* Certificate - Public key and ID bound by a CA signature.
* Certificate Signing Request (CSR) - Request for certification. Contains public key and ID to be certified.
* Certificate Revocation List (CRL) - List of revoked certificates. Issued by a CA at regular intervals.
* Certification Practice Statement (CPS) - Document describing structure and processes of a CA.

## CA Types:

* Root CA - CA at the root of a PKI hierarchy. Issues only CA certificates.
* Intermediate CA - CA below the root CA but not a signing CA. Issues only CA certificates.
*  Signing CA - CA at the bottom of a PKI hierarchy. Issues only user certificates.

## Certificate Types:

* CA Certificate - Certificate of a CA. Used to sign certificates and CRLs.
* Root Certificate - Self-signed CA certificate at the root of a PKI hierarchy. Serves as the PKI’s trust anchor.
* Cross Certificate - CA certificate issued by a CA external to the primary PKI hierarchy. Used to connect two PKIs and thus usually comes in pairs.
* User Certificate - End-user certificate issued for one or more purposes: email-protection, server-auth, client-auth, code-signing, etc. A user certificate cannot sign other certificates.

# File Format:
* Privacy Enhanced Mail (PEM) - Text format. Base-64 encoded data with header and footer lines. Preferred format in OpenSSL and most software based on it (e.g. Apache mod_ssl, stunnel).
* Distinguished Encoding Rules (DER) - Binary format. Preferred format in Windows environments and certain high-end vendors. Also the official format for Internet download of certificates and CRLs.  (Not used here)

# Additional information and alternatives

### Private CA Alternatives

Using self signed certificates is always a bad idea. It's far more secure to
self manage a certificate authority than it is to use self signed certificates.
Running a certificate authority is easy.

In addition to the scripts in this repository, here is a short recommended list
of scripts and resources for managing a certificate authority.

1. The [xca project][xca] provides a graphical front end to certificate
   authority management in openssl.  It is available for Windows, Linux, and Mac
   OS.
2. The OpenVPN project provides a nice [set of scripts][ovpn_scripts] for
   managing a certificate authority as well.
3. [Be your own CA][yourca_tut] tutorial provides a more manual method of
   certificate authority management outside of scripts or UI.  It provides
   openssl commands for certificate authority management.  Additionaly, one can
   read up on certificate management in the [SSL Certificates HOWTO][tldp_certs]
   at The Linux Documentation Project.
4. Use my scripts in this repository which is based on option `3` in this list.
   Supports server certs only.
5. Use [certificate-automation][cert_auto] which is similar to these scripts
   organized slightly differently.  Supports client certs as well.

Once a certificate authority is self managed simply add the CA certificate to
all browsers and mobile devices. Enjoy secure and validated certificates
everywhere.

### Public CA Alternatives

If a service you manage is designated for public access then self managing a
certificate authority may not be the best option.  Signed Domain Validated (DV)
certificates should still be the preferred method to secure your public service.

1. [CAcert.org][cacert] is a community driven certificate authority which
   provides free SSL certificates.  Note:  See the [inclusion
   page][cacert_inclusion] to see which applications and distros
   include the cacert.org root certificates.
2. [Let's Encrypt][lets_encrypt] is a free, automated, and open Certificate
   Authority.

Why in Bash Script?
=====
I love how meta variables can be leverage for templating various file layouts.
  
Written, developed, and testd using JetBrain PyCharm, community-edition with Bash Pro plugin for excellent step-by-step debugging while viewing ALL variables, defined or unused.
  
References
====
  
* [CACert](http://www.cacert.org/)
* [Inclusion Status, CACert](http://wiki.cacert.org/InclusionStatus)
* [Certificate Automation, by Berico-Rclayton, Github](https://github.com/berico-rclayton/certificate-automation)
* [Certificate Authority, byDocker Engine Security](https://docs.docker.com/engine/security/https/)
* [Let's Encrypt](https://letsencrypt.org/)
* [PKI, by OpenVPN](http://openvpn.net/index.php/open-source/documentation/howto.html#pki)
* [X193 TLS Certificates](http://www.tldp.org/HOWTO/SSL-Certificates-HOWTO/x195.html)
* [wiki_ma](https://en.wikipedia.org/wiki/Mutual_authentication)
* [wiki_san](https://en.wikipedia.org/wiki/Subject_Alternative_Name)
* [Project XCA](http://sourceforge.net/projects/xca/)
* [Be Your Own CA](http://www.g-loaded.eu/2005/11/10/be-your-own-ca/)
