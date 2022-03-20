This file is obsoleted: 

See https://egbert.net/blog/openssl-x509v3.html

Old source: https://github.com/egberts/tls-ca-manage/doc/X509V3-SETTINGS.md
New source: https://github.com/egberts/egberts.github.io/content/articles/openssl-x509v3.md


The basic layout of the openssl.cnf file are as given below but with respect to section, sectionalization, and reference by section.

Generic section:
----------------

* `[default]`
* `[ca]`
* `[req]`

[default] attributes:
-------------------
Default attributes may start at the beginning of the `openssl.cnf` configuration file before any section (as denoted by a pair of square-brackets `[ xxxx ]`) begins or be clustered together under a `[default]` section, or across both.

[jtable]
Attribute, Description, Section
`HOME`, sets the current working directory for all files referenced later, [default]
`RANDFILE`, a file holding the random seed (good for recreating unit tests); typically set to `$ENV::HOME/.rnd` or `$dir/private.rand`, [default,ca,req]
`default_conf`, reads the `/usr/lib/ssl/openssl.cnf` and seeds your configuration with., [default]
`oid_file`, is a filespec containing OID; uses `$ENV::HOME/.oid` file as a default?, [default,ca]
`oid_section`, follows the new oid-related section, [default]
`asn1`, the section name to the selected ASN1 attributes; used only by `openssl asn1pars` command., [default,asn1pars]
[/jtable]

Found in '[ca]':
=======================

Section names within [ca]
---------------------------
[jtable]
Attribute, Description, Section
`default_ca`, the section name to use for 'openssl ca' and overridden by `-name` CLI, [ca]
`x509_extensions`, the section name of X509v3 extension attributes to add to the cert; `-extensions` CLI overrides this., [ca]
`policy`, the section name that enforces which distinguished names to keep or force supplied or copy.; `-policy` CLI overrides this, [ca]
`crl_extensions`, the section name to hold CRL-related X509v3-only attributes; `-crlexts` overrides this;, [ca]
[/jtable]

Directories within [ca]
---------------------------
[jtable]
Attribute, Description, Section
`database`, the main database directory specification to hold `openssl`-generated files, [ca]
`certs`, the directory specification that is a holding area for newly-issued certificate PEM file, [ca]
`crl_dir`, the directory specification that is a holding area for CRL-related files, [ca]
`new_certs_dir`, the directory specification that is a holding area for newly-issued certificate PEM files, [ca]
[/jtable]

Files within [ca]
-----------------
[jtable]
Attribute, Description, Section
`certificate`, a file specification to the CA certificate PEM file; not sure if `-cert` CLI overrides this?, [ca]
`private_key`, a file specification to the CA private PEM file; `-keyfile` CLI overrides this, [ca]
`serial`, a file specification to the the current serial number text file; `-create-serial` can reset this; `-rand_serial` can bypass this., [ca]
`crl`, a file specification to the currentl CRL PEM file, [ca]
`oid_file`, a filespec containing OID; uses `$ENV::HOME/.oid` file as a default?, [default,ca]
[/jtable]

Attributes options within [ca]
------------------------------
[jtable]
Attribute, Description, Section
`default_days`, how long to certify for; `-days` overrides this setting., [ca]
`default_startdate`, options are `today` or a date format of `YYMMDDHHMMSSZ`, [ca]
`default_enddate`, a date format of `YYMMDDHHMMSSZ`, [ca]
`default_md`, default for non-EC public key message digest; can be `default` or any option listed in `openssl dgst -list`, [ca,req]
`preserve`, keep the ordering of distinguished names or not., [ca]
`name_opt`, options for Subject Name (SN) are `multiline` `-esc_msb` `utf8` or `ca_default`; more intensive options are `esc_2253` `esc_2254` `esc_ctrl` `esc_msb` `use_quote` `utf8` `ignore_type` `show_type` `dump_all` `dump_nostr` `dump_der` `compat` `sep_comma_plus` `sep_comma_plus_space` `sep_semi_plus_space` `sep_multiline` `dn_rev` `nofname` ` sname` `lname` `align` `oid` `space_eq` `dump_unknown` `RFC2253` `oneline` `multiline` `ca_default` [ca]
`cert_opt`, common options for certificate fields are `multiline` `-esc_msb` `utf8` or `ca_default`; other lesser options are `compatible` `no_header` `no_version` `no_serial` `no_signame` `no_validity` `no_subject` `no_issuer` `no_pubkey` `no_extensions` `no_sigdump` `no_aux` `no_attributes` `ext_default` `ext_error` `ext_parse` `ext_dump`, [ca]
`utf8`, `yes`/`no` value for UTF8 support, [ca]
`copy_extensions`, options are `none` `copy` or `copyall`, [ca]
`email_in_dn`, options are `no` or a valid email address, [ca]
`default_email_in_dn`, options are `no` or a valid email address, [ca]
`crlnumber`, a base 10 number for a serial number to the CRL certificateion, [ca]
`default_crl_days`, how long before next CRL; `-crldays` or `-crlhours` and `-crlsec` overrides this., [ca]
`default_crl_hours`, how long before next CRL; `-crldays` or `-crlhours` and `-crlsec` overrides this., [ca]
`default_crl_seconds`, how long before next CRL; `-crldays` or `-crlhours` and `-crlsec` overrides this., [ca]
[/jtable]



Found in '[req]':
==================
Section names within [req]
---------------------------
[jtable]
Attribute, Description, Section
`req_extensions`, the section name to use for 'openssl req' and overridden by `-reqexts` CLI, [ca]
`distinguished_name`, the section name to use for distinguished names., [req]
`x509_extensions`, the section name of X509v3 extension attributes to add to the self-signed cert (ie. RootCA); `-extensions` CLI overrides this.; only used for self-signed within [req], [ca]
`attributes`, the section name of attributes which commonly holds `challengePassword*`, [req]
`default_csr`, the section name to use for 'openssl req' and overridden by `-name` CLI, [req]
[/jtable]

Directories within [req]
---------------------------
There are no attributes related to directory path within the request `[ req `]section.

Files within [req]
---------------------------
[jtable]
Attribute, Description, Section
`default_keyfile`, the filename to use for holding private key used in request (CSR) certificate., [req]
[/jtable]

Attributes options within [req]
------------------------------
[jtable]
Attribute, Description, Section
`default_bits`, number of bits for non-EC algorithms, [req]
`default_md`, default for non-EC public key message digest; can be `default` or any option listed in `openssl dgst -list`, [ca,req]
`encrypt_key`, `yes`/`no` value as to whether to wrap a digest around the key using the `default_md` digest algorithm, [req]
`string_mask`, # This sets a mask for permitted string types. There are several options.  default: PrintableString, T61String, BMPString; pkix   : PrintableString, BMPString (PKIX recommendation before 2004); utf8only: only UTF8Strings (PKIX recommendation after 2004).; nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).; MASK:XXXX a literal mask value.; WARNING: ancient versions of Netscape crash on BMPStrings or UTF8Strings., [req]
`input_password`, password for private keys if not present will be prompted for; `-passin` overrides this., [req]
`output_password`, password for private keys if not present will be prompted for
`encrypt_rsa_key`, OBSOLETED; use `encrypt_key` instead, [req]
[/jtable]


Found in section name by [req]attributes=
-----------------------------------------

```ini
challengePassword               = A challenge password                 
challengePassword_min           = 4
challengePassword_max           = 20
```

See [OpenSSL Password](/openssl-password.html)


X509v3 extensions
=================

authorityKeyIdentifier (AKI) X509v3 extension attribute
-------------------------------------------------
AKI are used only with `openssl ca`? (TBD)

Some settings that authorityKeyIdentifier (AKI) can take:

```ini
authorityInfoAccess = caIssuers
authorityInfoAccess = OCSP
authorityInfoAccess = DNS:example.com
authorityInfoAccess = IP:127.0.0.1
authorityInfoAccess = URI:http://127.0.0.1:8080
authorityInfoAccess = email:johndoe@example.com
authorityInfoAccess = caIssuers;OCSP;URI:http://127.0.0.1:8080
```

authorityKeyIdentifier X509v3 extension attribute
-------------------------------------------------
```ini
authorityKeyIdentifier=keyid:always,issuer
```


Other X509v3 extension attributes
---------------------------------
Have not the time to document the rest.

```ini
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier=hash
certificatePolicies             = @cert_policy_section_ca
subjectAltName=email:copy
issuerAltName=issuer:cop
# nsCertType = objsign, sslCA, emailCA
# nsComment                       = "OpenSSL Generated Certificate"
#nsCaRevocationUrl              = http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo
```

Distinguished Names
-------------------
Distinguished Names (DN) are found commonly referenced by under `distinguished_names` commonly assigned under [req]-related sections.

DN attributes are defined in two different ways, depending on the `prompt=` attribute settings :

```ini
countryName                     = Country Name (2 letter code)
countryName_default             = AU
countryName_min                 = 2
countryName_max                 = 2

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = New South Wales

organizationName		= Organization Name (eg, company)
organizationName_default	= CAcert Inc.

organizationalUnitName		= Organizational Unit Name (eg, section)
organizationalUnitName_default	= http://www.CAcert.org

commonName			= Common Name (eg, YOUR name)
commonName_default		= CAcert Inc. Signing Authority
commonName_max			= 64
```



Certificate Policies
--------------------

```ini
[ my_cert_policy ]
CPS                             = "http://www.CAcert.org/index.php?id=10"
policyIdentifier                = my_policy_oid
```

