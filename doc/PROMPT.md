This file is obsoleted; 

see https://egbert.net/blog/openssl-prompt.html
Old source: https://github.com/egberts/tls-ca-manage/doc/PROMPT.md
New source: https://github.com/egberts/egberts.github.io/content/articles/openssl-prompt.md


title: To Prompt or Not to Prompt in OpenSSL
date: 2022-03-19 09:18
status: published
tags: OpenSSL
category: HOWTO
summary: How to simply changing prompt for distinguished names (DN) in OpenSSL
slug: openssl-prompt
lang: en
private: False

The Art of Prompt (in OpenSSL)
==============================

During the creation of a request certificate, the distinguished names
goes into the request cert.

Distinguished names covers:

* countryName
* stateOrProvinceName
* localityName
* 0.organizationName
* organizationalUnitName
* emailAddress
* commonName

Two ways to define the content of each distinguished names:

* Prompting
* Hardcoded

Prompting
=========
In the openssl.cnf that 'openssl req -config' references, if 
there is a `prompt=yes` statement that is found or 
the `[ req ]` section, then prompting gets enforced.

`yes` is the default value for `prompt=` attribute.

```ini
[ intermediate_ca_req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = US
stateOrProvinceName             = State or Province Name
stateOrProvinceName_default     = WA
localityName                    = Locality Name
localityName_default            = Seattle
0.organizationName              = Organization Name
0.organizationName_default      = Grilled Cheese Inc.
organizationalUnitName          = Organizational Unit Name
organizationalUnitName_default  = Grilled Cheese Intermediary CA
#### we use a UNIX pipe to shove 'commonName' into this file
####commonName                      = Common Name
emailAddress                    = Email Address
emailAddress_default            = grilledcheese@yummyinmytummy.us
```

Hardcoded (No Prompting)
========================

If there is a `prompt=no` statement that is found
within the `[ req ]` section, then prompting is disabled.

The declaration of distinguished names has changed once
`prompt=no` occurs:

```ini
[ intermediate_ca_req_distinguished_name_no_prompt ]
stateOrProvinceName             = WA
localityName                    = Seattle
0.organizationName              = Grilled Cheese Inc.
organizationalUnitName          = Grilled Cheese Intermediary CA
commonName                      = Grilled Cheese Intermediary CA (commonName)
emailAddress                    = grilledcheese@yummyinmytummy.us
```

Notice the different section name for ease of switching back and forth.

Notice that there is no longer any `_default`, `_min`, 
nor `_max` prefixes for the no-prompt distinguished names.


Example `prompt=no`
===================
An example of using `prompt=no` settings are:

```ini
[ req ]
prompt = no
default_bits = 4096
distinguished_name = req_distinguished_name
req_extensions = req_ext

[ req_distinguished_name ]
C=
ST=
L=
O=
OU=
CN=

[ req_ext ]
subjectAltName = @alt_names

[alt_names]
DNS.1 = hostname.domain.tld
DNS.2 = hostname
IP.1 = 10.20.30.40
```

Easy Prompt
===========

The easiest way to deal with flipping the `prompt=` back and forth is to include TWO of the same `[distinguished_name]`-type sections but with differing value settings:

```ini
[ req ]
prompt              = no
## for 'prompt=yes' (default):
#distinguished_names = req_distinguished_name
## for 'prompt=no':
distinguished_names = my_set_of_no_prompt_dn_req

[ my_set_of_no_prompt_dn_req ]
countryName			= AU
stateOrProvinceName             = none
localityName                    = none
0.organizationName              = Internet Widgits Pty Ltd
#1.organizationName             = World Wide Web Pty Ltd
organizationalUnitName          = none
commonName                      = none
emailAddress                    = none

# if you are falling back to /usr/lib/ssl/openssl.cnf as a default, omit this section
[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= AU
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some-State

localityName			= Locality Name (eg, city)

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= Internet Widgits Pty Ltd

# we can do this but it is not needed normally :-)
#1.organizationName		= Second Organization Name (eg, company)
#1.organizationName_default	= World Wide Web Pty Ltd

organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	=

commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64
```

Then it becomes a three-step of flipping the `prompt=` value and commenting/uncommenting the opposite of `distinguished_name` attribute settings.
