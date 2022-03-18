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

