This file is obsoleted, see OPENSSL_CNF.md
URL: https://egbert.net/blog/openssl-conf-by-section.html

new Source: https://github.com/egberts/egberts.github.io/content/articles/openssl-conf-by-section.md
old Source: https://github.com/egberts/tls-ca-manage/doc/OPENSSL-CONF.md

Section names:

* req
* ca
* x509 standard extensions


req section
===========
if following variables are not found in '[req]' section, then
unnamed or 'default section get searched too.

Section "req"  default settings are:

input_password=   # <string>
output_password=  # <string>
default_bits=2048 # <512-\*, 2048>
default_keyfile=  # <filespec>
oid_file=         # <filespec>
oid_section=      # <section>
RANDFILE=         # <filespec>
encrypt_key=yes   # <boolean> controlled by -nodes option
default_md=       # <digest> depends on non-curved signing algorithms
string_mask=utf8only   # RFC2459
req_extensions=   # <filespec> overriden by -reqexts option
x509_extensions=  # <filespec> overriden by -extensions option
prompt=           # <boolean> overrides distinguished_names & attributes
utf8=             # <boolean>
attributes=       # <section> contains [req] attributes
distinguished_name= # <section>


CA section
===========
The following is used by `openssl ca`.

If following variables are not found in the section 
specified by `-name` CLI option, then '[ default_ca ]' section
is used.

Section "[ default_ca ]"  default settings are:

oid_file=         # <filespec>
oid_section=      # <section>
new_certs_dir=    # <dirspec>   mandatory, same as `-outdir` CLI option
certificate=      # <filespec>  mandatory, same as `-certificate` CLI option
private=          # <filespec>  mandatory, same as `-keyfile` CLI option
RANDFILE=         # <filespec>
default_days=     # <days>      same as `-days` CLI option
default_startdate=<current_datetime> # <datetime>  current_time, same as `-startdate` CLI option
default_enddate=  # <datetime> mandatory OR with `default_days`, same as `-enddate` CLI option
default_crl_hours=  # <hours> mandatory OR with `default_crl_days`, same as `-crlhours` CLI option
default_crl_days=  # <datetime> mandatory OR with `default_crl_hours`, same as `-crldays` CLI option
default_md=       # <digest> depends on non-curved signing algorithms
database=         # <filespec> mandatory
unique_subject=yes # <boolean> (recommends 'no' for easier rollovers)
serial=           # <filespec> mandatory
crlnumber=        # <filespec> only if CRL is wanted
x509_extensions=  # <filespec> same as `-extensions`
crl_extensions=   # <filespec> same as `-crlexts`
preserve=         # <filespec> same as `-preserveDN`
email_in_dn=yes   # <boolean>  same as `-noemailDN`
policy=           # <policy>   same as `-policy`
name_opt=         # 
cert_opt=
copy_extensions=none # <none,copy,copyall>  Copies from [req]-related sections


X509 extensions section
=======================

if following variables are not found in an extension section, then
no other section will get searched.

X509 standard extensions section
--------------

X509 standard extensions section default settings are:

basicConstraints= # [critical,] keyname=keyvalue[;keyname=keyvalue]
keyUsage=         # [digitalSignature|nonRepudiation|keyEncipherment]
subjectKeyIdentifier= # hash, <hexstring>
authorityKeyIdentifier= # keyid[:always];issuer[:always]
subjectAltName=[IP:1.1.1.1]
subjectAltName=[email:john@doe.com]
subjectAltName=[UTF8:Jose Pena]
subjectAltName=[URI:http://ocsp.example.invalid:80]
subjectAltName=[dirname:dn_section]
subjectAltName=[RID:2.1.4.1.2.1.1]
issuerAltName=issuer:copy
authorityInfoAccess=OCSP;URI:http://ocsp.abc.com/
authorityInfoAccess=caIssuers;URI:http://ca.abc.com/ca.html
crlDistributionPoints=URI:http://crl.abc.com/my.crl,URI:http://crl.com/abc.crl


# only to appear in CRLs
crlDistributionPoint=[critical,]@my_crl_dp_section
[my_crl_dp_section]
  CRLissuer=dirName:my_crl_distinguished_name_section
  fullname=URI:http://ca.myhost.com/myca.crl
  onlysomereasons=keyCompromise, CACompromise
  onlyAA=FALSE
  onlyCA=TRUE
  onlyuser=FALSE
  [my_crl_distinguished_name_section_name]
  C=UK
  O=Organization
  CN=Some Name

issuingDistributionPoint=[critical,]@my_issuer_dp_section
[my_issuer_dp_section]
  indirectCRL=TRUE
  CRLissuer=dirName:my_issuer_distinguished_name_section
  fullname=URI:http://ca.myhost.com/myca.crl
  onlysomereasons=keyCompromise, CACompromise
  onlyAA=FALSE
  onlyCA=TRUE
  onlyuser=FALSE
  [my_issuer_distinguished_name_section]
  C=UK
  O=Organization
  CN=Some Name

# Raw ID 
certificatePolicies=<RID>[;<RID>]

output_password=  # <filespec>
default_bits=2048 # <512-\*, 2048>
default_keyfile=  # <filespec>
oid_file=         # <filespec>
oid_section=      # <section>
RANDFILE=         # <filespec>
encrypt_key=yes   # <boolean> controlled by -nodes option
default_md=       # <digest> depends on non-curved signing algorithms
string_mask=utf8only   # RFC2459
req_extensions=   # <filespec> overriden by -reqexts option
x509_extensions=  # <filespec> overriden by -extensions option
prompt=           # <boolean> overrides distinguished_names & attributes
utf8=             # <boolean>
attributes=       # <section> contains [req] attributes
distinguished_name= # <section>


CA section
===========
The following is used by `openssl ca`.

If following variables are not found in the section 
specified by `-name` CLI option, then '[ default_ca ]' section
is used.

Section "[ default_ca ]"  default settings are:

oid_file=         # <filespec>
oid_section=      # <section>
new_certs_dir=    # <dirspec>   mandatory, same as `-outdir` CLI option
certificate=      # <filespec>  mandatory, same as `-certificate` CLI option
private=          # <filespec>  mandatory, same as `-keyfile` CLI option
RANDFILE=         # <filespec>
default_days=     # <days>      same as `-days` CLI option
default_startdate=<current_datetime> # <datetime>  current_time, same as `-startdate` CLI option
default_enddate=  # <datetime> mandatory OR with `default_days`, same as `-enddate` CLI option
default_crl_hours=  # <hours> mandatory OR with `default_crl_days`, same as `-crlhours` CLI option
default_crl_days=  # <datetime> mandatory OR with `default_crl_hours`, same as `-crldays` CLI option
default_md=       # <digest> depends on non-curved signing algorithms
database=         # <filespec> mandatory
unique_subject=yes # <boolean> (recommends 'no' for easier rollovers)
serial=           # <filespec> mandatory
crlnumber=        # <filespec> only if CRL is wanted
x509_extensions=  # <filespec> same as `-extensions`
crl_extensions=   # <filespec> same as `-crlexts`
preserve=         # <filespec> same as `-preserveDN`
email_in_dn=yes   # <boolean>  same as `-noemailDN`
policy=           # <policy>   same as `-policy`
name_opt=         # 
cert_opt=
copy_extensions=none # <none,copy,copyall>  Copies from [req]-related sections


