What a mess.

We need a tabulation of keyUsage/extendedKeyUsage vs. 'openssl XXX -purpose'.

keyUsage: digitalSignature
extendedKeyUsage: OCSP Signing

Certificate purposes:
SSL client : No
SSL client CA : No
SSL server : No
SSL server CA : No
Netscape SSL server : No
Netscape SSL server CA : No
S/MIME signing : No
S/MIME signing CA : No
S/MIME encryption : No
S/MIME encryption CA : No
CRL signing : No
CRL signing CA : No
Any Purpose : Yes
Any Purpose CA : Yes
OCSP helper : Yes
OCSP helper CA : No
Time Stamp signing : No
Time Stamp signing CA : No


So, for now, this squishy table will have to do:

            SSL    SSL    Netscape  S/MIME   CRL     Any     OCSP    TimeStmp
            client server Svr Clnt  Sgn Enc  Sign CA Sign CA Sign CA Sign CA
                CA     CA
digitalSignature
  OCSP Signing
            n   n  n   n  n   n     n n n n  n    n  n     Y Y    n  n    n

