Covers the '-purpose' argument of 'openssl verify'

Also '-purpose' may be used (without an argument, 
if '-verify' is not used) in other openssl commands such as
'ca', 'req', and 'crl'.

Purpose options are:

 - slclient, 
 - sslserver, 
 - nssslserver, 
 - smimesign, 
 - smimeencrypt, 
 - crlsign, 
 - ocsphelper, 
 - timestampsign, and 
 - any
