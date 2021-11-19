
Red Hat puts all X.509/PEM files for use with TLS under `/etc/pki/tls`

Whereas, the rest of the Linux distro world puts it under `/etc/ssl`.

Why?  Because, they can.

------------------

Creating a symbolic link to 
    /etc/ssl/certs/ca-certificates.crt in 
    /etc/pki/tls/certs/ca-bundle.crt fixes the issue.

------------------

Simply create a ~/.curlrc file.

Then add the following lines to the file:

capath=/etc/ssl/certs/
cacert=/etc/ssl/certs/ca-certificates.crt


------------------

This is where Go looks for public root certificates:

"/etc/ssl/certs/ca-certificates.crt",                // Debian/Ubuntu/Gentoo etc.
"/etc/pki/tls/certs/ca-bundle.crt",                  // Fedora/RHEL 6
"/etc/ssl/ca-bundle.pem",                            // OpenSUSE
"/etc/pki/tls/cacert.pem",                           // OpenELEC
"/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS/RHEL 7
"/etc/ssl/cert.pem",                                 // Alpine Linux

Also:

"/etc/ssl/certs",               // SLES10/SLES11, https://golang.org/issue/12139
"/system/etc/security/cacerts", // Android
"/usr/local/share/certs",       // FreeBSD
"/etc/pki/tls/certs",           // Fedora/RHEL
"/etc/openssl/certs",           // NetBSD
"/var/ssl/certs",  
