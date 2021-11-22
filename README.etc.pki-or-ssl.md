
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

To complicate things further, this is where Debian looks for CA certificates:

-------------------------------
This article details how the rebuilding of Trusted Root CA occurs on a Debian
Linux using the `update-ca-certificates` tool as part of `ca-certificates`
Debian package.

Also it details what my current thoughts are regarding the auditable aspect of
Root CA, its intermediate CA, trusted CA and blacklisting CAs.

Executing the `update-ca-certificates --fresh` using `strace -f` has enabled me
to compile a list of files read and written.


The list of files that are opened and read-only are in the following order:

1. `/etc/ca-certificates.conf` file
2. `/usr/share/ca-certificates/*` directory
3. `/usr/share/ca-certificates/mozilla/*` directory
4. `/usr/share/ca-certificates/*/*` directory
5. `/usr/local/share/ca-certificates/*` directory
6. `/usr/local/share/ca-certificates/*/*` directory
7. `/etc/ssl/certs` directory
8. `$CWD/<all-certs-read-before>` files
9. `/usr/lib/ssl/openssl.cnf` file
10. `/etc/ca-certificates/update.d` directory
11. `/etc/ca-certificates/update.d/jks-keystore` directory
12. `/etc/default/cacerts` directory
13. `/etc/java-11-openjdk/security/nss.cfg` file
14. `/usr/share/ca-certificates-java` directory
15. `/usr/lib/jvm/java-11-openjdk-amd64/lib/jvm.cfg` file
16. `/usr/share/ca-certificates-java/ca-certificates-java.jar` file
17. `/etc/ca-certificates/update.d/mono-keystore` directory
18. `/etc/mono/4.5/machine.config` file
19. `/etc/mono/assemblies/cert-sync/cert-sync.config` file
20. `/etc/mono/assemblies/Mono.Security/Mono.Security.config` file
21. `/etc/mono/assemblies/mscorlib/mscorlib.config` file
22. `/etc/mono/assemblies/System/System.config` file
23. `/etc/mono/config` file
24. `/etc/ssl/certs/ca-certificates.crt` file
25. `$HOME/.mono/config` file
26. `/usr/lib/mono/4.5/cert-sync.exe.config` file
27. `/usr/lib/mono/4.5/cert-sync.exe.config` file
28. `/usr/lib/mono/4.5/mscorlib.dll.config` file
29. `/usr/lib/mono/gac/Mono.Security/4.0.0.0_0738eb9f132ed765/Mono.Security.dll.config` file
30. `/usr/lib/mono/gac/System/4.0.0.0__b77a5c561934e089/System.dll.config` file
31.  `/usr/share/.mono/certs/Trust/ski-*.cer` file
32.  `/usr/share/.mono/certs/new-certs/XXXXXXXX.0` file
33.  `$CWD/openssl` EXECUTABLE!!! (why look in $CWD?)
34.  `/usr/bin/openssl`
35.  `/usr/local/bin/openssl`
36.  `/usr/local/sbin/openssl`
37.  `/usr/sbin/openssl`  (VERY STRANGE ordering of /usr/[local/][s]bin/


Writes to the following text files:

1. `$CWD/ca-certificates.txt`
2. `/etc/ssl/certs/java/cacerts`


AUDITABLE OBSERVATION
=====================

OpenSSL binary, misordered lookup sequence of
---------------------------------------------

Observation of update-ca-certificates.

I noticed a very strange ordering of looking for the `openssl` binary.

Probably should have been something in the (re)order of:

1. $CWD/openssl  (probably should NOT have this entry)
2. /usr/local/sbin/openssl
2. /usr/local/bin/openssl
2. /usr/sbin/openssl
2. /usr/bin/openssl

Auditable Impact Toward CA Certificates
---------------------------------------

Probably should OUTPUT various 'modules' being touched up during the rebuilding
of CA certificates:

1.  MONO
2.  OpenJDK Java 11
3.  Mozilla

then

4.  OS System

Auditable Output of CA Certificates
-----------------------------------
Probably should OUTPUT what various CREATION of files:


1. `$CWD/ca-certificates.txt`
1. `/etc/ssl/certs/java/cacerts`

Better Summarization
--------------------

Probably should indicate those summarization AT THE END of its output, broken
down by CA-CERTIFICATE MODULES.  Like:

```
      OS System:
        Added:   0
        Deleted: 0
        Used:    0
      Mozilla package:
        Added:   0
        Deleted: 0
        Used:  129
      OpenJDK package:
        Added:   0
        Deleted: 0
        Used:   86
      MONO package:
        Added:   0
        Deleted: 0
        Used:   44
      Total Merge:   129

  Master File:  /usr/share/ca-certificates  (depends on distro)
  Master File:  /etc/ca-certificates
  Master File:  /etc/ssl/certs
  Master File:  /etc/pki/tls/certs
```

Will try and find appropriate package maintainer and/or author to let them know
of these findings.

Reference:

- [Security Shared System Certificates - Redhat](`https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/security_guide/sec-shared-system-certificates`)
- [Debian CA trust tool](https://manpages.debian.org/testing/p11-kit/trust.1.en.html)
