This file is obsoleted: 

see https://egbert.net/blog/openssl-password.html
Old source: https://github.com/egberts/tls-ca-manage/doc/PASSWORD.md
New source: https://github.com/egberts/egberts.github.io/content/articles/openssl-password.md

title: Many Ways to Pass a Password to OpenSSL
date: 2022-03-19 07:32
status: published
tags: OpenSSL
category: HOWTO
summary: See here the many ways to pass a password to the openssl command line.
slug: openssl-password
lang: en
private: False


There are two directions and two methods that a password can go with the `openssl` command:

* Reading a password or password file in [req] and [ca], only in openssl `req`, `x509`, `pkey`, `s_client`, or `s_server` commands.
* Writing to a password file, only in openssl `req` or `genpkey` commands.

and 

* directly into the command line
* by a file using a filename as a reference

and by file for only a password:

* unsecured
* secured by a digest algorithm

Pass A Password by Command Line
-------------------------------

pass the password directly on the command line to `openssl` 
```bash
openssl req ... -passin 'pass:mysecretpassword' ...
```

Of course, be mindful that your shell history will be recording this unless your shell setting has something like `HISTSIZE=0` to disable history recording.  Also, do not forget the memory of your terminal emulator (eg. scrollback line count, memory buffer, copy buffer).  

Just might be easier to avoid this method, so read on.


Pass A Password by File
-----------------------

To create an secured password file
```bash
echo "mysecretpassword" > password.txt
chmod 0600 password.txt
```

Then pass the filename of the password to the command line of `openssl`:

```bash
openssl req ... -passin 'file:password.txt' ...
```

The specification is simple:
```bash
openssl req ... -passin 'file:<filespec>' ...
```
where `<filespec>` is the filename, relative filename, or absolute file specification.

Securing A Password File
------------------------

Notice that 

The password file also can be secured with any one of the digest command options available.

In the `openssl req -help`, you will noticed the `-*` option.  That's the help notation for many-digest options.

To list the available digest command options, execute:
```console
$ openssl dgst -list
Supported digests:
-blake2b512                -blake2s256                -md4                      
-md5                       -md5-sha1                  -ripemd                   
-ripemd160                 -rmd160                    -sha1                     
-sha224                    -sha256                    -sha3-224                 
-sha3-256                  -sha3-384                  -sha3-512                 
-sha384                    -sha512                    -sha512-224               
-sha512-256                -shake128                  -shake256                 
-sm3                       -ssl3-md5                  -ssl3-sha1                
-whirlpool  
```

`-sha512` is preferred over `-sha3-512`, `-sha3-384`, `-sha3-256`, `-sha512-256` or `-sha512-224` for those two-numbered SHAs are actually the lowest number supported but stored in 512-bit data space.  Stick with `-sha512`.   

You could also experiment with `-blake2b512` safely than the rest of the unmentioned ones.
