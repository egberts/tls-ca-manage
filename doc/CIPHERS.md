

Some commands to use for cipher:

TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

```console
$ openssl dgst \
    -mac poly1305 \
    -macopt key:abcd1234abcd1234abcd1234abcd1234 \
    <filespec>
$
$ openssl dgst \
    -mac poly1305 \
    -macopt hexkey:ee00000000000000000000000000000000000000000000ffffffffffffffffff \
    <filespec>
```
