#
# Title: Remove info from PEM file leaving behind the public key

cat $1 | sed -n '/-----BEGIN/,/-----END/p'


