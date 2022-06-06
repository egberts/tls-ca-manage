

set auto-load safe-path /
add-auto-load-safe-path /home/wolfe/work/github/tls-ca-manage/examples/.gdbinit

# Automatically loads shared object (.so) library
# Turn off if using disparate target (from host) during a remote GDB session
set auto-solib-add on
  # default is on

#
sharedlibrary libssl1.1

directory ./libssl1.1
directory /home/wolfe/work/openssl/openssl-1.1.1k/
directory /home/wolfe/work/openssl/openssl-1.1.1k/crypto
directory /home/wolfe/work/openssl/openssl-1.1.1k/crypto/x509v3

symbol-file /lib/x86_64-linux-gnu/libssl.so.1.1
symbol-file /home/wolfe/work/openssl/openssl-1.1.1k/apps/openssl 



set args req -config /etc/ssl/etc/AcmeComponent-ca__ocsp__AcmeOCSP__req.cnf -reqexts ocsp_AcmeComponent_reqext -new -key /etc/ssl/private/AcmeOCSP.key -sha256 -out /etc/ssl/certs/AcmeOCSP.csr

b main
b do_cmd
b req_main
b auto_info
b b X509V3_EXT_REQ_add_nconf

run

