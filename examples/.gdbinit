
set auto-load safe-path /
add-auto-load-safe-path /home/wolfe/work/github/tls-ca-manage/examples/.gdbinit

set args req -config /etc/ssl/etc/MyCaRoot-ca.cnf -verbose -new -key /etc/ssl/ca/MyCaRoot-ca/private/MyCaRoot-ca.key -sha256 -out /etc/ssl/ca/MyCaRoot-ca.csr

b main
b do_cmd
b req_main
b auto_info
run

