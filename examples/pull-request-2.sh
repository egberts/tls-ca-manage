#!/bin/bash


bash -x ../tls-cert-manage.sh -f -d -d -d -v -v -v create tls-secured-portals server AcmeComponent
echo "retsts: $?"
exit

# strace -f 
/usr/bin/openssl req -verbose \
	-config /etc/ssl/etc/AcmeComponent-ca__server__tls-secured-portals__req.cnf \
	-reqexts server_AcmeComponent_reqext \
	-new \
	-key /etc/ssl/certs/tls-secured-portals.key \
	-sha256 \
	-out /etc/ssl/certs/tls-secured-portals.csr
retsts=$?
if [ $retsts -ne 0 ]; then
  echo "Error no $retsts; aborted."
  exit $retsts
fi
echo
echo "Done."
