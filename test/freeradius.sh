#!/bin/sh
set -ex

sed -i"" 's/default_eap_type = md5/default_eap_type = tls/' /etc/raddb/mods-enabled/eap
sed -i"" 's/private_key_password/#private_key_password/' /etc/raddb/mods-enabled/eap
sed -i"" 's/dh_file/#dh_file/' /etc/raddb/mods-enabled/eap
sed -i"" "s/\tmschap/\teap/" /etc/raddb/sites-enabled/default
sed -i"" "s/testing123/radius/" /etc/raddb/clients.conf

cfssl gencert -initca cfssl_ca_req.json | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem cfssl_server_req.json | cfssljson -bare server
cfssl gencert -ca ca.pem -ca-key ca-key.pem cfssl_client_req.json | cfssljson -bare client

cp ca.pem /etc/raddb/certs
cat server.pem server-key.pem > /etc/raddb/certs/server.pem

radiusd -X &
eapol_test -c eapol_test.conf