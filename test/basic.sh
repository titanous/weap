#!/bin/sh
set -ex

cfssl gencert -initca cfssl_ca_req.json | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem cfssl_server_req.json | cfssljson -bare server
cfssl gencert -ca ca.pem -ca-key ca-key.pem cfssl_client_req.json | cfssljson -bare client

./weapd -authkey radius &
eapol_test -c eapol_test.conf