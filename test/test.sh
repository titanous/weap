#!/bin/sh
set -ex

cfssl gencert -initca cfssl_ca_req.json | cfssljson -bare ca
cfssl gencert -ca ca.pem -ca-key ca-key.pem cfssl_server_req.json | cfssljson -bare server
cfssl gencert -ca ca.pem -ca-key ca-key.pem cfssl_client_req.json | cfssljson -bare client

cfssl gencert -initca cfssl_ca_req.json | cfssljson -bare ca2
cfssl gencert -ca ca2.pem -ca-key ca2-key.pem cfssl_client_req.json | cfssljson -bare client2

./weapd -authkey radius &

sleep 0.1

eapol_test -c eapol_test_tls12.conf

eapol_test -c eapol_test_tls13.conf > tls13.log 
grep 'TLSv1.3 read' tls13.log
grep 'MPPE keys OK: 1' tls13.log

eapol_test -c eapol_test_unauthorized_client.conf | grep "Access-Reject"

echo "ALL TESTS PASSED"