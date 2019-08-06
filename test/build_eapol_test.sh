#!/bin/sh

set -ex

apk add --no-cache git make gcc libc-dev openssl-dev linux-headers

git clone --depth=1 git://w1.fi/hostap.git
cd hostap/wpa_supplicant

cat <<EOF >.config
CONFIG_EAP_TLS=y
CONFIG_TLS=openssl
CONFIG_TLSV12=y
CONFIG_EAPOL_TEST=y
EOF

make eapol_test