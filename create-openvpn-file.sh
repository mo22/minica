#!/bin/bash
set -euo pipefail

./nanoca create --days 3650 --usage user_cert "$1"

echo "
# created by $( realpath "$0" ) $1
# place to /etc/openvpn/delta.conf

client

dev tun

proto udp4
remote delta.mxs.de 1194

resolv-retry infinite

nobind

persist-key
persist-tun

remote-cert-tls server

verb 3

<ca>
$( ./nanoca cacert )
</ca>

<cert>
$( ./nanoca cert "$1" )
</cert>

<key>
$( ./nanoca key "$1" )
</key>

" | tee "$1.ovpn"

