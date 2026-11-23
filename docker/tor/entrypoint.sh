#!/bin/sh
set -e
HASH=$(tor --quiet --hash-password "${TOR_CONTROL_PASSWORD:-changeme}")
cat > /tmp/torrc <<CONF
SocksPort 0.0.0.0:9050
ControlPort 0.0.0.0:9051
HashedControlPassword ${HASH}
DataDirectory /var/lib/tor
Log notice stdout
CONF
exec tor -f /tmp/torrc
