#!/bin/sh
set -e

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0

# Start strongSwan as a daemon
ipsec start

# Wait for charon to be ready
sleep 3

# Explicitly initiate the tunnel (site-a is the initiator)
ipsec up site-to-site || true

# Keep the container alive
exec tail -f /dev/null
