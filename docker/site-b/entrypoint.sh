#!/bin/sh
set -e

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.send_redirects=0

# Start strongSwan as a daemon
ipsec start

# Keep the container alive (site-b responds to initiation from site-a)
exec tail -f /dev/null
