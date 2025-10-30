#!/bin/sh
set -e

echo "Starting"
sleep 1

echo "Up loopback interface"
ip link set lo up || true
sleep 1

if ! ip addr show dev lo | grep -q "127.0.0.2"; then
  ip addr add 127.0.0.2/32 dev lo:0
  ip link set dev lo:0 up
fi

# Syslog
echo "Start Syslog egress vsock proxy"
socat TCP-LISTEN:514,bind=127.0.0.2,fork,reuseaddr,keepalive VSOCK-CONNECT:3:8001,keepalive &

# Ingress
echo "Start supervisor ingress vsock proxy"
socat VSOCK-LISTEN:9001,fork,keepalive TCP:127.0.0.1:9001,keepalive &
sleep 1

echo "Start supervisor"
supervisord -c /etc/supervisor/supervisord.conf
