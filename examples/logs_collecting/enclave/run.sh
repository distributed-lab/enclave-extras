#!/bin/sh
set -e

echo "Starting"
sleep 1

echo "Up loopback interface"
ip link set lo up || true
sleep 1

# Ingress
echo "Start supervisor ingress vsock proxy"
socat VSOCK-LISTEN:9001,fork,keepalive TCP:127.0.0.1:9001,keepalive &
sleep 1

echo "Start supervisor"
supervisord -c /etc/supervisor/supervisord.conf
