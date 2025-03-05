#!/bin/sh
set -e

echo "Starting"
sleep 15

echo "Up loopback interface"
ip link set lo up || true
sleep 15

echo "Setup /etc/hosts"
echo "127.0.0.2   kms.eu-central-1.amazonaws.com" >>/etc/hosts
echo "127.0.0.3   iam.amazonaws.com" >> /etc/hosts

echo "Ensure loopback addresses exist"
if ! ip addr show dev lo | grep -q "127.0.0.2"; then
  ip addr add 127.0.0.2/32 dev lo:0
  ip link set dev lo:0 up
fi
if ! ip addr show dev lo | grep -q "127.0.0.3"; then
  ip addr add 127.0.0.3/32 dev lo:0
  ip link set dev lo:0 up
fi
sleep 15

echo "Start vsock proxies"
socat TCP-LISTEN:443,bind=127.0.0.2,fork,reuseaddr,keepalive VSOCK-CONNECT:3:8002,keepalive &
socat TCP-LISTEN:443,bind=127.0.0.3,fork,reuseaddr,keepalive VSOCK-CONNECT:3:8003,keepalive &
sleep 15

echo "Start main process"
example
