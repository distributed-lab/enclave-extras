#!/bin/sh
set -e

echo "Up loopback interface"
ip link set lo up || true
sleep 15

echo "Ensure loopback addresses exist"
if ! ip addr show dev lo | grep -q "127.0.0.200"; then
  ip addr add 127.0.0.200/32 dev lo:0
  ip link set dev lo:0 up
fi
sleep 15

echo "Start vsock proxy"
# NFS
vscproxy -parentCID=3 -vsockPort=20000 -localAddr=127.0.0.200:2049 &
sleep 15

echo "Mounting persistent volume to /mnt/pv"
mkdir -p /mnt/pv
mount -t nfs4 127.0.0.200:/ /mnt/pv
sleep 15

# Run program
