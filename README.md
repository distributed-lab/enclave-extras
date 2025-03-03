# Enclave Extras

Utilities, libraries, templates, tips, and examples for working with AWS Nitro Enclave

## Table of Contents
- [Overview](#overview)
- [TCP/IP for Enclaves](#tcpip-for-enclaves)
- [Mounting persistent volume in Enclave](#mounting-persistent-volume-in-enclave)
- [GoLang and Nitro Secure Module](#golang-and-nitro-secure-module)
- [Cryptographic Attestation Module & KMS Integration](#cryptographic-attestation-module--kms-integration)

## Overview
TODO

## TCP/IP for Enclaves
AWS Nitro Enclave does not have the usual communication via the TCP/IP stack that is used everywhere. The only communication channel is vsock, which allows you to communicate with the parent EC2 instance and other Enclaves that are associated with the same parent instance. This makes it impossible to run regular applications because they use TCP/IP.

There are several solutions to this problem: one solution is to rewrite the application to work with vsock, but this still won't provide Internet access. Another solution is to use a proxy, this approach allows you to not modify the existing code, but still run it in AWS Nitro Enclave.

You can find vsock-proxy in the [aws-nitro-enclaves-cli](https://github.com/aws/aws-nitro-enclaves-cli) repository, but this is only one half, this proxy listens to the vsock port and redirects traffic to a specified IP address or domain and port. The other half is a reverse vsock proxy, this proxy listens to the IP:Port and redirects traffic to vsock. The implementation of the second half is in the [vscproxy](https://github.com/distributed-lab/enclave-extras/tree/main/vscproxy) package.

Inside AWS Nitro Enclave, a loopback interface will be used to interact with the Internet, different IP addresses of this interface will correspond to different domains/IP + Ports from the outside. To work with domains, you need to modify the **/etc/hosts** file. Below is an example of commands to run in parent instace and enclave.

### EC2 Instance
```bash
#!/bin/sh
sudo dnf install aws-nitro-enclaves-cli -y
sudo dnf install aws-nitro-enclaves-cli-devel -y

sudo usermod -aG ne $USER
sudo usermod -aG docker $USER

sudo tee -a /etc/nitro_enclaves/vsock-proxy.yaml <<EOF
- {address: kms.us-west-1.amazonaws.com, port: 443 }
- {address: 127.0.0.1, port: 2049 }
EOF

# Connections from Enclave
vsock-proxy 8000 kms.us-west-1.amazonaws.com 443 &
vsock-proxy 20000 127.0.0.1 2049 &

vscproxy 

nitro-cli run-enclave --eif-path /path/to/enclave.eif --enclave-cid 16 --cpu-count 2 --memory 4000 --debug-mode
```

### Enclave
```bash
#!/bin/sh
set -e

echo "Up loopback interface"
ip link set lo up || true
sleep 15

echo "Setup /etc/hosts"
echo "127.0.0.2   kms.us-west-1.amazonaws.com" >>/etc/hosts

echo "Ensure loopback addresses exist"
if ! ip addr show dev lo | grep -q "127.0.0.2"; then
  ip addr add 127.0.0.2/32 dev lo:0
  ip link set dev lo:0 up
fi
if ! ip addr show dev lo | grep -q "127.0.0.200"; then
  ip addr add 127.0.0.200/32 dev lo:0
  ip link set dev lo:0 up
fi
sleep 15

echo "Start vsock proxies"
# Connections from Enclave
vscproxy -parentCID=3 -vsockPort=8000 -localAddr=127.0.0.2:443 &
vscproxy -parentCID=3 -vsockPort=20000 -localAddr=127.0.0.200:2049 &
sleep 15

echo "Start main process"
# Another code
```

### Only socat proxy
```dockerfile
# Build socat
FROM debian:bookworm-slim AS socat-builder
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y \
    wget make gcc
RUN wget http://www.dest-unreach.org/socat/download/socat-1.7.4.4.tar.gz && \
    tar -xzf socat-1.7.4.4.tar.gz && \
    cd socat-1.7.4.4 && \
    ./configure && \
    make && \
    make install

FROM debian:bookworm-slim
COPY --from=socat-builder /usr/local/bin/socat /usr/local/bin/socat
ENTRYPOINT [ "/usr/local/bin/yourprogram" ]
```

#### Forward traffic from Enclave to EC2
```bash
# listen vsock on EC2 and forward to TCP
socat VSOCK-LISTEN:8002,fork,keepalive TCP:iam.amazonaws.com:443,keepalive &
```
```bash
# listen TCP in Enclave and forward to parent vsock (cid 3)
socat TCP-LISTEN:443,bind=127.0.0.2,fork,reuseaddr,keepalive VSOCK-CONNECT:3:8002,keepalive &
```


#### Forward traffic from EC2 to Enclave
```bash
# listen TCP on EC2 and forward to vsock (enclave cid)
socat TCP-LISTEN:2000,bind=127.0.0.1,fork,reuseaddr,keepalive VSOCK-CONNECT:16:2000,keepalive &
```
```bash
# listen vsock in Enclave and forward to TCP
socat VSOCK-LISTEN:2000,fork,keepalive TCP:127.0.0.1:2000,keepalive &
```


## Mounting persistent volume in Enclave
For mounting persistent volumes in Enclave, we considered such cases as SSHFS, Samba, and NFS. SSHFS was rejected because mounting a file system is only a part of SSH, and such a powerful tool can lead to increased audit complexity and reduced isolation. Samba, although designed for remote file systems, is a SMB protocol that works best with Windows hosts. That leaves Linux native NFSv4. The lack of authorization can lead to the fact that anyone can mount NFS, but properly configured exports solve this problem, and it also removes the need to hardcode remote fs credentials in enclave, as it was necessary to do with SSHFS and Samba. The lack of traffic encryption is a disadvantage, but it also increases speed. Benchmarks showed speeds of 200 MB/s for reading and 130 MB/s for writing (Enclave 2 CPU and 3GB memory).

### Install NFS Server
```bash
sudo apt update                                     # sudo yum update
sudo apt-get install nfs-kernel-server nfs-common   # sudo yum install -y nfs-utils
sudo echo "/path/to/exportdir 127.0.0.1/32(rw,insecure,fsid=0,crossmnt,no_subtree_check,sync)" >> /etc/exports
sudo systemctl restart nfs-kernel-server            # sudo systemctl restart nfs-server
```

### Mount NFS
NFSv4 uses only port 2049. In this example, it is assumed that the vsock proxy is already configured
```bash
sudo apt update                 # sudo yum update
sudo apt-get install nfs-common # sudo yum install -y nfs-utils
sudo mkdir -p /mnt/pv
sudo mount -t nfs4 127.0.0.200:/ /mnt/pv
```

## GoLang and Nitro Secure Module
NSM library wrap all methods of the [aws-nitro-enclaves-nsm-api](https://github.com/aws/aws-nitro-enclaves-nsm-api) library. CGO must be used at compile time. [Read more](https://github.com/distributed-lab/enclave-extras/tree/main/nsm)

## Cryptographic Attestation Module & KMS Integration
TODO
