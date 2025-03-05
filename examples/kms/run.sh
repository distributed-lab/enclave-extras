#!/bin/sh
sudo dnf install aws-nitro-enclaves-cli -y
sudo dnf install aws-nitro-enclaves-cli-devel -y
sudo usermod -aG ne $USER
sudo usermod -aG docker $USER

# Configure allocator
readonly NE_ALLOCATOR_SPEC_PATH="/etc/nitro_enclaves/allocator.yaml"
# Node resources that will be allocated for Nitro Enclaves
readonly CPU_COUNT=2
readonly MEMORY_MIB=4096
# Update enclave's allocator specification: allocator.yaml
sed -i "s/cpu_count:.*/cpu_count: $CPU_COUNT/g" $NE_ALLOCATOR_SPEC_PATH
sed -i "s/memory_mib:.*/memory_mib: $MEMORY_MIB/g" $NE_ALLOCATOR_SPEC_PATH

sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl enable --now docker

# TODO: Build socat in docker and just copy binary
yum install -y wget tar gcc libreadline-dev
wget http://www.dest-unreach.org/socat/download/socat-1.7.4.4.tar.gz
tar -xzf socat-1.7.4.4.tar.gz
cd socat-1.7.4.4
./configure
make
make install

socat VSOCK-LISTEN:8002,fork,keepalive TCP:kms.eu-central-1.amazonaws.com:443,keepalive &
socat VSOCK-LISTEN:8003,fork,keepalive TCP:iam.amazonaws.com:443,keepalive &

nitro-cli run-enclave --eif-path /path/to/eif --enclave-cid 16 --cpu-count 2 --memory 4000 --debug-mode
nitro-cli console --enclave-id $(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
