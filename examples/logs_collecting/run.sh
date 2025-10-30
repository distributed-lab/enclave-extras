#!/bin/bash -e

# Start vsock proxies

# Outbound enclave connections
# Syslog
socat VSOCK-LISTEN:8001,fork,keepalive TCP:$SYSLOG_SERVER,keepalive &

# Inbound enclave connections
# Supervisor
socat TCP-LISTEN:$SUPERVISOR_PORT,fork,reuseaddr,keepalive VSOCK-CONNECT:$ENCLAVE_CID:9001,keepalive &

nitro-cli run-enclave --eif-path /root/app.eif --enclave-cid $ENCLAVE_CID --cpu-count $CPU_COUNT --memory $MEMORY_MIB $EXTRA_OPTIONS
enclave_id=$(nitro-cli describe-enclaves | jq -r ".[0].EnclaveID")
echo "-------------------------------"
echo "Enclave ID is $enclave_id"
echo "-------------------------------"

nitro-cli console --enclave-id $enclave_id || true && tail -f /dev/null
