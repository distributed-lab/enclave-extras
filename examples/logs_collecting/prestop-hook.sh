#!/bin/sh
set -e

ENCLAVE_ID=ENCLAVE_ID_TO_REPLACE

echo "[preStop] Stopping nitro..."
supervisorctl -s http://127.0.0.1:9001 stop app || true
echo "[preStop] Nitro stopped"

echo "[preStop] Terminating enclave $ENCLAVE_ID..."
nitro-cli terminate-enclave --enclave-id $ENCLAVE_ID || true
echo "[preStop] Enclave terminated"

exit 0
