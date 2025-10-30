#!/bin/bash

set -euo pipefail

docker build -t app-base:latest --target app-base .
mkdir -p output
nitro-cli build-enclave --docker-uri app-base:latest --output-file output/app.eif
