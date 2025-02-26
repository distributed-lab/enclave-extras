# Enclave extras
Wrapper for working with AWS Nitro Enclave

## Features
- Reading PCR registers (`DescribePCR`)
- Modifying PCR (`ExtendPCR`)
- Locking PCR (`LockPCR`)
- Retrieving attestation document (`GetAttestationDoc`, `GetAttestationDocRaw`)

## Variable environments
- `NSMLIBDIR` - path to the `libnsm` library 
```bash
# code example
export NSMLIBDIR=/usr/local/lib
```