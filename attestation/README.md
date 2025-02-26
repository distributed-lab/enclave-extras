# Attestation
Wrapper for working with AWS Nitro Enclave

## Features
- Reading PCR registers (`DescribePCR`)
- Modifying PCR (`ExtendPCR`)
- Locking PCR (`LockPCR`)
- Retrieving attestation document (`GetAttestationDoc`, `GetAttestationDocRaw`)

## Environment variables
- `NSMLIBDIR` - path to the `libnsm` library 
```env
# .env file
NSMLIBDIR=/your/path/to/lib
```
---
- `CGO_LDFLAGS` - set flags for cgo (Optinal. You can use `-ldflags`)
```env
# use it in .env file
CGO_LDFLAGS="-L${NSMLIBDIR} -lnsm"
```
Or you can use flags `-ldflags "-L${NSMLIBDIR} -lnsm"` instead of `CGO_LDFLAGS`
```bash
# use it instead of CGO_LDFLAGS variable
go build -ldflags "-L${NSMLIBDIR} -lnsm" main.go
```