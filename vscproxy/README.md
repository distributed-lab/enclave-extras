# Vscproxy
This tool provides a vsock proxy
## Flags
- `parentCID` - the parent's context ID to connect. Default: 3
- `vsockPort` - the vsock port to connect. Default: 8000
- `localAddr` - the local address to listen on. Default: 127.0.0.1:443
- `attempts` - the number of attempts to connect. Default: 100
- `delay` - the duration to wait between attempts (in milliseconds). Default: 10000
### Example
```bash
# code example
./app --parentCID=3 --vsockPort=8000 --localAddr=127.0.0.1:443 --attempts=100 --delay=10000
```