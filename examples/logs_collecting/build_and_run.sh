docker build -t python-app:enclave-latest --target enclaved-app .

mkdir -p output

nitro-cli build-enclave --docker-uri python-app:enclave-latest --output-file output/python-app.eif

nitro-cli run-enclave --eif-path output/python-app.eif --enclave-cid 16 --cpu-count 2 --memory 2000 --debug-mode
