docker build -t python-app:enclave-latest --target enclaved-app .

mkdir -p output

nitro-cli build-enclave --docker-uri python-app:enclave-latest --output-file output/python-app.eif
