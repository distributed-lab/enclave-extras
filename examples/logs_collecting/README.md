# Collecting enclave app logs

Since AWS Nitro Enclave does not have persistent storage and does not output anything to stdout or stdin in production mode, collecting logs can be a problem if the application was not written for Enclave but runs in it. This example shows one way to solve this problem.

To run the example, you need to create an EC2 instance with Nitro Enclaves: Enabled, install [nitro-cli](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html) and [supervisor](https://supervisord.org/installing.html) (optionally, so that you can check the status of applications).

Clone the repository:
```sh
git clone --branch example/logs_collecting https://github.com/distributed-lab/enclave-extras.git
cd enclave-extras/examples/logs_collecting
```

Build Dockerfile with Enclave Image File:
```sh
./build.docker.sh
```

Start docker compose:
```sh
docker compose up
```

Now you can find logs in `./data` directory.

To interact with applications in Enclave, you should use:
```sh
supervisorctl -s http://127.0.0.1:9001
```
