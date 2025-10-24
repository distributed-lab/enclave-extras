# Collecting enclave app logs

Since AWS Nitro Enclave does not have persistent storage and does not output anything to stdout or stdin in production mode, collecting logs can be a problem if the application was not written for Enclave but runs in it. This example shows one way to solve this problem.

To run the example, you need to create an EC2 instance with Nitro Enclaves: Enabled, install [nitro-cli](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html) and [supervisor](https://supervisord.org/installing.html) (optionally, so that you can check the status of applications).

Clone the repository:
```sh
git clone --branch example/logs_collecting https://github.com/distributed-lab/enclave-extras.git
cd enclave-extras/examples/logs_collecting
```

Run socat, which will be used to manage applications in Enclave that are launched via supervisor:
```sh
socat TCP-LISTEN:9001,fork,reuseaddr,keepalive,bind=127.0.0.1 VSOCK-CONNECT:16:9001,keepalive &
```

If an error occurs, check if another socat is running on this port or if another application is running:
```sh
ps aux | grep socat
```

Run socat, which will accept connections from log_forwarder and save logs to a file, for example logs:
```sh
socat VSOCK-LISTEN:8001,fork,reuseaddr STDOUT | cat > logs &
```

Run the example:
```sh
./build_and_run.sh
```

To interact with applications in Enclave, you should use:
```sh
supervisorctl -s http://127.0.0.1:9001
```
