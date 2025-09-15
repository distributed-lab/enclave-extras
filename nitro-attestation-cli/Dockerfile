FROM golang:1.23.1-bookworm AS nitro-attestation-cli-builder
WORKDIR /workspace
COPY go.mod ./
RUN go mod download
COPY . ./
RUN mkdir -p target/bin
RUN go build -o target/bin/nitro-attestation-cli .

FROM debian:bookworm-slim AS nitro-attestation-cli
COPY --from=nitro-attestation-cli-builder /workspace/target/bin/nitro-attestation-cli /usr/local/bin/
ENTRYPOINT [ "nitro-attestation-cli" ]
