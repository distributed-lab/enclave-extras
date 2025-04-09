FROM rust:1.81.0-slim-bookworm AS nsmlib-builder
WORKDIR /workspace
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y git
RUN git clone https://github.com/aws/aws-nitro-enclaves-nsm-api.git && \
    cd aws-nitro-enclaves-nsm-api && \
    git checkout v0.4.0 && \
    mkdir -p /workspace/target/lib && \
    cargo build --release --manifest-path Cargo.toml -p nsm-lib && \
    install target/release/libnsm.a /workspace/target/lib/libnsm.a

FROM golang:1.23.1-bookworm AS nitro-attestation-cli-builder
WORKDIR /workspace
COPY pkgconfig /workspace/target/pkgconfig
RUN for file in /workspace/target/pkgconfig/*.pc; do \
    sed -i 's/\/path\/to\/lib/\/workspace\/target\/lib/g' "$file"; \
    done
COPY go.mod ./
RUN go mod download
COPY . ./
COPY --from=nsmlib-builder /workspace/target/ target/
RUN mkdir -p target/bin
RUN PKG_CONFIG_PATH=/workspace/target/pkgconfig go build -o target/bin/nitro-attestation-cli .

FROM debian:bookworm-slim AS nitro-attestation-cli
COPY --from=nitro-attestation-cli-builder /workspace/target/bin/nitro-attestation-cli /usr/local/bin/
ENTRYPOINT [ "nitro-attestation-cli" ]
