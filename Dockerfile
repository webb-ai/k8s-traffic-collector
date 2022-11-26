ARG BUILDARCH=amd64
ARG TARGETARCH=amd64

### Base builder image for native builds architecture
FROM golang:1.17-alpine AS builder-native-base
ENV CGO_ENABLED=1 GOOS=linux
RUN apk add --no-cache \
    libpcap-dev \
    g++ \
	curl \
    build-base \
    binutils-gold \
    bash \
    clang \
    llvm \
    libbpf-dev \
    linux-headers
COPY ./install-capstone.sh .
RUN ./install-capstone.sh


### Intermediate builder image for x86-64 to x86-64 native builds
FROM builder-native-base AS builder-from-amd64-to-amd64
ENV GOARCH=amd64
ENV BPF_TARGET=amd64 BPF_CFLAGS="-O2 -g -D__TARGET_ARCH_x86"


### Intermediate builder image for AArch64 to AArch64 native builds
FROM builder-native-base AS builder-from-arm64v8-to-arm64v8
ENV GOARCH=arm64
ENV BPF_TARGET=arm64 BPF_CFLAGS="-O2 -g -D__TARGET_ARCH_arm64"


### Builder image for x86-64 to AArch64 cross-compilation
FROM kubeshark/linux-arm64-musl-go-libpcap-capstone-bpf:capstone-5.0-rc2 AS builder-from-amd64-to-arm64v8
ENV CGO_ENABLED=1 GOOS=linux
ENV GOARCH=arm64 CGO_CFLAGS="-I/work/libpcap -I/work/capstone/include"
ENV BPF_TARGET=arm64 BPF_CFLAGS="-O2 -g -D__TARGET_ARCH_arm64 -I/usr/xcc/aarch64-linux-musl-cross/aarch64-linux-musl/include/"


### Builder image for AArch64 to x86-64 cross-compilation
FROM kubeshark/linux-x86_64-musl-go-libpcap-capstone-bpf:capstone-5.0-rc2 AS builder-from-arm64v8-to-amd64
ENV CGO_ENABLED=1 GOOS=linux
ENV GOARCH=amd64 CGO_CFLAGS="-I/libpcap -I/capstone/include"
ENV BPF_TARGET=amd64 BPF_CFLAGS="-O2 -g -D__TARGET_ARCH_x86  -I/usr/local/musl/x86_64-unknown-linux-musl/include/"


### Final builder image where the build happens
# Possible build strategies:
# BUILDARCH=amd64 TARGETARCH=amd64
# BUILDARCH=arm64v8 TARGETARCH=arm64v8
# BUILDARCH=amd64 TARGETARCH=arm64v8
# BUILDARCH=arm64v8 TARGETARCH=amd64
ARG BUILDARCH=amd64
ARG TARGETARCH=amd64
FROM builder-from-${BUILDARCH}-to-${TARGETARCH} AS builder

WORKDIR /app/build

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

WORKDIR /app/build/tlstapper
RUN rm *_bpfel_*
RUN GOARCH=${BUILDARCH} go generate tls_tapper.go

WORKDIR /app/build

RUN go build -ldflags="-extldflags=-static -s -w" -o worker .

### The shipped image
ARG TARGETARCH=amd64
FROM ${TARGETARCH}/busybox:latest

WORKDIR /app/data/
WORKDIR /app

COPY --from=builder ["/app/build/worker", "."]

ENTRYPOINT ["/app/worker"]
