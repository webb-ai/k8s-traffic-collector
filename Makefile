ARCH=$(shell uname -m)
ifeq ($(ARCH),$(filter $(ARCH),aarch64 arm64))
	BPF_TARGET=arm64
	BPF_ARCH_SUFFIX=arm64
else
	BPF_TARGET=amd64
	BPF_ARCH_SUFFIX=x86
endif

build:
	go build -ldflags="-extldflags=-static -s -w" -o worker .

bpf:
	BPF_TARGET="$(BPF_TARGET)" BPF_CFLAGS="-O2 -g -D__TARGET_ARCH_$(BPF_ARCH_SUFFIX)" go generate tracer/tracer.go

lint:
	golangci-lint run
