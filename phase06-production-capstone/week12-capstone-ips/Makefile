CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
IFACE ?= lo

.PHONY: all generate build run test clean

all: generate build

generate:
	cd cmd/ips-agent && go generate ./...

build:
	mkdir -p bin
	go build -v -o bin/ips-agent ./cmd/ips-agent

run: build
	sudo ./bin/ips-agent -iface $(IFACE) -ban-ttl 30s

# BPF_PROG_TEST_RUN unit tests (crafted packets, no interface attached); needs root
test: generate
	go test -exec sudo -v ./...

clean:
	rm -rf bin/ cmd/ips-agent/bpf_bpf*.go cmd/ips-agent/bpf_bpf*.o
