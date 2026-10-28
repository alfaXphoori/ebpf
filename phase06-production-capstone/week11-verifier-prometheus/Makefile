CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
IFACE ?= lo

.PHONY: all generate build run verifier-demo test clean

all: generate build

generate:
	go generate ./...

build:
	mkdir -p bin
	go build -v -o bin/metrics_exporter .
	go build -v -o bin/verifier_fail ./verifier_fail

run: build
	sudo ./bin/metrics_exporter -iface $(IFACE)

# Load the intentionally-broken programs and print the real verifier logs
verifier-demo: build
	-sudo ./bin/verifier_fail -case bounds
	-sudo ./bin/verifier_fail -case nullcheck
	sudo ./bin/verifier_fail -case fixed

# BPF_PROG_TEST_RUN + verifier rejection tests (no interface attached); needs root
test: generate
	go test -exec sudo -v ./...

clean:
	rm -rf bin/ bpf_*.go bpf_*.o verifier_fail/bpf_*.go verifier_fail/bpf_*.o
