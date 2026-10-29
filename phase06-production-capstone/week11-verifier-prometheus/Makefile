CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
IFACE ?= lo

# Verifier-log lab (verifier_fail/, make verifier-demo) moved to
# phase03-modern-ebpf-core/week06-ebpf-maps

.PHONY: all generate build run test clean

all: generate build

generate:
	go generate ./...

build:
	mkdir -p bin
	go build -v -o bin/metrics_exporter .

run: build
	sudo ./bin/metrics_exporter -iface $(IFACE)

# BPF_PROG_TEST_RUN tests for xdp_metrics_prog (no interface attached); needs root
test: generate
	go test -exec sudo -v ./...

clean:
	rm -rf bin/ bpf_*.go bpf_*.o
