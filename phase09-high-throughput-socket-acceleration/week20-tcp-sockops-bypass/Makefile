# ==============================================================================
# Makefile: Week 20 - TCP Sockops & Direct Socket Bypass Acceleration
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/sockops-accelerator
BENCH := $(BIN_DIR)/tcpbench
CGROUP ?= /sys/fs/cgroup/w20-sockops-lab

.PHONY: all generate build run test clean

all: generate build

generate:
	@echo "===> Generating Go bindings from sockops.c via bpf2go..."
	go generate ./...

build:
	@echo "===> Building userspace binaries $(BINARY) and $(BENCH)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .
	go build -v -o $(BENCH) ./cmd/tcpbench

run: build
	@echo "===> Running $(BINARY) on cgroup $(CGROUP) with sudo..."
	sudo ./$(BINARY) -cgroup $(CGROUP)

# Load/attach smoke test + end-to-end redirect test in a temporary cgroup (needs sudo)
test: generate
	@echo "===> Running eBPF tests with sudo..."
	go test -exec sudo -v ./...

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
