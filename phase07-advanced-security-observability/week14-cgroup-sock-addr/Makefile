# ==============================================================================
# Makefile: Week 14 - Zero-Trust Socket Egress Enforcer (cgroup/connect4)
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/sock-enforce

.PHONY: all generate build test run clean

all: generate build

generate:
	@echo "===> Generating Go bindings from sock_enforce.c via bpf2go..."
	go generate ./...

build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

test: generate
	@echo "===> Running eBPF tests with sudo..."
	go test -exec sudo -v ./...

run: build
	@echo "===> Running $(BINARY) with sudo..."
	sudo ./$(BINARY)

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
