# ==============================================================================
# Makefile: Week 06 - eBPF Maps & State Management (Cilium ebpf-go)
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/syscall-top
CLANG ?= clang

.PHONY: all generate build run clean

all: generate build

# Generate Go bindings and BPF bytecode using bpf2go
generate:
	@echo "===> Generating Go bindings from syscall_stats.c via bpf2go..."
	go generate ./...

# Build userspace binary
build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

# Run the userspace binary with sudo
run: build
	@echo "===> Running $(BINARY) with sudo..."
	sudo ./$(BINARY)

# Clean compiled objects and binaries
clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
