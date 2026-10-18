# ==============================================================================
# Makefile: Week 05 - Modern eBPF with libbpf & Cilium ebpf-go
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/exec-counter
CLANG ?= clang

.PHONY: all generate build run clean

all: generate build

# Run bpf2go code generation to compile counter.c to BPF bytecode and Go bindings
generate:
	@echo "===> Generating Go bindings from counter.c via bpf2go..."
	go generate ./...

# Build the userspace Go binary
build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

# Run the userspace binary with superuser privileges
run: build
	@echo "===> Running $(BINARY) with sudo..."
	sudo ./$(BINARY)

# Clean generated artifacts and binary outputs
clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
