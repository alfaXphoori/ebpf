# ==============================================================================
# Makefile: Week 07 - High-Speed XDP Packet Parsing & Ingress Firewall
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/xdp-firewall
IFACE ?= lo
BLOCK_IP ?= 127.0.0.100

.PHONY: all generate build test run clean

all: generate build

# Run bpf2go code generator
generate:
	@echo "===> Generating Go bindings from xdp_firewall.c via bpf2go..."
	go generate ./...

# Build userspace binary
build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

# Run BPF_PROG_TEST_RUN unit tests (needs root: go test re-executes the test binary via sudo)
test: generate
	@echo "===> Running BPF_PROG_TEST_RUN unit tests (main_test.go)..."
	go test -exec sudo -v ./...

# Run with target interface and optional block IP
run: build
	@echo "===> Running $(BINARY) on interface $(IFACE)..."
	sudo ./$(BINARY) -iface $(IFACE) -block-ip $(BLOCK_IP)

# Clean build artifacts
clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
