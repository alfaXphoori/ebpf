# ==============================================================================
# Makefile: Week 17 - Block I/O Latency Analyzer (CO-RE biolatency)
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/biolatency

.PHONY: all generate build run test clean

all: generate build

generate:
	@echo "===> Generating Go bindings from biolatency.c via bpf2go..."
	go generate ./...

build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

run: build
	@echo "===> Running $(BINARY) with sudo..."
	sudo ./$(BINARY)

test: generate
	@echo "===> Running Go + eBPF tests (requires sudo)..."
	go test -exec sudo -v ./...

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
