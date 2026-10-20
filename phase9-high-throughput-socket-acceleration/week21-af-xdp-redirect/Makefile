# ==============================================================================
# Makefile: Week 21 - AF_XDP Wire-Speed Packet Pipeline
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/af-xdp-pipeline
IFACE ?= lo

.PHONY: all generate build run clean

all: generate build

generate:
	@echo "===> Generating Go bindings from xsk_kern.c via bpf2go..."
	go generate ./...

build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

run: build
	@echo "===> Running $(BINARY) on interface $(IFACE)..."
	sudo ./$(BINARY) -iface $(IFACE)

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
