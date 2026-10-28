# ==============================================================================
# Makefile: Week 21 - AF_XDP Packet Pipeline (XDP -> XSKMAP -> UMEM)
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/af-xdp-pipeline
# Never use a host interface (or lo): run inside the lab netns from README section 3
IFACE ?= w21-xsk0
NETNS ?= w21-rx

.PHONY: all generate build run test clean

all: generate build

generate:
	@echo "===> Generating Go bindings from xsk_kern.c via bpf2go..."
	go generate ./...

build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

run: build
	@echo "===> Running $(BINARY) on interface $(IFACE) in netns $(NETNS)..."
	sudo ip netns exec $(NETNS) ./$(BINARY) -iface $(IFACE)

# BPF_PROG_TEST_RUN verdict tests on crafted packets (needs sudo)
test: generate
	@echo "===> Running eBPF tests with sudo..."
	go test -exec sudo -v ./...

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
