# ==============================================================================
# Makefile: Week 08 - TC & XDP Layer-4 Load Balancer
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/xdp-tc-lb
IFACE ?= lo
VIP ?= 10.10.1.100

.PHONY: all generate build run clean

all: generate build

# Run bpf2go for both xdp_lb.c and tc_egress.c
generate:
	@echo "===> Generating Go bindings from xdp_lb.c and tc_egress.c via bpf2go..."
	go generate ./...

# Build userspace binary
build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

# Run with target interface and VIP
run: build
	@echo "===> Running $(BINARY) on interface $(IFACE) with VIP $(VIP)..."
	sudo ./$(BINARY) -iface $(IFACE) -vip $(VIP)

# Clean all generated Go bindings, objects, and binary
clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f xdplb_bpfel.go xdplb_bpfeb.go xdplb_bpfel.o xdplb_bpfeb.o
	rm -f tcegress_bpfel.go tcegress_bpfeb.go tcegress_bpfel.o tcegress_bpfeb.o
