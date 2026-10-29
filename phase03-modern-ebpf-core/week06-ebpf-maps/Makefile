# ==============================================================================
# Makefile: Week 06 - eBPF Maps, Verifier Log & BPF_PROG_TEST_RUN (Cilium ebpf-go)
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/syscall-top
CLANG ?= clang

.PHONY: all generate build run verifier-demo test clean

all: generate build

# Generate Go bindings and BPF bytecode using bpf2go
# (syscall_stats.c, verifier_fail/verifier_fail.c, maps_testrun/map_types.c)
generate:
	@echo "===> Generating Go bindings via bpf2go..."
	go generate ./...

# Build userspace binaries
build:
	@echo "===> Building userspace binaries $(BINARY) and $(BIN_DIR)/verifier_fail..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .
	go build -v -o $(BIN_DIR)/verifier_fail ./verifier_fail

# Run the userspace binary with sudo
run: build
	@echo "===> Running $(BINARY) with sudo..."
	sudo ./$(BINARY)

# Load the intentionally-broken programs and print the real verifier logs
verifier-demo: build
	-sudo ./$(BIN_DIR)/verifier_fail -case bounds
	-sudo ./$(BIN_DIR)/verifier_fail -case nullcheck
	sudo ./$(BIN_DIR)/verifier_fail -case fixed

# Load tests + verifier rejection tests + BPF_PROG_TEST_RUN map tests
# (nothing is attached to a hook or interface); needs root
test: generate
	go test -exec sudo -v ./...

# Clean compiled objects and binaries
clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
	rm -f verifier_fail/bpf_bpf.go verifier_fail/bpf_bpf.o
	rm -f maps_testrun/maptypes_bpf.go maps_testrun/maptypes_bpf.o
