# ==============================================================================
# Makefile: Week 18 - On-CPU Profiler (perf_event) & Stack Collector
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/cpu-profiler
WORKLOAD := $(BIN_DIR)/busy

.PHONY: all generate build workload run clean

all: generate build workload

generate:
	@echo "===> Generating Go bindings from cpu_stacks.c via bpf2go..."
	go generate ./...

build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

workload:
	@echo "===> Building demo CPU workload $(WORKLOAD) (with frame pointers)..."
	mkdir -p $(BIN_DIR)
	clang -O1 -g -fno-omit-frame-pointer -o $(WORKLOAD) workload/busy.c

run: build
	@echo "===> Running $(BINARY) with sudo..."
	sudo ./$(BINARY)

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
