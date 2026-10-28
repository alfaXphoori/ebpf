# ==============================================================================
# Makefile: Week 22 - BPF Trampoline (fentry & fexit) Tracing
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/trampoline-tracer

.PHONY: all generate build test bench run clean

all: generate build

generate:
	@echo "===> Generating Go bindings from trampoline.c via bpf2go..."
	go generate ./...

build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

# Runtime test: attach fentry/fexit แล้วตรวจค่า return ที่ fexit อ่านได้ (ต้องใช้ root)
test: generate
	@echo "===> Running runtime tests (main_test.go)..."
	go test -exec sudo -v ./...

# วัด overhead: kprobe / kretprobe / fentry / fexit บน do_sys_openat2 (ใช้ bpftrace + bpf_stats)
bench:
	@echo "===> Measuring probe overhead (bench/run_bench.sh)..."
	./bench/run_bench.sh

run: build
	@echo "===> Running $(BINARY) with sudo..."
	sudo ./$(BINARY)

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
