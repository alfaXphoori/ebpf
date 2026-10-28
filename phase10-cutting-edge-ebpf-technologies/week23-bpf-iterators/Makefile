# ==============================================================================
# Makefile: Week 23 - BPF Iterators (bpf_iter_task)
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/task-iter

.PHONY: all generate build test run clean

all: generate build

generate:
	@echo "===> Generating Go bindings from task_iter.c via bpf2go..."
	go generate ./...

build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

# Runtime test: รัน iterator จริงแล้วตรวจว่าได้ 1 แถวต่อ 1 โปรเซส (ต้องใช้ root)
test: generate
	@echo "===> Running runtime tests (main_test.go)..."
	go test -exec sudo -v ./...

run: build
	@echo "===> Running $(BINARY) with sudo..."
	sudo ./$(BINARY)

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
