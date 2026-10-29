# ==============================================================================
# Makefile: Week 25 - struct_ops + sched_ext (BPF CPU scheduler)
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/scx-w25

.PHONY: all generate build test run run-vtime demo-stall demo-error demo-nice state clean

all: generate build

generate:
	@echo "===> Generating Go bindings from scx_w25.c via bpf2go..."
	go generate ./...

build:
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

# Runtime test: attach จริงในโหมด SWITCH_PARTIAL กับ workload ของเราเอง แล้ว detach (ต้องใช้ root)
# (struct_ops ใช้ BPF_PROG_TEST_RUN ไม่ได้) -p 1: ห้ามรันขนาน เพราะ sched_ext มีได้ทีละ 1 scheduler
test: generate
	@echo "===> Running runtime tests (main_test.go)..."
	go test -exec sudo -p 1 -v ./...
	@echo "sched_ext state after tests: $$(cat /sys/kernel/sched_ext/state)"

run: build
	@echo "===> Running $(BINARY) (FIFO, 10s) with sudo..."
	sudo ./$(BINARY)

run-vtime: build
	sudo ./$(BINARY) -mode vtime

# Safety-net demos: เฉพาะ task SCHED_EXT ของเราเองที่ได้รับผลกระทบ (SWITCH_PARTIAL)
demo-stall: build
	sudo ./$(BINARY) -fail stall -timeout 2000 -workload 4 -duration 15s
	sudo dmesg | grep -A3 'sched_ext:' | tail -n 8

demo-error: build
	sudo ./$(BINARY) -fail error -workload 4 -duration 10s
	sudo dmesg | grep -A3 'sched_ext:' | tail -n 8

# เทียบ FIFO vs vtime: spinner nice 0 x2 + nice 10 x2 ที่ pin ไว้บน CPU 3
demo-nice: build
	./nice_demo.sh fifo
	./nice_demo.sh vtime

state:
	@cd /sys/kernel/sched_ext && grep -H . state switch_all enable_seq nr_rejected root/ops 2>/dev/null || true

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR)
	rm -f bpf_bpfel.go bpf_bpfeb.go bpf_bpfel.o bpf_bpfeb.o
