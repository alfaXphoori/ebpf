# ==============================================================================
# Makefile: Week 24 - kfuncs + BPF Arena
# ==============================================================================

BIN_DIR := bin
BINARY := $(BIN_DIR)/kfunc-arena

# cilium/ebpf v0.22.0 ล้าง field `off` ของคำสั่ง MOV ตอน marshal ทำให้ addr_space_cast
# (ที่ arena ต้องใช้) เสีย เราจึง vendor dependency แล้ว backport fix จาก upstream
# (commit cc4947e) ลงใน vendor/ ก่อน build/test — ดู patches/ และ README หัวข้อ 2.5
PATCH := patches/cilium-ebpf-v0.22.0-addr-space-cast.patch
VENDOR_STAMP := vendor/.week24-patched

.PHONY: all generate build test run clean

all: generate build

generate:
	@echo "===> Generating Go bindings (task_kfunc.c, task_kfunc_broken.c, arena_list.c) via bpf2go..."
	go generate ./...

# re-vendor when imports change (any *.go, including tests)
$(VENDOR_STAMP): go.mod go.sum $(PATCH) $(wildcard *.go)
	@echo "===> Vendoring dependencies and applying $(PATCH)..."
	rm -rf vendor
	go mod vendor
	patch -p1 -d vendor/github.com/cilium/ebpf < $(PATCH)
	touch $@

build: $(VENDOR_STAMP)
	@echo "===> Building userspace binary $(BINARY)..."
	mkdir -p $(BIN_DIR)
	go build -v -o $(BINARY) .

# Runtime tests ผ่าน BPF_PROG_TEST_RUN (ต้องใช้ root)
test: generate $(VENDOR_STAMP)
	@echo "===> Running runtime tests (main_test.go)..."
	go test -exec sudo -v ./...

run: build
	@echo "===> Running $(BINARY) with sudo..."
	sudo ./$(BINARY)

clean:
	@echo "===> Cleaning build artifacts..."
	rm -rf $(BIN_DIR) vendor
	rm -f kfunc_bpfel.go kfunc_bpfeb.go kfunc_bpfel.o kfunc_bpfeb.o
	rm -f broken_bpfel.go broken_bpfeb.go broken_bpfel.o broken_bpfeb.o
	rm -f arena_bpfel.go arena_bpfeb.go arena_bpfel.o arena_bpfeb.o
