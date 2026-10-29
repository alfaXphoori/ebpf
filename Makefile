# ==============================================================================
# Root Makefile: eBPF Zero to Hero - build / test every Go + eBPF lab at once
# ==============================================================================
#
#   make              # = make all: go generate + go build for every lab
#   make test         # run BPF_PROG_TEST_RUN unit tests (labs that define a test target; needs sudo)
#   make check        # build + test + syntax-check scripts: run locally before every push (no GitHub CI)
#   make clean        # remove bin/ and bpf2go generated files in every lab
#   make list         # list all lab directories
#   make vmlinux      # (re)generate ./vmlinux.h from the running kernel's BTF
#   make week07       # build a single week (week01..week23)
#   make week07-test  # test a single week
#

LABS := $(sort $(patsubst %/Makefile,%,$(wildcard phase*/week*/Makefile)))

.PHONY: all test check clean list vmlinux $(LABS)

all: vmlinux.h
	@set -e; for d in $(LABS); do \
		echo "===> [build] $$d"; \
		$(MAKE) --no-print-directory -C $$d all; \
	done

# Only labs whose Makefile defines a `test` target are tested
test: vmlinux.h
	@set -e; for d in $(LABS); do \
		if grep -q '^test:' $$d/Makefile; then \
			echo "===> [test] $$d"; \
			$(MAKE) --no-print-directory -C $$d test; \
		fi; \
	done

# Everything the old GitHub Actions job ran, on the local Linux 7.0 machine
check: all test
	bash -n scripts/setup_env.sh phase01-network-foundation/*/*.sh
	python3 -m py_compile phase01-network-foundation/week01-packet-netns/raw_sniffer.py phase02-first-step-ebpf/week04-bcc-python/tcp_v4_latency.py
	@echo "===> check passed"

clean:
	@for d in $(LABS); do $(MAKE) --no-print-directory -C $$d clean; done

list:
	@for d in $(LABS); do echo $$d; done

# CO-RE labs include ../../vmlinux.h; generate it on first use
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Per-week shortcuts: `make week07`, `make week07-test`
week%:
	@d=$$(ls -d phase*/week$*-* 2>/dev/null | head -n 1); \
	if [ -z "$$d" ]; then echo "No such lab: week$*"; exit 1; fi; \
	if [ ! -f $$d/Makefile ]; then echo "$$d has no Makefile (script-only lab)"; exit 0; fi; \
	$(MAKE) --no-print-directory -C $$d all

week%-test:
	@d=$$(ls -d phase*/week$*-* 2>/dev/null | head -n 1); \
	if [ -z "$$d" ]; then echo "No such lab: week$*"; exit 1; fi; \
	$(MAKE) --no-print-directory -C $$d test
