# ==============================================================================
# Root Makefile: eBPF Zero to Hero - build / test every Go + eBPF lab at once
# ==============================================================================
#
#   make              # = make all: go generate + go build for every lab
#   make test         # run BPF_PROG_TEST_RUN unit tests (labs that define a test target; needs sudo)
#   make check        # build + test + vet + fmt + docs + syntax-check scripts (run locally before push)
#   make clean        # remove bin/ and bpf2go generated files in every lab
#   make list         # list all lab directories
#   make vmlinux      # (re)generate ./vmlinux.h from the running kernel's BTF
#   make diagrams     # re-render docs/diagrams/src/*.mmd into docs/diagrams/*.svg (needs docker)
#   make docs-check   # verify markdown links, diagram parity, and script permissions
#   make week07       # build a single week (week01..week26)
#   make week07-test  # test a single week
#

LABS := $(sort $(patsubst %/Makefile,%,$(wildcard phase*/week*/Makefile)))
GO_MODULES := $(sort $(patsubst %/go.mod,%,$(wildcard phase*/week*/go.mod)))

.PHONY: all test check vet fmt-check docs-check py-test clean list vmlinux diagrams $(LABS)

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

vet: vmlinux.h
	@set -e; for d in $(GO_MODULES); do \
		echo "===> [vet] $$d"; \
		(cd $$d && go vet ./...); \
	done

fmt-check:
	@unformatted=$$(gofmt -l $$(find phase* -name '*.go' -not -path '*/vendor/*' -not -name '*_bpf*.go')); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted Go files:"; echo "$$unformatted"; exit 1; \
	fi
	@echo "fmt-check OK"

docs-check:
	@python3 scripts/check_docs.py

py-test:
	@python3 -m unittest discover -s phase01-network-foundation/week01-packet-netns -p 'test_*.py' -v
	@python3 -m unittest discover -s phase08-system-performance-observability/week18-cpu-profiler-stacks -p 'test_*.py' -v
	@python3 -m unittest discover -s phase11-modern-ebpf-extensibility/week26-ecosystem-tetragon-cilium -p 'test_*.py' -v

# Everything the old GitHub Actions job ran, plus vet, fmt, docs, and Python tests
check: all test vet fmt-check docs-check py-test
	@bash -n $$(find scripts phase* -name '*.sh' -not -path '*/vendor/*' | sort)
	@python3 -m py_compile $$(find scripts phase* -name '*.py' -not -path '*/vendor/*' | sort)
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

# Course diagrams: edit docs/diagrams/src/<name>.mmd, then run this
diagrams:
	scripts/render_diagrams.sh

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
