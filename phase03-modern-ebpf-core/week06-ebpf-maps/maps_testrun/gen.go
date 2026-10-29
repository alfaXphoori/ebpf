// Package mapstestrun holds a small XDP program (map_types.c) whose only job is
// to let us unit-test map behaviour (HASH vs PERCPU_HASH vs LRU_HASH) with
// BPF_PROG_TEST_RUN. See maps_test.go; run with: make test
package mapstestrun

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf maptypes map_types.c
