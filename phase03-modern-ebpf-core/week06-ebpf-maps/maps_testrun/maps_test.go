package mapstestrun

// BPF_PROG_TEST_RUN tests for map_types.c.
//
// Program.Run() calls bpf(BPF_PROG_TEST_RUN): the kernel runs count_by_key
// once (or Repeat times) on a fake packet we pass in Data. Nothing is attached
// to any interface, so the tests are safe to run on any machine.
// Requires root: make test  (= go test -exec sudo -v ./...)

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const (
	xdpPass  = 2 // XDP_PASS
	maxKeys  = 8 // MAX_KEYS in map_types.c
	errHash  = 0 // index in update_errs
	errPcpu  = 1
	errLRU   = 2
	ethHLen  = 14 // XDP test_run rejects data shorter than an Ethernet header
	minusE2B = -int64(unix.E2BIG)
)

// load gives every test a fresh set of maps (empty, nothing shared between tests).
func load(t *testing.T) *maptypesObjects {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root for BPF_PROG_LOAD/BPF_PROG_TEST_RUN; run: make test (go test -exec sudo)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	objs := &maptypesObjects{}
	if err := loadMaptypesObjects(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier rejected map_types.c:\n%+v", ve)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { objs.Close() })
	return objs
}

// packet builds a minimal 14-byte "Ethernet frame" whose first 4 bytes are the key.
func packet(key uint32) []byte {
	pkt := make([]byte, ethHLen)
	binary.NativeEndian.PutUint32(pkt, key)
	return pkt
}

// run executes the XDP program `repeat` times on one packet via BPF_PROG_TEST_RUN.
func run(t *testing.T, prog *ebpf.Program, key uint32, repeat uint32) {
	t.Helper()
	ret, err := prog.Run(&ebpf.RunOptions{Data: packet(key), Repeat: repeat})
	if err != nil {
		t.Fatalf("BPF_PROG_TEST_RUN: %v", err)
	}
	if ret != xdpPass {
		t.Fatalf("return code = %d, want XDP_PASS (%d)", ret, xdpPass)
	}
}

func countEntries(t *testing.T, m *ebpf.Map) int {
	t.Helper()
	// walk the keys only (bpf(BPF_MAP_GET_NEXT_KEY)); works for per-CPU maps too
	n := 0
	var cur, next uint32
	var prev interface{} // nil = "give me the first key"
	for {
		err := m.NextKey(prev, &next)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return n
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
		cur = next
		prev = &cur
	}
}

func updateErr(t *testing.T, objs *maptypesObjects, idx uint32) maptypesUpdateErr {
	t.Helper()
	var e maptypesUpdateErr
	if err := objs.UpdateErrs.Lookup(idx, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

// One key, 1000 runs: HASH and LRU_HASH hold one shared counter; PERCPU_HASH
// holds one counter per possible CPU and user space has to sum them.
func TestSameKeyCounts(t *testing.T) {
	objs := load(t)
	const key, n = 42, 1000
	run(t, objs.CountByKey, key, n)

	var shared uint64
	if err := objs.HashMap.Lookup(uint32(key), &shared); err != nil || shared != n {
		t.Fatalf("hash_map[%d] = %d (err %v), want %d", key, shared, err, n)
	}
	if err := objs.LruMap.Lookup(uint32(key), &shared); err != nil || shared != n {
		t.Fatalf("lru_map[%d] = %d (err %v), want %d", key, shared, err, n)
	}

	// PERCPU lookup returns a slice with one element per *possible* CPU
	var perCPU []uint64
	if err := objs.PercpuMap.Lookup(uint32(key), &perCPU); err != nil {
		t.Fatal(err)
	}
	possible, err := ebpf.PossibleCPU()
	if err != nil {
		t.Fatal(err)
	}
	if len(perCPU) != possible {
		t.Fatalf("per-CPU slice has %d values, want %d (possible CPUs)", len(perCPU), possible)
	}
	var sum uint64
	for cpu, v := range perCPU {
		sum += v
		if v != 0 {
			t.Logf("percpu_map[%d] on CPU %d = %d", key, cpu, v)
		}
	}
	if sum != n {
		t.Fatalf("sum of percpu_map[%d] over %d CPUs = %d, want %d", key, possible, sum, n)
	}
}

// 20 distinct keys into maps with max_entries = 8:
// HASH/PERCPU_HASH refuse new keys with -E2BIG, LRU_HASH evicts old keys instead.
func TestFullMapHashVsLRU(t *testing.T) {
	objs := load(t)
	const keys = 20
	for k := uint32(1); k <= keys; k++ {
		run(t, objs.CountByKey, k, 1)
	}

	for _, tc := range []struct {
		name string
		m    *ebpf.Map
		idx  uint32
	}{{"hash_map", objs.HashMap, errHash}, {"percpu_map", objs.PercpuMap, errPcpu}} {
		if n := countEntries(t, tc.m); n != maxKeys {
			t.Errorf("%s has %d entries, want %d (max_entries)", tc.name, n, maxKeys)
		}
		e := updateErr(t, objs, tc.idx)
		if e.Count != keys-maxKeys || e.LastErr != minusE2B {
			t.Errorf("%s update errors = %+v, want count=%d last_err=%d (-E2BIG)", tc.name, e, keys-maxKeys, minusE2B)
		}
		t.Logf("%s: %d entries, %d failed inserts, last_err=%d (-E2BIG)", tc.name, maxKeys, e.Count, e.LastErr)
	}
	// the first 8 keys won, the newest key is missing from the plain HASH
	var v uint64
	if err := objs.HashMap.Lookup(uint32(keys), &v); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Errorf("hash_map[%d]: err = %v, want ErrKeyNotExist", keys, err)
	}

	n := countEntries(t, objs.LruMap)
	if n == 0 || n > maxKeys {
		t.Errorf("lru_map has %d entries, want 1..%d", n, maxKeys)
	}
	if e := updateErr(t, objs, errLRU); e.Count != 0 {
		t.Errorf("lru_map update errors = %+v, want none (LRU evicts instead of failing)", e)
	}
	if err := objs.LruMap.Lookup(uint32(keys), &v); err != nil || v != 1 {
		t.Errorf("lru_map[%d] = %d (err %v), want the newest key to be present with value 1", keys, v, err)
	}
	t.Logf("lru_map: %d entries after %d distinct keys, newest key %d present, 0 failed inserts", n, keys, keys)
}

// The kernel validates test input too: an XDP test packet must hold at least
// an Ethernet header, otherwise BPF_PROG_TEST_RUN fails with EINVAL before
// the program even runs.
func TestTooShortPacketRejected(t *testing.T) {
	objs := load(t)
	_, err := objs.CountByKey.Run(&ebpf.RunOptions{Data: make([]byte, ethHLen-1)})
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("Run with %d-byte packet: err = %v, want EINVAL", ethHLen-1, err)
	}
	t.Logf("%d-byte packet: %v", ethHLen-1, err)
}
