package main

// Asserts that the intentionally-broken programs are rejected by the verifier
// with the expected message, and that the fixed one is accepted.
// Requires root: make test  (= go test -exec sudo -v ./...)

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestVerifierRejectsBrokenPrograms(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to load eBPF programs; run: make test (go test -exec sudo)")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	for name, want := range map[string]string{
		"bounds":    "invalid access to packet",
		"nullcheck": "invalid mem access 'map_value_or_null'",
	} {
		t.Run(name, func(t *testing.T) {
			coll, err := loadCase(name, ebpf.ProgramOptions{})
			if err == nil {
				coll.Close()
				t.Fatalf("case %q was accepted by the verifier, expected rejection", name)
			}
			var ve *ebpf.VerifierError
			if !errors.As(err, &ve) {
				t.Fatalf("expected *ebpf.VerifierError, got %T: %v", err, err)
			}
			if log := strings.Join(ve.Log, "\n"); !strings.Contains(log, want) {
				t.Fatalf("verifier log does not contain %q:\n%+v", want, ve)
			}
		})
	}

	t.Run("fixed", func(t *testing.T) {
		coll, err := loadCase("fixed", ebpf.ProgramOptions{})
		if err != nil {
			t.Fatalf("fixed program rejected: %+v", err)
		}
		coll.Close()
	})
}
