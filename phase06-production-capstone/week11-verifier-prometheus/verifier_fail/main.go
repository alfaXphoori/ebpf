// verifier_fail loads one intentionally-broken XDP program and prints the
// real verifier log returned by the kernel (ebpf.VerifierError).
//
// Nothing is attached to any interface: the program is only loaded
// (BPF_PROG_LOAD) and closed again.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf bpf verifier_fail.c

// cases maps the -case flag to a program (SEC("xdp") function) in verifier_fail.c
var cases = map[string]string{
	"bounds":    "xdp_no_bounds_check",
	"nullcheck": "xdp_no_null_check",
	"fixed":     "xdp_fixed",
}

// loadCase loads a single program from the collection (plus the maps it uses).
// Loading the whole collection would stop at the first rejected program.
func loadCase(name string, opts ebpf.ProgramOptions) (*ebpf.Collection, error) {
	progName, ok := cases[name]
	if !ok {
		return nil, fmt.Errorf("unknown case %q", name)
	}
	spec, err := loadBpf()
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{progName: spec.Programs[progName]}
	return ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: opts})
}

func main() {
	keys := make([]string, 0, len(cases))
	for k := range cases {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	caseFlag := flag.String("case", "bounds", fmt.Sprintf("program to load: %v", keys))
	linesFlag := flag.Int("lines", 0, "print only the last N lines of the verifier log (0 = whole log)")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// LogLevelBranch|LogLevelStats: request the instruction-level trace up front
	// (by default cilium/ebpf only re-requests a log after a failed load).
	opts := ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats}
	if *caseFlag == "fixed" {
		opts.LogLevel = ebpf.LogLevelStats // summary only for the accepted program
	}

	coll, err := loadCase(*caseFlag, opts)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("[VERIFIER] program %q REJECTED\n", cases[*caseFlag])
			if *linesFlag > 0 {
				fmt.Printf("%-*v\n", *linesFlag, ve) // %-Nv = last N lines
			} else {
				fmt.Printf("%+v\n", ve) // %+v = whole log
			}
			os.Exit(1)
		}
		log.Fatalf("Load failed (not a verifier error): %v", err)
	}
	defer coll.Close()

	prog := coll.Programs[cases[*caseFlag]]
	fmt.Printf("[VERIFIER] program %q ACCEPTED\n%s", cases[*caseFlag], prog.VerifierLog)
}
