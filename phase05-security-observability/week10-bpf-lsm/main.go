package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" -target bpf bpf lsm_file_guard.c

const (
	matchName  = 1
	matchInode = 2
)

// lsmAlert matches C struct lsm_alert (304 bytes, little-endian)
type lsmAlert struct {
	Ino    uint64
	Dev    uint32
	Pid    uint32
	Uid    uint32
	Ret    int32
	Reason uint32
	Pad    uint32
	Comm   [16]byte
	Path   [256]byte
}

// inodeKey matches C struct inode_key
type inodeKey struct {
	Ino uint64
	Dev uint32
	Pad uint32
}

// enforceObjects / auditObjects โหลดเฉพาะ program ที่ต้องใช้ (พร้อม maps ทั้งหมด)
// เพื่อไม่ให้ program อีกตัวที่เคอร์เนลไม่รองรับทำให้การโหลดล้มทั้งก้อน
type enforceObjects struct {
	bpfMaps
	Prog *ebpf.Program `ebpf:"restrict_secret_files"`
}

type auditObjects struct {
	bpfMaps
	Prog *ebpf.Program `ebpf:"audit_secret_files"`
}

// bpfLSMActive คืน true ถ้า "bpf" อยู่ในรายการ LSM ที่เคอร์เนลเปิดใช้งานตอนบูต
func bpfLSMActive() bool {
	content, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		log.Printf("[WARN] Cannot read /sys/kernel/security/lsm: %v. Assuming BPF LSM is NOT enabled.", err)
		return false
	}
	activeLSMs := strings.TrimSpace(string(content))
	log.Printf("[INFO] Active Linux Security Modules: %s", activeLSMs)
	for _, m := range strings.Split(activeLSMs, ",") {
		if m == "bpf" {
			return true
		}
	}
	log.Println("[WARNING] 'bpf' is NOT in /sys/kernel/security/lsm!")
	log.Println("[WARNING] BPF LSM programs can still be loaded/attached, but the kernel will never call them.")
	log.Println("[WARNING] To enable BPF LSM, append 'bpf' to the lsm= boot parameter (see README section 'การเปิดใช้งาน BPF LSM').")
	return false
}

// kernelDev แปลง st_dev จาก stat() (encoding ของ user space) ให้เป็น
// sb->s_dev ภายในเคอร์เนล: MKDEV(major, minor) = major<<20 | minor
func kernelDev(statDev uint64) uint32 {
	return unix.Major(statDev)<<20 | unix.Minor(statDev)
}

func cStringToString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx >= 0 {
		return string(b[:idx])
	}
	return string(b)
}

func main() {
	blockAllFlag := flag.Bool("block-all", false, "Block matching file access for all users, including root (UID 0)")
	modeFlag := flag.String("mode", "auto", "auto | enforce (lsm/file_open) | audit (fentry/security_file_open, log only)")
	var protectPaths []string
	flag.Func("protect", "Protect a specific file by inode (repeatable), e.g. -protect /etc/app/key.pem", func(s string) error {
		protectPaths = append(protectPaths, s)
		return nil
	})
	flag.Parse()

	// 1. Remove Memlock limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// 2. Check kernel BPF LSM capability and pick mode
	lsmActive := bpfLSMActive()
	mode := *modeFlag
	switch mode {
	case "auto":
		if lsmActive {
			mode = "enforce"
		} else {
			mode = "audit"
			log.Println("[INFO] -mode=auto: BPF LSM inactive -> falling back to AUDIT mode (fentry/security_file_open, cannot block)")
		}
	case "enforce":
		if !lsmActive {
			log.Println("[WARNING] -mode=enforce on a kernel without active BPF LSM: attach may succeed but NOTHING will be blocked.")
		}
	case "audit":
	default:
		log.Fatalf("Unknown -mode %q (use auto, enforce or audit)", mode)
	}

	// 3. Load eBPF objects (เฉพาะ program ของโหมดที่เลือก)
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	var maps *bpfMaps
	var prog *ebpf.Program
	if mode == "enforce" {
		objs := enforceObjects{}
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			log.Fatalf("Failed to load eBPF objects (make sure your kernel has CONFIG_BPF_LSM=y and BTF): %v", err)
		}
		defer objs.bpfMaps.Close()
		defer objs.Prog.Close()
		maps, prog = &objs.bpfMaps, objs.Prog
	} else {
		objs := auditObjects{}
		if err := spec.LoadAndAssign(&objs, nil); err != nil {
			log.Fatalf("Failed to load eBPF objects (fentry needs BTF + CONFIG_DEBUG_INFO_BTF): %v", err)
		}
		defer objs.bpfMaps.Close()
		defer objs.Prog.Close()
		maps, prog = &objs.bpfMaps, objs.Prog
	}

	// 4. Configure policy map
	var policyKey uint32 = 0
	var policyVal uint32 = 0
	if *blockAllFlag {
		policyVal = 1
		log.Println("[POLICY] Enforce Mode: BLOCK ALL (including root UID 0)")
	} else {
		log.Println("[POLICY] Enforce Mode: BLOCK NON-ROOT (root UID 0 allowed)")
	}

	if err := maps.PolicyMap.Put(&policyKey, &policyVal); err != nil {
		log.Printf("[WARN] Failed to update policy map: %v", err)
	}

	// 5. Inode-based protection list
	for _, p := range protectPaths {
		var st unix.Stat_t
		if err := unix.Stat(p, &st); err != nil {
			log.Fatalf("Cannot stat -protect %q: %v", p, err)
		}
		key := inodeKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}
		var one uint8 = 1
		if err := maps.ProtectedInodes.Put(&key, &one); err != nil {
			log.Fatalf("Failed to add %q to protected_inodes: %v", p, err)
		}
		log.Printf("[POLICY] Protecting inode dev=%d:%d ino=%d (%s)", unix.Major(st.Dev), unix.Minor(st.Dev), st.Ino, p)
	}

	// 6. Attach hook
	var hook link.Link
	if mode == "enforce" {
		hook, err = link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			log.Fatalf("Failed to attach LSM program (verify kernel supports CONFIG_BPF_LSM=y): %v", err)
		}
		log.Println("[INFO] Attached BPF LSM hook 'lsm/file_open' (ENFORCE: matching opens return -EPERM)")
	} else {
		hook, err = link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			log.Fatalf("Failed to attach fentry program: %v", err)
		}
		log.Println("[INFO] Attached 'fentry/security_file_open' (AUDIT: matching opens are logged, NOT blocked)")
	}
	defer hook.Close()

	log.Println("[INFO] Watching for access to 'secret*' files and protected inodes...")

	// 7. Open Ring Buffer Reader
	rd, err := ringbuf.NewReader(maps.LsmEvents)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[INFO] Termination signal received. Detaching hook and exiting...")
		rd.Close()
	}()

	fmt.Printf("%-20s %-7s %-6s %-10s %-6s %s\n", "SECURITY_ACTION", "PID", "UID", "COMM", "MATCH", "PATH -> RESULT")
	fmt.Println(strings.Repeat("-", 100))

	var alert lsmAlert
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[INFO] Ringbuf reader closed. Goodbye.")
				return
			}
			log.Printf("[ERROR] Reading ringbuf record: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &alert); err != nil {
			log.Printf("[ERROR] Failed to decode LSM alert: %v", err)
			continue
		}

		comm := cStringToString(alert.Comm[:])
		path := cStringToString(alert.Path[:])

		match := "name"
		if alert.Reason == matchInode {
			match = "inode"
		}

		action, resultStr, color := "[AUDIT would-block]", "ALLOWED (audit only)", "\033[1;33m"
		if alert.Ret == -int32(syscall.EPERM) {
			action, resultStr, color = "[BLOCKED -EPERM]", "EPERM (Blocked)", "\033[1;31m"
		}

		fmt.Printf("%s%-20s\033[0m %-7d %-6d %-10s %-6s %s -> %s\n",
			color, action, alert.Pid, alert.Uid, comm, match, path, resultStr)
	}
}
