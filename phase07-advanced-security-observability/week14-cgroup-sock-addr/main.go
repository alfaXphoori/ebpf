//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf sock_enforce.c

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

const cgroupRoot = "/sys/fs/cgroup"

// denyEvent ต้องมี layout ตรงกับ struct deny_event ใน sock_enforce.c (28 ไบต์)
type denyEvent struct {
	Pid      uint32
	DstIP    uint32 // network byte order
	DstPort  uint16
	SockType uint8
	Match    uint8
	Comm     [16]byte
}

func sockTypeStr(t uint8) string {
	switch t {
	case 1:
		return "TCP"
	case 2:
		return "UDP"
	}
	return fmt.Sprintf("type%d", t)
}

// prepareCgroup ตรวจสอบ/สร้าง cgroup v2 สำหรับทดลอง คืนค่า true หากโปรแกรมนี้เป็นผู้สร้าง
func prepareCgroup(path string, allowRoot bool) (bool, error) {
	clean := filepath.Clean(path)
	if clean == cgroupRoot && !allowRoot {
		return false, fmt.Errorf("refusing to attach to the ROOT cgroup %s (affects every process on the host); use a dedicated cgroup or pass -allow-root", cgroupRoot)
	}
	if fi, err := os.Stat(clean); err == nil {
		if !fi.IsDir() {
			return false, fmt.Errorf("%s is not a directory", clean)
		}
		return false, nil
	}
	if filepath.Dir(clean) != cgroupRoot {
		return false, fmt.Errorf("%s does not exist (auto-create only supports %s/<name>)", clean, cgroupRoot)
	}
	if err := os.Mkdir(clean, 0o755); err != nil {
		return false, fmt.Errorf("create cgroup %s: %w", clean, err)
	}
	return true, nil
}

func main() {
	cgroupPath := flag.String("cgroup", cgroupRoot+"/w14-sock-enforce", "Target cgroup v2 path (created automatically if missing)")
	allowRoot := flag.Bool("allow-root", false, "Allow attaching to the root cgroup /sys/fs/cgroup (affects the whole host!)")
	blockPort := flag.Int("block-port", 2323, "Destination port to deny for connect() (TCP and connected UDP)")
	blockIPStr := flag.String("block-ip", "10.99.99.99", "Destination IPv4 address to deny (empty = none)")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Socket Egress Enforcer (cgroup/connect4)")
	fmt.Println("======================================================================")

	created, err := prepareCgroup(*cgroupPath, *allowRoot)
	if err != nil {
		log.Fatalf("[ERROR] %v", err)
	}
	if created {
		log.Printf("[INFO] Created dedicated test cgroup %s\n", *cgroupPath)
		defer func() {
			// rmdir จะสำเร็จก็ต่อเมื่อไม่มีโปรเซสเหลืออยู่ใน cgroup แล้วเท่านั้น
			if err := os.Remove(*cgroupPath); err != nil {
				log.Printf("[WARN] Could not remove cgroup %s: %v (move its processes out, then rmdir)", *cgroupPath, err)
			} else {
				log.Printf("[INFO] Removed test cgroup %s\n", *cgroupPath)
			}
		}()
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Register blocked port
	port := uint16(*blockPort)
	var initVal uint64 = 0
	if err := objs.BlockedPorts.Put(&port, &initVal); err != nil {
		log.Fatalf("Failed to add port %d to blocklist: %v", port, err)
	}
	log.Printf("[POLICY] Deny destination port: %d (TCP + connected UDP)\n", port)

	// Register blocked IP
	var ipKey uint32
	haveIP := false
	if *blockIPStr != "" {
		ip := net.ParseIP(*blockIPStr).To4()
		if ip == nil {
			log.Fatalf("Invalid IPv4 address: %q", *blockIPStr)
		}
		// NativeEndian ทำให้ไบต์ในหน่วยความจำเรียงแบบ network order เหมือน ctx->user_ip4 ทุกสถาปัตยกรรม
		ipKey = binary.NativeEndian.Uint32(ip)
		if err := objs.BlockedIps.Put(&ipKey, &initVal); err != nil {
			log.Fatalf("Failed to add IP %s to blocklist: %v", *blockIPStr, err)
		}
		haveIP = true
		log.Printf("[POLICY] Deny destination IPv4: %s\n", *blockIPStr)
	}

	// Attach to cgroup (ผ่าน BPF link: ถูก detach อัตโนมัติเมื่อโปรเซสนี้ปิด FD/จบการทำงาน)
	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    *cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.Sock4Connect,
	})
	if err != nil {
		log.Fatalf("Failed to attach to cgroup %s: %v", *cgroupPath, err)
	}
	defer cgroupLink.Close()

	rd, err := ringbuf.NewReader(objs.DenyEvents)
	if err != nil {
		log.Fatalf("Failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	log.Printf("[INFO] Attached cgroup/connect4 to %s\n", *cgroupPath)
	log.Printf("[INFO] Policy applies ONLY to processes inside this cgroup. Run a client with:\n")
	log.Printf("       sudo sh -c 'echo $$ > %s/cgroup.procs && exec <command>'\n", *cgroupPath)
	log.Printf("[INFO] Press Ctrl+C to detach and exit.\n\n")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		rd.Close()
	}()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}
		var ev denyEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			continue
		}
		dst := make(net.IP, 4)
		binary.NativeEndian.PutUint32(dst, ev.DstIP)
		reason := "port"
		if ev.Match == 1 {
			reason = "ip"
		}
		fmt.Printf("[%s] DENY connect() pid=%-7d comm=%-12s dst=%s:%d/%s (matched %s) -> EPERM\n",
			time.Now().Format("15:04:05"), ev.Pid, string(bytes.TrimRight(ev.Comm[:], "\x00")),
			dst, ev.DstPort, sockTypeStr(ev.SockType), reason)
	}

	fmt.Println("\n[INFO] Detaching from cgroup and stopping...")
	var portDrops, ipDrops uint64
	_ = objs.BlockedPorts.Lookup(&port, &portDrops)
	fmt.Printf("Final denies on port %d: %d\n", port, portDrops)
	if haveIP {
		_ = objs.BlockedIps.Lookup(&ipKey, &ipDrops)
		fmt.Printf("Final denies on IP %s: %d\n", *blockIPStr, ipDrops)
	}
}
