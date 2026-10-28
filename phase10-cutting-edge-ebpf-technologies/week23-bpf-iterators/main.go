//go:build linux
// +build linux

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-I../../" bpf task_iter.c

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// readIter creates a new iterator instance (เหมือน open ไฟล์ใหม่) แล้วอ่านจนจบ
// ทุกครั้งที่ Open() เคอร์เนลจะเริ่มเดิน task list ใหม่ตั้งแต่ต้น
func readIter(it *link.Iter) ([]byte, error) {
	rd, err := it.Open()
	if err != nil {
		return nil, err
	}
	defer rd.Close()
	return io.ReadAll(rd)
}

// procfsWalk เป็น baseline แบบที่เครื่องมืออย่าง ps ทำ: เปิด /proc/<pid>/status ทีละโปรเซส
// คืนจำนวนโปรเซส user-space (มี VmSize) และจำนวนไฟล์ status ที่พยายามเปิด
func procfsWalk() (procs int, files int, err error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		name := e.Name()
		if name[0] < '0' || name[0] > '9' {
			continue
		}
		data, err := os.ReadFile("/proc/" + name + "/status")
		files++
		if err != nil {
			continue // โปรเซสอาจจบไปแล้วระหว่างเดิน
		}
		// kernel threads ไม่มีบรรทัด VmSize
		if bytes.Contains(data, []byte("\nVmSize:")) {
			procs++
		}
	}
	return procs, files, nil
}

func countRows(out []byte) int {
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if !strings.HasPrefix(sc.Text(), "PID ") {
			n++
		}
	}
	return n
}

func main() {
	runs := flag.Int("runs", 5, "จำนวนรอบที่วัดเวลา (รายงานค่าที่ดีที่สุด best-of-N)")
	quiet := flag.Bool("quiet", false, "ไม่พิมพ์ตารางโปรเซส แสดงเฉพาะสรุปเวลา")
	flag.Parse()

	fmt.Println("======================================================================")
	fmt.Println(" eBPF Kernel Task Iterator (iter/task) vs procfs walk")
	fmt.Println("======================================================================")

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach BPF Iterator: ได้ link ที่ Open() ซ้ำได้หลายครั้ง (แต่ละครั้ง = 1 iteration)
	it, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpTask,
	})
	if err != nil {
		log.Fatalf("Failed to attach BPF iterator: %v", err)
	}
	defer it.Close()

	var output []byte
	bestIter := time.Duration(1<<63 - 1)
	for i := 0; i < *runs; i++ {
		start := time.Now()
		out, err := readIter(it)
		if err != nil {
			log.Fatalf("Failed to read from iterator: %v", err)
		}
		if d := time.Since(start); d < bestIter {
			bestIter = d
		}
		output = out
	}

	bestProc := time.Duration(1<<63 - 1)
	var procs, files int
	for i := 0; i < *runs; i++ {
		start := time.Now()
		p, f, err := procfsWalk()
		if err != nil {
			log.Fatalf("procfs walk failed: %v", err)
		}
		if d := time.Since(start); d < bestProc {
			bestProc = d
		}
		procs, files = p, f
	}

	if !*quiet {
		// หัวตาราง (PID UID THREADS ...) ถูกพิมพ์จากฝั่ง BPF เองเมื่อ seq_num == 0
		fmt.Print(string(output))
		fmt.Println("----------------------------------------------------------------------")
	}

	fmt.Printf("[iter/task ] %4d processes, %7d bytes in 1 seq_file, best of %d: %v\n",
		countRows(output), len(output), *runs, bestIter)
	fmt.Printf("[procfs    ] %4d processes, %4d x /proc/<pid>/status files, best of %d: %v\n",
		procs, files, *runs, bestProc)
	fmt.Println("(ตัวเลขขึ้นกับจำนวนโปรเซสและ load ของเครื่อง; procfs อ่านข้อมูลมากกว่าที่ iterator พิมพ์)")
}
