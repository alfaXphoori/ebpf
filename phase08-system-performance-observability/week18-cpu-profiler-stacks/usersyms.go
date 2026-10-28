//go:build linux
// +build linux

package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ===========================================================================
// User-space symbolizer แบบเรียบง่าย (สำหรับการเรียนรู้)
//
//   user IP --(/proc/<pid>/maps)--> ไฟล์ + file offset
//           --(ELF PT_LOAD)------> virtual address ภายในไฟล์ ELF
//           --(.symtab/.dynsym)--> ชื่อฟังก์ชัน
//
// ข้อจำกัด: ไม่ใช้ DWARF/debuginfod, ไม่ demangle C++/Rust,
// ไม่รู้จักโค้ด JIT (Java/Node/Python) และต้องอ่าน maps ได้ขณะโปรเซสยังมีชีวิต
// ===========================================================================

type vmaMapping struct {
	start, end, offset uint64
	path               string
}

type elfFunc struct {
	addr, size uint64
	name       string
}

type elfInfo struct {
	funcs []elfFunc
	loads []elf.ProgHeader
}

type userSymbolizer struct {
	maps map[uint32][]vmaMapping // pid -> memory mappings (snapshot ล่าสุดที่อ่านได้)
	elfs map[string]*elfInfo     // path -> symbol table (nil = เปิดไม่ได้)
}

func newUserSymbolizer() *userSymbolizer {
	return &userSymbolizer{maps: map[uint32][]vmaMapping{}, elfs: map[string]*elfInfo{}}
}

// snapshot อ่าน /proc/<pid>/maps เก็บเฉพาะ mapping ที่ executable
func (s *userSymbolizer) snapshot(pid uint32) {
	if pid == 0 {
		return
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return // โปรเซสจบไปแล้ว: ใช้ snapshot เดิม (ถ้ามี)
	}
	defer f.Close()

	var vmas []vmaMapping
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		// 55d0c0a00000-55d0c0a01000 r-xp 00001000 103:02 1234  /usr/bin/busy
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 || !strings.Contains(fields[1], "x") {
			continue
		}
		lo, hi, _ := strings.Cut(fields[0], "-")
		start, err1 := strconv.ParseUint(lo, 16, 64)
		end, err2 := strconv.ParseUint(hi, 16, 64)
		off, err3 := strconv.ParseUint(fields[2], 16, 64)
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		path := ""
		if len(fields) >= 6 {
			path = strings.TrimSuffix(strings.Join(fields[5:], " "), " (deleted)")
		}
		vmas = append(vmas, vmaMapping{start: start, end: end, offset: off, path: path})
	}
	if len(vmas) > 0 {
		s.maps[pid] = vmas
	}
}

func (s *userSymbolizer) loadELF(pid uint32, path string) *elfInfo {
	if info, ok := s.elfs[path]; ok {
		return info
	}
	// อ่านผ่าน /proc/<pid>/root ก่อน เพื่อให้ใช้ได้กับโปรเซสใน container (mount namespace อื่น)
	var ef *elf.File
	var err error
	for _, p := range []string{fmt.Sprintf("/proc/%d/root%s", pid, path), path} {
		if ef, err = elf.Open(p); err == nil {
			break
		}
	}
	if err != nil {
		s.elfs[path] = nil
		return nil
	}
	defer ef.Close()

	info := &elfInfo{}
	for _, p := range ef.Progs {
		if p.Type == elf.PT_LOAD {
			info.loads = append(info.loads, p.ProgHeader)
		}
	}
	add := func(syms []elf.Symbol) {
		for _, sym := range syms {
			if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Value != 0 {
				info.funcs = append(info.funcs, elfFunc{addr: sym.Value, size: sym.Size, name: sym.Name})
			}
		}
	}
	if syms, err := ef.Symbols(); err == nil { // .symtab (มีถ้าไม่ได้ strip)
		add(syms)
	}
	if syms, err := ef.DynamicSymbols(); err == nil { // .dynsym (shared library มีเสมอ)
		add(syms)
	}
	sort.Slice(info.funcs, func(i, j int) bool { return info.funcs[i].addr < info.funcs[j].addr })
	s.elfs[path] = info
	return info
}

// resolve แปลง user IP ของ pid เป็นชื่อฟังก์ชัน หรือ "[module+0xoffset]" / "0xaddr" ถ้าแปลไม่ได้
func (s *userSymbolizer) resolve(pid uint32, ip uint64) string {
	var vma *vmaMapping
	for i := range s.maps[pid] {
		if m := &s.maps[pid][i]; ip >= m.start && ip < m.end {
			vma = m
			break
		}
	}
	if vma == nil {
		return fmt.Sprintf("0x%x", ip)
	}
	if !strings.HasPrefix(vma.path, "/") { // [vdso], anonymous/JIT memory
		if vma.path == "" {
			return fmt.Sprintf("[anon+0x%x]", ip-vma.start)
		}
		return vma.path
	}

	fileOff := ip - vma.start + vma.offset
	module := filepath.Base(vma.path)
	info := s.loadELF(pid, vma.path)
	if info == nil {
		return fmt.Sprintf("[%s+0x%x]", module, fileOff)
	}

	// file offset -> ELF virtual address ผ่าน PT_LOAD segment ที่ครอบคลุม
	vaddr, found := uint64(0), false
	for _, p := range info.loads {
		if fileOff >= p.Off && fileOff < p.Off+p.Filesz {
			vaddr, found = fileOff-p.Off+p.Vaddr, true
			break
		}
	}
	if !found {
		return fmt.Sprintf("[%s+0x%x]", module, fileOff)
	}

	idx := sort.Search(len(info.funcs), func(i int) bool { return info.funcs[i].addr > vaddr }) - 1
	if idx >= 0 {
		fn := info.funcs[idx]
		if fn.size == 0 || vaddr < fn.addr+fn.size {
			return fn.name
		}
	}
	return fmt.Sprintf("[%s+0x%x]", module, fileOff)
}
