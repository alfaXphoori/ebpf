//go:build linux
// +build linux

package main

// A minimal, dependency-free AF_XDP socket (RX only) built directly on
// golang.org/x/sys/unix. It follows the same steps as libxdp's xsk_socket__create():
//
//   1. socket(AF_XDP, SOCK_RAW, 0)
//   2. allocate UMEM (page-aligned anonymous mmap) and register it: XDP_UMEM_REG
//   3. size the rings: XDP_UMEM_FILL_RING, XDP_UMEM_COMPLETION_RING, XDP_RX_RING
//   4. getsockopt(XDP_MMAP_OFFSETS) and mmap() each ring
//   5. hand empty frames to the kernel via the FILL ring
//   6. bind(ifindex, queue_id, XDP_COPY | XDP_ZEROCOPY)
//
// Ring protocol (single-producer / single-consumer, lock-free):
//   FILL ring : user space = producer, kernel = consumer  (empty frame addresses)
//   RX ring   : kernel = producer, user space = consumer  (filled frame descriptors)
//   COMP ring : kernel = producer, user space = consumer  (TX done; unused for RX-only)

import (
	"fmt"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// XSKConfig holds UMEM and ring sizes (all must be powers of two)
type XSKConfig struct {
	NumFrames uint32 // number of UMEM chunks
	FrameSize uint32 // chunk size: 2048 or 4096 (aligned mode)
	FillSize  uint32 // FILL ring entries
	CompSize  uint32 // COMPLETION ring entries
	RxSize    uint32 // RX ring entries
	ZeroCopy  bool   // XDP_ZEROCOPY instead of XDP_COPY (needs driver support)
}

// DefaultXSKConfig mirrors libxdp defaults (4096 frames x 2048 B = 8 MiB UMEM)
var DefaultXSKConfig = XSKConfig{
	NumFrames: 4096,
	FrameSize: 2048,
	FillSize:  4096,
	CompSize:  2048,
	RxSize:    2048,
}

// ring is a view on one mmap()ed ring shared with the kernel
type ring struct {
	mem      []byte
	producer *uint32
	consumer *uint32
	descs    unsafe.Pointer
	mask     uint32
	size     uint32
}

// XSK is an AF_XDP socket bound to one (ifindex, queue) pair
type XSK struct {
	fd       int
	cfg      XSKConfig
	umem     []byte
	fill, rx ring
	comp     ring
	recycle  []uint64
}

func setsockoptRaw(fd, level, opt int, p unsafe.Pointer, size uintptr) error {
	_, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(p), size, 0)
	if e != 0 {
		return e
	}
	return nil
}

func getsockoptRaw(fd, level, opt int, p unsafe.Pointer, size uintptr) error {
	l := uint32(size)
	_, _, e := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
		uintptr(p), uintptr(unsafe.Pointer(&l)), 0)
	if e != 0 {
		return e
	}
	return nil
}

// mapRing mmap()s one ring; descSize is 8 (FILL/COMP: u64 addr) or 16 (RX/TX: xdp_desc)
func mapRing(fd int, pgoff int64, off unix.XDPRingOffset, n uint32, descSize uint64) (ring, error) {
	length := int(off.Desc + uint64(n)*descSize)
	mem, err := unix.Mmap(fd, pgoff, length, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_POPULATE)
	if err != nil {
		return ring{}, err
	}
	base := unsafe.Pointer(&mem[0])
	return ring{
		mem:      mem,
		producer: (*uint32)(unsafe.Add(base, off.Producer)),
		consumer: (*uint32)(unsafe.Add(base, off.Consumer)),
		descs:    unsafe.Add(base, off.Desc),
		mask:     n - 1,
		size:     n,
	}, nil
}

// NewXSK creates an AF_XDP socket, registers UMEM, maps the rings and binds
// it to ifindex/queue. Insert FD() into an XSKMAP to start receiving.
func NewXSK(ifindex int, queue int, cfg XSKConfig) (_ *XSK, err error) {
	x := &XSK{fd: -1, cfg: cfg}
	defer func() {
		if err != nil {
			x.Close() // release whatever was set up before the failing step
		}
	}()

	// 1. The socket itself
	x.fd, err = unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_XDP): %w", err)
	}

	// 2. UMEM: one contiguous, page-aligned buffer divided into NumFrames chunks.
	//    mmap()ed memory is outside the Go heap, so the GC never moves it.
	umemLen := int(cfg.NumFrames * cfg.FrameSize)
	x.umem, err = unix.Mmap(-1, 0, umemLen, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANONYMOUS|unix.MAP_POPULATE)
	if err != nil {
		return nil, fmt.Errorf("mmap UMEM: %w", err)
	}
	reg := unix.XDPUmemReg{
		Addr:     uint64(uintptr(unsafe.Pointer(&x.umem[0]))),
		Len:      uint64(umemLen),
		Size:     cfg.FrameSize,
		Headroom: 0,
	}
	if err = setsockoptRaw(x.fd, unix.SOL_XDP, unix.XDP_UMEM_REG, unsafe.Pointer(&reg), unsafe.Sizeof(reg)); err != nil {
		return nil, fmt.Errorf("setsockopt(XDP_UMEM_REG): %w", err)
	}

	// 3. Ring sizes (FILL + COMPLETION are mandatory for every UMEM)
	if err = unix.SetsockoptInt(x.fd, unix.SOL_XDP, unix.XDP_UMEM_FILL_RING, int(cfg.FillSize)); err != nil {
		return nil, fmt.Errorf("setsockopt(XDP_UMEM_FILL_RING): %w", err)
	}
	if err = unix.SetsockoptInt(x.fd, unix.SOL_XDP, unix.XDP_UMEM_COMPLETION_RING, int(cfg.CompSize)); err != nil {
		return nil, fmt.Errorf("setsockopt(XDP_UMEM_COMPLETION_RING): %w", err)
	}
	if err = unix.SetsockoptInt(x.fd, unix.SOL_XDP, unix.XDP_RX_RING, int(cfg.RxSize)); err != nil {
		return nil, fmt.Errorf("setsockopt(XDP_RX_RING): %w", err)
	}

	// 4. Ask the kernel where producer/consumer/desc live inside each ring, then mmap
	var off unix.XDPMmapOffsets
	if err = getsockoptRaw(x.fd, unix.SOL_XDP, unix.XDP_MMAP_OFFSETS, unsafe.Pointer(&off), unsafe.Sizeof(off)); err != nil {
		return nil, fmt.Errorf("getsockopt(XDP_MMAP_OFFSETS): %w", err)
	}
	if x.fill, err = mapRing(x.fd, unix.XDP_UMEM_PGOFF_FILL_RING, off.Fr, cfg.FillSize, 8); err != nil {
		return nil, fmt.Errorf("mmap FILL ring: %w", err)
	}
	if x.comp, err = mapRing(x.fd, unix.XDP_UMEM_PGOFF_COMPLETION_RING, off.Cr, cfg.CompSize, 8); err != nil {
		return nil, fmt.Errorf("mmap COMPLETION ring: %w", err)
	}
	if x.rx, err = mapRing(x.fd, unix.XDP_PGOFF_RX_RING, off.Rx, cfg.RxSize, uint64(unsafe.Sizeof(unix.XDPDesc{}))); err != nil {
		return nil, fmt.Errorf("mmap RX ring: %w", err)
	}

	// 5. Give the kernel empty frames to write packets into
	addrs := make([]uint64, 0, cfg.FillSize)
	for i := uint32(0); i < cfg.NumFrames && i < cfg.FillSize; i++ {
		addrs = append(addrs, uint64(i*cfg.FrameSize))
	}
	x.fillFrames(addrs)

	// 6. Bind to the NIC queue
	flags := uint16(unix.XDP_COPY)
	if cfg.ZeroCopy {
		flags = unix.XDP_ZEROCOPY
	}
	if err = unix.Bind(x.fd, &unix.SockaddrXDP{Flags: flags, Ifindex: uint32(ifindex), QueueID: uint32(queue)}); err != nil {
		return nil, fmt.Errorf("bind(ifindex=%d, queue=%d, flags=%#x): %w", ifindex, queue, flags, err)
	}
	return x, nil
}

// FD returns the socket fd to be stored into BPF_MAP_TYPE_XSKMAP
func (x *XSK) FD() int { return x.fd }

// fillFrames pushes frame addresses onto the FILL ring (user space = producer)
func (x *XSK) fillFrames(addrs []uint64) int {
	prod := atomic.LoadUint32(x.fill.producer)
	cons := atomic.LoadUint32(x.fill.consumer)
	free := x.fill.size - (prod - cons)
	n := uint32(len(addrs))
	if n > free {
		n = free
	}
	for i := uint32(0); i < n; i++ {
		slot := (*uint64)(unsafe.Add(x.fill.descs, uintptr((prod+i)&x.fill.mask)*8))
		*slot = addrs[i]
	}
	// Store-release: descriptors must be visible before the new producer index
	atomic.StoreUint32(x.fill.producer, prod+n)
	return int(n)
}

// Poll waits up to timeoutMs for packets on the RX ring
func (x *XSK) Poll(timeoutMs int) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(x.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, timeoutMs)
	if err == unix.EINTR {
		return false, nil
	}
	return n > 0, err
}

// Receive consumes every descriptor currently on the RX ring, calls handle()
// with a slice that points INTO the UMEM (valid only during the callback),
// then recycles the frames back to the FILL ring. Returns packets processed.
func (x *XSK) Receive(handle func(pkt []byte)) int {
	cons := atomic.LoadUint32(x.rx.consumer)
	prod := atomic.LoadUint32(x.rx.producer) // load-acquire
	n := prod - cons
	if n == 0 {
		return 0
	}
	x.recycle = x.recycle[:0]
	for i := uint32(0); i < n; i++ {
		d := (*unix.XDPDesc)(unsafe.Add(x.rx.descs, uintptr((cons+i)&x.rx.mask)*unsafe.Sizeof(unix.XDPDesc{})))
		handle(x.umem[d.Addr : d.Addr+uint64(d.Len)])
		// In aligned mode Addr = chunk base + data offset; hand back the chunk base
		x.recycle = append(x.recycle, d.Addr&^uint64(x.cfg.FrameSize-1))
	}
	atomic.StoreUint32(x.rx.consumer, cons+n) // release RX slots to the kernel
	x.fillFrames(x.recycle)
	return int(n)
}

// Stats returns kernel-side socket counters (drops, ring full, fill empty...)
func (x *XSK) Stats() (unix.XDPStatistics, error) {
	var st unix.XDPStatistics
	err := getsockoptRaw(x.fd, unix.SOL_XDP, unix.XDP_STATISTICS, unsafe.Pointer(&st), unsafe.Sizeof(st))
	return st, err
}

// IsZeroCopy asks the kernel which mode the bound socket really uses
func (x *XSK) IsZeroCopy() (bool, error) {
	var opts uint32 // struct xdp_options { __u32 flags; }
	if err := getsockoptRaw(x.fd, unix.SOL_XDP, unix.XDP_OPTIONS, unsafe.Pointer(&opts), unsafe.Sizeof(opts)); err != nil {
		return false, err
	}
	return opts&unix.XDP_OPTIONS_ZEROCOPY != 0, nil
}

// Close unmaps the rings and UMEM and closes the socket
func (x *XSK) Close() error {
	for _, r := range []*ring{&x.rx, &x.comp, &x.fill} {
		if r.mem != nil {
			unix.Munmap(r.mem)
			r.mem = nil
		}
	}
	if x.fd >= 0 {
		unix.Close(x.fd)
		x.fd = -1
	}
	if x.umem != nil {
		unix.Munmap(x.umem)
		x.umem = nil
	}
	return nil
}
