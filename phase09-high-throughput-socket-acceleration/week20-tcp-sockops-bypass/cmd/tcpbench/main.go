// tcpbench: a tiny loopback TCP benchmark for Week 20.
//
// The server and the client run inside ONE process, so moving this process
// into the test cgroup puts BOTH ends of the connection under the sockops
// program. It measures:
//
//   - throughput : stream -bytes of pseudo-random data; with -verify (default)
//     both sides compute SHA-256 to prove redirected data arrives intact.
//     Use -verify=false for a pure throughput number (hashing costs CPU).
//   - latency    : -iters request/response round trips of -msg bytes
//
// Usage (inside the cgroup): ./bin/tcpbench -mode both
package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sort"
	"time"
)

func runThroughput(total, chunk int, verify bool) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		n   int64
		sum []byte
	}
	done := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		defer c.Close()
		if !verify {
			n, _ := io.Copy(io.Discard, c)
			done <- result{n, nil}
			return
		}
		h := sha256.New()
		n, _ := io.Copy(h, c)
		done <- result{n, h.Sum(nil)}
	}()

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		log.Fatal(err)
	}

	// Deterministic pseudo-random payload (fixed seed) so corruption is detectable
	buf := make([]byte, chunk)
	rand.New(rand.NewSource(20)).Read(buf)
	sent := sha256.New()

	start := time.Now()
	for left := total; left > 0; left -= chunk {
		n := chunk
		if left < n {
			n = left
		}
		// Rotate the buffer so every chunk is different
		buf[0]++
		if _, err := conn.Write(buf[:n]); err != nil {
			log.Fatal(err)
		}
		if verify {
			sent.Write(buf[:n])
		}
	}
	conn.Close()
	r := <-done
	elapsed := time.Since(start)

	integrity := "skipped"
	if verify {
		integrity = fmt.Sprint(r.n == int64(total) && bytes.Equal(r.sum, sent.Sum(nil)))
	}
	gbps := float64(r.n*8) / elapsed.Seconds() / 1e9
	fmt.Printf("[throughput] sent=%d recv=%d chunk=%d time=%v rate=%.2f Gbit/s integrity(sha256)=%s\n",
		total, r.n, chunk, elapsed.Round(time.Millisecond), gbps, integrity)
}

func runLatency(iters, size int) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	// Echo server
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, size)
		for {
			if _, err := io.ReadFull(c, b); err != nil {
				return
			}
			if _, err := c.Write(b); err != nil {
				return
			}
		}
	}()

	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	req := bytes.Repeat([]byte{'x'}, size)
	resp := make([]byte, size)
	rtts := make([]time.Duration, 0, iters)
	for i := 0; i < iters; i++ {
		req[0] = byte(i)
		t := time.Now()
		if _, err := conn.Write(req); err != nil {
			log.Fatal(err)
		}
		if _, err := io.ReadFull(conn, resp); err != nil {
			log.Fatal(err)
		}
		rtts = append(rtts, time.Since(t))
		if !bytes.Equal(req, resp) {
			log.Fatalf("echo mismatch at iteration %d", i)
		}
	}

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	var sum time.Duration
	for _, d := range rtts {
		sum += d
	}
	fmt.Printf("[latency]    iters=%d msg=%dB avg=%.1fus p50=%.1fus p99=%.1fus\n",
		iters, size,
		float64(sum.Nanoseconds())/float64(iters)/1e3,
		float64(rtts[iters/2].Nanoseconds())/1e3,
		float64(rtts[iters*99/100].Nanoseconds())/1e3)
}

func main() {
	mode := flag.String("mode", "both", "throughput | latency | both")
	total := flag.Int("bytes", 1<<30, "throughput: total bytes to stream")
	chunk := flag.Int("chunk", 64*1024, "throughput: bytes per write()")
	iters := flag.Int("iters", 20000, "latency: number of round trips")
	msg := flag.Int("msg", 64, "latency: message size in bytes")
	verify := flag.Bool("verify", true, "throughput: SHA-256 check of the received stream")
	flag.Parse()

	if *mode == "throughput" || *mode == "both" {
		runThroughput(*total, *chunk, *verify)
	}
	if *mode == "latency" || *mode == "both" {
		runLatency(*iters, *msg)
	}
}
