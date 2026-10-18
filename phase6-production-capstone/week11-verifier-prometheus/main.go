package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf bpf metrics_exporter.c

var (
	protocolNames = []string{"tcp", "udp", "icmp", "other"}

	packetDesc = prometheus.NewDesc(
		"ebpf_xdp_packets_total",
		"Total number of packets observed by eBPF XDP hook aggregated across all CPU cores",
		[]string{"protocol", "interface"},
		nil,
	)

	byteDesc = prometheus.NewDesc(
		"ebpf_xdp_bytes_total",
		"Total number of bytes observed by eBPF XDP hook aggregated across all CPU cores",
		[]string{"protocol", "interface"},
		nil,
	)
)

// xdpCollector implements prometheus.Collector to pull stats directly from eBPF per-cpu map
type xdpCollector struct {
	metricsMap *ebpf.Map
	ifaceName  string
	numCPUs    int
}

func newXDPCollector(m *ebpf.Map, ifaceName string) *xdpCollector {
	numCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		log.Printf("[WARN] Failed to get possible CPUs, defaulting to 1: %v", err)
		numCPUs = 1
	}
	return &xdpCollector{
		metricsMap: m,
		ifaceName:  ifaceName,
		numCPUs:    numCPUs,
	}
}

func (c *xdpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- packetDesc
	ch <- byteDesc
}

func (c *xdpCollector) Collect(ch chan<- prometheus.Metric) {
	for idx, proto := range protocolNames {
		key := uint32(idx)
		perCPUValues := make([]bpfProtoMetric, c.numCPUs)

		if err := c.metricsMap.Lookup(&key, &perCPUValues); err != nil {
			log.Printf("[ERROR] Map lookup for proto %s (key %d) failed: %v", proto, key, err)
			continue
		}

		var totalPackets uint64
		var totalBytes uint64

		for _, cpuVal := range perCPUValues {
			totalPackets += cpuVal.Packets
			totalBytes += cpuVal.Bytes
		}

		ch <- prometheus.MustNewConstMetric(
			packetDesc,
			prometheus.CounterValue,
			float64(totalPackets),
			proto,
			c.ifaceName,
		)

		ch <- prometheus.MustNewConstMetric(
			byteDesc,
			prometheus.CounterValue,
			float64(totalBytes),
			proto,
			c.ifaceName,
		)
	}
}

func main() {
	ifaceFlag := flag.String("iface", "lo", "Network interface to attach XDP (e.g. lo, eth0, ens33)")
	addrFlag := flag.String("addr", ":2112", "TCP address to listen on for HTTP Prometheus metrics")
	flag.Parse()

	// 1. Remove Memlock memory limits
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// 2. Validate interface
	iface, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		log.Fatalf("Network interface %q not found: %v", *ifaceFlag, err)
	}

	// 3. Load eBPF objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 4. Attach XDP program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMetricsProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP to %s: %v", *ifaceFlag, err)
	}
	defer xdpLink.Close()

	log.Printf("[INFO] Attached XDP metrics program to interface %s (index %d)", *ifaceFlag, iface.Index)

	// 5. Register Prometheus custom collector
	collector := newXDPCollector(objs.TrafficMetrics, *ifaceFlag)
	reg := prometheus.NewRegistry()
	reg.MustRegister(collector)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<h1>eBPF XDP Prometheus Exporter</h1>
<p>Monitoring interface: <strong>%s</strong></p>
<p><a href="/metrics">View /metrics</a></p>`, *ifaceFlag)
	})

	srv := &http.Server{
		Addr:    *addrFlag,
		Handler: mux,
	}

	// 6. Graceful shutdown handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("\n[INFO] Termination signal received. Stopping HTTP server and detaching XDP...")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	log.Printf("[INFO] Starting Prometheus metrics exporter at http://0.0.0.0%s/metrics", *addrFlag)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v", err)
	}
	log.Println("[INFO] Server stopped gracefully. Cleaned up.")
}
