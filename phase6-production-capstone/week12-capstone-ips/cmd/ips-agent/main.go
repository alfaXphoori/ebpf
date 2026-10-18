package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpf bpf ../../bpf/ips_kern.c

// Reason code constants
const (
	ReasonBlacklist  = 1
	ReasonSYNFlood   = 2
	ReasonICMPFlood  = 3
	ReasonManualBan  = 4

	MetricPassed            = 0
	MetricDroppedBlacklist  = 1
	MetricDroppedRatelimit  = 2
	MetricTotalBytes        = 3

	ConfSYNLimit  = 0
	ConfICMPLimit = 1
	ConfAutobanEn = 2
	ConfWindowNs  = 3
)

// ipsAlert matches C struct ips_alert
type ipsAlert struct {
	TsNs    uint64
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Reason  uint8
	Pad     uint16
	Pps     uint32
}

// blockEntry matches C struct block_entry
type blockEntry struct {
	BlockedAtNs uint64
	DropCount   uint64
	DropBytes   uint64
	Reason      uint32
	Pad         uint32
}

func reasonToString(r uint8) string {
	switch r {
	case ReasonBlacklist:
		return "BLACKLIST"
	case ReasonSYNFlood:
		return "SYN_FLOOD"
	case ReasonICMPFlood:
		return "ICMP_FLOOD"
	case ReasonManualBan:
		return "MANUAL_BAN"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", r)
	}
}

func protoToString(p uint8) string {
	switch p {
	case 6:
		return "TCP"
	case 1:
		return "ICMP"
	case 17:
		return "UDP"
	default:
		return fmt.Sprintf("IP(%d)", p)
	}
}

func uint32ToIP(ipInt uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipInt)
	return ip.String()
}

func ipToUint32(ipStr string) (uint32, error) {
	parsed := net.ParseIP(ipStr).To4()
	if parsed == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	return binary.BigEndian.Uint32(parsed), nil
}

// Thread-safe manager for tracking banned IP lifetimes
type BanManager struct {
	mu           sync.RWMutex
	bannedTimes  map[uint32]time.Time
	blacklistMap *ebpf.Map
	ttl          time.Duration
}

func NewBanManager(m *ebpf.Map, ttl time.Duration) *BanManager {
	return &BanManager{
		bannedTimes:  make(map[uint32]time.Time),
		blacklistMap: m,
		ttl:          ttl,
	}
}

func (bm *BanManager) RecordBan(ip uint32) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	bm.bannedTimes[ip] = time.Now()
}

func (bm *BanManager) ManualBan(ipStr string, reason uint32) error {
	ipUint, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}

	entry := blockEntry{
		BlockedAtNs: uint64(time.Now().UnixNano()),
		DropCount:   0,
		DropBytes:   0,
		Reason:      reason,
		Pad:         0,
	}

	if err := bm.blacklistMap.Put(&ipUint, &entry); err != nil {
		return fmt.Errorf("failed to insert into blacklist map: %w", err)
	}

	bm.RecordBan(ipUint)
	log.Printf("[CONTROL] IP %s manually blacklisted (reason=%d)", ipStr, reason)
	return nil
}

func (bm *BanManager) ManualUnban(ipStr string) error {
	ipUint, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}

	if err := bm.blacklistMap.Delete(&ipUint); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("failed to delete from blacklist map: %w", err)
	}

	bm.mu.Lock()
	delete(bm.bannedTimes, ipUint)
	bm.mu.Unlock()

	log.Printf("[CONTROL] IP %s unbanned from blacklist", ipStr)
	return nil
}

func (bm *BanManager) RunEvictionTicker(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bm.mu.Lock()
			now := time.Now()
			for ip, banTime := range bm.bannedTimes {
				if now.Sub(banTime) >= bm.ttl {
					// Remove expired IP from eBPF map
					if err := bm.blacklistMap.Delete(&ip); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
						log.Printf("[WARN] Failed to auto-unban IP %s: %v", uint32ToIP(ip), err)
					} else {
						log.Printf("\033[1;32m[IPS UNBAN]\033[0m IP %s unbanned after %v TTL expiration", uint32ToIP(ip), bm.ttl)
					}
					delete(bm.bannedTimes, ip)
				}
			}
			bm.mu.Unlock()
		}
	}
}

func (bm *BanManager) CountActiveBans() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.bannedTimes)
}

// Prometheus IPS Collector
type ipsPrometheusCollector struct {
	metricsMap *ebpf.Map
	banMgr     *BanManager
	numCPUs    int
}

var (
	metricPassedDesc = prometheus.NewDesc(
		"ips_passed_packets_total",
		"Total packets inspected and passed by Smart IPS",
		nil, nil,
	)
	metricDropBlacklistDesc = prometheus.NewDesc(
		"ips_dropped_blacklist_total",
		"Total packets dropped due to active IP blacklisting",
		nil, nil,
	)
	metricDropRateLimitDesc = prometheus.NewDesc(
		"ips_dropped_ratelimit_total",
		"Total packets dropped due to rate limit threshold violations",
		nil, nil,
	)
	metricTotalBytesDesc = prometheus.NewDesc(
		"ips_total_bytes",
		"Total network bytes processed by Smart IPS",
		nil, nil,
	)
	metricActiveBansDesc = prometheus.NewDesc(
		"ips_active_blacklisted_ips",
		"Current number of active blacklisted IP addresses",
		nil, nil,
	)
)

func (c *ipsPrometheusCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- metricPassedDesc
	ch <- metricDropBlacklistDesc
	ch <- metricDropRateLimitDesc
	ch <- metricTotalBytesDesc
	ch <- metricActiveBansDesc
}

func (c *ipsPrometheusCollector) Collect(ch chan<- prometheus.Metric) {
	readMetric := func(idx uint32) uint64 {
		perCPU := make([]uint64, c.numCPUs)
		if err := c.metricsMap.Lookup(&idx, &perCPU); err != nil {
			return 0
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		return sum
	}

	ch <- prometheus.MustNewConstMetric(metricPassedDesc, prometheus.CounterValue, float64(readMetric(MetricPassed)))
	ch <- prometheus.MustNewConstMetric(metricDropBlacklistDesc, prometheus.CounterValue, float64(readMetric(MetricDroppedBlacklist)))
	ch <- prometheus.MustNewConstMetric(metricDropRateLimitDesc, prometheus.CounterValue, float64(readMetric(MetricDroppedRatelimit)))
	ch <- prometheus.MustNewConstMetric(metricTotalBytesDesc, prometheus.CounterValue, float64(readMetric(MetricTotalBytes)))
	ch <- prometheus.MustNewConstMetric(metricActiveBansDesc, prometheus.GaugeValue, float64(c.banMgr.CountActiveBans()))
}

type BlacklistResponseItem struct {
	IP        string `json:"ip"`
	DropCount uint64 `json:"drop_count"`
	DropBytes uint64 `json:"drop_bytes"`
	Reason    string `json:"reason"`
}

func main() {
	ifaceFlag := flag.String("iface", "lo", "Network interface to attach XDP (e.g. lo, eth0, ens33)")
	ttlFlag := flag.Duration("ban-ttl", 30*time.Second, "Auto-ban TTL expiration duration")
	portFlag := flag.String("http-port", ":2112", "HTTP server port for Prometheus & REST API")
	synLimitFlag := flag.Uint64("syn-limit", 100, "TCP SYN rate limit threshold per second")
	icmpLimitFlag := flag.Uint64("icmp-limit", 50, "ICMP Echo rate limit threshold per second")
	flag.Parse()

	// 1. Remove Memlock memory limits
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// 2. Validate interface
	iface, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", *ifaceFlag, err)
	}

	// 3. Load eBPF Objects
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// 4. Configure Thresholds in config_map
	kSyn := uint32(ConfSYNLimit)
	kIcmp := uint32(ConfICMPLimit)
	kAutoban := uint32(ConfAutobanEn)
	kWin := uint32(ConfWindowNs)

	vAutoban := uint64(1)
	vWin := uint64(1000000000) // 1 second in ns

	_ = objs.ConfigMap.Put(&kSyn, synLimitFlag)
	_ = objs.ConfigMap.Put(&kIcmp, icmpLimitFlag)
	_ = objs.ConfigMap.Put(&kAutoban, &vAutoban)
	_ = objs.ConfigMap.Put(&kWin, &vWin)

	log.Printf("[CONFIG] SYN Limit=%d pps, ICMP Limit=%d pps, Window=1s, Auto-Ban TTL=%v",
		*synLimitFlag, *icmpLimitFlag, *ttlFlag)

	// 5. Attach XDP Program
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpSmartIps,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP to %s: %v", *ifaceFlag, err)
	}
	defer xdpLink.Close()
	log.Printf("[INFO] Smart IPS attached to interface %s (index %d)", *ifaceFlag, iface.Index)

	// 6. Ban Manager & TTL Eviction Loop
	banMgr := NewBanManager(objs.BlacklistMap, *ttlFlag)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go banMgr.RunEvictionTicker(ctx)

	// 7. Ring Buffer Alerts Consumer
	rd, err := ringbuf.NewReader(objs.IpsEvents)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %v", err)
	}
	defer rd.Close()

	go func() {
		var alert ipsAlert
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("[ERROR] Ringbuf read error: %v", err)
				continue
			}

			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &alert); err != nil {
				log.Printf("[ERROR] Failed to parse IPS alert: %v", err)
				continue
			}

			srcIP := uint32ToIP(alert.SrcIP)
			dstIP := uint32ToIP(alert.DstIP)
			reasonStr := reasonToString(alert.Reason)
			protoStr := protoToString(alert.Proto)

			// Record in TTL manager
			banMgr.RecordBan(alert.SrcIP)

			log.Printf("\033[1;31m[IPS ALERT]\033[0m %-11s | Proto=%-4s | Src=%s:%d -> Dst=%s:%d | Rate=%d PPS | Action=AUTO-BANNED",
				reasonStr, protoStr, srcIP, alert.SrcPort, dstIP, alert.DstPort, alert.Pps)
		}
	}()

	// 8. Prometheus Setup
	numCPUs, err := ebpf.PossibleCPUs()
	if err != nil {
		numCPUs = 1
	}
	promCollector := &ipsPrometheusCollector{
		metricsMap: objs.IpsMetrics,
		banMgr:     banMgr,
		numCPUs:    numCPUs,
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(promCollector)

	// 9. HTTP REST & Metrics Server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	// REST API: GET/POST/DELETE /api/blacklist
	mux.HandleFunc("/api/blacklist", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			var items []BlacklistResponseItem

			iter := objs.BlacklistMap.Iterate()
			var ipKey uint32
			var entry blockEntry
			for iter.Next(&ipKey, &entry) {
				items = append(items, BlacklistResponseItem{
					IP:        uint32ToIP(ipKey),
					DropCount: entry.DropCount,
					DropBytes: entry.DropBytes,
					Reason:    reasonToString(uint8(entry.Reason)),
				})
			}
			_ = json.NewEncoder(w).Encode(items)

		case http.MethodPost:
			var req struct {
				IP     string `json:"ip"`
				Reason uint32 `json:"reason"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request body", http.StatusBadRequest)
				return
			}
			if req.Reason == 0 {
				req.Reason = ReasonManualBan
			}
			if err := banMgr.ManualBan(req.IP, req.Reason); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprintf(w, `{"status":"banned","ip":%q}`, req.IP)

		case http.MethodDelete:
			ipStr := r.URL.Query().Get("ip")
			if ipStr == "" {
				http.Error(w, "missing ?ip= query parameter", http.StatusBadRequest)
				return
			}
			if err := banMgr.ManualUnban(ipStr); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"status":"unbanned","ip":%q}`, ipStr)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	// Friendly Web Dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>Smart eBPF IPS Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; background: #0f172a; color: #f8fafc; }
        h1 { color: #38bdf8; }
        .card { background: #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #334155; }
        th { color: #94a3b8; }
        a { color: #38bdf8; text-decoration: none; }
        .badge { background: #ef4444; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; }
    </style>
</head>
<body>
    <h1>Smart eBPF Intrusion Prevention System (IPS)</h1>
    <div class="card">
        <h3>System Status</h3>
        <p>Interface: <strong>{{.Interface}}</strong> | SYN Limit: <strong>{{.SYNLimit}} pps</strong> | ICMP Limit: <strong>{{.ICMPLimit}} pps</strong> | Ban TTL: <strong>{{.BanTTL}}</strong></p>
        <p>Telemetry: <a href="/metrics">Prometheus /metrics</a> | REST API: <a href="/api/blacklist">/api/blacklist</a></p>
    </div>
</body>
</html>`
		t := template.Must(template.New("dashboard").Parse(tmpl))
		_ = t.Execute(w, map[string]interface{}{
			"Interface": *ifaceFlag,
			"SYNLimit":  *synLimitFlag,
			"ICMPLimit": *icmpLimitFlag,
			"BanTTL":    *ttlFlag,
		})
	})

	srv := &http.Server{
		Addr:    *portFlag,
		Handler: mux,
	}

	// 10. Handle Termination
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("\n[INFO] Termination signal received. Stopping Smart IPS Daemon...")
		cancel()
		rd.Close()
		shutdownCtx, sCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer sCancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Printf("[INFO] Smart IPS Daemon active! Web/API running at http://0.0.0.0%s", *portFlag)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server error: %v", err)
	}
	log.Println("[INFO] Smart IPS cleanly shut down.")
}
