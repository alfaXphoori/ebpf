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
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-mcpu=v3" -target bpf bpf ../../bpf/ips_kern.c

// Reason code constants
const (
	ReasonBlacklist = 1
	ReasonSYNFlood  = 2
	ReasonICMPFlood = 3
	ReasonManualBan = 4

	MetricPassed           = 0
	MetricDroppedBlacklist = 1
	MetricDroppedRatelimit = 2
	MetricTotalBytes       = 3
	MetricAlertsLost       = 4

	ConfSYNLimit  = 0
	ConfICMPLimit = 1
	ConfAutobanEn = 2
	ConfWindowNs  = 3
	ConfBanTTLNs  = 4

	ActionBanned      = 1
	ActionRateLimited = 2
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
	Action  uint8
	Pad     uint8
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

func actionToString(a uint8) string {
	switch a {
	case ActionBanned:
		return "AUTO-BANNED"
	case ActionRateLimited:
		return "RATE-LIMITED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", a)
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
	binary.LittleEndian.PutUint32(ip, ipInt)
	return ip.String()
}

func ipToUint32(ipStr string) (uint32, error) {
	parsed := net.ParseIP(ipStr).To4()
	if parsed == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", ipStr)
	}
	return binary.LittleEndian.Uint32(parsed), nil
}

// monotonicNowNs returns CLOCK_MONOTONIC in nanoseconds: the same clock as
// bpf_ktime_get_ns() in the kernel, so Go and eBPF timestamps are comparable.
func monotonicNowNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		log.Fatalf("clock_gettime(CLOCK_MONOTONIC) failed: %v", err)
	}
	return uint64(ts.Nano())
}

// ipsConfig holds the runtime thresholds written into config_map
type ipsConfig struct {
	SYNLimit  uint64
	ICMPLimit uint64
	Autoban   bool
	Window    time.Duration
	BanTTL    time.Duration
}

// applyConfig writes every config slot read by the XDP program into config_map
func applyConfig(m *ebpf.Map, c ipsConfig) error {
	var autoban uint64
	if c.Autoban {
		autoban = 1
	}
	values := map[uint32]uint64{
		ConfSYNLimit:  c.SYNLimit,
		ConfICMPLimit: c.ICMPLimit,
		ConfAutobanEn: autoban,
		ConfWindowNs:  uint64(c.Window.Nanoseconds()),
		ConfBanTTLNs:  uint64(c.BanTTL.Nanoseconds()),
	}
	for k, v := range values {
		if err := m.Put(&k, &v); err != nil {
			return fmt.Errorf("config_map[%d]: %w", k, err)
		}
	}
	return nil
}

// BanManager manages blacklist lifetimes.
// The eBPF blacklist_map is the single source of truth: each entry carries its
// own blocked_at_ns, so bans created in the kernel are expired even when their
// ring buffer alert was never delivered to user space.
type BanManager struct {
	blacklistMap *ebpf.Map
	ttl          time.Duration
}

func NewBanManager(m *ebpf.Map, ttl time.Duration) *BanManager {
	return &BanManager{
		blacklistMap: m,
		ttl:          ttl,
	}
}

func (bm *BanManager) ManualBan(ipStr string, reason uint32) error {
	ipUint, err := ipToUint32(ipStr)
	if err != nil {
		return err
	}

	entry := blockEntry{
		BlockedAtNs: monotonicNowNs(),
		DropCount:   0,
		DropBytes:   0,
		Reason:      reason,
		Pad:         0,
	}

	if err := bm.blacklistMap.Put(&ipUint, &entry); err != nil {
		return fmt.Errorf("failed to insert into blacklist map: %w", err)
	}

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

	log.Printf("[CONTROL] IP %s unbanned from blacklist", ipStr)
	return nil
}

// ExpireBans deletes every blacklist entry older than the TTL and returns the
// removed IPs. Keys are collected first and deleted afterwards, because
// deleting from a hash map while iterating it can restart the iteration.
func (bm *BanManager) ExpireBans(nowNs uint64) ([]uint32, error) {
	if bm.ttl <= 0 {
		return nil, nil // TTL disabled: bans are permanent
	}
	ttlNs := uint64(bm.ttl.Nanoseconds())

	var expired []uint32
	var ipKey uint32
	var entry blockEntry
	iter := bm.blacklistMap.Iterate()
	for iter.Next(&ipKey, &entry) {
		if nowNs >= entry.BlockedAtNs && nowNs-entry.BlockedAtNs >= ttlNs {
			expired = append(expired, ipKey)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterate blacklist map: %w", err)
	}

	removed := expired[:0]
	for _, ip := range expired {
		if err := bm.blacklistMap.Delete(&ip); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				log.Printf("[WARN] Failed to auto-unban IP %s: %v", uint32ToIP(ip), err)
			}
			continue
		}
		removed = append(removed, ip)
	}
	return removed, nil
}

func (bm *BanManager) RunEvictionTicker(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed, err := bm.ExpireBans(monotonicNowNs())
			if err != nil {
				log.Printf("[WARN] TTL sweep failed: %v", err)
				continue
			}
			for _, ip := range removed {
				log.Printf("\033[1;32m[IPS UNBAN]\033[0m IP %s unbanned after %v TTL expiration", uint32ToIP(ip), bm.ttl)
			}
		}
	}
}

// CountActiveBans counts entries currently present in the kernel blacklist_map
func (bm *BanManager) CountActiveBans() int {
	var ipKey uint32
	var entry blockEntry
	n := 0
	iter := bm.blacklistMap.Iterate()
	for iter.Next(&ipKey, &entry) {
		n++
	}
	return n
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
	metricAlertsLostDesc = prometheus.NewDesc(
		"ips_alerts_lost_total",
		"Total alerts that could not be reserved in the ring buffer (buffer full)",
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
	ch <- metricAlertsLostDesc
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
	ch <- prometheus.MustNewConstMetric(metricAlertsLostDesc, prometheus.CounterValue, float64(readMetric(MetricAlertsLost)))
	ch <- prometheus.MustNewConstMetric(metricActiveBansDesc, prometheus.GaugeValue, float64(c.banMgr.CountActiveBans()))
}

type BlacklistResponseItem struct {
	IP        string `json:"ip"`
	DropCount uint64 `json:"drop_count"`
	DropBytes uint64 `json:"drop_bytes"`
	Reason    string `json:"reason"`
	BannedFor string `json:"banned_for"`
}

func main() {
	ifaceFlag := flag.String("iface", "lo", "Network interface to attach XDP (e.g. lo, eth0, ens33)")
	ttlFlag := flag.Duration("ban-ttl", 30*time.Second, "Auto-ban TTL expiration duration")
	portFlag := flag.String("http-port", ":2112", "HTTP server port for Prometheus & REST API")
	synLimitFlag := flag.Uint64("syn-limit", 100, "TCP SYN rate limit threshold per second")
	icmpLimitFlag := flag.Uint64("icmp-limit", 50, "ICMP Echo rate limit threshold per second")
	autobanFlag := flag.Bool("autoban", true, "Auto-ban offending IPs (false = rate-limit only: drop just the packets above the threshold)")
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
	cfg := ipsConfig{
		SYNLimit:  *synLimitFlag,
		ICMPLimit: *icmpLimitFlag,
		Autoban:   *autobanFlag,
		Window:    time.Second,
		BanTTL:    *ttlFlag,
	}
	if err := applyConfig(objs.ConfigMap, cfg); err != nil {
		log.Fatalf("Failed to write config_map: %v", err)
	}

	log.Printf("[CONFIG] SYN Limit=%d pps, ICMP Limit=%d pps, Window=%v, Auto-Ban=%v, Ban TTL=%v",
		cfg.SYNLimit, cfg.ICMPLimit, cfg.Window, cfg.Autoban, cfg.BanTTL)

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

			// TTL is tracked by blocked_at_ns inside blacklist_map itself,
			// so nothing needs to be recorded here.
			log.Printf("\033[1;31m[IPS ALERT]\033[0m %-11s | Proto=%-4s | Src=%s:%d -> Dst=%s:%d | Rate=%d PPS | Action=%s",
				reasonStr, protoStr, srcIP, alert.SrcPort, dstIP, alert.DstPort, alert.Pps, actionToString(alert.Action))
		}
	}()

	// 8. Prometheus Setup
	numCPUs, err := ebpf.PossibleCPU()
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
			items := []BlacklistResponseItem{}

			nowNs := monotonicNowNs()
			iter := objs.BlacklistMap.Iterate()
			var ipKey uint32
			var entry blockEntry
			for iter.Next(&ipKey, &entry) {
				var age time.Duration
				if nowNs > entry.BlockedAtNs {
					age = time.Duration(nowNs - entry.BlockedAtNs).Truncate(time.Second)
				}
				items = append(items, BlacklistResponseItem{
					IP:        uint32ToIP(ipKey),
					DropCount: entry.DropCount,
					DropBytes: entry.DropBytes,
					Reason:    reasonToString(uint8(entry.Reason)),
					BannedFor: age.String(),
				})
			}
			if err := iter.Err(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
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
        <p>Interface: <strong>{{.Interface}}</strong> | SYN Limit: <strong>{{.SYNLimit}} pps</strong> | ICMP Limit: <strong>{{.ICMPLimit}} pps</strong> | Auto-Ban: <strong>{{.Autoban}}</strong> | Ban TTL: <strong>{{.BanTTL}}</strong></p>
        <p>Telemetry: <a href="/metrics">Prometheus /metrics</a> | REST API: <a href="/api/blacklist">/api/blacklist</a></p>
    </div>
</body>
</html>`
		t := template.Must(template.New("dashboard").Parse(tmpl))
		_ = t.Execute(w, map[string]interface{}{
			"Interface": *ifaceFlag,
			"SYNLimit":  *synLimitFlag,
			"ICMPLimit": *icmpLimitFlag,
			"Autoban":   *autobanFlag,
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
