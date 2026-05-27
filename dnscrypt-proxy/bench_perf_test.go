package main

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
)

// Before/after microbenchmarks for the patches in commit "perf: cut per-query
// lock contention and hot-path allocations". Each _Before variant replicates
// the pre-patch code path; each _After variant uses the shipped path (or, for
// the lock changes, the shipped synchronization primitive). The contention
// benchmarks use RunParallel so the multi-core cost the patches target is
// actually exercised.
//
//	go test -run '^$' -bench Perf -benchmem .

var (
	benchStr          string
	benchParallelSink int64
)

// --- #6 StringReverse: []rune decode (before) vs bytewise ASCII (after) ---

func stringReverseRunesBefore(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < len(r)/2; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

const benchQName = "www.long-subdomain.example.co.uk"

func BenchmarkPerf6_StringReverse_Before(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchStr = stringReverseRunesBefore(benchQName)
	}
}

func BenchmarkPerf6_StringReverse_After(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchStr = StringReverse(benchQName)
	}
}

// --- #5 UDP pool key: addr.String() twice/query (before) vs once (after) ---

func BenchmarkPerf5_UDPPoolKey_Before(b *testing.B) {
	addr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchStr = addr.String() // Get
		benchStr = addr.String() // Put
	}
}

func BenchmarkPerf5_UDPPoolKey_After(b *testing.B) {
	addr := &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 443}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		k := addr.String() // computed once, reused for Get + Put
		benchStr = k
		benchStr = k
	}
}

// --- #3 plugin-globals lock: three RLock pairs/query (before) vs none ---
// Models the query/response/logging plugin loops in ApplyQueryPlugins,
// ApplyResponsePlugins and ApplyLoggingPlugins.

func BenchmarkPerf3_PluginDispatch_Before(b *testing.B) {
	var mu sync.RWMutex
	plugins := make([]int, 8)
	b.RunParallel(func(pb *testing.PB) {
		local := 0
		for pb.Next() {
			for pass := 0; pass < 3; pass++ {
				mu.RLock()
				for range plugins {
					local++
				}
				mu.RUnlock()
			}
		}
		atomic.AddInt64(&benchParallelSink, int64(local))
	})
}

func BenchmarkPerf3_PluginDispatch_After(b *testing.B) {
	plugins := make([]int, 8)
	b.RunParallel(func(pb *testing.PB) {
		local := 0
		for pb.Next() {
			for pass := 0; pass < 3; pass++ {
				for range plugins {
					local++
				}
			}
		}
		atomic.AddInt64(&benchParallelSink, int64(local))
	})
}

// --- #1 server selection: exclusive Lock/query (before) vs shared RLock ---
// Models getOne's WP2 selection: read-only "pick two, keep lower RTT".

type benchSel struct {
	mu   sync.RWMutex
	rtts []float64
}

func newBenchSel(n int) *benchSel {
	s := &benchSel{rtts: make([]float64, n)}
	for i := range s.rtts {
		s.rtts[i] = float64(10 + i)
	}
	return s
}

func (s *benchSel) pick(seed int) int {
	n := len(s.rtts)
	a := seed % n
	c := (seed * 7) % n
	if s.rtts[a] <= s.rtts[c] {
		return a
	}
	return c
}

func BenchmarkPerf1_ServerSelect_Before(b *testing.B) {
	sel := newBenchSel(10)
	b.RunParallel(func(pb *testing.PB) {
		seed, acc := 0, 0
		for pb.Next() {
			sel.mu.Lock() // pre-patch: exclusive lock for every query
			acc += sel.pick(seed)
			sel.mu.Unlock()
			seed++
		}
		atomic.AddInt64(&benchParallelSink, int64(acc))
	})
}

func BenchmarkPerf1_ServerSelect_After(b *testing.B) {
	sel := newBenchSel(10)
	b.RunParallel(func(pb *testing.PB) {
		seed, acc := 0, 0
		for pb.Next() {
			sel.mu.RLock() // patched WP2 path: shared read lock
			acc += sel.pick(seed)
			sel.mu.RUnlock()
			seed++
		}
		atomic.AddInt64(&benchParallelSink, int64(acc))
	})
}

// --- #2 updateServerStats: lock + O(n) name scan (before) vs O(1) pointer ---

type benchStatServer struct {
	name   string
	total  uint64
	failed uint64
}

func makeStatServers(n int) []*benchStatServer {
	servers := make([]*benchStatServer, n)
	for i := range servers {
		servers[i] = &benchStatServer{name: "server-" + string(rune('a'+i))}
	}
	return servers
}

func BenchmarkPerf2_UpdateStats_Before(b *testing.B) {
	var mu sync.Mutex
	servers := makeStatServers(10)
	target := servers[7].name
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			for _, s := range servers { // pre-patch: linear scan by name
				if s.name == target {
					s.total++
					break
				}
			}
			mu.Unlock()
		}
	})
}

func BenchmarkPerf2_UpdateStats_After(b *testing.B) {
	var mu sync.Mutex
	servers := makeStatServers(10)
	target := servers[7] // caller already holds the pointer
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.Lock()
			target.total++
			mu.Unlock()
		}
	})
}
