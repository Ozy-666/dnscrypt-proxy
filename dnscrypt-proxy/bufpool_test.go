package main

import (
	"testing"
	"time"
)

// Pooled hot-path buffer reuse should report 0 allocs/op.
func BenchmarkUDPQueryBufferPool(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := udpQueryBufferPool.Get().(*[]byte)
		buf := *p
		_ = buf[:1]
		udpQueryBufferPool.Put(p)
	}
}

// Baseline: per-call allocation of the same 4 KiB buffer.
func BenchmarkUDPQueryBufferMake(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, MaxDNSPacketSize-1)
		_ = buf[:1]
	}
}

func BenchmarkEncryptedResponseBufferPool(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p := encryptedResponseBufferPool.Get().(*[]byte)
		buf := *p
		_ = buf[:1]
		encryptedResponseBufferPool.Put(p)
	}
}

func BenchmarkEncryptedResponseBufferMake(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf := make([]byte, MaxDNSPacketSize)
		_ = buf[:1]
	}
}

// NewPluginsState should no longer allocate the session map eagerly.
func BenchmarkNewPluginsState(b *testing.B) {
	proxy := &Proxy{}
	start := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewPluginsState(proxy, "udp", nil, "udp", start)
	}
}
