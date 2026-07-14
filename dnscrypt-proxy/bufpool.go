package main

import "sync"

// Hot-path packet buffers. Under high QPS the per-query allocation of these
// fixed 4 KiB buffers dominates GC pressure, so they are pooled.
//
// Pools store *[]byte (not []byte) so the slice header itself is not copied
// into the interface, avoiding an allocation on Put.

// udpQueryBufferPool backs inbound UDP query reads (see Proxy.udpListener).
// The raw packet is unpacked into a *dns.Msg and re-packed in place; nothing
// retains the raw buffer past processIncomingQuery, so the worker goroutine
// returns it once processing completes.
var udpQueryBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, MaxDNSPacketSize-1)
		return &b
	},
}

// encryptedResponseBufferPool backs the encrypted UDP response read in the
// upstream exchange path.
//
// ALIASING CONTRACT: Decrypt returns a fresh buffer on success but returns the
// input buffer itself on every error path (crypto.go). A buffer from this pool
// may therefore only be returned once it is certain no live slice aliases it:
// before Decrypt runs, or after Decrypt succeeds. On a Decrypt error the buffer
// must be dropped (left to the GC), never Put back.
var encryptedResponseBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, MaxDNSPacketSize)
		return &b
	},
}
