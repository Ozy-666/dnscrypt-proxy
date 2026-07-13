package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// TestReadPrefixedLargeResponse verifies that a legitimate DNS response
// larger than the legacy 4 KiB cap (observed live: 6,816-byte cisco.com TXT)
// is read in full over TCP.  DNS-over-TCP frames are legal up to 65,535
// bytes; capping reads at 4 KiB made every larger answer SERVFAIL.
func TestReadPrefixedLargeResponse(t *testing.T) {
	for _, size := range []int{MinDNSPacketSize, 4095, 4096, 6816, MaxDNSTCPPacketSize} {
		payload := bytes.Repeat([]byte{0xAB}, size)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			frame := make([]byte, 2+len(payload))
			binary.BigEndian.PutUint16(frame[0:2], uint16(len(payload)))
			copy(frame[2:], payload)
			server.Write(frame)
		}()

		var conn net.Conn = client
		got, err := ReadPrefixed(&conn)
		if err != nil {
			t.Errorf("size %d: unexpected error: %v", size, err)
			client.Close()
			continue
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("size %d: payload mismatch (got %d bytes)", size, len(got))
		}
		client.Close()
	}
}

// TestReadPrefixedTooShort keeps the lower bound intact.
func TestReadPrefixedTooShort(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		payload := bytes.Repeat([]byte{0xAB}, MinDNSPacketSize-1)
		frame := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(payload)))
		copy(frame[2:], payload)
		// The reader rejects on the length header without draining the
		// payload, so this write legitimately errors when client closes.
		server.Write(frame)
	}()

	var conn net.Conn = client
	_, err := ReadPrefixed(&conn)
	client.Close()
	if err == nil {
		t.Error("undersized frame accepted")
	}
}

// TestDecryptAcceptsLargeCiphertext verifies the Decrypt size gate admits
// DNSCrypt-over-TCP responses above the legacy 4 KiB cap.  The crafted
// message passes the size/prefix gate and must then fail on the *nonce*
// check — not on "Invalid message size or prefix".
func TestDecryptAcceptsLargeCiphertext(t *testing.T) {
	proxy := &Proxy{}
	serverInfo := &ServerInfo{CryptoConstruction: XChacha20Poly1305}
	var sharedKey [32]byte

	responseHeaderLen := len(ServerMagic) + NonceSize
	encrypted := make([]byte, responseHeaderLen+TagSize+6816)
	copy(encrypted, ServerMagic[:])
	// Server nonce deliberately mismatches the client nonce below.
	for i := len(ServerMagic); i < responseHeaderLen; i++ {
		encrypted[i] = 0xFF
	}
	nonce := make([]byte, NonceSize)

	_, err := proxy.Decrypt(serverInfo, &sharedKey, encrypted, nonce)
	if err == nil {
		t.Fatal("expected an error (crafted message is not decryptable)")
	}
	if err.Error() == "Invalid message size or prefix" {
		t.Fatalf("6,816-byte ciphertext rejected by the size gate: %v", err)
	}
	if err.Error() != "Unexpected nonce" {
		t.Fatalf("expected nonce mismatch, got: %v", err)
	}
}
