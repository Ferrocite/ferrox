// hello-oracle dumps the exact `cipher_suites` field a Go crypto/tls ClientHello
// puts on the wire for a given config, so the Rust builder can be gated
// byte-identical against the reference the PattNG "unsafe" path actually runs.
//
// The field is the only non-trivially-derived, deterministic part of the hello:
// random, session_id and key_share carry fresh entropy every run, so they cannot
// be pinned. Everything the cipher_suites field depends on — the parsed IDs,
// crypto/tls' preference re-ordering, and which TLS 1.3 suites get appended — is
// a pure function of (config list, min version, max version, AES-hardware branch).
//
// It reads a script of cases and prints one `CS <hex>` line per case: the raw
// wire bytes of the field, i.e. the 2-byte big-endian length followed by the
// suite IDs, exactly as they appear in the ClientHello record.
package main

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// xrayMap turns the ':'-joined config string into ids the way xray-core does
// (config.go: split on ':', trim, keep only names crypto/tls knows, in order).
func xrayMap(list string) []uint16 {
	known := map[string]uint16{}
	for _, s := range tls.CipherSuites() {
		known[s.Name] = s.ID
	}
	for _, s := range tls.InsecureCipherSuites() {
		known[s.Name] = s.ID
	}
	var out []uint16
	for _, n := range strings.Split(list, ":") {
		n = strings.TrimSpace(n)
		if v, ok := known[n]; ok {
			out = append(out, v)
		}
	}
	return out
}

func version(s string) uint16 {
	switch s {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	}
	panic("bad version " + s)
}

// readClientHello drives a tls.Client over an in-memory pipe and returns the
// assembled ClientHello handshake body (no record or handshake header).
func readClientHello(cfg *tls.Config) []byte {
	client, server := net.Pipe()
	hs := tls.Client(client, cfg)
	go func() {
		// Triggers the ClientHello write; the rest of the handshake never
		// completes and the goroutine exits when the pipe is closed.
		_, _ = hs.Write([]byte{0})
	}()
	defer client.Close()

	var buf []byte
	chunk := make([]byte, 16*1024)
	for {
		n, err := server.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			if len(buf) >= 5 {
				break
			}
			panic(err)
		}
		if len(buf) >= 5 {
			recLen := int(buf[3])<<8 | int(buf[4])
			if len(buf) >= 5+recLen {
				break
			}
		}
	}
	// Handshake record -> body. Go sends the ClientHello in one record.
	if buf[0] != 0x16 {
		panic("first record is not a handshake")
	}
	recLen := int(buf[3])<<8 | int(buf[4])
	hsBytes := buf[5 : 5+recLen]
	if hsBytes[0] != 0x01 {
		panic("first handshake message is not a ClientHello")
	}
	hsLen := int(hsBytes[1])<<16 | int(hsBytes[2])<<8 | int(hsBytes[3])
	return hsBytes[4 : 4+hsLen]
}

// cipherSuitesField returns the wire bytes of the cipher_suites field: the
// 2-byte length plus the suite ids, sliced straight out of the hello body.
func cipherSuitesField(body []byte) []byte {
	at := 2 + 32 // client_version + random
	sidLen := int(body[at])
	at += 1 + sidLen
	csLen := int(body[at])<<8 | int(body[at+1])
	return body[at : at+2+csLen]
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		// <colon-joined-names> <min> <max>
		cfg := &tls.Config{
			ServerName:   "example.com",
			CipherSuites: xrayMap(parts[0]),
			MinVersion:   version(parts[1]),
			MaxVersion:   version(parts[2]),
		}
		field := cipherSuitesField(readClientHello(cfg))
		fmt.Printf("CS %s\n", hex.EncodeToString(field))
	}
}
