// The byte-identity oracle for the SOCKS5 client.
//
// It drives the *pinned* xray-core's own SOCKS5 client — `proxy/socks`'s
// `ClientHandshake` — over an in-memory pipe and dumps every octet the client
// writes. The Rust side (`ferrox-core`'s `socks` module) must produce the same
// octets for the same script.
//
// The reference writer is `xray-core/proxy/socks/protocol.go`'s
// `ClientHandshake`, at the rev `upstream/pins.toml` names. It writes the
// greeting `[5, 1, method]`, the RFC 1929 block `[1, ulen, user, plen, pass]`
// when a credential is configured, and the request
// `[5, cmd, 0, atyp, addr, port]`. The reference's UDP writer is the same
// file's `EncodeUDPPacket`: `[0, 0, 0]` then the address and the payload.
//
// Run: `go run . script.txt > expected.txt`

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/socks"
)

// A server that answers the client's greeting with the method the script names,
// then the credential reply, then the request reply, and records every octet the
// client wrote.
type recorder struct {
	out    *bytes.Buffer
	server *bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	return r.out.Write(p)
}

func (r *recorder) Read(p []byte) (int, error) {
	return r.server.Read(p)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: oracle <script.txt>")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		switch parts[0] {
		case "handshake":
			// handshake <method> <atyp> <addr> <port> [<user> <pass>]
			method := parts[1]
			atyp, addr, port := parts[2], parts[3], parts[4]
			user, pass := "", ""
			if method == "user" {
				user, pass = parts[5], parts[6]
			}
			record(out, method, user, pass, atyp, addr, port)
		case "udp":
			// udp <atyp> <addr> <port> <hex payload>
			recordUDP(out, parts[1], parts[2], parts[3], parts[4])
		default:
			panic("unknown script command " + parts[0])
		}
	}
	if err := sc.Err(); err != nil {
		panic(err)
	}
}

// The method byte the server selects.
func methodByte(name string) byte {
	if name == "user" {
		return 2
	}
	return 0
}

func record(out *bufio.Writer, method, user, pass, atyp, addr, port string) {
	var address net.Address
	switch atyp {
	case "ipv4":
		address = net.ParseAddress(addr)
	case "ipv6":
		address = net.ParseAddress(addr)
	default:
		address = net.ParseAddress(addr)
	}
	var p net.Port
	fmt.Sscanf(port, "%d", &p)

	req := &protocol.RequestHeader{
		Version: 5,
		Command: protocol.RequestCommandTCP,
		Address: address,
		Port:    p,
	}
	if method == "user" {
		req.User = &protocol.MemoryUser{Account: &socks.Account{Username: user, Password: pass}}
	}

	// The server's answers: the method the client must see, the credential reply,
	// and the request reply.
	var server bytes.Buffer
	server.Write([]byte{5, methodByte(method)})
	if method == "user" {
		server.Write([]byte{1, 0})
	}
	server.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})

	rec := &recorder{out: &bytes.Buffer{}, server: &server}
	if _, err := socks.ClientHandshake(req, rec, rec); err != nil {
		panic(err)
	}
	fmt.Fprintf(out, "BYTES %s\n", hex.EncodeToString(rec.out.Bytes()))
}

// The UDP datagram frame the reference's `EncodeUDPPacket` writes.
func recordUDP(out *bufio.Writer, atyp, addr, port, payload string) {
	var address net.Address
	address = net.ParseAddress(addr)
	var p net.Port
	fmt.Sscanf(port, "%d", &p)

	req := &protocol.RequestHeader{
		Version: 5,
		Command: protocol.RequestCommandUDP,
		Address: address,
		Port:    p,
	}
	data, err := hex.DecodeString(payload)
	if err != nil {
		panic(err)
	}
	msg, err := socks.EncodeUDPPacket(req, data)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(out, "BYTES %s\n", hex.EncodeToString(msg.Bytes()))
}
