// The oracle for matrix row 11: VLESS over httpUpgrade.
//
// It asks the pinned xray-core — the code under upstream/xray-core/transport/
// internet/httpupgrade at the rev named in upstream/pins.toml — what it does
// with a given head, request and answer, and prints one line per case, so the
// Rust side can be swept against the reference instead of argued from its
// source.
//
//	go run . --cases            the script
//	go run . < script.txt       the golden
//
// Three families, one per question:
//
//	frame  <label> <pad> <tail> <expect> <end> <head>
//	        where the reference's own parser ends the head, in octets.
//	serve  <label> <path> <host> <tail> <expect> <head>
//	        the reference server's verdict, the answer it writes, and whether
//	        the octets that arrived with the head survived it.
//	client <label> <ed> <path> <host> <key> <payload> <expect> <answer>
//	        the reference client's verdict, whether its payload rode ahead of
//	        the answer, the payload as it arrived, and the request it wrote.
//
// A head is the rest of its line, so a case reads as the bytes it is: `\r`,
// `\n`, `\t`, `\\` and `\s` (a space) name the octets they stand for, and
// `\xHH` names any other. The `frame` family's head is that text, then `pad`
// copies of `A`, then the terminator: the pad is the knob that moves the
// terminator across the group boundaries of both scanners.
//
// `expect` names the fields on which the tree and the reference are known to
// differ, and it is the script that says so, so the golden is free to hold
// only what the reference did. The flags combine:
//
//	same  the two sides agree on every field measured here
//	v+    the tree accepts where the reference refuses
//	v-    the tree refuses where the reference accepts
//	a     the answer carries the accept header, which the tree does not write
//	t     the octets that came with the head reached the tree but not the
//	      reference's handler
//	r     the request carries the key and the version, which the tree does
//	      not send
//	o     the payload's order differs
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/httpupgrade"
	"github.com/xtls/xray-core/transport/internet/stat"
)

const (
	// The reference's own head bound: `bufio.NewReader(io.LimitReader(conn, 12288))`.
	headLimit = 12288
	// The tree's own head bound: `HEAD_LIMIT` in the carrier.
	treeLimit = 65536
	// How long the client family waits for a payload before it answers.
	rideWindow = 250 * time.Millisecond
	// How long a serve family's handler waits for the octets that came with the head.
	tailWindow = 2 * time.Second
	// The key the reference's own masquerade adds, one per dial and random;
	// the golden carries it in this shape so the line stays reproducible.
	maskedValue = "AAAAAAAAAAAAAAAAAAAAAA=="
)

// discard drops the reference's log, which it writes to stdout where the
// golden has to be.
type discard struct{}

func (discard) Handle(log.Message) {}

func main() {
	log.RegisterHandler(discard{})
	args := os.Args[1:]
	if len(args) == 1 && args[0] == "--cases" {
		emitCases(os.Stdout)
		return
	}
	script := io.Reader(os.Stdin)
	if len(args) == 1 {
		file, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintln(os.Stderr, "httpupgrade-oracle:", err)
			os.Exit(1)
		}
		defer file.Close()
		script = file
	}
	if err := run(script, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "httpupgrade-oracle:", err)
		os.Exit(1)
	}
}

// emitCases writes the script: the length sweep that moves the terminator
// across every group boundary of both scanners, the tail sweep, the shapes the
// two sides read differently, and the served and dialled families.
func emitCases(w io.Writer) {
	// The head every length is a length of: a request line, a host, and a
	// header whose value the pad fills.
	const prefix = `GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nX-Pad:\s`
	base, err := unescape(prefix)
	if err != nil {
		panic(err)
	}
	for _, total := range lengths() {
		pad := total - len(base) - 4
		// The reference's own head bound is 12288 octets and the tree's is
		// 65536, so the two sides stop at different lengths.
		expect := "same"
		if total > headLimit && total <= treeLimit {
			expect = "v+"
		}
		fmt.Fprintf(w, "frame len-%d %d 0 %s crlf %s\n", total, pad, expect, prefix)
	}
	// The octets that arrive with the head: the reference reads them into a
	// buffer it then drops, so the tail's length moves what the reference
	// consumed without moving where the head ends.
	for _, tail := range []int{1, 2, 3, 7, 8, 15, 16, 63, 64, 255, 256, 4095, 4096, 4097} {
		fmt.Fprintf(w, "frame tail-%d 0 %d same crlf %s\n", tail, tail, prefix)
	}
	// A head the two sides read differently: a bare line feed, a method the
	// tree refuses, a path the reference decodes, a header the reference
	// reads once and the tree reads twice.
	fmt.Fprintf(w, "frame lf-1 0 0 v- none GET /tunnel HTTP/1.1\\nHost: oracle.example\\nX-Pad:\\s\\n\\n\n")
	serve(w, "post-1", "/tunnel", "oracle.example", "-", "v-",
		`POST /tunnel HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	serve(w, "pct-1", "/tunnel", "oracle.example", "-", "v-",
		`GET /tun%6Eel HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	serve(w, "dup-1", "/tunnel", "oracle.example", "-", "v-",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\nConnection: close\r\nUpgrade: websocket\r\n\r\n`)
	// The served side: the head, the answer, and the octets that came with it.
	serve(w, "ok-1", "/tunnel", "oracle.example", "-", "same",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	serve(w, "key-1", "/tunnel", "oracle.example", "-", "a",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nSec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEC==\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	serve(w, "tail-1", "/tunnel", "oracle.example", "early", "t",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	serve(w, "tail-key-1", "/tunnel", "oracle.example", "early", "a+t",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nSec-WebSocket-Key: AQIDBAUGBwgJCgsMDQ4PEC==\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	serve(w, "path-1", "/other", "oracle.example", "-", "same",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	serve(w, "host-1", "/tunnel", "other.example", "-", "v+",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	serve(w, "query-1", "/tunnel", "oracle.example", "-", "same",
		`GET /tunnel?ed=2048 HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	serve(w, "case-1", "/tunnel", "oracle.example", "-", "same",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nconnection: upgrade\r\nupgrade: WebSocket\r\n\r\n`)
	serve(w, "noupgrade-1", "/tunnel", "oracle.example", "-", "same",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nConnection: Upgrade\r\n\r\n`)
	serve(w, "noconn-1", "/tunnel", "oracle.example", "-", "same",
		`GET /tunnel HTTP/1.1\r\nHost: oracle.example\r\nUpgrade: websocket\r\n\r\n`)
	// The dialled side: the answer the reference accepts, and the ones it
	// refuses, with the budget that decides whether the payload rides.
	client(w, "ok-1", 0, "/tunnel", "oracle.example", "AQIDBAUGBwgJCgsMDQ4PEC==", 0, "r",
		`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	client(w, "ok-ride-1", 2048, "/tunnel", "oracle.example", "AQIDBAUGBwgJCgsMDQ4PEC==", 8, "r",
		`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	client(w, "hold-1", 0, "/tunnel", "oracle.example", "AQIDBAUGBwgJCgsMDQ4PEC==", 8, "r",
		`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	client(w, "reason-1", 0, "/tunnel", "oracle.example", "AQIDBAUGBwgJCgsMDQ4PEC==", 0, "v+r",
		`HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	client(w, "bare-1", 0, "/tunnel", "oracle.example", "AQIDBAUGBwgJCgsMDQ4PEC==", 0, "v+r",
		`HTTP/1.1 101\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	client(w, "code-1", 0, "/tunnel", "oracle.example", "AQIDBAUGBwgJCgsMDQ4PEC==", 0, "r",
		`HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n`)
	client(w, "noconn-1", 0, "/tunnel", "oracle.example", "AQIDBAUGBwgJCgsMDQ4PEC==", 0, "r",
		`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n`)
	client(w, "noupgrade-1", 0, "/tunnel", "oracle.example", "AQIDBAUGBwgJCgsMDQ4PEC==", 0, "r",
		`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n`)
	client(w, "case-1", 0, "/tunnel", "oracle.example", "AQIDBAUGBwgJCgsMDQ4PEC==", 0, "r",
		`HTTP/1.1 101 Switching Protocols\r\nconnection: upgrade\r\nupgrade: WebSocket\r\n\r\n`)
}

// lengths is the head lengths the sweep covers: every length around every
// group boundary of both scanners — the word the tree's scan reads, the round
// it reads in, the buffer the reference reads in, and the bound each side
// carries — and the bounds themselves.
func lengths() []int {
	var out []int
	seen := map[int]bool{}
	add := func(n int) {
		if n < 55 || seen[n] {
			return
		}
		seen[n] = true
		out = append(out, n)
	}
	for n := 55; n <= 70; n++ {
		add(n)
	}
	for _, boundary := range []int{8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, headLimit, 16384, 32768, treeLimit} {
		for n := boundary - 3; n <= boundary+3; n++ {
			add(n)
		}
	}
	return out
}

func serve(w io.Writer, label, path, host, tail, expect, head string) {
	fmt.Fprintf(w, "serve %s %s %s %s %s %s\n", label, path, host, tail, expect, head)
}

func client(w io.Writer, label string, ed uint32, path, host, key string, payload int, expect, answer string) {
	fmt.Fprintf(w, "client %s %d %s %s %s %d %s %s\n", label, ed, path, host, key, payload, expect, answer)
}

func run(in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		space := strings.IndexByte(line, ' ')
		if space < 0 {
			return fmt.Errorf("a case with no fields: %q", line)
		}
		kind, rest := line[:space], line[space+1:]
		switch kind {
		case "frame":
			fields := strings.SplitN(rest, " ", 6)
			if len(fields) != 6 {
				return fmt.Errorf("frame wants <label> <pad> <tail> <expect> <end> <head>, got %q", line)
			}
			pad, err := strconv.Atoi(fields[1])
			if err != nil {
				return err
			}
			tail, err := strconv.Atoi(fields[2])
			if err != nil {
				return err
			}
			head, err := unescape(fields[5])
			if err != nil {
				return err
			}
			head = append(head, bytes.Repeat([]byte("A"), pad)...)
			switch fields[4] {
			case "crlf":
				head = append(head, '\r', '\n', '\r', '\n')
			case "none":
			default:
				return fmt.Errorf("frame wants the end to be crlf or none, got %q", fields[4])
			}
			head = append(head, bytes.Repeat([]byte("B"), tail)...)
			verdict, offset := frame(head)
			fmt.Fprintf(out, "FRAME %s %s %s\n", fields[0], verdict, offset)
		case "serve":
			fields := strings.SplitN(rest, " ", 6)
			if len(fields) != 6 {
				return fmt.Errorf("serve wants <label> <path> <host> <tail> <expect> <head>, got %q", line)
			}
			var tail []byte
			if fields[3] != "-" {
				tailed, err := unescape(fields[3])
				if err != nil {
					return err
				}
				tail = tailed
			}
			head, err := unescape(fields[5])
			if err != nil {
				return err
			}
			verdict, answer, tailState, err := serveCase(fields[1], fields[2], head, tail)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "SERVE %s %s %s %s\n", fields[0], verdict, answer, tailState)
		case "client":
			fields := strings.SplitN(rest, " ", 8)
			if len(fields) != 8 {
				return fmt.Errorf("client wants <label> <ed> <path> <host> <key> "+
					"<payload> <expect> <answer>, got %q", line)
			}
			ed, err := strconv.ParseUint(fields[1], 10, 32)
			if err != nil {
				return err
			}
			payload, err := strconv.Atoi(fields[5])
			if err != nil {
				return err
			}
			answer, err := unescape(fields[7])
			if err != nil {
				return err
			}
			verdict, order, ridden, request, err := clientCase(uint32(ed), fields[2], fields[3], fields[4], payload, answer)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "CLIENT %s %s %s %s %s\n", fields[0], verdict, order, ridden, request)
		default:
			return fmt.Errorf("unknown case %q", kind)
		}
	}
	return scanner.Err()
}

// unescape turns the script's escapes into the bytes they name.
func unescape(field string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(field); i++ {
		if field[i] != '\\' {
			out = append(out, field[i])
			continue
		}
		i++
		if i == len(field) {
			return nil, fmt.Errorf("a trailing backslash in %q", field)
		}
		switch field[i] {
		case 'r':
			out = append(out, '\r')
		case 'n':
			out = append(out, '\n')
		case 't':
			out = append(out, '\t')
		case 's':
			out = append(out, ' ')
		case '\\':
			out = append(out, '\\')
		case 'x':
			if i+2 >= len(field) {
				return nil, fmt.Errorf("a short \\x escape in %q", field)
			}
			value, err := strconv.ParseUint(field[i+1:i+3], 16, 8)
			if err != nil {
				return nil, err
			}
			out = append(out, byte(value))
			i += 2
		default:
			return nil, fmt.Errorf("unknown escape \\%c in %q", field[i], field)
		}
	}
	return out, nil
}

// frame is where the reference's own parser ends the head, read the way its
// server reads it: a `bufio` over a `LimitReader`, and `http.ReadRequest` on
// top. A head it refused is "-" and a head it took is the octets it consumed.
func frame(head []byte) (string, string) {
	source := bytes.NewReader(head)
	reader := bufio.NewReader(io.LimitReader(source, headLimit))
	if _, err := http.ReadRequest(reader); err != nil {
		return "refuse", "-"
	}
	// The octets the parser took are the ones it read less the ones it left
	// in the buffer: the buffer may hold less than the whole head, so the
	// head's own length is not the answer.
	read := len(head) - source.Len()
	return "accept", strconv.Itoa(read - reader.Buffered())
}

// serveCase is the reference server's own verdict on a request, the answer it
// writes when it accepts, and whether the octets that arrived with the head
// survived it. The server is the pinned one, over a loopback socket.
func serveCase(path, host string, head, tail []byte) (string, string, string, error) {
	port, err := freePort()
	if err != nil {
		return "", "", "", err
	}
	seen := make(chan string, 1)
	listener, err := httpupgrade.ListenHTTPUpgrade(
		context.Background(),
		xnet.LocalHostIP,
		xnet.Port(port),
		&internet.MemoryStreamConfig{
			ProtocolName: "httpupgrade",
			ProtocolSettings: &httpupgrade.Config{
				Path: path,
				Host: host,
			},
		},
		func(conn stat.Connection) {
			// The handler reads what is left of the connection: the octets
			// that came with the head are still there if the server kept
			// them, and gone if the buffer that read them was dropped.
			buffer := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(tailWindow))
			n, err := conn.Read(buffer)
			switch {
			case n > 0:
				seen <- "kept"
			case err == io.EOF:
				seen <- "dropped"
			default:
				seen <- "none"
			}
			conn.Close()
		},
	)
	if err != nil {
		return "", "", "", err
	}
	defer listener.Close()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()
	// The head and the octets behind it in one write, so the reference's
	// reader has them both in hand when it stops at the head.
	_, _ = conn.Write(append(append([]byte{}, head...), tail...))
	conn.SetReadDeadline(time.Now().Add(tailWindow))
	buffer := make([]byte, 4096)
	var answer []byte
	for {
		n, err := conn.Read(buffer)
		answer = append(answer, buffer[:n]...)
		if err != nil || bytes.Contains(answer, []byte("\r\n\r\n")) {
			break
		}
	}
	if len(answer) == 0 {
		return "refuse", "-", "-", nil
	}
	encoded := hex.EncodeToString(answer)
	// The close is what tells the handler that nothing else is coming.
	conn.Close()
	state := "-"
	if len(tail) > 0 {
		state = "none"
		select {
		case state = <-seen:
		case <-time.After(tailWindow):
		}
	}
	return "accept", encoded, state, nil
}

// clientCase is the reference client's own verdict on an answer, whether its
// payload rode ahead of that answer, the payload as it arrived, and the
// request it wrote. The peer here is a plain socket that waits for the
// payload before it answers, so the order the two arrive in is the early-data
// rule itself.
func clientCase(ed uint32, path, host, key string, payload int, answer []byte) (string, string, string, string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", "", "", "", err
	}
	defer listener.Close()

	order := make(chan string, 1)
	ridden := make(chan string, 1)
	request := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			order <- "none"
			ridden <- ""
			return
		}
		defer conn.Close()
		buffer := make([]byte, 4096)
		var got []byte
		conn.SetReadDeadline(time.Now().Add(rideWindow))
		for {
			n, err := conn.Read(buffer)
			got = append(got, buffer[:n]...)
			if err != nil || bytes.Contains(got, []byte("\r\n\r\n")) {
				break
			}
		}
		end := bytes.Index(got, []byte("\r\n\r\n"))
		if end < 0 {
			order <- "none"
			ridden <- ""
			return
		}
		request <- append([]byte{}, got[:end+4]...)
		// The payload rides ahead of the answer when it arrived with the
		// request or reached the socket before the answer went out.
		early := got[end+4:]
		if len(early) == 0 {
			conn.SetReadDeadline(time.Now().Add(rideWindow))
			n, _ := conn.Read(buffer)
			early = append([]byte{}, buffer[:n]...)
		}
		if len(early) > 0 {
			order <- "P"
		} else {
			order <- "A"
		}
		conn.Write(answer)
		// The payload that came after the answer, if the client held it back.
		late := []byte{}
		conn.SetReadDeadline(time.Now().Add(rideWindow))
		for {
			n, err := conn.Read(buffer)
			late = append(late, buffer[:n]...)
			if err != nil {
				break
			}
		}
		if len(early) == 0 {
			early = late
		}
		ridden <- hex.EncodeToString(early)
	}()

	settings := &internet.MemoryStreamConfig{
		ProtocolName: "httpupgrade",
		ProtocolSettings: &httpupgrade.Config{
			Host: host,
			Path: path,
			Ed:   ed,
			Header: map[string]string{
				"Sec-WebSocket-Key": key,
			},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := httpupgrade.Dial(
		ctx,
		xnet.TCPDestination(xnet.DomainAddress("127.0.0.1"), xnet.Port(listener.Addr().(*net.TCPAddr).Port)),
		settings,
	)
	if err != nil {
		// The reference wrote its request before it read the answer, so the
		// request is on the wire even when the answer was refused.
		written := <-request
		return "refuse", <-order, <-ridden, hex.EncodeToString(project(written, key)), nil
	}
	defer conn.Close()
	written := <-request
	// The payload goes out as soon as the dial hands the connection back, so
	// a budget that holds the answer back lets it ride ahead of the answer.
	if payload > 0 {
		conn.Write(payloadBytes(payload))
	}
	verdict := "accept"
	if ed != 0 {
		// With a budget the reference hands the connection back unread, so
		// the first read is where the answer is judged.
		buffer := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Read(buffer); err != nil {
			verdict = "refuse"
		}
	}
	return verdict, <-order, <-ridden, hex.EncodeToString(project(written, key)), nil
}

// payloadBytes is the early data the client family rides: distinct octets, so
// an implementation that permutes them cannot pass.
func payloadBytes(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = 0xa0 + byte(i)
	}
	return out
}

// project keeps the request's protocol headers and drops the browser
// masquerade: its `User-Agent` names a Chrome version that moves with the
// date, so a golden that carried it would differ every day.
func project(request []byte, key string) []byte {
	lines := bytes.Split(request, []byte("\r\n"))
	kept := [][]byte{lines[0]}
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		name, value, ok := bytes.Cut(line, []byte(": "))
		if !ok {
			continue
		}
		switch strings.ToLower(string(name)) {
		case "host", "connection", "upgrade", "sec-websocket-version":
			kept = append(kept, line)
		case "sec-websocket-key":
			// The key the reference added of its own accord is random per
			// dial; the one the caller asked for is held to the byte.
			if bytes.Equal(value, []byte(key)) {
				kept = append(kept, line)
			} else {
				masked := make([]byte, 0, len(line))
				masked = append(masked, name...)
				masked = append(masked, ": "...)
				masked = append(masked, maskedValue...)
				kept = append(kept, masked)
			}
		}
	}
	out := bytes.Join(kept, []byte("\r\n"))
	return append(out, '\r', '\n')
}

// freePort takes a port the kernel says is free and hands it back; the
// reference binds it a moment later.
func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
