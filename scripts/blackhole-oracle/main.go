// The byte-identity oracle for the blackhole sink.
//
// It drives the *pinned* xray-core's own `proxy/blackhole` handler over an
// in-memory pipe and dumps every octet the handler writes to the client. The
// Rust side (`ferrox-core`'s `blackhole` module) must produce the same octets
// for the same script.
//
// The reference handler is `xray-core/proxy/blackhole/blackhole.go`'s
// `Handler.Process`, at the rev `upstream/pins.toml` names. It writes the
// configured answer to the link's writer — the 403 that `http.Response.Write`
// serialises for `http403response`, or the configured bytes for `custom`, or
// nothing for `none` — and then ends the flow.
//
// Run: `go run . script.txt > expected.txt`

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/blackhole"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// How long a case waits for the answer. The reference sleeps a second after
// writing it, so a case that waits less than that would race the handler.
const wait = 5 * time.Second

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: oracle <script.txt>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		var config *blackhole.Config
		switch fields[0] {
		case "none":
			config = &blackhole.Config{}
		case "http":
			config = &blackhole.Config{Response: &blackhole.Response{Type: "http"}}
		case "custom":
			var data []byte
			if len(fields) > 1 {
				decoded, err := hex.DecodeString(fields[1])
				if err != nil {
					panic(err)
				}
				data = decoded
			}
			config = &blackhole.Config{Response: &blackhole.Response{Type: "custom", CustomResponseData: data}}
		default:
			panic("unknown case " + fields[0])
		}
		fmt.Printf("BYTES %s\n", hex.EncodeToString(answer(config)))
	}
}

// The bytes the reference writes to the client for this configuration.
func answer(config *blackhole.Config) []byte {
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	handler, err := blackhole.New(ctx, config)
	if err != nil {
		panic(err)
	}
	reader, writer := pipe.New(pipe.WithoutSizeLimit())
	link := transport.Link{Reader: reader, Writer: writer}
	ended := make(chan struct{})
	go func() {
		// The reference's own test drives it the same way: the handler owns the
		// link and the reader takes what it wrote.
		_ = handler.Process(ctx, &link, nil)
		close(ended)
	}()
	mb, err := reader.ReadMultiBufferTimeout(wait)
	var out []byte
	if err == nil {
		out = make([]byte, mb.Len())
		mb.Copy(out)
	}
	<-ended
	return out
}
