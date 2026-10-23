// The byte-identity oracle for the DNS outbound.
//
// It drives the *pinned* xray-core's own `proxy/dns` handler over an
// in-memory pipe and dumps every octet the handler wrote to the client for
// each scripted query, TCP framing included. The Rust side (`ferrox-core`'s
// `dns` module) must produce the same octets for the same script.
//
// The reference handler is `xray-core/proxy/dns/dns.go`'s `Handler.Process`,
// at the rev `upstream/pins.toml` names. `Init` takes the interfaces directly,
// so the oracle needs no instance: a canned `dns.Client` stands in for the
// resolver and a fake dialer stands in for the tunnel.
//
// Run: `go run . script.txt > expected.txt`

package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	gnet "net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/log"
	vnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/policy"
	dnsd "github.com/xtls/xray-core/proxy/dns"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
	"golang.org/x/net/dns/dnsmessage"
)

// How long a case waits before its recorded bytes are declared final. An
// answer lands within microseconds; only an empty answer needs the whole wait.
const wait = time.Second

// How long the tunnel waits before it answers the forwarded query: long
// enough that the handler has dialled and written first, short enough that no
// case wedges.
const feedAfter = time.Second / 10

func tcpFrame(msg []byte) [][]byte {
	head := make([]byte, 2)
	binary.BigEndian.PutUint16(head, uint16(len(msg)))
	return [][]byte{head, msg}
}

// A canned resolver record: the IPs the fake `dns.Client` answers with, or one
// of the resolver-side failures the reference's `RCodeFromError` maps.
type canned struct {
	ips     []vnet.IP
	ttl     uint32
	kind    uint8 // ko: ok, empty: ErrEmptyResponse, refused: RCodeError
	refused uint16
}

const (
	ko = iota
	emptyK
	refusedK
)

// fakeClient answers a canned record per name, the way the reference's own
// `localdns` answers: one record per family the option asks for, the record's
// own TTL, `ErrEmptyResponse` when the family has no IP.
type fakeClient map[string]canned

func (fakeClient) Start() error      { return nil }
func (fakeClient) Close() error      { return nil }
func (fakeClient) Type() interface{} { return dns.ClientType() }

func (f fakeClient) LookupIP(domain string, option dns.IPOption) ([]vnet.IP, uint32, error) {
	c, ok := f[strings.ToLower(domain)]
	if !ok {
		return nil, 0, dns.ErrEmptyResponse
	}
	switch c.kind {
	case emptyK:
		return nil, 0, dns.ErrEmptyResponse
	case refusedK:
		return nil, 0, dns.RCodeError(c.refused)
	}
	var ips []vnet.IP
	for _, ip := range c.ips {
		v4 := ip.To4()
		if option.IPv4Enable && v4 != nil {
			ips = append(ips, ip)
		}
		if option.IPv6Enable && v4 == nil && len(ip) == vnet.IPv6len {
			ips = append(ips, ip)
		}
	}
	if len(ips) == 0 {
		return nil, 0, dns.ErrEmptyResponse
	}
	return ips, c.ttl, nil
}

// fakeDialer is the tunnel: one conn per dial; its far end answers the
// forwarded query with one message, framed the way the connection's own
// network frames, and then ends the stream.
type fakeDialer struct {
	msg  []byte
	gate chan struct{}
}

func (d *fakeDialer) Dial(ctx context.Context, dest vnet.Destination) (stat.Connection, error) {
	client, server := gnet.Pipe()
	go func() {
		<-d.gate
		if dest.Network == vnet.Network_TCP {
			head := make([]byte, 2)
			binary.BigEndian.PutUint16(head, uint16(len(d.msg)))
			_, _ = server.Write(head)
		}
		_, _ = server.Write(d.msg)
		_ = server.Close()
	}()
	return client, nil
}

func (d *fakeDialer) DestIpAddress() vnet.IP                                    { return nil }
func (d *fakeDialer) SetOutboundGateway(_ context.Context, _ *session.Outbound) {}

var _ internet.Dialer = (*fakeDialer)(nil)

// query is the query itself: the ID, the name, the type, class INET and the RD
// bit — the shape `proxy/dns`'s own test drives the handler with.
func query(id uint16, name string, t dnsmessage.Type) []byte {
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: t, Class: dnsmessage.ClassINET}},
	}
	raw, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return raw
}

func main() {
	// The recorded bytes are stdout alone: the reference
	// logs to stdout too, so the oracle silences its own logger.
	log.RegisterHandler(silent{})
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
		if line == "" || strings.HasPrefix(line, "/") || strings.HasPrefix(line, "#") {
			continue
		}
		out := drive(strings.Fields(line))
		fmt.Printf("BYTES %s\n", hex.EncodeToString(out))
	}
}

// One case: the handler serves the scripted query over a fresh pair of pipes
// with a fresh client and dialer, and the oracle records every octet it wrote
// to the client.
//
// Script line: <kind> <net> <id-hex> <name> <qtype-hex> [attr ...]
//
// kinds:
//
//	hijack   the default A/AAAA path; needs `ips=`
//	reject   a Return action; needs `rcode=<hex>` via a rule or the form below
//	drop     a Drop action; records nothing
//	direct   a Direct action rule forwards to the tunnel; needs `feed=<hex>`
//	broken   <name> is the raw query in hex; the reference's parse refuses it
//	oversize a declared TCP size past the bound; the connection ends
//
// attrs:
//
//	ips=v4:192.0.2.11,v6:2001:db8::1 | empty | nxdomain  the fake resolver's record
//	ttl=<u32>    the record's TTL
//	rule=<qtype|*>/<domain rule>/<action>/<rcode|->   one pb rule, in order
//	feed=<hex>   the tunnel's answer message, raw
//	dest=<tcp|udp>  the rewrite network of the tunnel, for `direct`
func drive(fields []string) []byte {
	kindf, network := fields[0], fields[1]
	// `broken` lines carry the raw query in the third field and nothing else;
	// every other kind carries <id-hex> <name> <qtype-hex> and attributes.
	brokenHex := ""
	if kindf == "broken" {
		brokenHex = fields[2]
	}
	var id, name, t string
	if len(fields) > 3 {
		id, name, t = fields[2], fields[3], fields[4]
	}
	kind := kindf
	var config dnsd.Config
	var client fakeClient
	var dialer *fakeDialer
	// Attributes are `key=value`; a `broken` line has none.
	for _, attr := range fields[min(len(fields), 5):] {
		key, value, _ := strings.Cut(attr, "=")
		switch key {
		case "rule":
			// <qtype-hex|*>/<domain rule>/<action>/<rcode-hex|->
			parts := strings.Split(value, "/")
			if len(parts) != 4 {
				panic("bad rule " + value)
			}
			action, ok := dnsd.RuleAction_value[parts[2]]
			if !ok {
				panic("unknown action " + parts[2])
			}
			rule := &dnsd.DNSRuleConfig{Action: dnsd.RuleAction(action)}
			if parts[0] != "*" {
				qCode, err := strconv.ParseUint(parts[0], 16, 16)
				if err != nil {
					panic(err)
				}
				rule.QType = []int32{int32(qCode)}
			}
			if parts[3] != "-" {
				rCode, err := strconv.ParseUint(parts[3], 16, 16)
				if err != nil {
					panic(err)
				}
				rule.RCode = uint32(rCode)
			}
			parsed, err := geodata.ParseDomainRules([]string{parts[1]}, geodata.Domain_Substr)
			if err != nil {
				panic(err)
			}
			rule.Domain = parsed
			config.Rule = append(config.Rule, rule)
		case "ips":
			c := canned{}
			switch value {
			case "empty":
				c.kind = emptyK
			case "nxdomain":
				c.kind = refusedK
				c.refused = 3
			default:
				for _, got := range strings.Split(value, ",") {
					var text string
					if rest, found := strings.CutPrefix(got, "v4:"); found {
						text = rest
					} else {
						text = strings.TrimPrefix(got, "v6:")
					}
					ip := vnet.ParseIP(text)
					if ip == nil {
						panic("bad ip " + got)
					}
					c.ips = append(c.ips, ip)
				}
				c.ttl = dns.DefaultTTL
			}
			if client == nil {
				client = fakeClient{}
			}
			client[name] = c
		case "ttl":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				panic(err)
			}
			c := client[name]
			c.ttl = uint32(n)
			client[name] = c
		case "feed":
			decoded, err := hex.DecodeString(value)
			if err != nil {
				panic(err)
			}
			dialer = &fakeDialer{msg: decoded, gate: make(chan struct{})}
		case "dest":
			var network vnet.Network
			switch value {
			case "tcp":
				network = vnet.Network_TCP
			case "udp":
				network = vnet.Network_UDP
			default:
				panic("unknown dest network " + value)
			}
			config.RewriteServer = &vnet.Endpoint{Address: vnet.NewIPOrDomain(vnet.ParseAddress("127.0.0.1")), Port: 5353, Network: network}
		default:
			panic("unknown attr " + key)
		}
	}

	var queryMsg []byte
	switch kind {
	case "hijack":
		if client == nil {
			panic("hijack without canned resolver")
		}
		fallthrough
	case "reject", "drop", "direct":
		qcode, err := strconv.ParseUint(t, 16, 16)
		if err != nil {
			panic(err)
		}
		qid, err := strconv.ParseUint(id, 16, 16)
		if err != nil {
			panic(err)
		}
		queryMsg = query(uint16(qid), name, dnsmessage.Type(qcode))
	case "broken":
		decoded, err := hex.DecodeString(brokenHex)
		if err != nil {
			panic(err)
		}
		queryMsg = decoded
	case "oversize":
		qcode, err := strconv.ParseUint(t, 16, 16)
		if err != nil {
			panic(err)
		}
		qid, err := strconv.ParseUint(id, 16, 16)
		if err != nil {
			panic(err)
		}
		queryMsg = query(uint16(qid), name, dnsmessage.Type(qcode))
	default:
		panic("unknown kind " + kind)
	}

	src := vnet.Network_UDP
	if network == "tcp" {
		src = vnet.Network_TCP
	}

	handler := new(dnsd.Handler)
	if err := handler.Init(&config, client, policy.DefaultManager{}); err != nil {
		panic(err)
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{
		Target: vnet.Destination{Network: src, Address: vnet.LocalHostIP, Port: 53},
	}})

	r1, w1 := pipe.New(pipe.WithoutSizeLimit())
	r2, w2 := pipe.New(pipe.WithoutSizeLimit())
	link := transport.Link{Reader: r1, Writer: w2}

	go func() {
		_ = handler.Process(ctx, &link, dialer)
	}()

	if kind == "direct" {
		// The tunnel answers only once the handler has dialled it: the dial
		// happens on the first byte the handler writes, and the gate opens a
		// beat later, so the query is always in the pipe first.
		go func() {
			time.Sleep(feedAfter)
			close(dialer.gate)
		}()
	}

	writeQuery := func() {
		var parts [][]byte
		if kind == "oversize" {
			// A declared size past the bound: the connection ends before the
			// payload is ever read.
			head := make([]byte, 2)
			binary.BigEndian.PutUint16(head, uint16(buf.Size)+1)
			parts = append(parts, head, queryMsg)
		} else if src == vnet.Network_TCP {
			parts = tcpFrame(queryMsg)
		} else {
			parts = [][]byte{queryMsg}
		}
		var mb buf.MultiBuffer
		for _, part := range parts {
			b := buf.New()
			_, _ = b.Write(part)
			mb = append(mb, b)
		}
		if err := w1.WriteMultiBuffer(mb); err != nil {
			panic(err)
		}
	}
	writeQuery()
	_ = w1.Close()

	var out []byte
	for i := 0; i < 16; i++ {
		mb, err := r2.ReadMultiBufferTimeout(wait)
		if err != nil {
			break
		}
		got := make([]byte, mb.Len())
		mb.Copy(got)
		out = append(out, got...)
	}
	return out
}

// A log handler that keeps the record clean: the reference's handler logs to
// stdout, the oracle's stdout is the record.
type silent struct{}

func (silent) Handle(m log.Message) {}
func (silent) Close() error         { return nil }
