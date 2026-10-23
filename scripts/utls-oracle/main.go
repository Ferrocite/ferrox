// utls-oracle dumps the exact ClientHello each pinned uTLS preset builds, so the
// Rust shaped-hello builder can be gated byte-identical against the reference
// xray-core actually runs.
//
// The per-connection entropy is erased before printing: random, session id, every
// key-exchange byte and the ECH cover payload are fresh in both implementations,
// so the shipped hello is built with those fields zeroed too. The GREASE draws are
// real (the hello-phase reads return zeros, which pins them), because a GREASE
// value is a fixed function of the draw and must match byte for byte.
//
// Chrome presets shuffle their middle extensions with a fresh crypto/rand seed at
// spec creation, so for those the oracle prints the extension multiset, the positions
// of the GREASE, padding and PSK entries the shuffle never moves, and the body ahead of
// the extensions, which carries the cipher list the shuffle leaves alone.
package main

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

var presets = map[string]utls.ClientHelloID{
	"Hello360_7_5":                     utls.Hello360_7_5,
	"Hello360_11_0":                    utls.Hello360_11_0,
	"HelloAndroid_11_OkHttp":           utls.HelloAndroid_11_OkHttp,
	"HelloChrome_58":                   utls.HelloChrome_58,
	"HelloChrome_70":                   utls.HelloChrome_70,
	"HelloChrome_72":                   utls.HelloChrome_72,
	"HelloChrome_96":                   utls.HelloChrome_96,
	"HelloChrome_100":                  utls.HelloChrome_100,
	"HelloChrome_100_PSK":              utls.HelloChrome_100_PSK,
	"HelloChrome_106_Shuffle":          utls.HelloChrome_106_Shuffle,
	"HelloChrome_112_PSK_Shuf":         utls.HelloChrome_112_PSK_Shuf,
	"HelloChrome_114_Padding_PSK_Shuf": utls.HelloChrome_114_Padding_PSK_Shuf,
	"HelloChrome_115_PQ":               utls.HelloChrome_115_PQ,
	"HelloChrome_115_PQ_PSK":           utls.HelloChrome_115_PQ_PSK,
	"HelloChrome_120":                  utls.HelloChrome_120,
	"HelloChrome_120_PQ":               utls.HelloChrome_120_PQ,
	"HelloChrome_131":                  utls.HelloChrome_131,
	"HelloChrome_133":                  utls.HelloChrome_133,
	"HelloEdge_85":                     utls.HelloEdge_85,
	"HelloEdge_106":                    utls.HelloEdge_106,
	"HelloQQ_11_1":                     utls.HelloQQ_11_1,
	"HelloFirefox_55":                  utls.HelloFirefox_55,
	"HelloFirefox_63":                  utls.HelloFirefox_63,
	"HelloFirefox_99":                  utls.HelloFirefox_99,
	"HelloFirefox_102":                 utls.HelloFirefox_102,
	"HelloFirefox_105":                 utls.HelloFirefox_105,
	"HelloFirefox_120":                 utls.HelloFirefox_120,
	"HelloFirefox_148":                 utls.HelloFirefox_148,
	"HelloIOS_11_1":                    utls.HelloIOS_11_1,
	"HelloIOS_12_1":                    utls.HelloIOS_12_1,
	"HelloIOS_13":                      utls.HelloIOS_13,
	"HelloIOS_14":                      utls.HelloIOS_14,
	"HelloSafari_16_0":                 utls.HelloSafari_16_0,
	"HelloSafari_26_3":                 utls.HelloSafari_26_3,
}

// helloRand zeroes the four hello-phase draws — random, session id, the ten GREASE
// bytes and the session id ApplyPreset overwrites — and forwards the rest so key
// generation still sees valid scalars. The oracle erases that key material later.
type helloRand struct{ zeros int }

func (r *helloRand) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) && r.zeros > 0 {
		p[n] = 0
		n++
		r.zeros--
	}
	if n < len(p) {
		m, err := crand.Read(p[n:])
		return n + m, err
	}
	return n, nil
}

func readHello(id utls.ClientHelloID) []byte {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		panic(err)
	}
	pinECH(&spec)

	client, server := net.Pipe()
	defer client.Close()
	// A psk preset holds an empty psk extension, which the pin refuses to send; concealing it is the only way that preset's other bytes reach the wire.
	cfg := &utls.Config{
		ServerName:         "example.com",
		InsecureSkipVerify: true,
		Rand:               &helloRand{zeros: 106},
		OmitEmptyPsk:       true,
	}
	uconn := utls.UClient(client, cfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		panic(err)
	}
	go func() { _ = uconn.Handshake() }()

	var buf []byte
	chunk := make([]byte, 16*1024)
	for {
		n, err := server.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if len(buf) >= 5 {
			recLen := int(buf[3])<<8 | int(buf[4])
			if len(buf) >= 5+recLen {
				break
			}
		}
		if err != nil {
			panic(err)
		}
	}
	if buf[0] != 0x16 {
		panic("first record is not a handshake")
	}
	recLen := int(buf[3])<<8 | int(buf[4])
	hs := buf[5 : 5+recLen]
	if hs[0] != 0x01 {
		panic("first handshake message is not a ClientHello")
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	return hs[4 : 4+hsLen]
}

// pinECH fixes the cover's random candidates to the first one the preset names, so
// the only remaining entropy is the payload, which normalization erases.
func pinECH(spec *utls.ClientHelloSpec) {
	for _, ext := range spec.Extensions {
		ech, ok := ext.(*utls.GREASEEncryptedClientHelloExtension)
		if !ok {
			continue
		}
		if len(ech.CandidateCipherSuites) > 0 {
			ech.CandidateCipherSuites = ech.CandidateCipherSuites[:1]
		}
		if len(ech.CandidatePayloadLens) > 0 {
			ech.CandidatePayloadLens = ech.CandidatePayloadLens[:1]
		}
		ech.CandidateConfigIds = []uint8{0}
		ech.EncapsulatedKey = make([]byte, 32)
	}
}

type extension struct {
	kind uint16
	raw  []byte
}

// normalize zeros the entropy the two implementations cannot share and returns the
// ClientHello up to its extension vector plus each normalized extension.
func normalize(body []byte) ([]byte, []extension) {
	b := append([]byte(nil), body...)
	for i := 2; i < 34; i++ {
		b[i] = 0
	}
	sidLen := int(b[34])
	for i := 35; i < 35+sidLen; i++ {
		b[i] = 0
	}
	at := 35 + sidLen
	csLen := int(binary.BigEndian.Uint16(b[at:]))
	at += 2 + csLen
	compLen := int(b[at])
	at += 1 + compLen
	extLen := int(binary.BigEndian.Uint16(b[at:]))
	at += 2
	end := at + extLen

	var exts []extension
	for at < end {
		kind := binary.BigEndian.Uint16(b[at:])
		length := int(binary.BigEndian.Uint16(b[at+2:]))
		value := b[at+4 : at+4+length]
		switch kind {
		case 0x0033:
			zeroKeyShare(value)
		case 0xfe0d:
			zeroECHPayload(value)
		}
		exts = append(exts, extension{kind: kind, raw: b[at : at+4+length]})
		at += 4 + length
	}
	return b[:end-extLen], exts
}

func zeroKeyShare(body []byte) {
	total := int(binary.BigEndian.Uint16(body))
	at := 2
	for at+4 <= 2+total {
		length := int(binary.BigEndian.Uint16(body[at+2:]))
		for i := at + 4; i < at+4+length; i++ {
			body[i] = 0
		}
		at += 4 + length
	}
}

func zeroECHPayload(body []byte) {
	encLen := int(binary.BigEndian.Uint16(body[6:]))
	at := 8 + encLen
	payloadLen := int(binary.BigEndian.Uint16(body[at:]))
	for i := at + 2; i < at+2+payloadLen; i++ {
		body[i] = 0
	}
}

func grease(kind uint16) bool {
	return kind&0x0f0f == 0x0a0a
}

func invariant(kind uint16) bool {
	return grease(kind) || kind == 0x0015 || kind == 0x0029
}

func kinds(id utls.ClientHelloID) []string {
	spec, err := utls.UTLSIdToSpec(id)
	if err != nil {
		panic(err)
	}
	out := make([]string, 0, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		out = append(out, fmt.Sprintf("%T", ext))
	}
	return out
}

// shuffled draws the spec twice: a preset wrapped in ShuffleChromeTLSExtensions
// almost surely reorders its middle window on the second draw, a fixed one never does.
func shuffled(id utls.ClientHelloID) bool {
	first := kinds(id)
	for i := 0; i < 4; i++ {
		next := kinds(id)
		if len(first) != len(next) {
			return true
		}
		for j := range first {
			if first[j] != next[j] {
				return true
			}
		}
	}
	return false
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
		id, ok := presets[parts[1]]
		if !ok {
			panic("unknown preset " + parts[1])
		}
		body := readHello(id)
		prefix, exts := normalize(body)
		if !shuffled(id) {
			out := append([]byte(nil), prefix...)
			for _, ext := range exts {
				out = append(out, ext.raw...)
			}
			fmt.Printf("CH %s %s\n", parts[0], hex.EncodeToString(out))
			continue
		}
		var fixed []int
		for i, ext := range exts {
			if invariant(ext.kind) {
				fixed = append(fixed, i)
			}
		}
		sort.Slice(exts, func(i, j int) bool {
			return bytes.Compare(exts[i].raw, exts[j].raw) < 0
		})
		var sorted []byte
		for _, ext := range exts {
			sorted = append(sorted, ext.raw...)
		}
		var indices []string
		for _, i := range fixed {
			indices = append(indices, fmt.Sprint(i))
		}
		fmt.Printf("SH %s %s %s %s\n", parts[0], hex.EncodeToString(sorted), strings.Join(indices, ","), hex.EncodeToString(prefix))
	}
}
