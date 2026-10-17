package main

import (
    "bufio"
    "crypto/cipher"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "net"
    "os"
    "strconv"
    "strings"

    "github.com/xtls/xray-core/common/buf"
    xcrypto "github.com/xtls/xray-core/common/crypto"
    "github.com/xtls/xray-core/transport/internet/finalmask/mkcp/aes128gcm"
    "github.com/xtls/xray-core/transport/internet/finalmask/mkcp/header"
    "github.com/xtls/xray-core/transport/internet/finalmask/mkcp/original"
    "github.com/xtls/xray-core/transport/internet/kcp"
)

type recorder struct{}

func (recorder) Write(seg kcp.Segment) error {
    raw := make([]byte, seg.ByteSize())
    seg.Serialize(raw)
    fmt.Printf("SEG %s\n", hex.EncodeToString(raw))
    return nil
}

type sizer interface{ Size() int }

// mkcpConn builds one family's mask conn exactly as finalmask's loader does;
// the raw PacketConn is nil because the per-datagram ReadFrom/WriteTo paths
// under test never touch the embedded socket.
func mkcpConn(token string) net.PacketConn {
    switch {
    case token == "orig":
        c, err := original.NewConnClient(&original.Config{}, nil)
        if err != nil {
            panic(err)
        }
        return c
    case token == "srtp", token == "dtls", token == "utp", token == "wechat", token == "wireguard", strings.HasPrefix(token, "dns"):
        id, domain := int32(-1), ""
        switch token {
        case "srtp":
            id = 2
        case "dtls":
            id = 1
        case "utp":
            id = 3
        case "wechat":
            id = 4
        case "wireguard":
            id = 5
        default:
            id = 0
            domain = strings.TrimPrefix(token, "dns:")
            if domain == "dns" || domain == "" {
                domain = "-"
            }
        }
        if id == 0 {
            if domain == "-" {
                domain = "www.baidu.com"
            }
        } else {
            domain = ""
        }
        c, err := header.NewConnClient(&header.Config{ID: id, Domain: domain}, nil)
        if err != nil {
            panic(err)
        }
        return c
    case strings.HasPrefix(token, "aes:"):
        pw := strings.TrimPrefix(token, "aes:")
        c, err := aes128gcm.NewConnClient(&aes128gcm.Config{Password: pw}, nil)
        if err != nil {
            panic(err)
        }
        return c
    default:
        panic("unknown mask token " + token)
    }
}

// composeSeal replays headerManagerConn.WriteTo over the pinned conns: the
// configured list reversed once, payload copied at the gap sum, entries
// applied inner to outer. The UDPSize bound is the manager's own.
func composeSeal(tokens []string, payload []byte) []byte {
    conns := make([]net.PacketConn, 0, len(tokens))
    for i := len(tokens) - 1; i >= 0; i-- {
        conns = append(conns, mkcpConn(tokens[i]))
    }
    sizes := make([]int, len(conns))
    sum := 0
    for i, c := range conns {
        sizes[i] = c.(sizer).Size()
        sum += sizes[i]
    }
    b := make([]byte, 4096)
    n := copy(b[sum:], payload)
    for i := len(conns) - 1; i >= 0; i-- {
        n, _ = conns[i].WriteTo(b[sum-sizes[i]:n+sum], nil)
        sum -= sizes[i]
    }
    return append([]byte{}, b[:n]...)
}

// composeOpen replays headerManagerConn.ReadFrom: short datagrams and any
// entry failing its own check drop the packet.
func composeOpen(tokens []string, frame []byte) ([]byte, bool) {
    conns := make([]net.PacketConn, 0, len(tokens))
    for i := len(tokens) - 1; i >= 0; i-- {
        conns = append(conns, mkcpConn(tokens[i]))
    }
    sizes := make([]int, len(conns))
    sum := 0
    for i, c := range conns {
        sizes[i] = c.(sizer).Size()
        sum += sizes[i]
    }
    if len(frame) < sum {
        return nil, false
    }
    p := append([]byte{}, frame...)
    buf := p
    for i := range conns {
        n, _, err := conns[i].ReadFrom(buf)
        if err != nil {
            return nil, false
        }
        buf = buf[sizes[i] : n+sizes[i]]
    }
    return append([]byte{}, buf...), true
}

func hdrToken(id int, domain string) string {
    if id == 0 {
        if domain == "-" {
            return "dns"
        }
        return "dns:" + domain
    }
    names := map[int]string{1: "dtls", 2: "srtp", 3: "utp", 4: "wechat", 5: "wireguard"}
    return names[id]
}

func main() {
    f, err := os.Open(os.Args[1])
    if err != nil {
        panic(err)
    }
    defer f.Close()

    var sw *kcp.SendingWindow
    var al *kcp.AckList
    var rtt kcp.RoundTripInfo

    sc := bufio.NewScanner(f)
    for sc.Scan() {
        line := strings.TrimSpace(sc.Text())
        if line == "" || strings.HasPrefix(line, "#") {
            continue
        }
        parts := strings.Fields(line)
        switch parts[0] {
        case "sw_new":
            sw = kcp.NewSendingWindow(recorder{}, func(rate uint32) {
                fmt.Printf("loss %d\n", rate)
            })
        case "sw_push":
            p := buf.New()
            p.Write([]byte(strings.Join(parts[2:], " ")))
            n, _ := strconv.Atoi(parts[1])
            sw.Push(uint32(n), p)
        case "sw_flush":
            cur, _ := strconv.Atoi(parts[1])
            rto, _ := strconv.Atoi(parts[2])
            max, _ := strconv.Atoi(parts[3])
            sw.Flush(uint32(cur), uint32(rto), uint32(max))
        case "sw_fastack":
            n, _ := strconv.Atoi(parts[1])
            rto, _ := strconv.Atoi(parts[2])
            sw.HandleFastAck(uint32(n), uint32(rto))
        case "sw_remove":
            n, _ := strconv.Atoi(parts[1])
            fmt.Printf("removed %v\n", sw.Remove(uint32(n)))
        case "sw_clear":
            una, _ := strconv.Atoi(parts[1])
            sw.Clear(uint32(una))
        case "sw_len":
            fmt.Printf("len %d\n", sw.Len())
        case "sw_first":
            fmt.Printf("first %d\n", sw.FirstNumber())
        case "al_new":
            mss, _ := strconv.Atoi(parts[1])
            al = kcp.NewAckList(recorder{}, uint32(mss))
        case "al_add":
            n, _ := strconv.Atoi(parts[1])
            ts, _ := strconv.Atoi(parts[2])
            al.Add(uint32(n), uint32(ts))
        case "al_clear":
            una, _ := strconv.Atoi(parts[1])
            al.Clear(uint32(una))
        case "al_flush":
            cur, _ := strconv.Atoi(parts[1])
            rto, _ := strconv.Atoi(parts[2])
            al.Flush(uint32(cur), uint32(rto))
        case "rtt_update":
            rtt_a, _ := strconv.Atoi(parts[1])
            rtt_b, _ := strconv.Atoi(parts[2])
            rtt.Update(uint32(rtt_a), uint32(rtt_b))
        case "rtt_peer":
            rtt_a, _ := strconv.Atoi(parts[1])
            rtt_b, _ := strconv.Atoi(parts[2])
            rtt.UpdatePeerRTO(uint32(rtt_a), uint32(rtt_b))
        case "rtt_timeout":
            fmt.Printf("timeout %d\n", rtt.Timeout())
        case "orig_seal":
            plain, _ := hex.DecodeString(parts[1])
            var aead cipher.AEAD = original.NewSimple()
            fmt.Printf("ORIG_SEAL %s\n", hex.EncodeToString(aead.Seal(nil, nil, plain, nil)))
        case "orig_open":
            frame, _ := hex.DecodeString(parts[1])
            var aead cipher.AEAD = original.NewSimple()
            out, err := aead.Open(nil, nil, frame, nil)
            if err != nil {
                fmt.Println("ORIG_OPEN err")
            } else {
                fmt.Printf("ORIG_OPEN %s\n", hex.EncodeToString(out))
            }
        case "hdr_size":
            id, _ := strconv.Atoi(parts[1])
            c := mkcpConn(hdrToken(id, parts[2]))
            fmt.Printf("HDR_SIZE %d\n", c.(sizer).Size())
        case "hdr_frame":
            id, _ := strconv.Atoi(parts[1])
            count, _ := strconv.Atoi(parts[4])
            payload, _ := hex.DecodeString(parts[3])
            c := mkcpConn(hdrToken(id, parts[2]))
            size := c.(sizer).Size()
            for i := 0; i < count; i++ {
                p := make([]byte, size+len(payload))
                copy(p[size:], payload)
                c.WriteTo(p, nil)
                out := hex.EncodeToString(p)
                if id == 0 {
                    out = "????" + out[4:] // the transaction id is random per datagram
                }
                fmt.Printf("HDR_FRAME %d %s\n", i, out)
            }
        case "aes_size":
            c := mkcpConn("aes:" + parts[1])
            fmt.Printf("AES_SIZE %d\n", c.(sizer).Size())
        case "aes_fixed":
            // The pinned derivation with a fixed nonce: SHA256(password)[0..16]
            // through the same crypto.NewAesGcm the package builds its AEAD
            // with, framing nonce || ct || tag.
            hash := sha256.Sum256([]byte(parts[1]))
            nonce, _ := hex.DecodeString(parts[2])
            plain, _ := hex.DecodeString(parts[3])
            aead := xcrypto.NewAesGcm(hash[:16])
            wire := append([]byte{}, nonce...)
            wire = aead.Seal(wire, nonce, plain, nil)
            fmt.Printf("AES_WIRE %s\n", hex.EncodeToString(wire))
        case "aes_open":
            frame, _ := hex.DecodeString(parts[2])
            c := mkcpConn("aes:" + parts[1])
            p := append([]byte{}, frame...)
            n, _, err := c.ReadFrom(p)
            if err != nil {
                fmt.Println("AES_OPEN err")
            } else {
                // The conn decrypts in place and leaves the plaintext right
                // where the nonce ended; the manager slices [12 : 12+n].
                fmt.Printf("AES_OPEN %s\n", hex.EncodeToString(p[12:12+n]))
            }
        case "compose_seal":
            payload, _ := hex.DecodeString(parts[2])
            fmt.Printf("COMPOSE %s\n", hex.EncodeToString(composeSeal(strings.Split(parts[1], ","), payload)))
        case "compose_open":
            frame, _ := hex.DecodeString(parts[2])
            out, ok := composeOpen(strings.Split(parts[1], ","), frame)
            if !ok {
                fmt.Println("COMPOSE_OPEN err")
            } else {
                fmt.Printf("COMPOSE_OPEN %s\n", hex.EncodeToString(out))
            }
        }
    }
}
