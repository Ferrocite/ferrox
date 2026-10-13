package main

import (
    "bufio"
    "encoding/hex"
    "fmt"
    "os"
    "strconv"
    "strings"

    "github.com/xtls/xray-core/common/buf"
    "github.com/xtls/xray-core/transport/internet/kcp"
)

type recorder struct{}

func (recorder) Write(seg kcp.Segment) error {
    raw := make([]byte, seg.ByteSize())
    seg.Serialize(raw)
    fmt.Printf("SEG %s\n", hex.EncodeToString(raw))
    return nil
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
        }
    }
}
