package main

import (
    "fmt"
    "net"
    "os"
    "strconv"
    "sync"
    "time"

    "github.com/xtls/xray-core/transport/internet/kcp"
)

var cfg = &kcp.Config{
    Mtu: 1350, Tti: 50, UplinkCapacity: 5, DownlinkCapacity: 20,
    CwndMultiplier: 1, MaxSendingWindow: 2 * 1024 * 1024,
}

func feed(sock *net.UDPConn, conn *kcp.Connection, mu *sync.Mutex, peer **net.UDPAddr) {
    reader := &kcp.KCPPacketReader{}
    buf := make([]byte, 65536)
    for {
        n, src, err := sock.ReadFromUDP(buf)
        if err != nil {
            return
        }
        segments := reader.Read(buf[:n])
        if len(segments) == 0 {
            continue
        }
        mu.Lock()
        if *peer == nil {
            *peer = src
        }
        mu.Unlock()
        conn.Input(segments)
    }
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func main() {
    mode := os.Args[1]
    switch mode {
    case "server":
        port, _ := strconv.Atoi(os.Args[2])
        sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
        if err != nil {
            panic(err)
        }
        var mu sync.Mutex
        var peer *net.UDPAddr
        w := writerFunc(func(p []byte) (int, error) {
            mu.Lock()
            defer mu.Unlock()
            if peer == nil {
                return 0, fmt.Errorf("no peer yet")
            }
            return sock.WriteToUDP(p, peer)
        })
        conn := kcp.NewConnection(kcp.ConnMetadata{
            LocalAddr:    sock.LocalAddr(),
            RemoteAddr:   sock.LocalAddr(),
            Conversation: 7,
        }, w, sock, cfg)
        go feed(sock, conn, &mu, &peer)
        data := make([]byte, 65536)
        for {
            n, err := conn.Read(data)
            if err != nil {
                return
            }
            conn.Write(data[:n])
        }
    case "client":
        peerAddr, err := net.ResolveUDPAddr("udp", os.Args[2])
        if err != nil {
            panic(err)
        }
        sock, err := net.DialUDP("udp", nil, peerAddr)
        if err != nil {
            panic(err)
        }
        conn := kcp.NewConnection(kcp.ConnMetadata{
            LocalAddr:    sock.LocalAddr(),
            RemoteAddr:   sock.RemoteAddr(),
            Conversation: 7,
        }, sock, sock, cfg)
        var mu sync.Mutex
        var peer *net.UDPAddr
        go feed(sock, conn, &mu, &peer)
        conn.Write([]byte(os.Args[3]))
        conn.SetReadDeadline(time.Now().Add(10 * time.Second))
        data := make([]byte, 65536)
        n, err := conn.Read(data)
        if err != nil {
            fmt.Println("ERR:", err)
            os.Exit(1)
        }
        fmt.Println("echo:", string(data[:n]))
    }
}
