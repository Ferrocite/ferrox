// tls12-oracle dumps, per TLS 1.2 cipher suite, the exact byte stream Go's own
// crypto/tls — the record layer uTLS runs — puts on the wire: the plaintext
// handshake, the ChangeCipherSpec, the encrypted Finished and one application
// record each way with known payloads, plus that session's master secret from
// the key log.
//
// The shaped client is gated by opening the capture. Its key block, the PRF's
// per-suite hash, the CBC record's MAC, padding and explicit IV and the
// static-RSA key transport all have to agree with Go for these bytes to decrypt,
// verify and re-seal. `rsa.EncryptPKCS1v15` with a pad reader that never yields
// a zero byte is deterministic, so the RSA encryption gets a byte gate too.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// The CBC and static-RSA suites Go implements, each with the certificate its own
// key agreement needs.
var suites = []struct {
	id  uint16
	rsa bool
}{
	{0xc009, false}, // ECDHE-ECDSA-AES128-CBC-SHA
	{0xc00a, false}, // ECDHE-ECDSA-AES256-CBC-SHA
	{0xc023, false}, // ECDHE-ECDSA-AES128-CBC-SHA256
	{0xc013, true},  // ECDHE-RSA-AES128-CBC-SHA
	{0xc014, true},  // ECDHE-RSA-AES256-CBC-SHA
	{0xc027, true},  // ECDHE-RSA-AES128-CBC-SHA256
	{0x002f, true},  // RSA-AES128-CBC-SHA
	{0x0035, true},  // RSA-AES256-CBC-SHA
	{0x003c, true},  // RSA-AES128-CBC-SHA256
	{0x009c, true},  // RSA-AES128-GCM-SHA256
	{0x009d, true},  // RSA-AES256-GCM-SHA384
	{0x000a, true},  // RSA-3DES-EDE-CBC-SHA
	{0xc012, true},  // ECDHE-RSA-3DES-EDE-CBC-SHA
}

const (
	clientPayload = "ferrox-c2s"
	serverPayload = "ferrox-s2c-payload"
)

// tee keeps every byte that crosses one TCP connection, in both directions.
type tee struct {
	net.Conn
	in  bytes.Buffer // client to server
	out bytes.Buffer // server to client
}

func (t *tee) Read(b []byte) (int, error) {
	n, err := t.Conn.Read(b)
	t.in.Write(b[:n])
	return n, err
}

func (t *tee) Write(b []byte) (int, error) {
	n, err := t.Conn.Write(b)
	t.out.Write(b[:n])
	return n, err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	rsaCert, err := selfSigned(true)
	if err != nil {
		return err
	}
	ecdsaCert, err := selfSigned(false)
	if err != nil {
		return err
	}
	for _, s := range suites {
		cert := ecdsaCert
		if s.rsa {
			cert = rsaCert
		}
		if err := capture(s.id, cert); err != nil {
			return fmt.Errorf("suite %#04x: %w", s.id, err)
		}
	}
	return rsaVectors()
}

// capture runs one Go-to-Go TLS 1.2 session over loopback and prints the bytes
// the record layer wrote, both ways, with the master secret the key log saw.
func capture(suite uint16, cert tls.Certificate) error {
	keyLog := &lineCollector{}
	conf := func() *tls.Config {
		return &tls.Config{
			CipherSuites: []uint16{suite},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			KeyLogWriter: keyLog,
		}
	}
	serverConf := conf()
	serverConf.Certificates = []tls.Certificate{cert}
	clientConf := conf()
	clientConf.InsecureSkipVerify = true
	clientConf.ServerName = "example.com"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()

	type leg struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan leg, 1)
	go func() {
		conn, err := ln.Accept()
		accepted <- leg{conn, err}
	}()

	dialled, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return err
	}
	clientConn := <-accepted
	if clientConn.err != nil {
		return clientConn.err
	}
	for _, conn := range []net.Conn{dialled, clientConn.conn} {
		if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return err
		}
	}
	shared := &tee{Conn: clientConn.conn}
	server := tls.Server(shared, serverConf)
	client := tls.Client(dialled, clientConf)

	// Both flights have to be in motion at once: a client that waits for the
	// ServerKeyExchange while the server waits for the ClientKeyExchange parks
	// the pair, so the server leg reads and answers from its own goroutine.
	done := make(chan error, 1)
	go func() {
		if err := server.Handshake(); err != nil {
			done <- err
			return
		}
		got := make([]byte, len(clientPayload))
		if _, err := io.ReadFull(server, got); err != nil {
			done <- err
			return
		}
		if string(got) != clientPayload {
			done <- fmt.Errorf("server saw %q", got)
			return
		}
		_, err := server.Write([]byte(serverPayload))
		done <- err
	}()

	if err := client.Handshake(); err != nil {
		return err
	}
	if _, err := client.Write([]byte(clientPayload)); err != nil {
		return err
	}
	back := make([]byte, len(serverPayload))
	if _, err := io.ReadFull(client, back); err != nil {
		return err
	}
	if err := <-done; err != nil {
		return err
	}
	if string(back) != serverPayload {
		return fmt.Errorf("client saw %q", back)
	}
	_ = client.Close()
	_ = server.Close()

	master := keyLog.master()
	if master == "" {
		return fmt.Errorf("no CLIENT_RANDOM line in the key log")
	}
	fmt.Printf("KEY %04x %s\n", suite, master)
	fmt.Printf("C2S %04x %s\n", suite, hex.EncodeToString(shared.in.Bytes()))
	fmt.Printf("S2C %04x %s\n", suite, hex.EncodeToString(shared.out.Bytes()))
	return nil
}

// lineCollector keeps the key log's master-secret line. Both legs of the session
// write their own line to the same writer, so the slices live behind a lock.
type lineCollector struct {
	mu    sync.Mutex
	lines []string
}

func (c *lineCollector) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range bytes.Split(p, []byte("\n")) {
		if len(line) > 0 {
			c.lines = append(c.lines, string(line))
		}
	}
	return len(p), nil
}

func (c *lineCollector) master() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, line := range c.lines {
		fields := bytes.Fields([]byte(line))
		if len(fields) == 3 && string(fields[0]) == "CLIENT_RANDOM" {
			return string(fields[2])
		}
	}
	return ""
}

// selfSigned mints the one-day certificate the handshake needs, RSA for the
// static-RSA suites and ECDSA for the signing ones.
func selfSigned(withRSA bool) (tls.Certificate, error) {
	var key any
	var err error
	if withRSA {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(0x4e524f58),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(key), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func publicKey(key any) any {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	}
	return nil
}

// repeatRead yields one byte forever, so the padding is the same run whatever
// number of bytes the encryptor consumes — crypto/rsa reads one byte from the
// reader up front to defeat a leaking reader, and a fixed-size buffer would make
// that optional read decide where the padding starts.
type repeatReader struct {
	b byte
}

func (r *repeatReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = r.b
	}
	return len(p), nil
}

// rsaVectors prints two kinds of gate for the static-RSA key transport.
//
// `RSA` is crypto/rsa's own PKCS#1 v1.5 ciphertext for a 48-byte premaster with an
// all-nonzero padding, so the padding length, the separator and the modular
// exponentiation are one deterministic output; the same private key decrypts it
// back, which proves the padding is well-formed and not just a string of bytes.
//
// `MODEXP` is the same message encoded by hand as `0x00 || 0x02 || PS || 0x00 || M`
// raised to several public exponents by Go's bignum, because a generated key's
// private exponent only inverts the exponent it was made for. The e=65537 row is
// asserted to equal the `RSA` row above it, so the hand-built encoding is witnessed
// to be the one crypto/rsa used, and the small exponents gate the exponent path
// that a real leaf's SPKI carries.
func rsaVectors() error {
	msg := make([]byte, 48)
	copy(msg, []byte{0x03, 0x03})
	for i := 2; i < len(msg); i++ {
		msg[i] = byte(i + 1)
	}
	for _, bits := range []int{1024, 2048, 3072, 4096} {
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return fmt.Errorf("%d-bit key: %w", bits, err)
		}
		k := key.Size()
		ct, err := rsa.EncryptPKCS1v15(&repeatReader{0x11}, &key.PublicKey, msg)
		if err != nil {
			return fmt.Errorf("%d-bit encrypt: %w", bits, err)
		}
		back, err := rsa.DecryptPKCS1v15(nil, key, ct)
		if err != nil || !bytes.Equal(back, msg) {
			return fmt.Errorf("%d-bit round trip: %v", bits, err)
		}
		nhex := hex.EncodeToString(key.N.Bytes())
		fmt.Printf("RSA %s 65537 %s %s\n", nhex, hex.EncodeToString(msg), hex.EncodeToString(ct))

		em := make([]byte, k)
		em[1] = 2
		for i := 2; i < k-len(msg)-1; i++ {
			em[i] = 0x11
		}
		copy(em[k-len(msg):], msg)
		m := new(big.Int).SetBytes(em)
		for _, e := range []int{65537, 3, 5, 17} {
			c := new(big.Int).Exp(m, big.NewInt(int64(e)), key.N)
			row := c.Bytes()
			if len(row) < k {
				row = append(make([]byte, k-len(row)), row...)
			}
			if e == 65537 && !bytes.Equal(row, ct) {
				return fmt.Errorf("%d-bit: the hand-built encoding is not the one crypto/rsa used", bits)
			}
			fmt.Printf("MODEXP %s %d %s %s\n", nhex, e, hex.EncodeToString(em), hex.EncodeToString(row))
		}
	}
	return nil
}
