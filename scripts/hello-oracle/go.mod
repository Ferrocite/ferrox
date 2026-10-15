module hellooracle

// The oracle uses only the Go standard library crypto/tls: a PattNG "unsafe" TLS
// hello is built by crypto/tls with config.CipherSuites set (xray-core parses the
// ':' list into that field), so the reference for the cipher_suites wire bytes is
// crypto/tls itself. No third-party module, so the golden is reproducible anywhere
// a Go toolchain runs.
go 1.24
