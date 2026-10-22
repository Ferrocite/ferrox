#!/usr/bin/env bash

UUID="f47ac10b-58cc-4372-a567-0e02b2c3d479"
PASSWORD="matrix-secret"
SS_PASSWORD="matrix-shadowsocks-password"

matrix_srvport() {
  python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

server_config() {
  local port="$3"
  cat <<EOF
{"inbounds": [{"tag": "matrix-server", "listen": "127.0.0.1", "port": $port, $1}],
 "outbounds": [{$2}, {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
 "routing": {"rules": [{"type": "field", "inboundTag": ["harness-socks"], "outboundTag": "proxy"}, {"type": "field", "inboundTag": ["matrix-server"], "outboundTag": "direct"}]}}
EOF
}

vless_server() {
  echo "\"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"none\"}$1"
}
vless_client() {
  echo "\"tag\": \"proxy\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $2, \"users\": [{\"id\": \"$UUID\", \"encryption\": \"none\"}]}]}$1"
}
# The TLS arm's fixture: a self-signed certificate and its key, minted into the ignored target
# tree by the harness at run time, so no private key is ever in the tree and no CA is needed in
# the runner's store. The path is absolute, because the engines do not read it the same way:
# `xray-core` resolves a relative certificate path against its own executable directory rather
# than the directory it was spawned in, so a relative path finds the file for one engine and
# not for another. On Windows the absolute path is the one Windows spells, because a Git-Bash
# path is not one a native engine can open; the pin is hashed off the minted file, so the two
# cannot drift.
matrix_tls_dir() {
  local dir="target/matrix-tls" root
  case "${OS:-}" in
    Windows_NT) root="$(pwd -W 2>/dev/null || pwd)" ;;
    *) root="$(pwd)" ;;
  esac
  dir="$root/$dir"
  if [[ ! -s "$dir/cert.pem" ]]; then
    "${bench_bin:?no harness binary to mint the fixture}" make-tls "$dir" || return 1
  fi
  echo "$dir"
}

matrix_tls_pin() {
  python3 -c 'import base64, hashlib, sys
pem = open(sys.argv[1]).read()
body = "".join(line for line in pem.splitlines() if line and not line.startswith("-----"))
print(hashlib.sha256(base64.b64decode(body)).hexdigest())' "$1"
}

# The server's TLS: the identity the client is asked to trust.
tls_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

# The client's TLS: the roots this tree reads, the pin the reference reads, and the
# verify certificate the third reference reads. Each takes the one it knows.
tls_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

stream_json() {
  case "$1" in
    tcp) echo '"streamSettings": {"network": "tcp"}' ;;
    ws) echo '"streamSettings": {"network": "ws", "wsSettings": {"path": "/tunnel"}}' ;;
    grpc) echo '"streamSettings": {"network": "grpc", "grpcSettings": {"serviceName": "TunnelService"}}' ;;
    xhttp) echo '"streamSettings": {"network": "xhttp", "xhttpSettings": {"path": "/share"}}' ;;
  esac
}

scenario_config() {
  local port="$2"
  case "$1" in
    vless-raw-*) server_config "$(vless_server ', "streamSettings": {"network": "tcp"}')" "$(vless_client ', "streamSettings": {"network": "tcp"}' "$port")" "$port" ;;
    vless-tls-raw-*) server_config "$(vless_server ", $(tls_server_settings)")" "$(vless_client ", $(tls_client_settings)" "$port")" "$port" ;;
    vless-ws-*) server_config "$(vless_server ", $(stream_json ws)")" "$(vless_client ", $(stream_json ws)" "$port")" "$port" ;;
    vless-grpc-*) server_config "$(vless_server ", $(stream_json grpc)")" "$(vless_client ", $(stream_json grpc)" "$port")" "$port" ;;
    vless-xhttp-*) server_config "$(vless_server ", $(stream_json xhttp)")" "$(vless_client ", $(stream_json xhttp)" "$port")" "$port" ;;
    vmess-raw-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, \"streamSettings\": {\"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, \"streamSettings\": {\"network\": \"tcp\"}" "$port" ;;
    trojan-raw-*) server_config "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}" "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"password\": \"$PASSWORD\"}]}" "$port" ;;
    shadowsocks-raw-*) server_config "\"protocol\": \"shadowsocks\", \"settings\": {\"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\", \"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"shadowsocks\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\"}]}" "$port" ;;
    *) echo "::error::unknown scenario $1" >&2; return 1 ;;
  esac
}

MIB=1024
KIb=$((1024 * MIB))
GIB=$((1024 * 1024))

standard_scenarios() {
  echo "vless-raw-down-1 download 1 131072 65536"
  echo "vless-raw-down-8 download 8 16384 65536"
  echo "vless-raw-up-1 upload 1 131072 65536"
  echo "vless-raw-duplex-8 full-duplex 8 8192 65536"
  echo "vless-ws-down-8 download 8 16384 65536"
  echo "vless-grpc-down-8 download 8 16384 65536"
  echo "vless-xhttp-down-8 download 8 16384 65536"
  echo "vmess-raw-down-8 download 8 16384 65536"
  echo "trojan-raw-down-8 download 8 16384 65536"
  echo "shadowsocks-raw-down-8 download 8 16384 65536"
  echo "vless-raw-setup-1k download 1 1000 8"
  echo "vless-tls-raw-down-8 download 8 16384 65536"
  echo "vless-tls-raw-up-1 upload 1 131072 65536"
  echo "vless-tls-raw-duplex-8 full-duplex 8 8192 65536"
}

scenarios() {
  case "${1:-$tier}" in
    smoke) echo "vless-raw-down-1 download 1 131072 65536" ;;
    standard) standard_scenarios ;;
    full)
      standard_scenarios
      echo "vless-raw-down-16 download 16 8192 65536"
      echo "vless-ws-down-16 download 16 8192 65536"
      echo "vless-raw-duplex-16 full-duplex 16 4096 65536"
      echo "vless-tls-raw-duplex-16 full-duplex 16 4096 65536"
      ;;
  esac
}
