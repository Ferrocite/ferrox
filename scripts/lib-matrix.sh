#!/usr/bin/env bash

UUID="f47ac10b-58cc-4372-a567-0e02b2c3d479"
PASSWORD="matrix-secret"
SS_PASSWORD="matrix-shadowsocks-password"
SS2022_PASSWORD="MDEyMzQ1Njc4OUFCQ0RFRg=="
HYSTERIA_AUTH="matrix-hysteria-auth"

matrix_srvport() {
  python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

matrix_udp_srvport() {
  python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

matrix_udp_carrier() {
  case "$1" in
    *-kcp-*|*-hysteria-*) return 0 ;;
    *) return 1 ;;
  esac
}

server_config() {
  local port="$3" cover="${4:-}"
  local extra=""
  local routes="{\"type\": \"field\", \"inboundTag\": [\"matrix-server\"], \"outboundTag\": \"direct\"}"
  if [[ -n "$cover" ]]; then
    extra=", $cover"
    routes="$routes, {\"type\": \"field\", \"inboundTag\": [\"matrix-cover\"], \"outboundTag\": \"direct\"}"
  fi
  cat <<EOF
{"inbounds": [{"tag": "matrix-server", "listen": "127.0.0.1", "port": $port, $1}$extra],
 "outbounds": [{$2}, {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
 "routing": {"rules": [{"type": "field", "inboundTag": ["harness-socks"], "outboundTag": "proxy"}, $routes]}}
EOF
}

# REALITY's server dials `dest` for the certificate it presents, so the fixture gives it a live
# TLS inbound in the same process instead of a public endpoint the runner would have to reach.
cover_inbound() {
  local port="$1" dir
  dir="$(matrix_tls_dir)"
  echo "{\"tag\": \"matrix-cover\", \"listen\": \"127.0.0.1\", \"port\": $port, \"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"none\"}, \"streamSettings\": {\"network\": \"tcp\", \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}}"
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

matrix_reality_dir() {
  local dir="target/matrix-reality" root
  case "${OS:-}" in
    Windows_NT) root="$(pwd -W 2>/dev/null || pwd)" ;;
    *) root="$(pwd)" ;;
  esac
  dir="$root/$dir"
  mkdir -p "$dir"
  if [[ ! -s "$dir/keys.txt" ]]; then
    "${ferrox_bin:?no ferrox binary to mint the reality keypair}" x25519 >"$dir/keys.txt" || return 1
  fi
  echo "$dir"
}

matrix_reality_private() {
  sed -n 's/^PrivateKey: //p' "$(matrix_reality_dir)/keys.txt"
}

matrix_reality_public() {
  sed -n 's/^Password (PublicKey): //p' "$(matrix_reality_dir)/keys.txt"
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

# The TLS arm of a carried lane: the same identity the tcp arm uses, under the carrier's framing.
tls_ws_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"ws\", \"security\": \"tls\", \"wsSettings\": {\"path\": \"/tunnel\"}, \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

tls_ws_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"ws\", \"security\": \"tls\", \"wsSettings\": {\"path\": \"/tunnel\"}, \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

tls_grpc_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"grpc\", \"grpcSettings\": {\"serviceName\": \"TunnelService\"}, \"security\": \"tls\", \"tlsSettings\": {\"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

tls_grpc_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"grpc\", \"grpcSettings\": {\"serviceName\": \"TunnelService\"}, \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

reality_server_settings() {
  local network="$1" carrier="$2"
  echo "\"streamSettings\": {\"network\": \"$network\"$carrier, \"security\": \"reality\", \"realitySettings\": {\"dest\": \"${MATRIX_REALITY_DEST:-127.0.0.1:9}\", \"serverNames\": [\"carrier.test\"], \"privateKey\": \"$(matrix_reality_private)\", \"shortIds\": [\"0123456789abcdef\"]}}"
}

reality_client_settings() {
  local network="$1" carrier="$2"
  echo "\"streamSettings\": {\"network\": \"$network\"$carrier, \"security\": \"reality\", \"realitySettings\": {\"serverName\": \"carrier.test\", \"fingerprint\": \"chrome\", \"publicKey\": \"$(matrix_reality_public)\", \"shortId\": \"0123456789abcdef\"}}"
}

kcp_settings() {
  echo '"streamSettings": {"network": "kcp", "kcpSettings": {"mtu": 1350, "tti": 50, "uplinkCapacity": 5, "downlinkCapacity": 20, "congestion": false, "readBufferSize": 2, "writeBufferSize": 2, "header": {"type": "none"}, "seed": "matrix"}}'
}

httpupgrade_settings() {
  echo '"streamSettings": {"network": "httpupgrade", "httpupgradeSettings": {"path": "/tunnel", "host": "carrier.test"}}'
}

hysteria_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"hysteria\", \"hysteriaSettings\": {\"version\": 2, \"auth\": \"$HYSTERIA_AUTH\"}, \"security\": \"tls\", \"tlsSettings\": {\"alpn\": [\"h3\"], \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

hysteria_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"hysteria\", \"hysteriaSettings\": {\"version\": 2, \"auth\": \"$HYSTERIA_AUTH\"}, \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"h3\"], \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
}

vless_server_vision() {
  echo "\"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\", \"flow\": \"xtls-rprx-vision\"}], \"decryption\": \"none\"}$1"
}

vless_client_vision() {
  echo "\"tag\": \"proxy\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $2, \"users\": [{\"id\": \"$UUID\", \"encryption\": \"none\", \"flow\": \"xtls-rprx-vision\"}]}]}$1"
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
  local port="$2" cover="${3:-}" cover_json=""
  if [[ -n "$cover" ]]; then cover_json="$(cover_inbound "$cover")"; fi
  case "$1" in
    vless-raw-*) server_config "$(vless_server ', "streamSettings": {"network": "tcp"}')" "$(vless_client ', "streamSettings": {"network": "tcp"}' "$port")" "$port" ;;
    vless-tls-raw-*) server_config "$(vless_server ", $(tls_server_settings)")" "$(vless_client ", $(tls_client_settings)" "$port")" "$port" ;;
    vless-ws-*) server_config "$(vless_server ", $(stream_json ws)")" "$(vless_client ", $(stream_json ws)" "$port")" "$port" ;;
    vless-grpc-*) server_config "$(vless_server ", $(stream_json grpc)")" "$(vless_client ", $(stream_json grpc)" "$port")" "$port" ;;
    vless-xhttp-*) server_config "$(vless_server ", $(stream_json xhttp)")" "$(vless_client ", $(stream_json xhttp)" "$port")" "$port" ;;
    vmess-raw-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, \"streamSettings\": {\"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, \"streamSettings\": {\"network\": \"tcp\"}" "$port" ;;
    trojan-raw-*) server_config "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}" "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"password\": \"$PASSWORD\"}]}" "$port" ;;
    trojan-tls-raw-*) server_config "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}, $(tls_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"password\": \"$PASSWORD\"}]}, $(tls_client_settings)" "$port" ;;
    vless-tls-ws-*) server_config "$(vless_server ", $(tls_ws_server_settings)")" "$(vless_client ", $(tls_ws_client_settings)" "$port")" "$port" ;;
    shadowsocks-raw-*) server_config "\"protocol\": \"shadowsocks\", \"settings\": {\"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\", \"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"shadowsocks\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"method\": \"aes-256-gcm\", \"password\": \"$SS_PASSWORD\"}]}" "$port" ;;
    shadowsocks2022-raw-*) server_config "\"protocol\": \"shadowsocks\", \"settings\": {\"method\": \"2022-blake3-aes-128-gcm\", \"password\": \"$SS2022_PASSWORD\", \"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"shadowsocks\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"method\": \"2022-blake3-aes-128-gcm\", \"password\": \"$SS2022_PASSWORD\"}]}" "$port" ;;
    vless-httpupgrade-*) server_config "$(vless_server ", $(httpupgrade_settings)")" "$(vless_client ", $(httpupgrade_settings)" "$port")" "$port" ;;
    vless-tls-grpc-*) server_config "$(vless_server ", $(tls_grpc_server_settings)")" "$(vless_client ", $(tls_grpc_client_settings)" "$port")" "$port" ;;
    vless-reality-raw-*) server_config "$(vless_server ", $(reality_server_settings tcp "")")" "$(vless_client ", $(reality_client_settings tcp "")" "$port")" "$port" "$cover_json" ;;
    vless-reality-grpc-*) server_config "$(vless_server ", $(reality_server_settings grpc ', "grpcSettings": {"serviceName": "TunnelService"}')")" "$(vless_client ", $(reality_client_settings grpc ', "grpcSettings": {"serviceName": "TunnelService"}')" "$port")" "$port" "$cover_json" ;;
    vless-reality-xhttp-*) server_config "$(vless_server ", $(reality_server_settings xhttp ', "xhttpSettings": {"path": "/share"}')")" "$(vless_client ", $(reality_client_settings xhttp ', "xhttpSettings": {"path": "/share"}')" "$port")" "$port" "$cover_json" ;;
    vless-vision-tls-raw-*) server_config "$(vless_server_vision ", $(tls_server_settings)")" "$(vless_client_vision ", $(tls_client_settings)" "$port")" "$port" ;;
    vless-vision-reality-raw-*) server_config "$(vless_server_vision ", $(reality_server_settings tcp "")")" "$(vless_client_vision ", $(reality_client_settings tcp "")" "$port")" "$port" "$cover_json" ;;
    vless-kcp-*) server_config "$(vless_server ", $(kcp_settings)")" "$(vless_client ", $(kcp_settings)" "$port")" "$port" ;;
    vless-hysteria-*) server_config "$(vless_server ", $(hysteria_server_settings)")" "$(vless_client ", $(hysteria_client_settings)" "$port")" "$port" ;;
    vmess-tls-ws-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, $(tls_ws_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, $(tls_ws_client_settings)" "$port" ;;
    trojan-tls-ws-*) server_config "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}, $(tls_ws_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"password\": \"$PASSWORD\"}]}, $(tls_ws_client_settings)" "$port" ;;
    *) echo "::error::unknown scenario $1" >&2; return 1 ;;
  esac
}

MIB=1024
KIb=$((1024 * MIB))
GIB=$((1024 * 1024))

standard_scenarios() {
  echo "vless-raw-down-1 download 1 2048 65536"
  echo "vless-raw-down-8 download 8 256 65536"
  echo "vless-raw-up-1 upload 1 2048 65536"
  echo "vless-raw-duplex-8 full-duplex 8 128 65536"
  echo "vless-ws-down-8 download 8 256 65536"
  echo "vless-grpc-down-8 download 8 256 65536"
  echo "vless-xhttp-down-8 download 8 256 65536"
  echo "vmess-raw-down-8 download 8 256 65536"
  echo "trojan-raw-down-8 download 8 256 65536"
  echo "shadowsocks-raw-down-8 download 8 256 65536"
  echo "vless-raw-setup-1k download 1 1000 8"
  echo "vless-tls-raw-down-8 download 8 256 65536"
  echo "vless-tls-raw-up-1 upload 1 2048 65536"
  echo "vless-tls-raw-duplex-8 full-duplex 8 128 65536"
  echo "vless-tls-ws-down-8 download 8 256 65536"
  echo "trojan-tls-raw-down-8 download 8 256 65536"
  echo "vless-httpupgrade-down-8 download 8 256 65536"
  echo "vless-tls-grpc-down-8 download 8 256 65536"
  echo "vless-reality-raw-down-8 download 8 256 65536"
  echo "vless-reality-grpc-down-8 download 8 256 65536"
  echo "vless-reality-xhttp-down-8 download 8 256 65536"
  echo "vless-vision-tls-raw-down-8 download 8 256 65536"
  echo "vless-vision-reality-raw-down-8 download 8 256 65536"
  echo "vless-kcp-down-8 download 8 256 65536"
  echo "vless-hysteria-down-8 download 8 256 65536"
  echo "shadowsocks2022-raw-down-8 download 8 256 65536"
  echo "vmess-tls-ws-down-8 download 8 256 65536"
  echo "trojan-tls-ws-down-8 download 8 256 65536"
}

scenarios() {
  case "${1:-$tier}" in
    smoke) echo "vless-raw-down-1 download 1 2048 65536" ;;
    standard) standard_scenarios ;;
    full)
      standard_scenarios
      echo "vless-raw-down-16 download 16 128 65536"
      echo "vless-ws-down-16 download 16 128 65536"
      echo "vless-raw-duplex-16 full-duplex 16 64 65536"
      echo "vless-tls-raw-duplex-16 full-duplex 16 64 65536"
      ;;
  esac
}
