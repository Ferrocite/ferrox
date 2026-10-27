#!/usr/bin/env bash

UUID="f47ac10b-58cc-4372-a567-0e02b2c3d479"
PASSWORD="matrix-secret"
SS_PASSWORD="matrix-shadowsocks-password"
SS2022_PASSWORD="MDEyMzQ1Njc4OUFCQ0RFRg=="
HYSTERIA_AUTH="matrix-hysteria-auth"
HYSTERIA_V1_OBFS="matrix-hysteria-v1-xplus"
VLESS_ENC_CLIENT="mlkem768x25519plus.native.1rtt.2KpP3KYKjxF9Rew2c-oAq0YdFawg9Lhc6yzMrSWfZcAzN8O2MrVQEHCAKfOVdCyDAvIEI-gcswjOvDCsZcTPiFITitJt1SGrYsjF4pc_7cua3CNgZ5qUBrZEKRGvcQkdpYswh2ozDxApJParJXa8s-h9YeEWRKG8aGhwQhBq5RVIepsFaAa2SDQA7YUn2rBWKFmJc9gngJQfDftticxhWPC0h9BMgBxx5tiU46tNu1ifyjaWOcVoIwtxfFCSv-p2btNHJJeBOAdQ61dC46qdO2CzujO4clRz0TrB2tliQBi0BKVG8mgYtxZFOGoDtre3sTYO6CS5xExmcOp9zUrHBeoFo5quBZFr5nZ84pQ0NrYBigwemDFE0htQM1YHCFESm1eY_sWSfRGkCLC2KqVXh0cClKjIF2Fazgaoy6qACttDccd0YVtVzFgyNAi1tKXKjNMhgZIyx5e_QmhjJcdDCOS0tzE-ecJRggZ31XzLlPVCeeiuliwJ_UzOWXHOJ0wYiwwtiZhQYIwF7GqHBmF6hrqbSLm0Pau5wLKSUdc3OgjGxWMs34okmnoIvTWoA1Am-IKxCISsCdy-iqFghasCdruLb7luKgMT7soJ95NY0LQOn4FSonEZPKIP_rBvmKJJWyOtl6qThFNzfYBQD2pTM4aXZKrOrYB7kbI_CPqM9dE740IM-suSyoEBCSi8NCB6feoMw5PNdTRDhnyuFPjKL3o_61gMjJwsW8Vq3CKMVByMJXq8QqCmQlyRXxhFVTcNdAYOeePA_JczfWIOGzCIc5wuuAHFxzfAfpWMtlEe3BMxYySXEBTG8meB7nYULth9XorFvYyM7giO4_h7YGqZEfe5hDxnAUpN00nLEwaWNfhaq9x4p7KkCEG6xIFzBhN__7OJUTgARjCagHAxBgSWDCY8qqHI4ZYpzxTI8qkPvTRZBylJZkOhGKdI_XCb9ulTy0cpeeAIF2Fw_UF7RKQ7IrnF1Ycza7MFQzd1i6wPE8fDgBFE1Jgfi_Fg8UsZtSS_q_xnV-pqOPAkDcK9MDt7obIejfHPaKTBZfa-_kp-67l_TRaudHCWoDQ4mtaZcTRo8kNX4BZ1ibUqytYU-IucCfnG32iOlVxCSzA_2CiQqvgiApu3KfiqekBM2YoaIoDEFzmwJVlsSvMDufCf3mo43YhkQFdEHxFLkpgS4WcGPCK59PuM8lNzlDXCvkeNY2lwN8yv7sI06YCz31Q38gqNjsmrBPRYTOQ550Ag8UoTE5dZUOUfhMMaomIYOnA2zUpU_tWy-Vq-F8AL8vVyjEtJRunGY-Q1D9qIaCI1YHmiKQLACiOwR6RDu-Ok0SmtCKeI9iNfqYgbnYyXP2VVIGcpw7uIwVeW_bVMnYqZIgzL4_kMQqGwmGImusoHKvNhRVc6wrkzCdhbXpmAK0nIhtSde4Q9JYqrTVmQBGRLLEc9tAK8-4ydcvJJ3PWCablnEASktKvInUh3g0xQ2teRoqC_fXCi--E0VySRQ7CGWmA8RxNJmvA2WakGplG5QhoK8hSNiIgXmXph_MQO6M34HQtfqyHVqeItfyOmgns747xGrPs"
VLESS_ENC_SERVER="mlkem768x25519plus.native.600.7SIPAtLwXE0BAcgnUkP8ERcxxHc0NMa-7GE0fcqjc4b8ckDaZ2WEGg7FvAbJs_0ovWXWLWz4CYwjGoqT9TaiMw"

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
    *-kcp-*|*-hysteria-*|*-quic-*|hysteria-*|masque-*) return 0 ;;
    *) return 1 ;;
  esac
}

matrix_server_serves() {
  case "$1:$2" in
    xray-core:hysteria-v1-*) return 1 ;;
    sing-box:hysteria-v1-*) return 0 ;;
    xray-core:*-quic-*) return 1 ;;
    sing-box:*-quic-*) return 0 ;;
    sing-box:*) return 1 ;;
  esac
  return 0
}

# A pair can carry a scenario's transport and still not interoperate at its pins. Name that
# here rather than letting the cell fail as a workload fault: the reason reaches the bundle's
# skipped list, so a reader sees which side is behind instead of a zero.
matrix_engine_skip_reason() {
  local engine="$1" id="$2"
  if [[ "$engine" == "leaf" && "$id" == vless-* && "$id" != *-vision-* ]]; then
    printf '%s\n' "leaf at this pin only sends VLESS with the Vision flow, which this scenario does not configure"
    return 0
  fi
  case "$engine:$id" in
    sing-box:*-xhttp-*|sing-box:*-kcp-*)
      printf '%s\n' "sing-box at this pin has no xhttp or KCP transport" ;;
    sing-box:*-hysteria-*)
      printf '%s\n' "sing-box at this pin has no VLESS over Hysteria transport" ;;
    sing-box:*-encryption-*)
      printf '%s\n' "sing-box at this pin has no VLESS encryption field" ;;
    xray-core:*-quic-*)
      printf '%s\n' "xray-core at this pin removed the QUIC transport; xhttp stream-one h3 replaces it" ;;
    xray-rust:*-quic-*)
      printf '%s\n' "xray-rust at this pin removed the QUIC transport" ;;
    zeronet:*-quic-*)
      printf '%s\n' "zeronet at this pin has no VLESS over QUIC transport" ;;
    leaf:*-xhttp-*)
      printf '%s\n' "leaf at this pin has no xhttp transport" ;;
    leaf:*-kcp-*)
      printf '%s\n' "leaf at this pin has no KCP transport" ;;
    leaf:*-hysteria-*|leaf:hysteria-v1-*)
      printf '%s\n' "leaf at this pin has no Hysteria transport" ;;
    leaf:*-encryption-*)
      printf '%s\n' "leaf at this pin has no VLESS encryption" ;;
    leaf:*-grpc-*)
      printf '%s\n' "leaf at this pin has no gRPC transport" ;;
    leaf:*-httpupgrade-*)
      printf '%s\n' "leaf at this pin has no HTTPUpgrade transport" ;;
    leaf:shadowsocks2022-*)
      printf '%s\n' "leaf at this pin has no Shadowsocks 2022" ;;
    xray-rust:*-hysteria-*)
      printf '%s\n' "xray-rust at this pin has no VLESS over Hysteria; its Hysteria outbound is the native proxy protocol" ;;
    xray-core-rust:masque-*|zeronet:masque-*|sing-box:masque-*|xray-rust:masque-*|leaf:masque-*)
      printf '%s\n' "$engine at this pin has no MASQUE CONNECT-IP outbound" ;;
    *)
      return 1 ;;
  esac
  return 0
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
vless_server_encryption() {
  echo "\"protocol\": \"vless\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}], \"decryption\": \"$VLESS_ENC_SERVER\"}$1"
}
vless_client_encryption() {
  echo "\"tag\": \"proxy\", \"protocol\": \"vless\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $2, \"users\": [{\"id\": \"$UUID\", \"encryption\": \"$VLESS_ENC_CLIENT\"}]}]}$1"
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

# QUIC is TLS by definition, and the ALPN is the one every pin reads: h3. xray-core-rust
# otherwise defaults its TLS to h2/http1.1, which a h3-only lane refuses.
quic_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"streamSettings\": {\"network\": \"quic\", \"security\": \"tls\", \"tlsSettings\": {\"alpn\": [\"h3\"], \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}, \"quicSettings\": {}}"
}

quic_client_settings() {
  local dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"streamSettings\": {\"network\": \"quic\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"h3\"], \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}, \"quicSettings\": {}}"
}

# MASQUE CONNECT-IP is TLS by definition; the h3 ALPN names the carrier this cell measures.
masque_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"protocol\": \"masque\", \"settings\": {\"users\": [{\"email\": \"matrix@carrier.test\", \"pass\": \"$PASSWORD\"}], \"address\": [\"10.13.0.1/24\", \"fd13::1/64\"]}, \"streamSettings\": {\"network\": \"masque\", \"security\": \"tls\", \"tlsSettings\": {\"alpn\": [\"h3\"], \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

masque_client_settings() {
  local port="$1" dir pin
  dir="$(matrix_tls_dir)"
  pin="$(matrix_tls_pin "$dir/cert.pem")"
  echo "\"tag\": \"proxy\", \"protocol\": \"masque\", \"settings\": {\"address\": \"127.0.0.1\", \"port\": $port}, \"streamSettings\": {\"network\": \"masque\", \"security\": \"tls\", \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"h3\"], \"caCertFile\": \"$dir/cert.pem\", \"pinnedPeerCertSha256\": \"$pin\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"usage\": \"verify\"}]}}"
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

hysteria_v1_server_settings() {
  local dir
  dir="$(matrix_tls_dir)"
  echo "\"protocol\": \"hysteria\", \"settings\": {\"version\": 1, \"users\": [{\"auth\": \"$HYSTERIA_AUTH\"}]}, \"streamSettings\": {\"network\": \"hysteria\", \"security\": \"tls\", \"tlsSettings\": {\"alpn\": [\"hysteria\"], \"obfs\": \"$HYSTERIA_V1_OBFS\", \"certificates\": [{\"certificateFile\": \"$dir/cert.pem\", \"keyFile\": \"$dir/key.pem\"}]}}"
}

hysteria_v1_client_settings() {
  local dir port="$1"
  dir="$(matrix_tls_dir)"
  echo "\"tag\": \"proxy\", \"protocol\": \"hysteria\", \"settings\": {\"version\": 1, \"address\": \"127.0.0.1\", \"port\": $port, \"auth\": \"$HYSTERIA_AUTH\"}, \"streamSettings\": {\"network\": \"hysteria\", \"security\": \"tls\", \"hysteriaSettings\": {\"version\": 1, \"auth\": \"$HYSTERIA_AUTH\"}, \"tlsSettings\": {\"serverName\": \"carrier.test\", \"alpn\": [\"hysteria\"], \"caCertFile\": \"$dir/cert.pem\", \"obfs\": \"$HYSTERIA_V1_OBFS\"}}"
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
    vless-encryption-raw-*) server_config "$(vless_server_encryption ', "streamSettings": {"network": "tcp"}')" "$(vless_client_encryption ', "streamSettings": {"network": "tcp"}' "$port")" "$port" ;;
    vless-encryption-tls-raw-*) server_config "$(vless_server_encryption ", $(tls_server_settings)")" "$(vless_client_encryption ", $(tls_client_settings)" "$port")" "$port" ;;
    vless-encryption-reality-raw-*) server_config "$(vless_server_encryption ", $(reality_server_settings tcp "")")" "$(vless_client_encryption ", $(reality_client_settings tcp "")" "$port")" "$port" "$cover_json" ;;
    vless-tls-raw-*) server_config "$(vless_server ", $(tls_server_settings)")" "$(vless_client ", $(tls_client_settings)" "$port")" "$port" ;;
    vless-ws-*) server_config "$(vless_server ", $(stream_json ws)")" "$(vless_client ", $(stream_json ws)" "$port")" "$port" ;;
    vless-grpc-*) server_config "$(vless_server ", $(stream_json grpc)")" "$(vless_client ", $(stream_json grpc)" "$port")" "$port" ;;
    vless-xhttp-*) server_config "$(vless_server ", $(stream_json xhttp)")" "$(vless_client ", $(stream_json xhttp)" "$port")" "$port" ;;
    vmess-raw-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, \"streamSettings\": {\"network\": \"tcp\"}" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, \"streamSettings\": {\"network\": \"tcp\"}" "$port" ;;
    vmess-tls-raw-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, $(tls_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, $(tls_client_settings)" "$port" ;;
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
    vless-quic-*) server_config "$(vless_server ", $(quic_server_settings)")" "$(vless_client ", $(quic_client_settings)" "$port")" "$port" ;;
    vless-kcp-*) server_config "$(vless_server ", $(kcp_settings)")" "$(vless_client ", $(kcp_settings)" "$port")" "$port" ;;
    vless-hysteria-*) server_config "$(vless_server ", $(hysteria_server_settings)")" "$(vless_client ", $(hysteria_client_settings)" "$port")" "$port" ;;
    hysteria-v1-*) server_config "$(hysteria_v1_server_settings)" "$(hysteria_v1_client_settings "$port")" "$port" ;;
    vmess-tls-ws-*) server_config "\"protocol\": \"vmess\", \"settings\": {\"clients\": [{\"id\": \"$UUID\"}]}, $(tls_ws_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"vmess\", \"settings\": {\"vnext\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"users\": [{\"id\": \"$UUID\", \"security\": \"auto\"}]}]}, $(tls_ws_client_settings)" "$port" ;;
    trojan-tls-ws-*) server_config "\"protocol\": \"trojan\", \"settings\": {\"clients\": [{\"password\": \"$PASSWORD\"}]}, $(tls_ws_server_settings)" "\"tag\": \"proxy\", \"protocol\": \"trojan\", \"settings\": {\"servers\": [{\"address\": \"127.0.0.1\", \"port\": $port, \"password\": \"$PASSWORD\"}]}, $(tls_ws_client_settings)" "$port" ;;
    masque-*) server_config "$(masque_server_settings)" "$(masque_client_settings "$port")" "$port" ;;
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
  echo "vless-encryption-raw-down-8 download 8 256 65536"
  echo "vless-tls-raw-down-8 download 8 256 65536"
  echo "vless-encryption-tls-raw-down-8 download 8 256 65536"
  echo "vless-tls-raw-up-1 upload 1 2048 65536"
  echo "vless-tls-raw-duplex-8 full-duplex 8 128 65536"
  echo "vless-tls-ws-down-8 download 8 256 65536"
  echo "trojan-tls-raw-down-8 download 8 256 65536"
  echo "vless-httpupgrade-down-8 download 8 256 65536"
  echo "vless-tls-grpc-down-8 download 8 256 65536"
  echo "vless-reality-raw-down-8 download 8 256 65536"
  echo "vless-encryption-reality-raw-down-8 download 8 256 65536"
  echo "vless-reality-grpc-down-8 download 8 256 65536"
  echo "vless-reality-xhttp-down-8 download 8 256 65536"
  echo "vless-vision-tls-raw-down-8 download 8 256 65536"
  echo "vless-vision-reality-raw-down-8 download 8 256 65536"
  echo "vless-kcp-down-8 download 8 256 65536"
  echo "vless-quic-down-8 download 8 256 65536"
  echo "vless-hysteria-down-8 download 8 256 65536"
  echo "hysteria-v1-down-8 download 8 256 65536"
  echo "shadowsocks2022-raw-down-8 download 8 256 65536"
  echo "vmess-tls-ws-down-8 download 8 256 65536"
  echo "trojan-tls-ws-down-8 download 8 256 65536"
  echo "masque-down-8 download 8 256 65536"
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
      echo "vmess-raw-up-1 upload 1 2048 65536"
      echo "vmess-raw-duplex-8 full-duplex 8 128 65536"
      echo "trojan-raw-up-1 upload 1 2048 65536"
      echo "trojan-raw-duplex-8 full-duplex 8 128 65536"
      echo "shadowsocks-raw-up-1 upload 1 2048 65536"
      echo "shadowsocks-raw-duplex-8 full-duplex 8 128 65536"
      echo "shadowsocks2022-raw-up-1 upload 1 2048 65536"
      echo "shadowsocks2022-raw-duplex-8 full-duplex 8 128 65536"
      echo "vless-httpupgrade-up-1 upload 1 2048 65536"
      echo "vless-httpupgrade-duplex-8 full-duplex 8 128 65536"
      echo "vless-grpc-up-1 upload 1 2048 65536"
      echo "vless-grpc-duplex-8 full-duplex 8 128 65536"
      echo "vless-xhttp-up-1 upload 1 2048 65536"
      echo "vless-xhttp-duplex-8 full-duplex 8 128 65536"
      echo "vless-kcp-up-1 upload 1 2048 65536"
      echo "vless-kcp-duplex-8 full-duplex 8 128 65536"
      echo "vless-quic-up-1 upload 1 2048 65536"
      echo "vless-quic-duplex-8 full-duplex 8 128 65536"
      echo "vless-hysteria-up-1 upload 1 2048 65536"
      echo "vless-hysteria-duplex-8 full-duplex 8 128 65536"
      echo "hysteria-v1-up-1 upload 1 2048 65536"
      echo "hysteria-v1-duplex-8 full-duplex 8 128 65536"
      echo "vless-reality-raw-up-1 upload 1 2048 65536"
      echo "vless-reality-raw-duplex-8 full-duplex 8 128 65536"
      echo "vless-vision-tls-raw-up-1 upload 1 2048 65536"
      echo "vless-vision-tls-raw-duplex-8 full-duplex 8 128 65536"
      echo "vless-tls-grpc-up-1 upload 1 2048 65536"
      echo "vless-tls-grpc-duplex-8 full-duplex 8 128 65536"
      echo "vless-tls-ws-up-1 upload 1 2048 65536"
      echo "vless-tls-ws-duplex-8 full-duplex 8 128 65536"
      echo "vmess-tls-ws-up-1 upload 1 2048 65536"
      echo "vmess-tls-ws-duplex-8 full-duplex 8 128 65536"
      echo "vmess-tls-raw-down-8 download 8 256 65536"
      echo "vmess-tls-raw-up-1 upload 1 2048 65536"
      echo "vmess-tls-raw-duplex-8 full-duplex 8 128 65536"
      echo "trojan-tls-raw-up-1 upload 1 2048 65536"
      echo "trojan-tls-raw-duplex-8 full-duplex 8 128 65536"
      echo "trojan-tls-ws-up-1 upload 1 2048 65536"
      echo "trojan-tls-ws-duplex-8 full-duplex 8 128 65536"
      ;;
  esac
}
