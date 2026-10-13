#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

status=0

if git grep -I -n -E 'to_socket_addrs|lookup_host|getaddrinfo|hickory|trust-dns' -- crates/ferrox-core/src; then
  echo "::error::ferrox-core must not resolve DNS — the parser decides without a resolver (see transport.rs)"
  status=1
fi

if git grep -I -n -E 'Box::leak|mem::forget|::forget\(|ManuallyDrop|into_raw' -- crates/ferrox-core/src; then
  echo "::error::ferrox-core must not launder lifetimes — the allocation gate is zero, use borrows"
  status=1
fi

if git grep -I -n -E 'println!|print!|eprintln!|eprint!|dbg!' -- crates/ferrox-core/src; then
  echo "::error::ferrox-core is a library — printing lives in ferrox-bench/ferrox-app"
  status=1
fi

if git grep -I -n -E 'Instant::now|SystemTime::now' -- crates/ferrox-core/src \
    ':!crates/ferrox-core/src/kcp/**' \
    ':!crates/ferrox-core/src/chacha/calibrate.rs'; then
  echo "::error::ferrox-core must stay deterministic — wall-clock reads live in ferrox-bench (two named exceptions: kcp/ is retransmission-timed by definition, chacha/calibrate.rs picks between two byte-identical one-block cores)"
  status=1
fi

exit "$status"
