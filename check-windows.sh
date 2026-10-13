#!/usr/bin/env bash
exec "$(cd "$(dirname "$0")" && pwd)/cross-gate.sh" x86_64-pc-windows-msvc "$@"
