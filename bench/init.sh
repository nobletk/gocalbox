#!/usr/bin/env bash
# Makes the benchmark folder on this machine: bench/init.sh DIR, with an
# absolute DIR that is new or empty. Every benchmark script works in this
# folder only, and deletes nothing outside it.
set -euo pipefail
export LC_ALL=C
. "$(dirname -- "${BASH_SOURCE[0]}")/lib/safe.sh"
[ "$#" -eq 1 ] || { echo "usage: bench/init.sh DIR" >&2; exit 2; }
bench_init "$1"
