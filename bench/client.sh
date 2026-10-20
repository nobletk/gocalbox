#!/usr/bin/env bash
# Runs the transfer baseline from a client machine against a gocalbox server
# started with bench/server.sh on another machine. Run from the repository
# root on the client. Writes a CSV with the server's CPU time per operation.
#
# Requirements:
#   - key-based ssh to the server with no password prompt; passwordless sudo
#     there when DROP_CACHES=1. One ssh connection is opened and shared by
#     every remote command of the run.
#   - bash 5 or later; GNU coreutils 8.24 or later on the server
#   - both machines' clocks synchronised (NTP): server CPU is joined by timestamp
#   - the server's CPU is sampled every 0.1 s, so server_cpu_s is meaningful only
#     for operations longer than about one second
#
# Options (environment variables):
#   SERVER_HOST              address the client connects to (required)
#   SERVER_SSH               user@host for ssh (required)
#   SERVER_BENCH             the server's benchmark folder, as given to bench/server.sh (required)
#   BENCH_DIR                this machine's benchmark folder (required), made with bench/init.sh: an
#                            absolute path. Everything this script writes but its results lives in it,
#                            and it deletes nothing outside it, here or on the server.
#   PORT=18080               server port
#   SIZES="64K 1M 16M 256M 1G 5G"  file sizes (IEC units)
#   REPS=5                   repetitions per measurement
#   DROP_CACHES=1            drop the server's page cache before each download
#   TRANSPORT=https-h2       https-h2 (HTTPS with HTTP/2, as browsers use it) or https-h1 (HTTPS
#                            with HTTP/1.1); against a server from before HTTPS it is http.
#                            SERVER_HOST must be a name or address in the server's certificate:
#                            a private address or a LAN name (bench/server.sh prints them)
#
# Columns that need a definition:
#   durable_upper_seconds  upload time plus an fsync of the stored file run over ssh right
#                          after it: an upper bound on replying only once the file is on disk.
#                          The environment file records the ssh overhead included.
#   http_code              for upload_batch rows, 201 when all 100 uploads got it, otherwise
#                          every code with its count, such as "201x97 507x3"
#   transport              the TRANSPORT of the run; results from before this column existed are http
set -euo pipefail
trap 'echo "client.sh: failed at line $LINENO" >&2' ERR
export LC_ALL=C

: "${SERVER_HOST:?set SERVER_HOST to the server's address}"
: "${SERVER_SSH:?set SERVER_SSH to user@server}"
: "${SERVER_BENCH:?set SERVER_BENCH to the server's benchmark folder}"
SIZES=${SIZES:-"64K 1M 16M 256M 1G 5G"}
REPS=${REPS:-5}
PORT=${PORT:-18080}
DROP_CACHES=${DROP_CACHES:-1}

[ -d bench ] && [ -d cmd/gocalbox ] || { echo "run from the repository root" >&2; exit 1; }
[ -z "${WORK:-}${SERVER_WORK:-}" ] || { echo "WORK and SERVER_WORK are replaced by BENCH_DIR and SERVER_BENCH, folders made with bench/init.sh" >&2; exit 1; }
. bench/lib/safe.sh
bench_use "${BENCH_DIR:-}" || exit 1
WORK=$BENCH_DIR/client
DATA=$BENCH_DIR/data
[ "${BASH_VERSINFO[0]}" -ge 5 ] || { echo "needs bash 5 or later" >&2; exit 1; }
for tool in curl numfmt awk ssh seq xargs stat sort uniq; do command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }; done

SSH=(ssh -o BatchMode=yes -o ControlPath="${XDG_RUNTIME_DIR:-/tmp}/gocalbox-bench-$$.sock")
# ControlPersist ends the shared connection after 10 idle minutes if this script is killed before its exit trap runs.
"${SSH[@]}" -o ControlMaster=yes -o ControlPersist=600 -fN "$SERVER_SSH" > /dev/null
trap '"${SSH[@]}" -O exit "$SERVER_SSH" 2>/dev/null || true' EXIT
remote() { "${SSH[@]}" "$SERVER_SSH" "$@"; }
# On the server, files are deleted only through its own copy of bench/lib/safe.sh, in its benchmark folder.
remote_rm() { remote "$(printf '%q ' bash "$SRV_SAFE" rm "$SRV_BENCH" "$@")"; }
remote_empty() { remote "$(printf '%q ' bash "$SRV_SAFE" empty "$SRV_BENCH" "$1")"; }

case $(remote "sync --help" 2>&1 || true) in
  *--file-system*) ;;
  *) echo "sync on the server cannot flush a single file; needs GNU coreutils 8.24 or later" >&2; exit 1 ;;
esac
REMOTE_MS=$(for _ in $(seq 11); do a=$EPOCHREALTIME; remote true; b=$EPOCHREALTIME; awk -v a="$a" -v b="$b" 'BEGIN{printf "%.2f\n", (b-a)*1000}'; done | sort -n | sed -n 6p)

# Sets SRV_COMMIT, SRV_DIRTY, SRV_BENCH, SRV_SAFE, SRV_ROOT, SRV_SAMPLES, SRV_ENV, SRV_GOVERNOR, SRV_CMD,
# SRV_CONSOLE_LOG, SRV_SCHEME, SRV_CA, SRV_USER and SRV_PASSWORD from the server's run.env.
eval "$(remote "cat $(printf %q "$SERVER_BENCH/server/run.env")")"
[ -n "${SRV_SAFE:-}" ] && [ -n "${SRV_BENCH:-}" ] || { echo "the server's bench/server.sh is older than this client; update it" >&2; exit 1; }
SCHEME=${SRV_SCHEME:-http}
if [ "$SCHEME" = https ]; then TRANSPORT=${TRANSPORT:-https-h2}; else TRANSPORT=${TRANSPORT:-http}; fi
case $SCHEME/$TRANSPORT in
  https/https-h2) WANT_HTTP=2;   CURL=(curl -sS --http2) ;;
  https/https-h1) WANT_HTTP=1.1; CURL=(curl -sS --http1.1) ;;
  http/http)      WANT_HTTP=1.1; CURL=(curl -sS --http1.1) ;;
  *) echo "TRANSPORT=$TRANSPORT does not match the server, which speaks $SCHEME" >&2; exit 1 ;;
esac
URL="$SCHEME://$SERVER_HOST:$PORT"
mkdir -p "$WORK"
if [ "$SCHEME" = https ]; then
  remote "cat '$SRV_CA'" > "$WORK/server-ca.crt"
  CURL+=(--cacert "$WORK/server-ca.crt")
fi
GOT_HTTP=$("${CURL[@]}" -o /dev/null -w '%{http_version}' "$URL/") ||
  { echo "cannot reach $URL; over HTTPS, SERVER_HOST must be a name or address in the server's certificate" >&2; exit 1; }
[ "$GOT_HTTP" = "$WANT_HTTP" ] || { echo "negotiated HTTP/$GOT_HTTP, not HTTP/$WANT_HTTP; for https-h2, curl needs HTTP/2 support (curl -V lists HTTP2)" >&2; exit 1; }
# login USER PASSWORD FILE logs in and writes the session cookie to FILE as a header for curl -H @FILE,
# so neither the password nor the cookie appears on a command line.
login() {
  local token
  token=$(printf '{"username":"%s","password":"%s"}' "$1" "$2" |
    "${CURL[@]}" -o /dev/null -D - -H 'Content-Type: application/json' --data-binary @- "$URL/api/auth/login" |
    sed -n 's/^[Ss]et-[Cc]ookie: __Host-gocalbox-session=\([^;]*\);.*/\1/p')
  [ -n "$token" ] || { echo "cannot log in as $1" >&2; exit 1; }
  (umask 077; printf 'Cookie: __Host-gocalbox-session=%s\n' "$token" > "$3")
}
if [ -n "${SRV_PASSWORD:-}" ]; then
  login "$SRV_USER" "$SRV_PASSWORD" "$WORK/session-header"
  CURL+=(-H "@$WORK/session-header")
fi
[ "$SRV_DIRTY" = 0 ] || echo "warning: the server's tree was dirty; results are marked dirty=$SRV_DIRTY" >&2
[ "${SRV_GOVERNOR:-n/a}" = performance ] || echo "warning: the server's CPU governor is '${SRV_GOVERNOR:-unknown}', not 'performance'; results will not be comparable" >&2

STAMP=$(date +%Y%m%d-%H%M%S)
RUN="bench/results/client-$SRV_COMMIT-$STAMP"
CSV="$RUN.csv"; ENV="$RUN-env.txt"
RAW="$WORK/rows-$STAMP.raw"; CODES="$WORK/codes-$STAMP"
mkdir -p bench/results "$DATA"
: > "$RAW"

# Random, so neither compression nor sparse files flatter the numbers.
for s in $SIZES; do
  f="$DATA/$s.bin"
  [ -f "$f" ] || { echo "generating $s"; head -c "$(numfmt --from=iec "$s")" /dev/urandom > "$f"; }
done
[ -f "$DATA/batch-1M.bin" ] || head -c 1048576 /dev/urandom > "$DATA/batch-1M.bin"

{
  echo "client: $(hostname)   date: $(date -Is)"
  echo "server: $SERVER_HOST:$PORT (commit $SRV_COMMIT, dirty=$SRV_DIRTY)"
  echo "server command: ${SRV_CMD:-unknown (server.sh older than this client)}"
  echo "server cpu governor: ${SRV_GOVERNOR:-unknown}"
  echo "server console event log: ${SRV_CONSOLE_LOG:-on (server.sh older than this client)}"
  echo "transport: $TRANSPORT (negotiated HTTP/$GOT_HTTP; $("${CURL[@]}" --version | head -1))"
  uname -srm
  grep -m1 'model name' /proc/cpuinfo || true
  echo "cpus: $(nproc)   $(grep MemTotal /proc/meminfo)"
  echo "cpu governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
  echo "network interfaces:"; ip -br addr 2>/dev/null | grep -v '^lo' || echo "n/a"
  echo "ping to server (20 packets):"; ping -c 20 -q "$SERVER_HOST" | tail -1 || true
  echo "remote command overhead over the shared ssh connection, median of 11: $REMOTE_MS ms"
  echo "sizes: $SIZES"
  echo "reps: $REPS"
  echo "drop caches before downloads: $DROP_CACHES"
} > "$ENV"

sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.4f", b-a}'; }
rate() { awk -v b="$1" -v s="$2" 'BEGIN{printf "%.1f", (s>0)?b/1048576/s:0}'; }
tally() { sort "$1" | uniq -c | awk -v n="$2" '{k[NR]=$1; c[NR]=$2} END {if (NR==1 && k[1]==n) {print c[1]; exit} for (i=1; i<=NR; i++) printf "%s%sx%s", (i>1?" ":""), c[i], k[i]; print ""}'; }
raw() { echo "$*" >> "$RAW"; }

for s in $SIZES; do
  src="$DATA/$s.bin"; bytes=$(stat -c %s "$src")
  for rep in $(seq "$REPS"); do
    remote sync
    t0=$EPOCHREALTIME
    IFS=, read -r code secs < <("${CURL[@]}" -o /dev/null -w '%{http_code},%{time_total}\n' -F "myFile=@$src" "$URL/api/upload")
    t1=$EPOCHREALTIME
    durable=
    if [ "$code" = 201 ]; then
      remote "sync -- '$SRV_ROOT/$s.bin'"
      t2=$EPOCHREALTIME
      durable=$(awk -v a="$secs" -v b="$(sub "$t1" "$t2")" 'BEGIN{printf "%.4f", a+b}')
    fi
    raw "upload,$bytes,1,1,$rep,$secs,$(rate "$bytes" "$secs"),$durable,$t0,$t1,$code"

    if [ "$DROP_CACHES" = 1 ]; then remote "sudo -n sh -c 'echo 3 > /proc/sys/vm/drop_caches'"; fi
    t0=$EPOCHREALTIME
    IFS=, read -r code secs < <("${CURL[@]}" -o /dev/null -w '%{http_code},%{time_total}\n' "$URL/files/$s.bin")
    t1=$EPOCHREALTIME
    raw "download,$bytes,1,1,$rep,$secs,$(rate "$bytes" "$secs"),,$t0,$t1,$code"
    remote_rm "$SRV_ROOT/$s.bin"
  done
  echo "done: $s"
done

batch="$DATA/batch-1M.bin"
for conc in 1 4 16; do
  for rep in $(seq "$REPS"); do
    remote_empty "$SRV_ROOT"; remote sync
    : > "$CODES"
    t0=$EPOCHREALTIME
    seq 100 | xargs -P "$conc" -I{} "${CURL[@]}" -o /dev/null -w '%{http_code}\n' -F "myFile=@$batch;filename=f{}.bin" "$URL/api/upload" >> "$CODES" || true
    t1=$EPOCHREALTIME
    code=$(tally "$CODES" 100)
    [ "$code" = 201 ] || echo "warning: 100 x 1M at concurrency $conc, rep $rep: $code" >&2
    secs=$(sub "$t0" "$t1")
    raw "upload_batch,1048576,100,$conc,$rep,$secs,$(rate $((100*1048576)) "$secs"),,$t0,$t1,$code"
  done
  echo "done: 100 x 1M at concurrency $conc"
done
remote_empty "$SRV_ROOT"

# The server's samples are copied after the run, so they cover every operation.
SAMPLES_LOCAL="$WORK/samples-$STAMP.csv"
remote "cat '$SRV_SAMPLES'" > "$SAMPLES_LOCAL"
echo "server peak RSS (kB): $(tail -1 "$SAMPLES_LOCAL" | cut -d, -f3)" >> "$ENV"

awk -v commit="$SRV_COMMIT" -v dirty="$SRV_DIRTY" -v transport="$TRANSPORT" '
function cpu_at(t,  lo, hi, mid) {
  if (t <= T[1]) return C[1]
  if (t >= T[n]) return C[n]
  lo = 1; hi = n
  while (hi - lo > 1) { mid = int((lo + hi) / 2); if (T[mid] <= t) lo = mid; else hi = mid }
  return C[lo]
}
BEGIN { FS = ","; print "commit,dirty,scenario,size_bytes,files,concurrency,rep,seconds,mib_per_s,durable_upper_seconds,server_cpu_s,http_code,transport" }
FILENAME == ARGV[1] { T[++n] = $1 + 0; C[n] = $2 + 0; next }
{ printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%.4f,%s,%s\n", commit, dirty, $1, $2, $3, $4, $5, $6, $7, $8, cpu_at($10 + 0) - cpu_at($9 + 0), $11, transport }
' "$SAMPLES_LOCAL" "$RAW" > "$CSV"

bench_rm "$RAW" "$CODES"
echo "results: $CSV"
echo "client environment: $ENV"
echo "server environment: copy $SRV_ENV from the server after stopping bench/server.sh"
