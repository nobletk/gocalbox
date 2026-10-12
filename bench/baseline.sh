#!/usr/bin/env bash
# Records a transfer baseline for the current commit: single uploads and
# downloads per file size, and concurrent small uploads. Writes CSV and an
# environment description to bench/results/.
#
# Run from the repository root:   bench/baseline.sh
# Options (environment variables):
#   SIZES="64K 1M 16M 256M 1G 5G"  file sizes (IEC units)
#   REPS=5                          repetitions per measurement
#   WORK=bench/.work                scratch space; must be on the disk you serve from
#   DROP_CACHES=1                   drop the page cache before each download (asks for sudo)
#   LOG_EVENTS=1                    keep the server's console event log on; by default it is
#                                   turned off where the server allows it, so its cost is not measured
#
# Columns that need a definition:
#   durable_upper_seconds  upload time plus an fsync of the stored file started right after it:
#                          an upper bound on replying only once the file is on disk
#   http_code              for upload_batch rows, 201 when all 100 uploads got it, otherwise
#                          every code with its count, such as "201x97 507x3"
set -euo pipefail
trap 'echo "baseline.sh: failed at line $LINENO" >&2' ERR
export LC_ALL=C

SIZES=${SIZES:-"64K 1M 16M 256M 1G 5G"}
REPS=${REPS:-5}
WORK=${WORK:-$PWD/bench/.work}
DROP_CACHES=${DROP_CACHES:-0}
LOG_EVENTS=${LOG_EVENTS:-0}
PORT=${PORT:-18080}
URL="http://localhost:$PORT"

[ -f go.mod ] && [ -d cmd/gocalbox ] || { echo "run from the repository root" >&2; exit 1; }
[ "${BASH_VERSINFO[0]}" -ge 5 ] || { echo "needs bash 5 or later" >&2; exit 1; }
for tool in curl numfmt awk git go sort uniq; do command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }; done
case $(sync --help 2>&1 || true) in
  *--file-system*) ;;
  *) echo "sync cannot flush a single file; needs GNU coreutils 8.24 or later" >&2; exit 1 ;;
esac

COMMIT=$(git rev-parse --short HEAD)
DIRTY=0; git diff --quiet HEAD -- . ':!bench' || DIRTY=1
[ "$DIRTY" = 1 ] && echo "warning: uncommitted changes; results are marked dirty=1" >&2
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p bench/results "$WORK/data"
CSV="bench/results/$COMMIT-$STAMP.csv"
ENV="bench/results/$COMMIT-$STAMP-env.txt"
ROOT="$WORK/root"; AUDIT="$WORK/audit.jsonl"; CODES="$WORK/codes"
rm -rf "${ROOT:?}" "$AUDIT"; mkdir -p "$ROOT"

# Random, so neither compression nor sparse files flatter the numbers.
for s in $SIZES; do
  f="$WORK/data/$s.bin"
  [ -f "$f" ] || { echo "generating $s"; head -c "$(numfmt --from=iec "$s")" /dev/urandom > "$f"; }
done
[ -f "$WORK/data/batch-1M.bin" ] || head -c 1048576 /dev/urandom > "$WORK/data/batch-1M.bin"

GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)
[ "$GOVERNOR" = performance ] || echo "warning: CPU governor is '$GOVERNOR', not 'performance'; results will not be comparable" >&2

go build -o "$WORK/gocalbox" ./cmd/gocalbox
SERVER_CMD=("$WORK/gocalbox" -port "$PORT" -root "$ROOT" -audit-log "$AUDIT" -max-upload-mb 0)
CONSOLE_LOG=on
if [ "$LOG_EVENTS" != 1 ]; then
  case $("$WORK/gocalbox" -h 2>&1 || true) in
    *-log-events*) SERVER_CMD+=(-log-events=false); CONSOLE_LOG=off ;;
    *) echo "warning: this server has no -log-events flag, so its console event log is part of what is measured" >&2 ;;
  esac
fi
"${SERVER_CMD[@]}" > "$WORK/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null || true' EXIT
for _ in $(seq 100); do curl -fs -o /dev/null "$URL/" && break; sleep 0.1; done

TICK=$(getconf CLK_TCK)
# Sets CPU to the server's CPU time in clock ticks. It does not fork, so it adds nothing to the timings around it.
read_cpu() { local f; read -r -a f < "/proc/$PID/stat"; CPU=$(( f[13] + f[14] )); }
cpus() { awk -v a="$1" -v b="$2" -v t="$TICK" 'BEGIN{printf "%.4f", (b-a)/t}'; }
sub() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.4f", b-a}'; }
rate() { awk -v b="$1" -v s="$2" 'BEGIN{printf "%.1f", (s>0)?b/1048576/s:0}'; }
tally() { sort "$1" | uniq -c | awk -v n="$2" '{k[NR]=$1; c[NR]=$2} END {if (NR==1 && k[1]==n) {print c[1]; exit} for (i=1; i<=NR; i++) printf "%s%sx%s", (i>1?" ":""), c[i], k[i]; print ""}'; }
row() { echo "$COMMIT,$DIRTY,$*" >> "$CSV"; }

{
  echo "commit: $COMMIT (dirty=$DIRTY)   date: $(date -Is)"
  go version
  uname -srm
  grep -m1 'model name' /proc/cpuinfo || true
  echo "cpus: $(nproc)   $(grep MemTotal /proc/meminfo)"
  echo "served folder: $ROOT"
  findmnt -no SOURCE,FSTYPE,OPTIONS -T "$ROOT" || true
  lsblk -dno NAME,ROTA,MODEL "$(findmnt -no SOURCE -T "$ROOT" | sed 's/\[.*//')" 2>/dev/null || true
  echo "free space on served volume: $(df -B1 --output=avail "$ROOT" 2>/dev/null | tail -1 | tr -d ' ' || true) bytes"
  echo "cpu governor: $GOVERNOR"
  echo "server command: ${SERVER_CMD[*]@Q}"
  echo "console event log: $CONSOLE_LOG"
  echo "sizes: $SIZES"
  echo "reps: $REPS"
  echo "drop caches before downloads: $DROP_CACHES"
} > "$ENV"

echo "commit,dirty,scenario,size_bytes,files,concurrency,rep,seconds,mib_per_s,durable_upper_seconds,server_cpu_s,http_code" > "$CSV"

for s in $SIZES; do
  src="$WORK/data/$s.bin"; bytes=$(stat -c %s "$src")
  for rep in $(seq "$REPS"); do
    sync
    read_cpu; c0=$CPU
    IFS=, read -r code secs < <(curl -sS -o /dev/null -w '%{http_code},%{time_total}\n' -F "myFile=@$src" "$URL/api/upload")
    t0=$EPOCHREALTIME
    read_cpu; c1=$CPU
    durable=
    if [ "$code" = 201 ]; then
      sync -- "$ROOT/$s.bin"
      t1=$EPOCHREALTIME
      durable=$(awk -v a="$secs" -v b="$(sub "$t0" "$t1")" 'BEGIN{printf "%.4f", a+b}')
    fi
    row "upload,$bytes,1,1,$rep,$secs,$(rate "$bytes" "$secs"),$durable,$(cpus "$c0" "$c1"),$code"

    if [ "$DROP_CACHES" = 1 ]; then sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'; fi
    read_cpu; c0=$CPU
    IFS=, read -r code secs < <(curl -sS -o /dev/null -w '%{http_code},%{time_total}\n' "$URL/files/$s.bin")
    read_cpu; c1=$CPU
    row "download,$bytes,1,1,$rep,$secs,$(rate "$bytes" "$secs"),,$(cpus "$c0" "$c1"),$code"
    rm -f "$ROOT/$s.bin"
  done
  echo "done: $s"
done

batch="$WORK/data/batch-1M.bin"
for conc in 1 4 16; do
  for rep in $(seq "$REPS"); do
    rm -rf "${ROOT:?}"/*; sync
    : > "$CODES"
    read_cpu; c0=$CPU; t0=$EPOCHREALTIME
    seq 100 | xargs -P "$conc" -I{} curl -sS -o /dev/null -w '%{http_code}\n' -F "myFile=@$batch;filename=f{}.bin" "$URL/api/upload" >> "$CODES" || true
    t1=$EPOCHREALTIME; read_cpu; c1=$CPU
    code=$(tally "$CODES" 100)
    [ "$code" = 201 ] || echo "warning: 100 x 1M at concurrency $conc, rep $rep: $code" >&2
    secs=$(sub "$t0" "$t1")
    row "upload_batch,1048576,100,$conc,$rep,$secs,$(rate $((100*1048576)) "$secs"),,$(cpus "$c0" "$c1"),$code"
  done
  echo "done: 100 x 1M at concurrency $conc"
done
rm -rf "${ROOT:?}"/* "$CODES"

echo "server peak RSS: $(grep VmHWM /proc/$PID/status | awk '{print $2, $3}')" >> "$ENV"
echo "audit records: $(wc -l < "$AUDIT")" >> "$ENV"
echo "results: $CSV"
