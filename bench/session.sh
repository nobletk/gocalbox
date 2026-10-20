#!/usr/bin/env bash
# Runs a benchmark session: every cell of a matrix file, repeated, in a
# shuffled order, against servers started with bench/server.sh, and records
# the session's environment. Run from the repository root on the client:
#
#   bench/session.sh bench/sessions/1-loopback.txt
#
# A matrix file has two kinds of lines; # starts a comment:
#   server NAME [VAR=VALUE ...]   a server: bench/server.sh's settings (BUILD_TAGS, SERVER_REV,
#                                 SERVER_FLAGS, LOG_EVENTS and the GOCALBOX_BENCH_* variables);
#                                 a VALUE of $NAME is taken from this script's environment
#   cell ID SERVER TOOL [KEY=VALUE ...]
#                                 a measurement, against the server SERVER, or - for none.
#     engine     resumable uploads with the load client: transport=https-h2|https-h1, size,
#                files=1, users=1, parallel=4, resume-at, retry-for
#     upload     one single-request upload with curl: transport, size
#     download   one download with curl: transport, size
#     batch      files=100 single-request uploads of 1 MiB at once: transport, conc=1
#     inprocess  the load client with the engine in this process (server -): size, files=1,
#                users=1, parallel=4, audit-parts=0, audit-wait=1, resume-at, min-free-mb=1024
#   Every cell also takes reps=N, its measured repetitions.
#
# The runs are grouped by server, since a server restarts between groups:
# the groups run in a shuffled order, and in each, the warm-ups first and
# then the measured runs, shuffled. The order is written with the results.
#
# Options (environment variables):
#   BENCH_DIR      this machine's benchmark folder (required), made with bench/init.sh. Everything
#                  this script writes but its results lives in it, here and in SERVER_BENCH on the
#                  server, and it deletes nothing outside them.
#   SERVER_SSH     user@host of the server, with key-based ssh; unset, the server runs here
#   SERVER_HOST    the server's address as this machine reaches it; localhost when the server runs
#                  here. Over the network, a name or address in the server's certificate.
#   SERVER_BENCH   the server's benchmark folder (default BENCH_DIR when the server runs here)
#   SERVER_REPO    this repository on the server, at the same commit (default this one when the
#                  server runs here)
#   PORT=18080     the server's port
#   CELLS=         run only the cells whose ID starts with one of these, separated by commas
#   SEED=          the shuffle's seed; by default a random one, recorded with the results
#   REPS=10        measured repetitions of a cell; BIG_REPS=5 for files of 5 GiB and more
#   WARMUP=1       repetitions of a cell before its measured ones, written with rep 0
#   DROP_CACHES=1  drop the server's page cache before each download (passwordless sudo there)
#   IPERF=1        measure the link with iperf3 at the start and the end (needs iperf3 on both)
#   PLAN_ONLY=1    write the order and stop
set -Eeuo pipefail
trap 'echo "session.sh: failed at line $LINENO" >&2' ERR
export LC_ALL=C

MATRIX=${1:?usage: bench/session.sh MATRIX}
SERVER_SSH=${SERVER_SSH:-}
PORT=${PORT:-18080}
CELLS=${CELLS:-}
REPS=${REPS:-10}
BIG_REPS=${BIG_REPS:-5}
WARMUP=${WARMUP:-1}
DROP_CACHES=${DROP_CACHES:-1}
IPERF=${IPERF:-1}
PLAN_ONLY=${PLAN_ONLY:-0}
IPERF_PORT=${IPERF_PORT:-5201}

[ -f go.mod ] && [ -d cmd/gocalbox ] || { echo "run from the repository root" >&2; exit 1; }
[ -z "${WORK:-}" ] || { echo "WORK is replaced by BENCH_DIR, a folder made with bench/init.sh" >&2; exit 1; }
[ -z "$(compgen -e GOCALBOX_BENCH_ || true)" ] || { echo "unset the GOCALBOX_BENCH_* variables: the matrix sets them for each server" >&2; exit 1; }
# The matrix sets these for each server; a server started here would take them from this shell.
unset SERVER_FLAGS SERVER_REV BUILD_TAGS LOG_EVENTS LOAD_USERS ALLOWED_HOSTS BIND
. bench/lib/safe.sh
. bench/lib/env.sh
bench_use "${BENCH_DIR:-}" || exit 1
[ "${BASH_VERSINFO[0]}" -ge 5 ] || { echo "needs bash 5 or later" >&2; exit 1; }
for tool in curl numfmt awk go git shuf openssl sort; do command -v "$tool" > /dev/null || { echo "missing: $tool" >&2; exit 1; }; done
[ -f "$MATRIX" ] || { echo "no matrix file $MATRIX" >&2; exit 1; }
for n in REPS BIG_REPS WARMUP; do [[ ${!n} =~ ^[0-9]+$ ]] || { echo "$n must be a number" >&2; exit 1; }; done
if [ -n "$SERVER_SSH" ]; then
  : "${SERVER_HOST:?set SERVER_HOST to the server's address as this machine reaches it}"
  : "${SERVER_BENCH:?set SERVER_BENCH to the server's benchmark folder}"
  : "${SERVER_REPO:?set SERVER_REPO to this repository on the server}"
  BIND=0.0.0.0
else
  SERVER_HOST=${SERVER_HOST:-localhost}
  SERVER_BENCH=${SERVER_BENCH:-$BENCH_DIR}
  SERVER_REPO=${SERVER_REPO:-$PWD}
  BIND=127.0.0.1
fi
SEED=${SEED:-$(od -An -tu4 -N4 /dev/urandom | tr -d ' ')}
WORK=$BENCH_DIR/session
DATA=$BENCH_DIR/data
mkdir -p "$WORK" "$DATA" bench/results

# --- The matrix -----------------------------------------------------------

declare -A PROFILE_ENV=() PROFILE_USERS=() CELL_SERVER=() CELL_TOOL=() CELL_ARGS=()
CELL_IDS=()
SERVER_VARS=" BUILD_TAGS SERVER_REV SERVER_FLAGS LOG_EVENTS GOCALBOX_BENCH_H2_CONN_WINDOW GOCALBOX_BENCH_H2_STREAM_WINDOW GOCALBOX_BENCH_PART_SIZE "
declare -A TOOL_KEYS=(
  [engine]=" transport size files users parallel resume-at retry-for reps "
  [upload]=" transport size reps "
  [download]=" transport size reps "
  [batch]=" transport conc files reps "
  [inprocess]=" size files users parallel audit-parts audit-wait resume-at min-free-mb reps "
)
bad() { echo "$MATRIX:$LINE_NO: $*" >&2; exit 1; }
# value KEY DEFAULT prints the cell's value of KEY.
value() { local kv; for kv in $ARGS; do [ "${kv%%=*}" = "$1" ] && { echo "${kv#*=}"; return; }; done; echo "$2"; }
is_size() { [[ $1 =~ ^[0-9]+[KMG]?$ ]]; }
is_count() { [[ $1 =~ ^[1-9][0-9]*$ ]]; }

check_cell() {
  local kv k v
  for kv in $ARGS; do
    [[ $kv = *=* ]] || bad "not KEY=VALUE: $kv"
    k=${kv%%=*}; v=${kv#*=}
    [[ ${TOOL_KEYS[$TOOL]} = *" $k "* ]] || bad "$TOOL takes no $k"
    case $k in
      transport) [[ $v = https-h2 || $v = https-h1 ]] || bad "transport must be https-h2 or https-h1" ;;
      size) is_size "$v" || bad "size must be bytes, or a number with K, M or G" ;;
      files | users | parallel | conc | min-free-mb) is_count "$v" || bad "$k must be a number from 1" ;;
      reps) [[ $v =~ ^[0-9]+$ ]] || bad "reps must be a number" ;;
      audit-parts | audit-wait) [[ $v = 0 || $v = 1 ]] || bad "$k must be 0 or 1" ;;
      resume-at) [[ $v =~ ^0?\.[0-9]+$ ]] || bad "resume-at must be a share such as 0.5" ;;
      retry-for) [[ $v =~ ^[0-9]+(ms|s|m)$ ]] || bad "retry-for must be a duration such as 30s" ;;
    esac
  done
  case $TOOL in
    engine | upload | download | inprocess) is_size "$(value size x)" || bad "$TOOL needs a size" ;;
  esac
  if [ "$TOOL" = inprocess ]; then
    [ "$SERVER" = - ] || bad "an inprocess cell runs without a server; give - as its server"
    [ -z "$SERVER_SSH" ] || bad "an inprocess cell measures this machine, so it runs only with the server here, without SERVER_SSH"
  else
    [ -n "${PROFILE_ENV[$SERVER]+x}" ] || bad "no server named $SERVER above this line"
  fi
}

LINE_NO=0
while read -r -a WORDS || [ "${#WORDS[@]}" -gt 0 ]; do
  LINE_NO=$((LINE_NO + 1))
  [ "${#WORDS[@]}" -eq 0 ] || [[ ${WORDS[0]} = \#* ]] && continue
  case ${WORDS[0]} in
    server)
      NAME=${WORDS[1]:-}
      [[ $NAME =~ ^[A-Za-z0-9._-]+$ ]] || bad "a server needs a name of letters, digits, . _ and -"
      [ -z "${PROFILE_ENV[$NAME]+x}" ] || bad "server $NAME again"
      SETTINGS=
      for kv in "${WORDS[@]:2}"; do
        [[ $kv = *=* ]] || bad "not VAR=VALUE: $kv"
        k=${kv%%=*}; v=${kv#*=}
        [[ $SERVER_VARS = *" $k "* ]] || bad "bench/server.sh takes no $k here"
        if [[ $v =~ ^\$([A-Za-z_][A-Za-z0-9_]*)$ ]]; then
          ref=${BASH_REMATCH[1]}
          [ -n "${!ref:-}" ] || bad "$k=\$$ref, but $ref is not set"
          v=${!ref}
        fi
        [[ $v =~ ^[A-Za-z0-9._,=+:/@^~-]*$ ]] || bad "unusual characters in $k"
        SETTINGS+="$k=$v "
      done
      PROFILE_ENV[$NAME]=$SETTINGS
      PROFILE_USERS[$NAME]=0 ;;
    cell)
      [ "${#WORDS[@]}" -ge 4 ] || bad "cell ID SERVER TOOL [KEY=VALUE ...]"
      ID=${WORDS[1]}; SERVER=${WORDS[2]}; TOOL=${WORDS[3]}; ARGS="${WORDS[*]:4}"
      [[ $ID =~ ^[A-Za-z0-9._-]+$ ]] || bad "a cell needs an ID of letters, digits, . _ and -"
      [ -z "${CELL_TOOL[$ID]+x}" ] || bad "cell $ID again"
      [ -n "${TOOL_KEYS[$TOOL]+x}" ] || bad "no tool $TOOL: engine, upload, download, batch or inprocess"
      check_cell
      if [ -n "$CELLS" ]; then
        keep=0
        IFS=, read -r -a prefixes <<< "$CELLS"
        for p in "${prefixes[@]}"; do [ -n "$p" ] && [[ $ID = "$p"* ]] && keep=1; done
        [ "$keep" = 1 ] || continue
      fi
      CELL_IDS+=("$ID"); CELL_SERVER[$ID]=$SERVER; CELL_TOOL[$ID]=$TOOL; CELL_ARGS[$ID]=$ARGS
      if [ "$TOOL" = engine ] && [ "$(value users 1)" -gt "${PROFILE_USERS[$SERVER]}" ]; then
        PROFILE_USERS[$SERVER]=$(value users 1)
      fi ;;
    *) bad "a line starts with server or cell" ;;
  esac
done < "$MATRIX"
[ "${#CELL_IDS[@]}" -gt 0 ] || { echo "no cell to run${CELLS:+ with CELLS=$CELLS}" >&2; exit 1; }

# --- The order --------------------------------------------------------------

# shuffled KEY reads lines and prints them in an order that only the seed and
# KEY decide.
shuffled() {
  shuf --random-source=<(openssl enc -aes-256-ctr -pass "pass:$SEED-$1" -nosalt -pbkdf2 -in /dev/zero 2> /dev/null || true)
}
reps_of() {
  local ARGS=${CELL_ARGS[$1]} size
  size=$(value size 0)
  if [ -n "$(value reps '')" ]; then value reps ''
  elif [ "$(numfmt --from=iec "$size")" -ge $((5 << 30)) ]; then echo "$BIG_REPS"
  else echo "$REPS"; fi
}

STAMP=$(date +%Y%m%d-%H%M%S)
NAME=$(basename "$MATRIX"); NAME=${NAME%.*}
RUN="bench/results/session-$NAME-$STAMP"
CSV="$RUN.csv"; ORDER="$RUN-order.csv"; ENV="$RUN-env.txt"
PLAN=$WORK/plan-$STAMP
: > "$PLAN"
SERVERS=$(for id in "${CELL_IDS[@]}"; do echo "${CELL_SERVER[$id]}"; done | sort -u | shuffled servers)
for srv in $SERVERS; do
  for id in "${CELL_IDS[@]}"; do
    [ "${CELL_SERVER[$id]}" = "$srv" ] || continue
    for _ in $(seq "$WARMUP"); do echo "$srv $id 0"; done
  done | shuffled "warmup-$srv" >> "$PLAN"
  for id in "${CELL_IDS[@]}"; do
    [ "${CELL_SERVER[$id]}" = "$srv" ] || continue
    for r in $(seq "$(reps_of "$id")"); do echo "$srv $id $r"; done
  done | shuffled "runs-$srv" >> "$PLAN"
done
echo "seq,server,cell,rep,t0,t1,outcome" > "$ORDER"
if [ "$PLAN_ONLY" = 1 ]; then
  awk '{printf "%d,%s,%s,%s,,,planned\n", NR, $1, $2, $3}' "$PLAN" >> "$ORDER"
  bench_rm "$PLAN"
  echo "seed $SEED: $(($(wc -l < "$ORDER") - 1)) runs; order: $ORDER"
  exit 0
fi

# --- The server -------------------------------------------------------------

if [ -n "$SERVER_SSH" ]; then
  SSH=(ssh -o BatchMode=yes -o ControlPath="${XDG_RUNTIME_DIR:-/tmp}/gocalbox-session-$$.sock")
  # ControlPersist ends the shared connection after 10 idle minutes if this script is killed before its exit trap runs.
  "${SSH[@]}" -o ControlMaster=yes -o ControlPersist=600 -fN "$SERVER_SSH" > /dev/null
  remote() { "${SSH[@]}" "$SERVER_SSH" "$@" < /dev/null; }
  close_ssh() { "${SSH[@]}" -O exit "$SERVER_SSH" 2> /dev/null || true; }
else
  remote() { bash -c "$*" < /dev/null; }
  close_ssh() { :; }
fi
q() { printf '%q ' "$@"; }
REMOTE_SAFE=$SERVER_REPO/bench/lib/safe.sh
# On the server, files are deleted only through its own copy of bench/lib/safe.sh, in its benchmark folder.
remote_rm() { local cmd; cmd=$(q bash "$REMOTE_SAFE" rm "$SERVER_BENCH" "$@"); remote "$cmd"; }
remote_cat() { local cmd; cmd=$(q cat -- "$1"); remote "$cmd"; }
server_sh() { local cmd; cmd="cd $(q "$SERVER_REPO") && $(q env "BENCH_DIR=$SERVER_BENCH" bash bench/server.sh "$@")"; remote "$cmd"; }

SERVING=
start_server() {
  local srv=$1 log=$SERVER_BENCH/server/console.log state settings pid
  read -r -a settings <<< "${PROFILE_ENV[$srv]}"
  remote "mkdir -p $(q "$SERVER_BENCH/server")"
  remote_rm "$SERVER_BENCH/server/run.env" "$SERVER_BENCH/server/ready"
  # A simple command in the background, so that nothing holds this session's output open.
  pid=$(remote "cd $(q "$SERVER_REPO") || exit 1; $(q env "${settings[@]}" "BENCH_DIR=$SERVER_BENCH" "PORT=$PORT" "BIND=$BIND" \
    "LOAD_USERS=${PROFILE_USERS[$srv]}" nohup bash bench/server.sh) > $(q "$log") 2>&1 < /dev/null & echo \$!")
  [[ $pid =~ ^[0-9]+$ ]] || { echo "cannot start bench/server.sh for server $srv" >&2; exit 1; }
  SERVING=$srv
  state=starting
  for _ in $(seq 3000); do
    state=$(remote "$(q test -f "$SERVER_BENCH/server/ready") && echo ready || { kill -0 $pid 2> /dev/null && echo starting || echo gone; }")
    case $state in
      ready) break ;;
      gone) SERVING=; echo "bench/server.sh for server $srv stopped:" >&2; remote_cat "$log" | tail -20 >&2; exit 1 ;;
    esac
    sleep 0.2
  done
  [ "$state" = ready ] || { echo "bench/server.sh for server $srv didn't start in 10 minutes" >&2; exit 1; }
  SERVER_PID=$(remote_cat "$SERVER_BENCH/server/ready")
  [[ $SERVER_PID =~ ^[0-9]+$ ]] || { echo "bench/server.sh for server $srv wrote no server PID" >&2; exit 1; }
  # Sets SRV_COMMIT, SRV_DIRTY, SRV_ROOT, SRV_SAMPLES, SRV_ENV, SRV_SCHEME, SRV_CA, SRV_USER,
  # SRV_PASSWORD, SRV_LOAD_PASSWORD, SRV_REQUESTS, SRV_LOG and the rest of the server's run.env.
  eval "$(remote_cat "$SERVER_BENCH/server/run.env")"
  [ "$SRV_SCHEME" = https ] || { echo "server $srv speaks $SRV_SCHEME; the session measures HTTPS only" >&2; exit 1; }
  URL="https://$SERVER_HOST:$PORT"
  bench_rm "$WORK/server-ca.crt" "$WORK/session-header"
  remote_cat "$SRV_CA" > "$WORK/server-ca.crt"
  token=$(printf '{"username":"%s","password":"%s"}' "$SRV_USER" "$SRV_PASSWORD" |
    curl -sS --cacert "$WORK/server-ca.crt" -o /dev/null -D - -H 'Content-Type: application/json' --data-binary @- "$URL/api/auth/login" |
    sed -n 's/^[Ss]et-[Cc]ookie: __Host-gocalbox-session=\([^;]*\);.*/\1/p' || true)
  if [ -z "$token" ]; then
    echo "cannot log in to server $srv at $URL; SERVER_HOST must be in its certificate:" >&2
    remote_cat "$log" | grep "HTTPS certificate" >&2 || true
    exit 1
  fi
  (umask 077; printf 'Cookie: __Host-gocalbox-session=%s\n' "$token" > "$WORK/session-header")
  [ "$SRV_DIRTY" = 0 ] || echo "warning: server $srv was built from a dirty tree; its rows are marked dirty=1" >&2
}

# server_alive succeeds while the block's server runs.
server_alive() { remote "kill -0 $SERVER_PID 2> /dev/null"; }

# stop_server stops the server and keeps its environment file, samples,
# log and request log with the session's results, as far as they exist.
stop_server() {
  local srv=$SERVING
  [ -n "$srv" ] || return 0
  SERVING=
  server_sh stop || echo "warning: server $srv had stopped before the end of its runs" >&2
  [ -n "${SRV_ENV:-}" ] || return 0
  remote_cat "$SERVER_REPO/$SRV_ENV" > "$RUN-server-$srv-env.txt" || true
  remote_cat "$SRV_SAMPLES" > "$RUN-server-$srv-samples.csv" || true
  remote_cat "$SRV_LOG" > "$RUN-server-$srv.log" || true
  if [ -n "${SRV_REQUESTS:-}" ]; then remote_cat "$SRV_REQUESTS" > "$RUN-server-$srv-requests.jsonl" || true; fi
}
trap 'stop_server || true; close_ssh' EXIT
PLACED=()

# --- The runs -----------------------------------------------------------------

# data SIZE prints the path of a file of SIZE bytes made from a fixed seed,
# so every session sends the same incompressible bytes. Its SHA-256 is kept
# next to it.
data() {
  local f=$DATA/fixed-$1.bin n
  if [ ! -f "$f" ] || [ ! -f "$f.sha256" ]; then
    n=$(numfmt --from=iec "$1")
    # openssl ends on the broken pipe once head has its bytes.
    (openssl enc -aes-256-ctr -pass "pass:gocalbox-$1" -nosalt -pbkdf2 -in /dev/zero 2> /dev/null || true) | head -c "$n" > "$f.part"
    [ "$(stat -c %s "$f.part")" = "$n" ] || { echo "cannot make the $1 data file" >&2; exit 1; }
    sha256sum < "$f.part" | cut -d' ' -f1 > "$f.sha256"
    mv -- "$f.part" "$f"
  fi
  echo "$f"
}

curl_for() { CURL=(curl -sS --cacert "$WORK/server-ca.crt" -H "@$WORK/session-header"); case $1 in https-h2) CURL+=(--http2) ;; *) CURL+=(--http1.1) ;; esac; }
rate() { awk -v b="$1" -v s="$2" 'BEGIN {printf "%.3f", (s > 0) ? b / 1048576 / s : 0}'; }
EMPTY=$(printf ',%.0s' $(seq 13))
# row SCENARIO SIZE FILES CONC REP SECONDS DURABLE CODE TRANSPORT T0 T1 writes a curl run's row, with the
# load client's columns empty but its start, for the server's CPU to be joined to by time.
row() {
  printf '%s,%s,%s,%s,%s,%s,%s,%.6f,%s,%s,,%s,%s%s,%s|%s|%s\n' "$SRV_COMMIT" "$SRV_DIRTY" "$1" "$2" "$3" "$4" "$5" "$6" \
    "$(rate "$(($2 * $3))" "$6")" "$7" "$8" "$9" "$EMPTY" "${10}" "${10}" "${11}" >> "$RAW"
}

LOAD=$WORK/gocalbox-load
bench_rm "$LOAD"
go build -o "$LOAD" ./cmd/gocalbox-load

# run_cell ID REP runs one repetition of a cell, appends its row to RAW, and
# sets OUTCOME.
run_cell() {
  local id=$1 rep=$2 ARGS=${CELL_ARGS[$1]} transport size bytes src name code secs got t0 t1 durable
  local tmp=$WORK/load-$STAMP.csv args
  transport=$(value transport https-h2)
  OUTCOME=ok
  case ${CELL_TOOL[$id]} in
    engine | inprocess)
      args=(-csv "$tmp" -reps 1 -size "$(value size 0)" -files "$(value files 1)" -users "$(value users 1)" -parallel "$(value parallel 4)")
      [ -z "$(value resume-at '')" ] || args+=(-resume-at "$(value resume-at '')")
      [ -z "$(value retry-for '')" ] || args+=(-retry-for "$(value retry-for '')")
      bench_rm "$tmp"
      if [ "${CELL_TOOL[$id]}" = engine ]; then
        printf '%s\n' "$SRV_LOAD_PASSWORD" | "$LOAD" "${args[@]}" -url "https://$SERVER_HOST:$PORT" -ca "$WORK/server-ca.crt" \
          -transport "$transport" 2>> "$WORK/load.log" || OUTCOME=failed
      else
        "$LOAD" "${args[@]}" -bench-dir "$BENCH_DIR" -audit-parts="$([ "$(value audit-parts 0)" = 1 ] && echo true || echo false)" \
          -audit-wait="$([ "$(value audit-wait 1)" = 1 ] && echo true || echo false)" -min-free-mb "$(value min-free-mb 1024)" \
          < /dev/null 2>> "$WORK/load.log" || OUTCOME=failed
      fi
      if [ "$OUTCOME" = ok ] && [ "$(wc -l < "$tmp")" = 2 ]; then
        # The run's own start and length place it among the server's samples.
        tail -1 "$tmp" | awk -F, -v OFS=, -v id="$id" -v rep="$rep" -v c="${SRV_COMMIT:-}" -v d="${SRV_DIRTY:-}" '
          { if (c != "") { $1 = c; $2 = d }; $3 = id; $7 = rep; printf "%s|%.6f|%.6f\n", $0, $NF, $NF + $8 }' >> "$RAW"
        code=$(tail -1 "$tmp" | cut -d, -f12)
        [ "$code" = 201 ] || OUTCOME="answered $code"
      else
        OUTCOME=failed
      fi
      bench_rm "$tmp" ;;
    upload)
      size=$(value size 0); src=$(data "$size"); bytes=$(stat -c %s "$src"); name="u-$id.bin"
      curl_for "$transport"
      remote sync
      t0=$EPOCHREALTIME
      IFS=, read -r code secs < <("${CURL[@]}" -o /dev/null -w '%{http_code},%{time_total}\n' -F "myFile=@$src;filename=$name" "$URL/api/upload" || echo "000,0")
      t1=$EPOCHREALTIME
      durable=
      if [ "$code" = 201 ]; then
        a=$EPOCHREALTIME
        remote "$(q sync -- "$SRV_ROOT/$name")"
        durable=$(awk -v s="$secs" -v a="$a" -v b="$EPOCHREALTIME" 'BEGIN {printf "%.6f", s + b - a}')
        # The stored file is checked after the timing.
        got=$(remote "$(q stat -c %s -- "$SRV_ROOT/$name") && $(q sha256sum -- "$SRV_ROOT/$name")" | awk '{printf "%s ", $1}')
        if [ "$got" != "$bytes $(cat "$src.sha256") " ]; then code="$code wrong_file"; OUTCOME="stored size and SHA-256 ${got% } differ from the source's"; fi
        remote_rm "$SRV_ROOT/$name"
      else
        OUTCOME="answered $code"
      fi
      row "$id" "$bytes" 1 1 "$rep" "$secs" "$durable" "$code" "$transport" "$t0" "$t1" ;;
    download)
      size=$(value size 0); bytes=$(numfmt --from=iec "$size"); name="d-$size.bin"
      curl_for "$transport"
      [ "$DROP_CACHES" != 1 ] || remote "sudo -n sh -c 'echo 3 > /proc/sys/vm/drop_caches'"
      local sum=$WORK/sum-$STAMP
      bench_rm "$sum"
      t0=$EPOCHREALTIME
      if [ "$rep" = 0 ]; then
        # A warm-up checks the bytes too; measured runs discard them, so the hash costs them nothing.
        IFS=, read -r code secs got < <({ "${CURL[@]}" -o - -w '%{stderr}%{http_code},%{time_total},%{size_download}\n' "$URL/files/$name" |
          sha256sum | cut -d' ' -f1 > "$sum"; } 2>&1 | tail -1 || echo "000,0,0")
      else
        IFS=, read -r code secs got < <("${CURL[@]}" -o /dev/null -w '%{http_code},%{time_total},%{size_download}\n' "$URL/files/$name" || echo "000,0,0")
      fi
      t1=$EPOCHREALTIME
      if [ "$code" != 200 ]; then OUTCOME="answered $code"
      elif [ "$got" != "$bytes" ]; then code="$code wrong_size"; OUTCOME="got $got of $bytes bytes"
      elif [ -f "$sum" ] && [ "$(cat "$sum")" != "$(cat "$(data "$size").sha256")" ]; then code="$code wrong_file"; OUTCOME="got other bytes"; fi
      bench_rm "$sum"
      row "$id" "$bytes" 1 1 "$rep" "$secs" "" "$code" "$transport" "$t0" "$t1" ;;
    batch)
      local n conc codes=$WORK/codes-$STAMP names=()
      n=$(value files 100); conc=$(value conc 1); src=$(data 1M)
      curl_for "$transport"
      : > "$codes"
      remote sync
      t0=$EPOCHREALTIME
      seq "$n" | xargs -P "$conc" -I{} "${CURL[@]}" -o /dev/null -w '%{http_code}\n' -F "myFile=@$src;filename=b-$id-{}.bin" "$URL/api/upload" >> "$codes" || true
      t1=$EPOCHREALTIME
      code=$(sort "$codes" | uniq -c | awk -v n="$n" '{k[NR] = $1; c[NR] = $2} END {if (NR == 1 && k[1] == n) {print c[1]; exit}
        for (i = 1; i <= NR; i++) printf "%s%sx%s", (i > 1 ? " " : ""), c[i], k[i]; print ""}')
      [ "$code" = 201 ] || OUTCOME="answered $code"
      for i in $(seq "$n"); do names+=("$SRV_ROOT/b-$id-$i.bin"); done
      remote_rm "${names[@]}"
      bench_rm "$codes"
      row "$id" 1048576 "$n" "$conc" "$rep" "$(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.6f", b - a}')" "" "$code" "$transport" "$t0" "$t1" ;;
  esac
}

# place_downloads uploads the files the server's download cells fetch.
place_downloads() {
  local srv=$1 id size src code ARGS
  for id in "${CELL_IDS[@]}"; do
    [ "${CELL_SERVER[$id]}" = "$srv" ] && [ "${CELL_TOOL[$id]}" = download ] || continue
    ARGS=${CELL_ARGS[$id]}; size=$(value size 0); src=$(data "$size")
    [[ " ${PLACED[*]} " = *" $size "* ]] && continue
    curl_for https-h2
    code=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -F "myFile=@$src;filename=d-$size.bin" "$URL/api/upload" || true)
    [ "$code" = 201 ] || { echo "cannot place the $size file for downloads on server $srv: $code" >&2; exit 1; }
    PLACED+=("$size")
  done
}

# iperf DIRECTION prints iperf3's TCP rate from this machine to the server,
# or back with -R, in Mbit/s.
iperf() {
  remote "$(q iperf3 -s -1 -D -p "$IPERF_PORT")" > /dev/null 2>&1 || { echo n/a; return; }
  sleep 0.5
  iperf3 -c "$SERVER_HOST" -p "$IPERF_PORT" -t 10 -f m ${1:+"$1"} 2> /dev/null |
    awk '/receiver/ {r = $(NF - 2)} END {print (r == "" ? "n/a" : r)}'
}
link_rates() {
  if [ "$IPERF" = 1 ] && command -v iperf3 > /dev/null; then
    UP=$(iperf ""); DOWN=$(iperf -R)
  else
    UP=n/a; DOWN=n/a
  fi
}

# --- The session --------------------------------------------------------------

for s in $(for id in "${CELL_IDS[@]}"; do ARGS=${CELL_ARGS[$id]}
  case ${CELL_TOOL[$id]} in upload | download) value size 0 ;; batch) echo 1M ;; esac; done | sort -u); do
  data "$s" > /dev/null
done

if [ "$DROP_CACHES" = 1 ]; then
  for id in "${CELL_IDS[@]}"; do
    [ "${CELL_TOOL[$id]}" = download ] || continue
    remote "sudo -n sh -c 'echo 3 > /proc/sys/vm/drop_caches'" ||
      { echo "DROP_CACHES=1 needs passwordless sudo on the server to drop its page cache; or set DROP_CACHES=0" >&2; exit 1; }
    break
  done
fi
link_rates; UP0=$UP; DOWN0=$DOWN
{
  echo "session: $MATRIX   seed: $SEED   started: $(date -Is)"
  echo "client commit: $(git rev-parse --short HEAD) (dirty=$(git diff --quiet HEAD -- . ':!bench' && echo 0 || echo 1))"
  echo "server: ${SERVER_SSH:-this machine} at $SERVER_HOST:$PORT, repository $SERVER_REPO, benchmark folder $SERVER_BENCH"
  echo "reps: $REPS, $BIG_REPS from 5 GiB; warm-ups: $WARMUP; drop caches before downloads: $DROP_CACHES"
  echo "cells: ${CELLS:-all}"
  echo "iperf3 at the start, Mbit/s: to the server $UP0, from the server $DOWN0"
  echo "--- this machine"
  bench_describe "$BENCH_DIR"
  echo "--- the matrix"
  cat -- "$MATRIX"
} > "$ENV"
"$LOAD" -header > "$CSV"

# end_block stops the block's server, joins its CPU time to each row of
# the block by the run's start and end, and appends the rows to the CSV.
end_block() {
  local samples=/dev/null size left cmd
  [ -n "$CURRENT" ] || return 0
  if [ "$CURRENT" != - ]; then
    for size in "${PLACED[@]}"; do remote_rm "$SRV_ROOT/d-$size.bin" || true; done
    left=
    if [ -n "${SRV_ROOT:-}" ]; then
      cmd="cd $(q "$SRV_ROOT") && find . -path ./.gocalbox -prune -o -type f -print"
      left=$(remote "$cmd" 2> /dev/null || true)
    fi
    if [ -n "$left" ]; then
      echo "warning: runs on server $CURRENT left files in its served folder: $(echo $left)" | tee -a "$ENV" >&2
    fi
    stop_server
    samples=$RUN-server-$CURRENT-samples.csv
    [ -s "$samples" ] || samples=/dev/null
  fi
  # Rows are written before anything is deleted; a block whose rows can't be
  # written keeps them in its raw file.
  awk -F'|' -v OFS=, '
    function cpu_at(t,  lo, hi, mid) {
      if (t <= T[1]) return C[1]
      if (t >= T[n]) return C[n]
      lo = 1; hi = n
      while (hi - lo > 1) { mid = int((lo + hi) / 2); if (T[mid] <= t) lo = mid; else hi = mid }
      return C[lo]
    }
    FILENAME == ARGV[1] { split($0, s, ","); T[++n] = s[1] + 0; C[n] = s[2] + 0; next }
    {
      m = split($1, f, ",")
      if (n > 0 && $2 != "" && $3 != "") f[11] = sprintf("%.4f", cpu_at($3 + 0) - cpu_at($2 + 0))
      line = f[1]; for (i = 2; i <= m; i++) line = line "," f[i]; print line
    }' "$samples" "$RAW" >> "$CSV" || { echo "warning: the rows of server $CURRENT are kept in $RAW" >&2; CURRENT=; return 1; }
  bench_rm "$RAW"
  CURRENT=
}

TOTAL=$(wc -l < "$PLAN")
SEQ=0
CURRENT=
RAW=
PLACED=()
FAILED=0
trap 'end_block || true; close_ssh; bench_rm "$PLAN" || true' EXIT
while read -r srv id rep <&3; do
  if [ "$srv" != "$CURRENT" ]; then
    end_block
    CURRENT=$srv
    RAW=$WORK/raw-$STAMP; : > "$RAW"
    PLACED=()
    unset "${!SRV_@}"
    SRV_COMMIT=; SRV_DIRTY=
    GONE=0
    if [ "$srv" != - ]; then
      echo "server $srv: starting"
      start_server "$srv"
      echo "server $srv: serving at $URL (commit $SRV_COMMIT${SRV_BUILD_TAGS:+, build tags $SRV_BUILD_TAGS})"
      place_downloads "$srv"
    fi
  fi
  SEQ=$((SEQ + 1))
  if [ "$GONE" = 1 ]; then
    echo "$SEQ,$srv,$id,$rep,,,skipped: the server had stopped" >> "$ORDER"
    FAILED=$((FAILED + 1))
    continue
  fi
  t0=$EPOCHREALTIME
  run_cell "$id" "$rep"
  t1=$EPOCHREALTIME
  # The order is a CSV: an outcome holds no comma.
  echo "$SEQ,$srv,$id,$rep,$t0,$t1,${OUTCOME//,/;}" >> "$ORDER"
  [ "$OUTCOME" = ok ] || { FAILED=$((FAILED + 1)); echo "warning: $id rep $rep: $OUTCOME" >&2; }
  if [ "$OUTCOME" != ok ] && [ "$srv" != - ] && ! server_alive; then
    GONE=1
    echo "warning: server $srv stopped; the rest of its runs are skipped" | tee -a "$ENV" >&2
  fi
  echo "[$SEQ/$TOTAL] $id rep $rep: $OUTCOME"
done 3< "$PLAN"
end_block
bench_rm "$PLAN" "$LOAD" "$WORK/server-ca.crt" "$WORK/session-header"

link_rates
{
  echo "iperf3 at the end, Mbit/s: to the server $UP, from the server $DOWN"
  echo "finished: $(date -Is)   runs: $SEQ   not ok: $FAILED"
  echo "--- this machine's network at the end"
  bench_network
} >> "$ENV"
for pair in "$UP0 $UP to" "$DOWN0 $DOWN from"; do
  set -- $pair
  if awk -v a="$1" -v b="$2" 'BEGIN {exit !(a + 0 > 0 && b + 0 > 0 && (b > a * 1.2 || b < a * 0.8))}'; then
    echo "warning: iperf3's rate $3 the server changed from $1 to $2 Mbit/s during the session; run it again" | tee -a "$ENV" >&2
  fi
done
[ "$FAILED" = 0 ] || echo "warning: $FAILED runs were not ok; their rows are marked in http_code and the order file" >&2
echo "results: $CSV"
echo "order: $ORDER"
echo "environment: $ENV"
