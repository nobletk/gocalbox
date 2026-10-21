#!/usr/bin/env bash
# Serves gocalbox for bench/client.sh or bench/session.sh. Run from the
# repository root on the server. Stays in the foreground; Ctrl-C, or
# bench/server.sh stop with the same BENCH_DIR, stops the server and writes
# its environment file.
#
# The server speaks HTTPS with a certificate from a local CA in
# $BENCH_DIR/server/tls, which bench/client.sh fetches over ssh; plain HTTP is
# not served on the network. A server built from a commit before HTTPS speaks
# plain HTTP.
#
# A server with logins gets an admin "bench" with a random password, which
# bench/client.sh reads from $BENCH_DIR/server/run.env over ssh to log in.
#
# Options (environment variables):
#   PORT=18080               port to listen on
#   BIND=0.0.0.0             address to listen on
#   ALLOWED_HOSTS=           extra Host names to accept, comma-separated (for example a DNS name)
#   BENCH_DIR                the benchmark folder (required), made with bench/init.sh: an absolute
#                            path on the disk you serve from. Everything this script writes but its
#                            environment file lives in it, and it deletes nothing outside it.
#   LOG_EVENTS=1             keep the server's console event log on; by default it is
#                            turned off where the server allows it, so its cost is not measured
#   SERVER_FLAGS=            more server flags, separated by commas, such as -audit-parts
#   SERVER_REV=              serve this commit instead of the working tree, built from git archive
#   BUILD_TAGS=              build tags, such as bench for the benchmark-only build, which takes
#                            the GOCALBOX_BENCH_* variables and logs every request to
#                            $BENCH_DIR/server/requests.jsonl
#   LOAD_USERS=0             contributors load00, load01, … for bench/session.sh's load client, with
#                            one random password in $BENCH_DIR/server/run.env
#   ENV_DIR=bench/results    where the environment file goes; bench/session.sh has it written into the
#                            benchmark folder and adds it to the session's results
set -euo pipefail
export LC_ALL=C

PORT=${PORT:-18080}
BIND=${BIND:-0.0.0.0}
ALLOWED_HOSTS=${ALLOWED_HOSTS:-}
LOG_EVENTS=${LOG_EVENTS:-0}
SERVER_FLAGS=${SERVER_FLAGS:-}
SERVER_REV=${SERVER_REV:-}
BUILD_TAGS=${BUILD_TAGS:-}
LOAD_USERS=${LOAD_USERS:-0}
ENV_DIR=${ENV_DIR:-bench/results}

[ -f go.mod ] && [ -d cmd/gocalbox ] || { echo "run from the repository root" >&2; exit 1; }
[ -z "${WORK:-}" ] || { echo "WORK is replaced by BENCH_DIR, a folder made with bench/init.sh" >&2; exit 1; }
. bench/lib/safe.sh
. bench/lib/env.sh
bench_use "${BENCH_DIR:-}" || exit 1
WORK=$BENCH_DIR/server
ROOT="$WORK/root"
AUDIT="$WORK/audit.jsonl"
TLS_DIR="$WORK/tls"
SAMPLES="$WORK/samples.csv"
PIDFILE="$WORK/server.pid"
SERVERPID="$WORK/gocalbox.pid"
READY="$WORK/ready"
REQUESTS="$WORK/requests.jsonl"

# started PID prints when the process PID started, which tells it from a
# later process given the same PID.
started() {
  local s
  s=$(cat "/proc/$1/stat" 2> /dev/null) || return 1
  s=${s##*) }
  set -- $s
  echo "${20}"
}

# record FILE PID writes the process PID to FILE, with when it started.
record() { echo "$2 $(started "$2")" > "$1"; }

# alive FILE prints the PID FILE records, if that process still runs.
alive() {
  local pid start
  [ -f "$1" ] || return 1
  read -r pid start < "$1" || return 1
  [[ $pid =~ ^[0-9]+$ ]] && [ "$pid" != "$$" ] && [ -n "$start" ] && [ "$(started "$pid")" = "$start" ] && echo "$pid"
}

# ended PID SECONDS waits for the process PID to end.
ended() {
  for _ in $(seq $(($2 * 10))); do kill -0 "$1" 2> /dev/null || return 0; sleep 0.1; done
  return 1
}

# stop ends the server.sh running with this BENCH_DIR, and waits for it to
# write its environment file. A server whose bench/server.sh was killed is
# stopped too.
if [ "${1:-}" = stop ]; then
  if pid=$(alive "$PIDFILE"); then
    kill -TERM "$pid"
    ended "$pid" 60 || { echo "bench/server.sh did not stop within a minute" >&2; exit 1; }
  elif pid=$(alive "$SERVERPID"); then
    kill -TERM "$pid"
    ended "$pid" 30 || kill -KILL "$pid"
    bench_rm "$PIDFILE" "$SERVERPID" "$READY"
    echo "stopped the server that a bench/server.sh killed before it had left running"
  else
    echo "no bench/server.sh is running with $BENCH_DIR" >&2; exit 1
  fi
  exit 0
fi
[ "$#" = 0 ] || { echo "usage: bench/server.sh [stop]" >&2; exit 2; }
[[ $LOAD_USERS =~ ^[0-9]{1,2}$ ]] || { echo "LOAD_USERS must be a number from 0 to 99" >&2; exit 1; }
case " ${BUILD_TAGS//,/ } " in
  *" bench "*) BENCH_BUILD=1 ;;
  *) BENCH_BUILD=0
     if [ -n "$(compgen -e GOCALBOX_BENCH_ || true)" ]; then
       echo "the GOCALBOX_BENCH_* variables need BUILD_TAGS=bench; without it the server ignores them" >&2; exit 1
     fi ;;
esac
for tool in git go awk getconf curl tar; do command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }; done

mkdir -p "$WORK"
if alive "$PIDFILE" > /dev/null || alive "$SERVERPID" > /dev/null; then
  echo "another bench/server.sh, or a server it left, is running with $BENCH_DIR; stop it with bench/server.sh stop" >&2; exit 1
fi
bench_rm "$PIDFILE" "$SERVERPID" "$READY"
record "$PIDFILE" "$$"
trap 'bench_rm "$PIDFILE"' EXIT
trap 'exit 1' INT TERM

SRC=$PWD
if [ -n "$SERVER_REV" ]; then
  COMMIT=$(git rev-parse --short "$SERVER_REV^{commit}")
  DIRTY=0
  # Built from the commit alone, so nothing of the working tree is measured.
  SRC=$WORK/src
  bench_rm "$SRC"; mkdir -p "$SRC"
  git archive "$COMMIT" | tar -x -C "$SRC"
else
  COMMIT=$(git rev-parse --short HEAD)
  DIRTY=0; git diff --quiet HEAD -- . ':!bench' || DIRTY=1
  [ "$DIRTY" = 1 ] && echo "warning: uncommitted changes; results are marked dirty=1" >&2
fi
STAMP=$(date +%Y%m%d-%H%M%S)
TICK=$(getconf CLK_TCK)
ENV="$ENV_DIR/server-$COMMIT-$STAMP-env.txt"

mkdir -p "$ENV_DIR"
bench_rm "$ROOT" "$AUDIT" "$SAMPLES" "$REQUESTS"; mkdir -p "$ROOT"
GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)
[ "$GOVERNOR" = performance ] || echo "warning: CPU governor is '$GOVERNOR', not 'performance'; results will not be comparable" >&2
(cd "$SRC" && go build ${BUILD_TAGS:+-tags "$BUILD_TAGS"} -o "$WORK/gocalbox" ./cmd/gocalbox)
BENCH_SETTINGS=$(compgen -e GOCALBOX_BENCH_ | while read -r v; do printf '%s=%s ' "$v" "${!v}"; done || true)
BENCH_SETTINGS=${BENCH_SETTINGS% }
if [ "$BENCH_BUILD" = 1 ]; then
  export GOCALBOX_BENCH_REQUEST_LOG=$REQUESTS
fi

ALLOW=()
[ -n "$ALLOWED_HOSTS" ] && ALLOW=(-allowed-hosts "$ALLOWED_HOSTS")
IFS=, read -r -a EXTRA <<< "$SERVER_FLAGS"
SERVER_CMD=("$WORK/gocalbox" -host "$BIND" -port "$PORT" -root "$ROOT" -audit-log "$AUDIT" \
  -max-upload-mb 0 "${ALLOW[@]}" "${EXTRA[@]}")
FLAGS=$("$WORK/gocalbox" -h 2>&1 || true)
case $FLAGS in
  # Servers from before logins refuse a network address without it.
  *-insecure-no-auth*) SERVER_CMD+=(-insecure-no-auth) ;;
esac
SCHEME=http
CA=
CURL=(curl -fs --max-time 2)
case $FLAGS in
  *-tls-dir*) SERVER_CMD+=(-tls-dir "$TLS_DIR"); SCHEME=https; CA="$TLS_DIR/ca.crt"; CURL+=(--cacert "$CA") ;;
esac
CONSOLE_LOG=on
if [ "$LOG_EVENTS" != 1 ]; then
  case $FLAGS in
    *-log-events*) SERVER_CMD+=(-log-events=false); CONSOLE_LOG=off ;;
    *) echo "warning: this server has no -log-events flag, so its console event log is part of what is measured" >&2 ;;
  esac
fi

LOGIN_USER=
LOGIN_PW=
LOAD_PW=
case $FLAGS in
  *-state*)
    # Without an admin the server starts in setup mode and refuses every file request.
    STATE="$WORK/state.db"; bench_rm "$STATE"
    BENCH_PW=$(head -c 24 /dev/urandom | base64)
    printf '%s\n' "$BENCH_PW" | "$WORK/gocalbox" users add -username bench -role admin -state "$STATE" -audit-log "$AUDIT" > /dev/null
    SERVER_CMD+=(-state "$STATE")
    case $FLAGS in *-session-idle*) LOGIN_USER=bench; LOGIN_PW=$BENCH_PW ;; esac
    if [ "$LOAD_USERS" -gt 0 ]; then
      LOAD_PW=$(head -c 24 /dev/urandom | base64)
      for i in $(seq 0 $((LOAD_USERS - 1))); do
        printf '%s\n' "$LOAD_PW" | "$WORK/gocalbox" users add -username "$(printf 'load%02d' "$i")" -role contributor -state "$STATE" -audit-log "$AUDIT" > /dev/null
      done
    fi ;;
  *) [ "$LOAD_USERS" = 0 ] || { echo "this server has no logins, so LOAD_USERS can't make its users" >&2; exit 1; } ;;
esac

FREE_AT_START=$(df -B1 --output=avail "$ROOT" 2>/dev/null | tail -1 | tr -d ' ' || true)

# Read by bench/client.sh over ssh, which evaluates it. It holds the password, so only the owner may read it.
bench_rm "$WORK/run.env"
(umask 077; {
  printf 'SRV_COMMIT=%q\n' "$COMMIT"
  printf 'SRV_DIRTY=%q\n' "$DIRTY"
  printf 'SRV_BENCH=%q\n' "$BENCH_DIR"
  printf 'SRV_SAFE=%q\n' "$PWD/bench/lib/safe.sh"
  printf 'SRV_ROOT=%q\n' "$ROOT"
  printf 'SRV_SAMPLES=%q\n' "$SAMPLES"
  printf 'SRV_ENV=%q\n' "$ENV"
  printf 'SRV_GOVERNOR=%q\n' "$GOVERNOR"
  printf 'SRV_CMD=%q\n' "${SERVER_CMD[*]@Q}"
  printf 'SRV_CONSOLE_LOG=%q\n' "$CONSOLE_LOG"
  printf 'SRV_SCHEME=%q\n' "$SCHEME"
  printf 'SRV_CA=%q\n' "$CA"
  printf 'SRV_USER=%q\n' "$LOGIN_USER"
  printf 'SRV_PASSWORD=%q\n' "$LOGIN_PW"
  printf 'SRV_LOAD_USERS=%q\n' "$LOAD_USERS"
  printf 'SRV_LOAD_PASSWORD=%q\n' "$LOAD_PW"
  printf 'SRV_BUILD_TAGS=%q\n' "$BUILD_TAGS"
  printf 'SRV_BENCH_SETTINGS=%q\n' "$BENCH_SETTINGS"
  printf 'SRV_REQUESTS=%q\n' "$([ "$BENCH_BUILD" = 1 ] && echo "$REQUESTS")"
  printf 'SRV_LOG=%q\n' "$WORK/server.log"
} > "$WORK/run.env")

PID=
SAMP_PID=
finish() {
  # A second stop while this runs mustn't cut it short: the environment file and the pid files come last.
  trap '' INT TERM
  [ -n "$SAMP_PID" ] && kill "$SAMP_PID" 2>/dev/null || true
  [ -n "$PID" ] && kill "$PID" 2>/dev/null || true
  [ -n "$PID" ] && wait "$PID" 2>/dev/null || true
  {
    echo "server: $COMMIT (dirty=$DIRTY)${SERVER_REV:+ from SERVER_REV=$SERVER_REV}   started: $STAMP"
    echo "build tags: ${BUILD_TAGS:-none}"
    echo "benchmark settings: ${BENCH_SETTINGS:-none}"
    bench_describe "$ROOT"
    echo "free space on served volume at start: ${FREE_AT_START:-unknown} bytes"
    echo "server command: ${SERVER_CMD[*]@Q}"
    echo "console event log: $CONSOLE_LOG"
    echo "scheme: $SCHEME"
    echo "load users: $LOAD_USERS"
    echo "server peak RSS (kB): $(tail -1 "$SAMPLES" 2>/dev/null | cut -d, -f3 || true)"
    echo "audit records: $(wc -l < "$AUDIT" 2>/dev/null || echo 0)"
  } > "$ENV"
  bench_rm "$PIDFILE" "$SERVERPID" "$READY"
  echo "stopped; environment written to $ENV"
}
# Installed before the server starts, so a failure below cannot leave it running.
trap finish EXIT
trap 'exit 0' INT TERM

"${SERVER_CMD[@]}" > "$WORK/server.log" 2>&1 &
PID=$!
record "$SERVERPID" "$PID"

# Cumulative CPU seconds and peak RSS (kB) every 0.1 s, joined by the client to each operation's timestamps.
(
  while kill -0 "$PID" 2>/dev/null; do
    echo "$(date +%s.%N),$(awk -v t="$TICK" '{print ($14+$15)/t}' "/proc/$PID/stat" 2>/dev/null || echo 0),$(awk '/VmHWM/{print $2}' "/proc/$PID/status" 2>/dev/null || echo 0)" >> "$SAMPLES"
    sleep 0.1
  done
) &
SAMP_PID=$!

LOCAL=127.0.0.1
[ "$BIND" = 0.0.0.0 ] || [ "$BIND" = :: ] || LOCAL=$BIND
UP=0
for _ in $(seq 150); do
  if "${CURL[@]}" -o /dev/null "$SCHEME://$LOCAL:$PORT/" 2>/dev/null; then UP=1; break; fi
  kill -0 "$PID" 2>/dev/null || break
  sleep 0.1
done
[ "$UP" = 1 ] || { echo "the server didn't start; its log:" >&2; tail -20 "$WORK/server.log" >&2; exit 1; }
if [ "$BENCH_BUILD" = 1 ] && ! grep -q "BENCHMARK BUILD" "$WORK/server.log"; then
  echo "BUILD_TAGS=bench, but the server is no benchmark build (a commit from before it?)" >&2; exit 1
fi
echo "$PID" > "$READY"
echo "serving $SCHEME on $BIND:$PORT (commit $COMMIT); press Ctrl-C to stop"
[ "$SCHEME" = https ] && grep -m1 "HTTPS certificate" "$WORK/server.log" | sed 's/^[0-9/]* [0-9:]* //' || true

wait "$PID" || true
