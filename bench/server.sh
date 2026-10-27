#!/usr/bin/env bash
# Serves gocalbox, or a baseline (tusd, or OpenSSH's sshd for SFTP and scp),
# for bench/client.sh or bench/session.sh. Run from the repository root on
# the server. Stays in the foreground; Ctrl-C, or
# bench/server.sh stop with the same BENCH_DIR, stops the server and writes
# its environment file. bench/server.sh crash, with the same BENCH_DIR, kills
# the server with SIGKILL and starts it again on the same folder and state,
# as after a crash, and returns once it serves again.
#
# The server speaks HTTPS with a certificate from a local CA in
# $BENCH_DIR/server/tls, which bench/client.sh fetches over ssh; plain HTTP is
# not served on the network. A server built from a commit before HTTPS speaks
# plain HTTP.
#
# A server with logins gets an admin "bench" with a random password, which
# bench/client.sh reads from $BENCH_DIR/server/run.env over ssh to log in.
#
# KIND=tusd serves tusd, the reference tus server, over HTTPS with a
# certificate from a local CA in $BENCH_DIR/server/tls-tusd, storing in the
# served folder; uploads are created at /files/, without logins.
#
# KIND=sshd runs a private OpenSSH server as this user, on PORT, with its own
# host key and configuration in $BENCH_DIR/server/ssh: it takes only the key
# AUTHORIZED_KEY, as this user, and only for SFTP (which scp uses too),
# starting in the served folder. SFTP can reach what this user can, as with
# any sshd. The system's sshd and its settings are left alone.
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
#   KIND=gocalbox            gocalbox, tusd or sshd; LOG_EVENTS, ALLOWED_HOSTS, PORT and BIND apply to each,
#                            the settings of the gocalbox build to gocalbox only
#   TUSD=tusd                with KIND=tusd: tusd v2, a released binary, on PATH or as a path
#   SSHD=                    with KIND=sshd: OpenSSH's sshd, by default the one on PATH or in /usr/sbin
#   AUTHORIZED_KEY=          with KIND=sshd: the public key that may log in, one line of an
#                            authorized_keys file
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
KIND=${KIND:-gocalbox}
TUSD=${TUSD:-tusd}
SSHD=${SSHD:-}
AUTHORIZED_KEY=${AUTHORIZED_KEY:-}

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
KILLED_CPU="$WORK/killed-cpu"
READY="$WORK/ready"
REQUESTS="$WORK/requests.jsonl"
KIND_FILE="$WORK/kind"

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
    bench_rm "$PIDFILE" "$SERVERPID" "$READY" "$KILLED_CPU"
    echo "stopped the server that a bench/server.sh killed before it had left running"
  else
    echo "no bench/server.sh is running with $BENCH_DIR" >&2; exit 1
  fi
  exit 0
fi
if [ "${1:-}" = crash ]; then
  pid=$(alive "$PIDFILE") || { echo "no bench/server.sh is running with $BENCH_DIR" >&2; exit 1; }
  old=$(cat "$READY" 2> /dev/null) || { echo "the server with $BENCH_DIR isn't serving yet" >&2; exit 1; }
  # Killing sshd's listener would leave its sessions running.
  [ "$(cat "$KIND_FILE" 2> /dev/null)" != sshd ] || { echo "bench/server.sh crash doesn't crash an sshd" >&2; exit 1; }
  start=$EPOCHREALTIME
  kill -USR1 "$pid"
  for _ in $(seq 1200); do
    new=$(cat "$READY" 2> /dev/null || true)
    if [ -n "$new" ] && [ "$new" != "$old" ]; then
      echo "killed the server and started it again; it served again after $(awk -v a="$start" -v b="$EPOCHREALTIME" 'BEGIN {printf "%.3f", b - a}')s"
      exit 0
    fi
    kill -0 "$pid" 2> /dev/null || { echo "bench/server.sh ended instead of starting the server again" >&2; exit 1; }
    sleep 0.1
  done
  echo "the server didn't serve again within 2 minutes" >&2; exit 1
fi
[ "$#" = 0 ] || { echo "usage: bench/server.sh [stop|crash]" >&2; exit 2; }
[[ $LOAD_USERS =~ ^[0-9]{1,2}$ ]] || { echo "LOAD_USERS must be a number from 0 to 99" >&2; exit 1; }
case $KIND in
  gocalbox) ;;
  tusd | sshd)
    for v in BUILD_TAGS SERVER_REV SERVER_FLAGS; do
      [ -z "${!v}" ] || { echo "$v is for gocalbox; KIND=$KIND would ignore it" >&2; exit 1; }
    done
    [ "$LOAD_USERS" = 0 ] || { echo "LOAD_USERS is for gocalbox; KIND=$KIND has no users to make" >&2; exit 1; }
    [ -z "$(compgen -e GOCALBOX_BENCH_ || true)" ] || { echo "the GOCALBOX_BENCH_* variables are for gocalbox; KIND=$KIND would ignore them" >&2; exit 1; } ;;
  *) echo "KIND must be gocalbox, tusd or sshd" >&2; exit 1 ;;
esac
case " ${BUILD_TAGS//,/ } " in
  *" bench "*) BENCH_BUILD=1 ;;
  *) BENCH_BUILD=0
     if [ -n "$(compgen -e GOCALBOX_BENCH_ || true)" ]; then
       echo "the GOCALBOX_BENCH_* variables need BUILD_TAGS=bench; without it the server ignores them" >&2; exit 1
     fi ;;
esac
case $KIND in
  gocalbox) TOOLS="git go awk getconf curl tar" ;;
  tusd) TOOLS="git awk getconf curl openssl" ;;
  sshd) TOOLS="git go awk getconf ssh-keygen id" ;;
esac
for tool in $TOOLS; do command -v "$tool" >/dev/null || { echo "missing: $tool" >&2; exit 1; }; done

mkdir -p "$WORK"
if alive "$PIDFILE" > /dev/null || alive "$SERVERPID" > /dev/null; then
  echo "another bench/server.sh, or a server it left, is running with $BENCH_DIR; stop it with bench/server.sh stop" >&2; exit 1
fi
bench_rm "$PIDFILE" "$SERVERPID" "$READY" "$KILLED_CPU" "$KIND_FILE"
echo "$KIND" > "$KIND_FILE"
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
# tusd_cert makes a CA and a certificate signed by it for this machine's names
# and addresses, as gocalbox makes its own, with the same kind of key.
tusd_cert() {
  local dir=$1 sans="DNS:localhost,IP:127.0.0.1,IP:::1" a h
  bench_rm "$dir"; mkdir -p "$dir"
  h=$(hostname 2> /dev/null || true)
  [[ $h =~ ^[A-Za-z0-9.-]+$ ]] && sans+=",DNS:$h"
  # Arch's hostname has no -I, so the addresses come from ip where it is.
  for a in $({ { ip -o addr show 2> /dev/null || true; } | awk '{sub(/\/.*/, "", $4); print $4}'; hostname -I 2> /dev/null | tr ' ' '\n' || true; } | sort -u); do
    [[ $a =~ ^[0-9A-Fa-f.:]+$ ]] && [[ $a != fe80:* && $a != 127.0.0.1 && $a != ::1 ]] && sans+=",IP:$a"
  done
  IFS=, read -r -a hosts <<< "$ALLOWED_HOSTS"
  for a in "${hosts[@]}"; do
    if [[ $a =~ ^[0-9.]+$ || $a = *:* ]]; then sans+=",IP:$a"; elif [[ $a =~ ^[A-Za-z0-9.-]+$ ]]; then sans+=",DNS:$a"; fi
  done
  (umask 077
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 30 -subj "/CN=gocalbox benchmark tusd CA" \
      -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" -keyout "$dir/ca.key" -out "$dir/ca.crt" 2> /dev/null
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" -keyout "$dir/server.key" -out "$dir/server.csr" 2> /dev/null
    openssl x509 -req -in "$dir/server.csr" -CA "$dir/ca.crt" -CAkey "$dir/ca.key" -days 30 -set_serial "0x$(openssl rand -hex 8)" \
      -extfile <(printf 'subjectAltName=%s\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "$sans") \
      -out "$dir/server.crt" 2> /dev/null) || { echo "openssl cannot make tusd's certificate" >&2; exit 1; }
  bench_rm "$dir/server.csr" "$dir/ca.key"
  chmod 644 "$dir/ca.crt"
}

# sshd_quote prints a path as sshd_config reads it, refusing the characters
# it would read otherwise: quotes, backslashes, and % with its expansions.
sshd_quote() {
  [[ $1 != *[\"\\%]* && $1 != *$'\n'* ]] || { echo "sshd can't be given a path with \", \\, % or a new line: $1" >&2; exit 1; }
  printf '"%s"' "$1"
}

VERSION=
SSH_USER=
HOSTKEY=
LOGIN_USER=
LOGIN_PW=
LOAD_PW=
BENCH_SETTINGS=
READY_PATH=/
case $KIND in
  gocalbox)
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
    ;;
  tusd)
    TUSD_BIN=$(command -v -- "$TUSD" || true)
    [ -n "$TUSD_BIN" ] && [ -x "$TUSD_BIN" ] || { echo "no tusd at '$TUSD': put tusd v2 on PATH, or set TUSD to its path (bench/README.md)" >&2; exit 1; }
    VERSION=$("$TUSD_BIN" -version 2>&1 | head -5 | tr -s '\n' ' ' || true)
    FLAGS=$("$TUSD_BIN" -help 2>&1 || true)
    for f in -host -port -upload-dir -base-path -tls-certificate -tls-key; do
      [[ $FLAGS = *"$f"* ]] || { echo "this tusd has no $f flag; bench/README.md names the version to use" >&2; exit 1; }
    done
    TLS_DIR="$WORK/tls-tusd"
    tusd_cert "$TLS_DIR"
    SERVER_CMD=("$TUSD_BIN" -host "$BIND" -port "$PORT" -upload-dir "$ROOT" -base-path /files/ \
      -tls-certificate "$TLS_DIR/server.crt" -tls-key "$TLS_DIR/server.key")
    # tusd logs every request, and no flag stops it: -verbose=false leaves the fewest lines.
    CONSOLE_LOG="on, every request"
    if [ "$LOG_EVENTS" != 1 ]; then
      case $FLAGS in
        *-verbose*) SERVER_CMD+=(-verbose=false); CONSOLE_LOG="on, every request, with -verbose=false" ;;
        *) echo "warning: this tusd has no -verbose flag" >&2 ;;
      esac
    fi
    SCHEME=https
    CA="$TLS_DIR/ca.crt"
    # tusd answers OPTIONS on its endpoint with the protocol's versions.
    CURL=(curl -fs --max-time 2 --cacert "$CA" -X OPTIONS)
    READY_PATH=/files/ ;;
  sshd)
    if [ -z "$SSHD" ]; then
      SSHD=$(command -v sshd || true)
      for c in /usr/sbin/sshd /usr/bin/sshd; do [ -n "$SSHD" ] || { [ -x "$c" ] && SSHD=$c; }; done
    fi
    # sshd runs only from an absolute path, which it uses to start its sessions.
    [[ $SSHD = /* ]] && [ -x "$SSHD" ] || { echo "no sshd at '${SSHD:-}': install OpenSSH, or set SSHD to its absolute path" >&2; exit 1; }
    [[ $AUTHORIZED_KEY =~ ^(ssh-ed25519|ecdsa-sha2-nistp[0-9]+|ssh-rsa)\ [A-Za-z0-9+/=]+( [^$'\n']*)?$ ]] ||
      { echo "KIND=sshd needs AUTHORIZED_KEY, the client's public key: one line of an authorized_keys file" >&2; exit 1; }
    VERSION=$("$SSHD" -V 2>&1 | head -1 || true)
    SSH_DIR="$WORK/ssh"
    mkdir -p "$SSH_DIR"
    HOSTKEY="$SSH_DIR/host_ed25519"
    [ -f "$HOSTKEY" ] || ssh-keygen -q -t ed25519 -N '' -C "gocalbox benchmark sshd" -f "$HOSTKEY" > /dev/null
    SSH_USER=$(id -un)
    [[ $SSH_USER =~ ^[A-Za-z0-9._][A-Za-z0-9._-]*$ ]] || { echo "the user name '$SSH_USER' can't be named in sshd's settings" >&2; exit 1; }
    bench_rm "$SSH_DIR/authorized_keys" "$SSH_DIR/sshd_config" "$SSH_DIR/sshd.pid"
    (umask 077; printf '%s\n' "$AUTHORIZED_KEY" > "$SSH_DIR/authorized_keys")
    # Only this user, only with the key, only SFTP, in the served folder: no shell, no forwarding, and none of the
    # system's settings. internal-sftp starts no login shell, whose start-up files could slow or break a transfer.
    {
      echo "Port $PORT"
      echo "ListenAddress $BIND"
      echo "HostKey $(sshd_quote "$HOSTKEY")"
      echo "PidFile $(sshd_quote "$SSH_DIR/sshd.pid")"
      echo "AuthorizedKeysFile $(sshd_quote "$SSH_DIR/authorized_keys")"
      echo "AllowUsers $SSH_USER"
      echo "AuthenticationMethods publickey"
      echo "PubkeyAuthentication yes"
      echo "PasswordAuthentication no"
      echo "KbdInteractiveAuthentication no"
      echo "PermitRootLogin no"
      echo "UsePAM no"
      echo "StrictModes no"
      echo "DisableForwarding yes"
      echo "PermitTTY no"
      echo "PermitUserRC no"
      echo "Subsystem sftp internal-sftp"
      echo "ForceCommand internal-sftp -d $(sshd_quote "$ROOT")"
    } > "$SSH_DIR/sshd_config"
    out=$("$SSHD" -t -f "$SSH_DIR/sshd_config" 2>&1) || { echo "sshd refuses its settings: $out" >&2; exit 1; }
    # A connection's monitor exits without waiting for its session's process: only a subreaper above sshd
    # is left to reap it, and so to count its CPU time.
    go build -o "$WORK/subreaper" ./bench/subreaper
    SERVER_CMD=("$WORK/subreaper" "$SSHD" -D -e -f "$SSH_DIR/sshd_config")
    CONSOLE_LOG=on
    SCHEME=ssh
    CA= ;;
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
  printf 'SRV_KIND=%q\n' "$KIND"
  printf 'SRV_VERSION=%q\n' "$VERSION"
  printf 'SRV_SSH_USER=%q\n' "$SSH_USER"
  printf 'SRV_HOSTKEY=%q\n' "${HOSTKEY:+$HOSTKEY.pub}"
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
    echo "kind: $KIND${VERSION:+   version: $VERSION}"
    echo "build tags: ${BUILD_TAGS:-none}"
    echo "benchmark settings: ${BENCH_SETTINGS:-none}"
    bench_describe "$ROOT"
    echo "free space on served volume at start: ${FREE_AT_START:-unknown} bytes"
    echo "server command: ${SERVER_CMD[*]@Q}"
    echo "console event log: $CONSOLE_LOG"
    echo "scheme: $SCHEME"
    echo "load users: $LOAD_USERS"
    echo "crashes: ${CRASHES:-0}"
    echo "server peak RSS (kB): $(tail -1 "$SAMPLES" 2>/dev/null | cut -d, -f3 || true)$([ "$KIND" = sshd ] && echo ", the largest sum over sshd's processes")"
    echo "audit records: $(wc -l < "$AUDIT" 2>/dev/null || echo 0)"
  } > "$ENV"
  bench_rm "$PIDFILE" "$SERVERPID" "$READY" "$KILLED_CPU" "$KIND_FILE"
  echo "stopped; environment written to $ENV"
}
# Installed before the server starts, so a failure below cannot leave it running.
trap finish EXIT
trap 'exit 0' INT TERM

"${SERVER_CMD[@]}" > "$WORK/server.log" 2>&1 &
PID=$!
record "$SERVERPID" "$PID"

# tree_usage PID prints the CPU clock ticks of a process and every process below it, and the sum of
# the peak RSS (kB) of those below it: PID is the subreaper, whose memory isn't the server's. A
# process's time counts once: while it runs, by its own time, and once it is reaped, in its parent's
# time of children reaped, which then counts for the parent alone. Builtins only, so that sampling
# a tree of sshd's costs no more processes than sampling gocalbox does.
tree_usage() {
  local -a todo=("$1") f kids
  local p s ticks=0 rss=0 k v c tf i=0
  while [ "$i" -lt "${#todo[@]}" ]; do
    p=${todo[$i]}; i=$((i + 1))
    { read -r s < "/proc/$p/stat"; } 2> /dev/null || continue
    read -r -a f <<< "${s##*) }"
    ticks=$((ticks + f[11] + f[12] + f[13] + f[14]))
    if [ "$i" -gt 1 ]; then
      while read -r k v _; do
        if [ "$k" = VmHWM: ]; then rss=$((rss + v)); break; fi
      done 2> /dev/null < "/proc/$p/status" || true
    fi
    for tf in /proc/"$p"/task/*/children; do
      # The file's one line has no line end, so read fails at its end, having read it.
      kids=()
      { read -r -a kids < "$tf" || true; } 2> /dev/null
      for c in "${kids[@]}"; do todo+=("$c"); done
    done
  done
  [ "$i" -gt 0 ] && [ "$ticks" -gt 0 ] || [ -d "/proc/$1" ] || return 1
  echo "$ticks $rss"
}

# CPU seconds and peak RSS (kB) every 0.1 s, joined by the client to each operation's timestamps.
# Both carry on across a crash and restart, so that a run's CPU is the difference of two samples.
# sshd's sessions are processes of their own, counted with it, under the subreaper that runs it.
(
  base=0; last=0; cur=; peak=0
  while kill -0 $$ 2> /dev/null; do
    p=
    read -r p _ < "$SERVERPID" 2> /dev/null || true
    rss=
    if [ "$KIND" = sshd ] && [ -n "$p" ] && read -r ticks rss < <(tree_usage "$p") && [ -n "$ticks" ]; then
      [ "${rss:-0}" -le "$peak" ] || peak=$rss
      # A child reaped between the scan's read of its parent and of the child itself, or one being
      # re-parented, is missed by that scan; its time is back in the next. Sampled this way, the true
      # value only grows, so a sample never falls below the one before.
      [ "$ticks" -ge "$last" ] || ticks=$last
      last=$ticks
      echo "${EPOCHREALTIME},$(awk -v t="$ticks" -v k="$TICK" 'BEGIN {print t / k}'),$peak" >> "$SAMPLES"
    elif [ "$KIND" != sshd ] && [ -n "$p" ] && cpu=$(awk -v t="$TICK" '{sub(/.*\) /, ""); print ($12+$13)/t}' "/proc/$p/stat" 2> /dev/null) && [ -n "$cpu" ]; then
      if [ "$p" != "$cur" ]; then
        # A killed server's last CPU time, read while it was stopped, counts what it used after its last sample.
        if [ -n "$cur" ] && read -r kp kc < "$KILLED_CPU" 2> /dev/null && [ "$kp" = "$cur" ]; then last=$kc; fi
        base=$(awk -v a="$base" -v b="$last" 'BEGIN {print a + b}'); cur=$p
      fi
      last=$cpu
      rss=$(awk '/VmHWM/{print $2}' "/proc/$p/status" 2> /dev/null || echo 0)
      [ "${rss:-0}" -le "$peak" ] || peak=$rss
      echo "$(date +%s.%N),$(awk -v a="$base" -v b="$cpu" 'BEGIN {print a + b}'),$peak" >> "$SAMPLES"
    fi
    sleep 0.1
  done
) &
SAMP_PID=$!

LOCAL=127.0.0.1
[ "$BIND" = 0.0.0.0 ] || [ "$BIND" = :: ] || LOCAL=$BIND
# serving waits until the server answers, and fails if it ends first.
serving() {
  for _ in $(seq 150); do
    if [ "$SCHEME" = ssh ]; then
      # sshd greets every connection with its version.
      [ "$(timeout 2 bash -c 'exec 3<> "/dev/tcp/$0/$1" && head -c 4 <&3' "$LOCAL" "$PORT" 2> /dev/null)" = SSH- ] && return 0
    elif "${CURL[@]}" -o /dev/null "$SCHEME://$LOCAL:$PORT$READY_PATH" 2>/dev/null; then return 0; fi
    kill -0 "$PID" 2>/dev/null || return 1
    sleep 0.1
  done
  return 1
}
serving || { echo "the server didn't start; its log:" >&2; tail -20 "$WORK/server.log" >&2; exit 1; }
if [ "$BENCH_BUILD" = 1 ] && ! grep -q "BENCHMARK BUILD" "$WORK/server.log"; then
  echo "BUILD_TAGS=bench, but the server is no benchmark build (a commit from before it?)" >&2; exit 1
fi
CRASH=0
CRASHES=0
# crash stops the server, keeps its CPU time for the samples, and kills it. Killing it here, rather than
# in the loop below, ends a wait that began after the loop looked at CRASH.
crash() {
  local cpu
  CRASH=1
  kill -STOP "$PID" 2> /dev/null || return 0
  for _ in $(seq 100); do
    [ "$(awk '{sub(/.*\) /, ""); print $1}' "/proc/$PID/stat" 2> /dev/null)" != T ] || break
    sleep 0.01
  done
  cpu=$(awk -v t="$TICK" '{sub(/.*\) /, ""); print ($12+$13)/t}' "/proc/$PID/stat" 2> /dev/null || true)
  [ -z "$cpu" ] || echo "$PID $cpu" > "$KILLED_CPU"
  kill -KILL "$PID" 2> /dev/null || true
}
# Before the ready file, which bench/server.sh crash waits for: a USR1 without the trap would end this script.
trap crash USR1
echo "$PID" > "$READY"
echo "serving $SCHEME on $BIND:$PORT (commit $COMMIT); press Ctrl-C to stop"
[ "$SCHEME" = https ] && grep -m1 "HTTPS certificate" "$WORK/server.log" | sed 's/^[0-9/]* [0-9:]* //' || true

while :; do
  # A USR1 that came before the wait has killed the server already.
  [ "$CRASH" = 1 ] || wait "$PID" || true
  [ "$CRASH" = 1 ] || break
  CRASH=0
  CRASHES=$((CRASHES + 1))
  kill -KILL "$PID" 2> /dev/null || true
  wait "$PID" 2> /dev/null || true
  bench_rm "$READY"
  echo "$(date '+%Y/%m/%d %H:%M:%S') bench/server.sh: killed the server with SIGKILL; starting it again" >> "$WORK/server.log"
  "${SERVER_CMD[@]}" >> "$WORK/server.log" 2>&1 &
  PID=$!
  record "$SERVERPID" "$PID"
  serving || { echo "the server didn't start again; its log:" >&2; tail -20 "$WORK/server.log" >&2; exit 1; }
  echo "$PID" > "$READY"
  echo "the server serves again after a crash"
done
