#!/usr/bin/env bash
# Keeps the benchmark scripts from deleting anything they didn't make.
#
# Everything a benchmark writes lives in one benchmark folder per machine,
# made by bench/init.sh, which leaves a marker file with a random ID in it.
# The scripts refuse a folder without the marker, and delete only through
# bench_rm and bench_empty, which refuse anything outside it.
#
# Sourced by the scripts:  . bench/lib/safe.sh; bench_use "$BENCH_DIR"
# Run as a command, over ssh on the other machine too:
#   bash safe.sh init DIR          make DIR the benchmark folder
#   bash safe.sh rm DIR PATH...    delete each PATH inside the folder DIR
#   bash safe.sh empty DIR PATH    delete what PATH holds, but its hidden entries

BENCH_MARK=.gocalbox-bench
# The marker's one line: an ID of 32 hex digits, and a line end, CRLF or none.
BENCH_MARK_LINE=$'^gocalbox-bench ([0-9a-f]{32})(\r?\n)?$'

bench_fail() {
  echo "safe.sh: $*" >&2
  return 1
}

# bench_init DIR makes DIR the benchmark folder: it must be missing, empty,
# or a benchmark folder already.
bench_init() {
  local dir=${1:-}
  [ -n "$dir" ] || { bench_fail "no folder given"; return 1; }
  [[ $dir = /* ]] || { bench_fail "the benchmark folder must be an absolute path: $dir"; return 1; }
  if [ -L "$dir" ]; then
    bench_fail "the benchmark folder is a link: $dir"; return 1
  fi
  if [ -e "$dir" ]; then
    [ -d "$dir" ] || { bench_fail "not a folder: $dir"; return 1; }
    if [ -e "$dir/$BENCH_MARK" ] || [ -L "$dir/$BENCH_MARK" ]; then
      bench_use "$dir" || return 1
      echo "$BENCH_DIR is already a benchmark folder"
      return 0
    fi
    if [ -n "$(ls -A -- "$dir")" ]; then
      bench_fail "$dir holds files already; give a new or empty folder"; return 1
    fi
  fi
  mkdir -p -- "$dir" || return 1
  local id
  id=$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')
  [[ $id =~ ^[0-9a-f]{32}$ ]] || { bench_fail "cannot read random bytes"; return 1; }
  (umask 077; printf 'gocalbox-bench %s\n' "$id" > "$dir/$BENCH_MARK") || return 1
  bench_use "$dir" || return 1
  echo "$BENCH_DIR is now the benchmark folder"
}

# bench_use DIR checks that DIR is a benchmark folder and sets BENCH_DIR to
# its real path and BENCH_ID to its marker's ID.
bench_use() {
  local dir=${1:-} real mark
  BENCH_DIR=
  BENCH_ID=
  [ -n "$dir" ] || { bench_fail "no benchmark folder given; make one with bench/init.sh"; return 1; }
  [[ $dir = /* ]] || { bench_fail "the benchmark folder must be an absolute path: $dir"; return 1; }
  [ -d "$dir" ] && [ ! -L "$dir" ] || { bench_fail "not a folder: $dir"; return 1; }
  real=$(realpath -e -- "$dir") || return 1
  mark=
  if [ -f "$real/$BENCH_MARK" ] && [ ! -L "$real/$BENCH_MARK" ] && [ "$(stat -c %s -- "$real/$BENCH_MARK")" -le 64 ]; then
    # Read whole: the dot keeps the line ends that $(...) would drop, and the
    # size shows a NUL byte, which bash drops too.
    mark=$(cat -- "$real/$BENCH_MARK"; echo .)
    mark=${mark%.}
    [ "$(printf '%s' "$mark" | wc -c)" = "$(stat -c %s -- "$real/$BENCH_MARK")" ] || mark=
  fi
  [[ $mark =~ $BENCH_MARK_LINE ]] ||
    { bench_fail "$dir is not a benchmark folder; make one with bench/init.sh"; return 1; }
  [ "$real" != / ] || { bench_fail "the benchmark folder can't be /"; return 1; }
  BENCH_DIR=$real
  BENCH_ID=${BASH_REMATCH[1]}
}

# bench_inside PATH prints PATH as it lies in BENCH_DIR, with its folder's
# links resolved, or fails: it must be absolute, not a link, not the folder
# itself or its marker, and on the folder's file system.
bench_inside() {
  local p=${1:-} parent base real
  [ -n "${BENCH_DIR:-}" ] || { bench_fail "no benchmark folder in use"; return 1; }
  [ -n "$p" ] || { bench_fail "an empty path"; return 1; }
  [[ $p = /* ]] || { bench_fail "not an absolute path: $p"; return 1; }
  [ ! -L "$p" ] || { bench_fail "a link: $p"; return 1; }
  base=$(basename -- "$p")
  case $base in
    . | .. | / ) bench_fail "not a name: $p"; return 1 ;;
  esac
  parent=$(realpath -e -- "$(dirname -- "$p")") || { bench_fail "no such folder: $(dirname -- "$p")"; return 1; }
  real=${parent%/}/$base
  case $real in
    "$BENCH_DIR"/*) ;;
    *) bench_fail "outside the benchmark folder $BENCH_DIR: $p"; return 1 ;;
  esac
  [ "$real" != "$BENCH_DIR/$BENCH_MARK" ] || { bench_fail "the benchmark folder's marker: $p"; return 1; }
  if [ -e "$real" ] && [ "$(stat -c %d -- "$real")" != "$(stat -c %d -- "$BENCH_DIR")" ]; then
    bench_fail "on another file system than the benchmark folder: $p"; return 1
  fi
  # A bind mount of the folder's own file system has its device number.
  if bench_mounted "$real"; then
    bench_fail "a file system is mounted in the benchmark folder on the way to, at or inside $p, or the mount table can't be read"; return 1
  fi
  printf '%s\n' "$real"
}

# bench_mounted PATH succeeds if a file system is mounted inside BENCH_DIR at
# PATH, inside it, or on the way to it, or if the mount table can't be read.
bench_mounted() {
  local esc dir target
  [ -r /proc/self/mountinfo ] || return 0
  esc=$(bench_mount_escape "$1"); dir=$(bench_mount_escape "$BENCH_DIR")
  while read -r _ _ _ _ target _; do
    [[ $target = "$dir"/* ]] || continue
    if [ "$target" = "$esc" ] || [[ $target = "$esc"/* ]] || [[ $esc = "$target"/* ]]; then return 0; fi
  done < /proc/self/mountinfo
  return 1
}

# bench_mount_escape PATH prints PATH as /proc/self/mountinfo writes a mount
# point: with \, space, tab and newline as octal escapes.
bench_mount_escape() {
  local e=$1
  e=${e//\\/\\134}; e=${e// /\\040}; e=${e//$'\t'/\\011}; e=${e//$'\n'/\\012}
  printf '%s' "$e"
}

# bench_rm PATH... deletes each PATH, which must lie in BENCH_DIR. A path
# that doesn't exist is skipped.
bench_rm() {
  local p real
  [ "$#" -gt 0 ] || { bench_fail "nothing to delete"; return 1; }
  for p in "$@"; do
    real=$(bench_inside "$p") || return 1
    [ -e "$real" ] || continue
    rm -rf --one-file-system -- "$real" || return 1
  done
}

# bench_empty DIR deletes what DIR holds, but its hidden entries, such as a
# served folder's .gocalbox, which the running server still uses.
bench_empty() {
  local dir e real
  real=$(bench_inside "${1:-}") || return 1
  [ -d "$real" ] || { bench_fail "not a folder: $1"; return 1; }
  for e in "$real"/*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    if [ -L "$e" ]; then
      bench_rm_link "$e" || return 1
    else
      bench_rm "$e" || return 1
    fi
  done
}

# bench_rm_link LINK deletes a link inside BENCH_DIR, not what it points to.
bench_rm_link() {
  local p=${1:-} parent
  [ -L "$p" ] || { bench_fail "not a link: $p"; return 1; }
  parent=$(realpath -e -- "$(dirname -- "$p")") || return 1
  case $parent/ in
    "$BENCH_DIR"/*) ;;
    *) bench_fail "outside the benchmark folder $BENCH_DIR: $p"; return 1 ;;
  esac
  rm -f -- "$parent/$(basename -- "$p")"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  set -u
  export LC_ALL=C
  cmd=${1:-}
  shift || true
  case $cmd in
    init) bench_init "${1:-}" ;;
    rm) bench_use "${1:-}" && shift && bench_rm "$@" ;;
    empty) bench_use "${1:-}" && bench_empty "${2:-}" ;;
    *) echo "usage: safe.sh init DIR | rm DIR PATH... | empty DIR PATH" >&2; exit 2 ;;
  esac
fi
