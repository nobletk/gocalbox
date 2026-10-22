#!/bin/sh
# Cuts this machine off from one address for a few seconds, as a pulled cable
# would, for bench/session.sh's network-cut cells. Installed as root, it is
# run as:
#
#   sudo -n /usr/local/sbin/gocalbox-netcut ADDRESS SECONDS
#
# ADDRESS is an IPv4 or IPv6 address, SECONDS a whole number from 1 to 60.
# Every packet to or from ADDRESS is dropped, through an nftables table of its
# own, inet gocalbox_bench; nothing else in the firewall is touched. The cut
# ends by itself: the address sits in a set whose element the kernel removes
# after SECONDS, so traffic flows again even if this script is killed. The
# script then deletes its table. It writes no file but its lock,
# /run/gocalbox-netcut.lock.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C

die() { echo "gocalbox-netcut: $*" >&2; exit "${CODE:-1}"; }
CODE=2
[ "$#" -eq 2 ] || die "usage: gocalbox-netcut ADDRESS SECONDS"
addr=$1
secs=$2
case $secs in
  '' | *[!0-9]* | 0*) die "SECONDS must be a whole number from 1 to 60" ;;
esac
[ "$secs" -le 60 ] || die "SECONDS must be a whole number from 1 to 60"
case $addr in
  *:*)
    case $addr in *[!0-9A-Fa-f:]* | *:::* | *::*::*) die "not an IPv4 or IPv6 address: $addr" ;; esac
    groups=0
    set -f; IFS=:
    for g in $addr; do
      groups=$((groups + 1))
      [ "${#g}" -le 4 ] || die "not an IPv4 or IPv6 address: $addr"
    done
    set +f; unset IFS
    case $addr in
      *::*) [ "$groups" -le 8 ] ;;
      *) [ "$groups" -eq 8 ] ;;
    esac || die "not an IPv4 or IPv6 address: $addr"
    family=ip6; type=ipv6_addr ;;
  *)
    # grep checks line by line: anything but digits and dots, a newline above all, is refused first.
    case $addr in *[!0-9.]*) die "not an IPv4 or IPv6 address: $addr" ;; esac
    echo "$addr" | grep -Eq '^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$' ||
      die "not an IPv4 or IPv6 address: $addr"
    family=ip; type=ipv4_addr ;;
esac
CODE=1
[ "$(id -u)" -eq 0 ] || die "must run as root, through sudo"
command -v nft > /dev/null || die "nft isn't installed (the nftables package)"

# One cut at a time: a second would delete the first one's table.
exec 9> /run/gocalbox-netcut.lock
flock -n 9 || die "another cut is running"

trap 'nft delete table inet gocalbox_bench 2> /dev/null || true' EXIT
trap 'exit 1' INT TERM HUP
# Adding and deleting first replaces a table a killed run left behind, in the
# same transaction that makes the new one.
nft -f - << EOF
add table inet gocalbox_bench
delete table inet gocalbox_bench
table inet gocalbox_bench {
  set cut {
    type $type
    flags timeout
    elements = { $addr timeout ${secs}s }
  }
  chain input {
    type filter hook input priority -300; policy accept;
    $family saddr @cut drop
  }
  chain output {
    type filter hook output priority -300; policy accept;
    $family daddr @cut drop
  }
}
EOF
echo "gocalbox-netcut: cut off from $addr for ${secs}s"
sleep "$secs"
echo "gocalbox-netcut: $addr is reachable again"
