#!/usr/bin/env bash
# What a benchmark session records of a machine. Sourced by the scripts:
#   . bench/lib/env.sh; bench_describe FOLDER

# bench_describe FOLDER prints the system, CPU, memory, power (on a laptop),
# the disk and file system FOLDER lies on, the network, the clock's
# synchronisation, and the tools' versions.
bench_describe() {
  # What can't be read is left out, without stopping the script.
  (set +eE +o pipefail; trap - ERR; bench_describe_all "$@")
}

# bench_network prints the network interfaces with their link speed, and the
# Wi-Fi link: what a session records at its start and again at its end.
bench_network() {
  (set +eE +o pipefail; trap - ERR; bench_network_all)
}

bench_network_all() {
  local n w
  echo "network:"
  for n in /sys/class/net/*; do
    [ "${n##*/}" = lo ] && continue
    echo "  ${n##*/}: $(cat "$n/operstate" 2> /dev/null || true), $(cat "$n/speed" 2> /dev/null || echo '?') Mb/s, $( (ip -br addr show "${n##*/}" | awk '{$1 = $2 = ""; print}' | sed 's/^ *//') 2> /dev/null || true)"
  done
  if command -v iw > /dev/null; then
    for w in $(iw dev 2>/dev/null | awk '$1 == "Interface" {print $2}'); do
      echo "  wifi $w: $(iw dev "$w" link 2>/dev/null | awk '/freq|signal|tx bitrate|rx bitrate|SSID/ {sub(/^[ \t]+/, ""); printf "%s; ", $0}')"
    done
  else
    echo "  wifi: not recorded (no iw)"
  fi
}

bench_describe_all() {
  local dir=${1:-$PWD} src p
  echo "host: $(hostname)   date: $(date -Is)"
  echo "kernel: $(uname -srvm)"
  if [ -r /etc/os-release ]; then (. /etc/os-release; echo "os: ${PRETTY_NAME:-unknown}"); fi
  echo "cpu: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | sed 's/^[^:]*: //')   cpus: $(nproc)"
  echo "memory: $(awk '/MemTotal/ {printf "%.1f GiB", $2/1048576}' /proc/meminfo 2>/dev/null)"
  echo "cpu governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
  for p in /sys/class/power_supply/*; do
    [ "$(cat "$p/type" 2>/dev/null)" = Mains ] && echo "on mains: $(cat "$p/online" 2>/dev/null | sed 's/1/yes/;s/0/no/')"
  done
  echo "clock synchronised: $(timedatectl show -p NTPSynchronized --value 2>/dev/null || echo unknown)"
  echo "folder: $dir"
  echo "  file system: $(findmnt -no SOURCE,FSTYPE,OPTIONS -T "$dir" 2>/dev/null || echo unknown)"
  echo "  free: $(df -B1 --output=avail "$dir" 2>/dev/null | tail -1 | tr -d ' ') bytes"
  src=$(findmnt -no SOURCE -T "$dir" 2>/dev/null | sed 's/\[.*//')
  # Through encryption, LVM or partitions, down to the disk.
  if [ -n "$src" ]; then
    lsblk -s -P -o NAME,TYPE,TRAN,ROTA,SIZE,MODEL "$src" 2>/dev/null | grep 'TYPE="disk"' | sed 's/^/  disk: /' || true
  fi
  bench_network_all
  echo "go: $(go version 2>/dev/null || echo none)"
  echo "curl: $(curl --version 2>/dev/null | head -1)"
  if command -v iperf3 > /dev/null; then echo "iperf3: $(iperf3 --version 2>&1 | head -1)"; else echo "iperf3: none"; fi
}
