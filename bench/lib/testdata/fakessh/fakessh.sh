# login HOST checks the configuration against fakesshd's, connects to it, and sets ROOT.
setting() { awk -v k="$1" '$1 == k {sub(/^[ \t]*[^ \t]+[ \t]+/, ""); gsub(/"/, ""); print; exit}' "$conf"; }
login() {
  local port hostkey keys hostname
  [ "$(awk '$1 == "Host" {print $2}' "$conf")" = "$1" ] || { echo "fake ssh: no Host $1 in $conf" >&2; exit 255; }
  { read -r port; read -r hostkey; read -r keys; read -r ROOT; } < "$FAKE_SSH_STATE/server"
  hostname=$(setting HostName)
  [ "$(setting Port)" = "$port" ] || { echo "fake ssh: port $(setting Port), not $port" >&2; exit 255; }
  grep -qxF "[$hostname]:$port $(echo "$hostkey" | awk '{print $1, $2}')" "$(setting UserKnownHostsFile)" ||
    { echo "fake ssh: Host key verification failed." >&2; exit 255; }
  grep -qF "$(awk '{print $1, $2}' "$(setting IdentityFile).pub")" "$keys" || { echo "fake ssh: Permission denied (publickey)." >&2; exit 255; }
  [ "$(setting BatchMode)" = yes ] && [ "$(setting IdentitiesOnly)" = yes ] || { echo "fake ssh: not in batch mode with its key alone" >&2; exit 255; }
  exec 3<> "/dev/tcp/$hostname/$port" || exit 255
  head -c 4 <&3 > /dev/null
  printf x >&3
  # The session's work ends before the transfer does.
  until read -r -t 5 l <&3 && [ "$l" = done ]; do :; done
  exec 3<&-
}
