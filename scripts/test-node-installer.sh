#!/usr/bin/env bash
# Never run the installer on the host. The only bind mount is a read-only script.
set -eu
src=$(cd "$(dirname "$0")/../internal/panel" && pwd)/install.sh
docker run --rm -i --pull=never --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges --tmpfs /opt:exec,mode=755 --tmpfs /etc/systemd/system:mode=755 \
  --tmpfs /tmp:exec --mount "type=bind,source=$src,target=/installer,readonly" \
  --entrypoint bash python:3.13-slim -se <<'TESTS'
mkdir /tmp/bin
export PATH=/tmp/bin:$PATH
cat > /tmp/bin/systemctl <<'MOCK'
#!/bin/bash
if [[ $1 == show ]]; then
  unit=${!#}; path=/etc/systemd/system/$unit
  if [[ -e /tmp/vendor ]]; then path=/usr/lib/systemd/system/$unit; fi
  case "$*" in
    *LoadState*) if [[ -e $path || -e /tmp/vendor ]]; then echo loaded; else echo not-found; exit 4; fi;;
    *FragmentPath*) echo "$path";;
    *) exit 1;;
  esac
  exit 0
fi
printf '%s\n' "$*" >>/tmp/changes
[[ $1 != disable || ! -f /tmp/stop-fails ]]
MOCK
cat > /tmp/bin/curl <<'MOCK'
#!/bin/bash
[[ $1 != '' && ${@: -2:1} == -o ]] || exit 2
[[ ! -f /tmp/download-fails ]] || exit 1
printf '#!/bin/sh\nexit 0\n' > "${!#}"
MOCK
printf '#!/bin/sh\nexit 0\n' >/tmp/bin/sleep
chmod +x /tmp/bin/*
install_node() { bash /installer -n "$1" -u https://test.invalid -t fixture >/dev/null; }
uninstall_node() { bash /installer -n "$1" --uninstall >/dev/null; }
reject() { : >/tmp/changes; if "$@" 2>/dev/null; then echo 'unexpected success' >&2; exit 1; fi; test ! -s /tmp/changes; }
unit=/etc/systemd/system/sample.service
dir=/opt/sample
install_node sample
test -s "$dir/.kaze-install-v1" || { echo 'missing installer ownership record' >&2; exit 1; }
install_node sample
touch "$dir/kaze-node.json" "$dir/kaze-traffic-v2.outbox" "$dir/kaze-traffic-v2.outbox.tmp"
uninstall_node sample
test ! -e "$dir" && test ! -e "$unit" || exit 1
: >/tmp/changes; uninstall_node sample; test ! -s /tmp/changes
echo 'PASS install, reinstall, clean and repeat uninstall'
install_node upgrade
rm /opt/upgrade/.kaze-install-v1
printf 'cached state\n' >/opt/upgrade/kaze-node.json
bash /installer -n upgrade -u https://test.invalid -t rotated --rev-port 21555 >/dev/null
grep -Fxq 'cached state' /opt/upgrade/kaze-node.json
test -s /opt/upgrade/.kaze-install-v1
uninstall_node upgrade
echo 'PASS stock legacy service upgrade preserves node state'
install_node sample
mkdir "$dir/notes"; touch "$dir/notes/keep" /opt/neighbor
uninstall_node sample
test -f "$dir/notes/keep" && test -f /opt/neighbor && test ! -e "$unit" && test ! -e "$dir/env" || exit 1
install_node sample
test -f "$dir/notes/keep"
uninstall_node sample
echo 'PASS unknown contents and neighboring files preserved'
reject uninstall_node ''; reject uninstall_node '-bad'; reject install_node '..'
echo 'PASS invalid names rejected before mutations'
mkdir /opt/legacy; touch /opt/legacy/env /etc/systemd/system/legacy.service
reject uninstall_node legacy; reject install_node legacy
test -f /opt/legacy/env && test -f /etc/systemd/system/legacy.service || exit 1
echo 'PASS legacy directory and unit untouched'
ln -s /opt/legacy /opt/alias; reject uninstall_node alias; reject install_node alias
ln -s /tmp/no-unit /etc/systemd/system/link.service; reject install_node link
install_node owned; ln -s /opt/neighbor /opt/owned/kaze-node.json; reject uninstall_node owned
rm /opt/owned/kaze-node.json; printf '# edited\n' >> /etc/systemd/system/owned.service
reject uninstall_node owned; reject install_node owned
echo 'PASS symlinks and modified unit rejected'
touch /tmp/vendor; reject install_node vendor; rm /tmp/vendor
echo 'PASS system service name collision refused'
touch /tmp/download-fails; reject install_node partial
test ! -e /opt/partial; rm /tmp/download-fails
install_node partial; uninstall_node partial
echo 'PASS fresh install can retry a failed download'
install_node busy; touch /tmp/stop-fails
if uninstall_node busy; then exit 1; fi
test -f /opt/busy/env && test -f /etc/systemd/system/busy.service || exit 1
echo 'PASS failed service stop leaves files intact'
TESTS
