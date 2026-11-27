#!/usr/bin/env bash
# Kaze 节点端一键对接脚本
#
#   bash <(curl -fsSL https://面板地址/install.sh) -u https://面板地址 -t 对接令牌
#
# 可选参数:
#   -n 名称              服务名与安装目录名,默认 kaze-node(同一台机器多开时改这个)
#   --port 端口          出口:指定隧道监听端口
#   --rev-port 端口      入口:开启反向隧道监听,让内网里的出口主动连进来
#   --connect-host 地址  指定对端连接本机使用的地址(专线内网 IP 等)
#   --bind 地址          监听绑定的本机地址
#   --uninstall          卸载
# 环境变量:
#   OPTIMIZE=1           写入一组常用的内核网络参数(BBR、连接队列、缓冲区)
set -euo pipefail

PANEL=""; TOKEN=""; NAME="kaze-node"; EXTRA=""; UNINSTALL=0
add_port() {
  [[ $2 =~ ^[0-9]{1,5}$ ]] && (( 10#$2 <= 65535 )) || { echo "端口无效" >&2; exit 1; }
  EXTRA="$EXTRA -$1 $2"
}
add_host() {
  [[ $2 =~ ^[a-zA-Z0-9_.:-]+$ ]] || { echo "节点地址无效" >&2; exit 1; }
  EXTRA="$EXTRA -$1 $2"
}
while [ $# -gt 0 ]; do
  case "$1" in
    -u) PANEL="${2%/}"; shift 2 ;;
    -t) TOKEN="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    --port) add_port port "$2"; shift 2 ;;
    --rev-port) add_port rev-port "$2"; shift 2 ;;
    --connect-host) add_host connect-host "$2"; shift 2 ;;
    --bind) add_host bind "$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "请使用 root 运行"; exit 1; }
command -v systemctl >/dev/null || { echo "需要 systemd"; exit 1; }
die() { printf '%s\n' "$*" >&2; exit 1; }
case "$NAME" in ''|-*|*[!a-zA-Z0-9_-]*) die '实例名不能为空、不能以 - 开头，只允许字母、数字、- 和 _' ;; esac

DIR="/opt/$NAME"
UNIT="/etc/systemd/system/$NAME.service"
MARK="$DIR/.kaze-install-v1"
MARK_TMP="$DIR/.kaze-install-v1.tmp"
UNIT_TMP="$UNIT.kaze-tmp"
ENV_TMP="$DIR/env.kaze-tmp"
# 固定文件清单，不从标记或目录内容读取待删除的路径。
FILES=("$DIR/kaze-node" "$DIR/env" "$DIR/kaze-node.json" "$DIR/kaze-node.json.tmp" "$DIR/kaze-traffic-v2.outbox" "$DIR/kaze-traffic-v2.outbox.tmp" "$MARK_TMP" "$ENV_TMP" "$UNIT_TMP")
exists() { [[ -e $1 || -L $1 ]]; }
trusted() {
  local mode
  [[ ! -L $1 && $(stat -c %u -- "$1") == 0 ]] || return 1
  mode=$(stat -c %a -- "$1") || return 1
  (( (8#$mode & 022) == 0 ))
}
for parent in /opt /etc /etc/systemd /etc/systemd/system; do
  [[ -d $parent ]] && trusted "$parent" || die "父目录不安全或不存在: $parent"
done
# 协调同时运行的安装/卸载；锁定稳定的父目录，不需创建锁文件。
exec 9</opt
flock -x 9 || die '无法取得安装锁'
unit_record() { local digest; digest=$(sha256sum < "$1") || return 1; printf 'kaze-node-v1 %s %s\n' "$NAME" "${digest%% *}"; }
trusted_file() { [[ -f $1 ]] && trusted "$1" && [[ $(stat -c %h -- "$1") == 1 ]]; }

render_unit() {
  local extra=$1
  cat <<EOT
[Unit]
Description=Kaze node ($NAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$DIR/env
ExecStart=$DIR/kaze-node$extra
Restart=always
RestartSec=3
LimitNOFILE=1048576
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOT
}

# Recognize only the stock 1.0/1.1 service and its supported arguments.
legacy_matches() {
  trusted_file "$DIR/kaze-node" && trusted_file "$DIR/env" && [[ -x $DIR/kaze-node ]] || return 1
  local start extra
  local -a env_lines
  mapfile -t env_lines < "$DIR/env"
  [[ ${#env_lines[@]} == 3 && ${env_lines[0]} == KAZE_PANEL=http* &&
     ${env_lines[1]} == KAZE_TOKEN=?* && ${env_lines[2]} == "KAZE_STATE=$DIR" ]] || return 1
  start=$(sed -n 's/^ExecStart=//p' "$UNIT")
  [[ $start == "$DIR/kaze-node"* ]] || return 1
  extra=${start#"$DIR/kaze-node"}
  [[ $extra =~ ^(\ -(port|rev-port)\ [0-9]{1,5}|\ -(connect-host|bind)\ [a-zA-Z0-9_.:-]+)*$ ]] || return 1
  render_unit "$extra" | cmp -s - "$UNIT"
}

managed=0
inactive_record="kaze-node-v1 $NAME inactive"
if exists "$DIR" || exists "$UNIT"; then
  [[ -d $DIR ]] && trusted "$DIR" || die "安装目录不安全: $DIR"
  if ! exists "$UNIT"; then
    trusted_file "$MARK" && grep -Fxq -- "$inactive_record" "$MARK" || die '未能确认安装目录归属'
    rc=0; load=$(systemctl show --property=LoadState --value "$NAME.service") || rc=$?
    [[ $load == not-found && ($rc == 0 || $rc == 4) ]] || die '已有同名服务'
  elif exists "$MARK"; then
    trusted_file "$UNIT" || die '服务文件归属异常'
    trusted_file "$MARK" || die '安装标记归属异常，未做更改'
    record=$(unit_record "$UNIT")
    grep -Fxq -- "$record" "$MARK" || die '安装标记与当前实例或服务文件不匹配，未做更改'
  else
    trusted_file "$UNIT" || die '服务文件归属异常'
    [[ $UNINSTALL == 0 ]] && legacy_matches || die '未能确认旧安装归属，未做更改'
  fi
  if exists "$UNIT"; then
    [[ $(systemctl show --property=FragmentPath --value "$NAME.service") == "$UNIT" ]] || die '生效的服务文件不属于该实例'
  fi
  for f in "${FILES[@]}"; do
    if exists "$f"; then
      trusted_file "$f" || die "实例文件归属异常: $f"
    fi
  done
  managed=1
else
  if exists "$UNIT_TMP"; then trusted_file "$UNIT_TMP" || die "服务临时文件归属异常: $UNIT_TMP"; fi
  rc=0; load=$(systemctl show --property=LoadState --value "$NAME.service") || rc=$?
  [[ $load == not-found && ($rc == 0 || $rc == 4) ]] || die '已有同名服务或无法确认该名称可用'
fi

if [ "$UNINSTALL" = "1" ]; then
  if (( ! managed )); then echo "未安装 $NAME，无需卸载"; exit 0; fi
  if exists "$UNIT"; then systemctl disable --now "$NAME.service" || die '停用服务失败，未删除文件'; fi
  { if exists "$UNIT"; then unit_record "$UNIT"; fi; printf '%s\n' "$inactive_record"; } > "$MARK_TMP"
  mv -fT -- "$MARK_TMP" "$MARK"
  rm -f -- "$UNIT" "${FILES[@]}"
  if [[ -z $(find "$DIR" -mindepth 1 -maxdepth 1 ! -name '.kaze-install-v1' -printf x -quit) ]]; then
    rm -f -- "$MARK"
    rmdir -- "$DIR"
  fi
  systemctl daemon-reload
  [[ ! -d $DIR ]] || printf '已保留未列入清单的文件: %s\n' "$DIR"
  echo "已卸载 $NAME"
  exit 0
fi

[ -n "$PANEL" ] && [ -n "$TOKEN" ] || { echo "用法: install.sh -u 面板地址 -t 对接令牌"; exit 1; }

panel_pattern='^https?://[][a-zA-Z0-9.:_~/%+-]+$'
[[ $PANEL =~ $panel_pattern ]] || die '面板地址格式无效'
[[ $TOKEN =~ ^[a-zA-Z0-9_-]+$ ]] || die '对接令牌格式无效'

if [ "${OPTIMIZE:-0}" = "1" ]; then
  trusted /etc/sysctl.d && [[ -d /etc/sysctl.d ]] || die 'sysctl 目录不安全'
  conf=/etc/sysctl.d/99-kaze.conf
  if exists "$conf"; then trusted_file "$conf" || die 'sysctl 配置文件归属异常'; fi
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "不支持的架构: $(uname -m)"; exit 1 ;;
esac

umask 077
download=''
cleanup_download() {
  [[ -z $download ]] || rm -f -- "$download"
  # 新安装下载失败时，仅回收本次新建且仍为空的目录，允许直接重试。
  if (( ! managed )); then rmdir --ignore-fail-on-non-empty -- "$DIR"; fi
}
if (( ! managed )); then mkdir -m 700 -- "$DIR"; fi
trap cleanup_download EXIT
download=$(mktemp -- "$DIR/.download.XXXXXXXX")
echo "下载节点端 ($ARCH) ..."
curl -fL --retry 3 "$PANEL/dl/kaze-node-linux-$ARCH" -o "$download"
chmod 700 "$download"
"$download" -v >/dev/null || { echo "下载的文件无法运行"; exit 1; }
if (( ! managed )); then printf '%s\n' "$inactive_record" > "$MARK"; fi
mv -fT -- "$download" "$DIR/kaze-node"
trap - EXIT

# Accept either exact unit digest during the atomic unit replacement.
printf 'KAZE_PANEL=%s\nKAZE_TOKEN=%s\nKAZE_STATE=%s\n' "$PANEL" "$TOKEN" "$DIR" > "$ENV_TMP"
render_unit "$EXTRA" > "$UNIT_TMP"
chmod 644 "$UNIT_TMP"
{
  if exists "$UNIT"; then unit_record "$UNIT"; else printf '%s\n' "$inactive_record"; fi
  unit_record "$UNIT_TMP"
} > "$MARK_TMP"
mv -fT -- "$MARK_TMP" "$MARK"
mv -fT -- "$ENV_TMP" "$DIR/env"
mv -fT -- "$UNIT_TMP" "$UNIT"
unit_record "$UNIT" > "$MARK_TMP"
mv -fT -- "$MARK_TMP" "$MARK"

if [ "${OPTIMIZE:-0}" = "1" ]; then

  conf_tmp=$(mktemp /etc/sysctl.d/.kaze.XXXXXXXX)
  trap 'rm -f -- "$conf_tmp"' EXIT
  cat > "$conf_tmp" <<EOT
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.ip_local_port_range=10000 65535
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_tw_reuse=1
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.ipv4.tcp_rmem=4096 131072 33554432
net.ipv4.tcp_wmem=4096 65536 33554432
net.ipv4.tcp_mtu_probing=1
fs.file-max=2097152
EOT
  chmod 644 "$conf_tmp"
  mv -fT -- "$conf_tmp" "$conf"
  trap - EXIT
  sysctl --system >/dev/null 2>&1 || true
  echo "已写入内核网络参数 /etc/sysctl.d/99-kaze.conf"
fi

systemctl daemon-reload
systemctl enable "$NAME" >/dev/null 2>&1
systemctl restart "$NAME"
sleep 1
systemctl --no-pager --lines=5 status "$NAME" || true
echo
echo "安装完成。查看日志: journalctl -fu $NAME"
