#!/usr/bin/env bash
# Kaze 节点端一键对接脚本
#
#   bash <(curl -fsSL https://面板地址/install.sh) -u https://面板地址 -t 对接令牌
#
# 可选参数:
#   -n 名称              服务名与安装目录名,默认 kaze-node(同一台机器多开时改这个)
#   --port 端口          出口:指定隧道监听端口
#   --connect-host 地址  出口:指定入口连接本机使用的地址(专线内网 IP 等)
#   --bind 地址          监听绑定的本机地址
#   --uninstall          卸载
# 环境变量:
#   OPTIMIZE=1           写入一组常用的内核网络参数(BBR、连接队列、缓冲区)
set -euo pipefail

PANEL=""; TOKEN=""; NAME="kaze-node"; EXTRA=""; UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    -u) PANEL="${2%/}"; shift 2 ;;
    -t) TOKEN="$2"; shift 2 ;;
    -n) NAME="$2"; shift 2 ;;
    --port) EXTRA="$EXTRA -port $2"; shift 2 ;;
    --connect-host) EXTRA="$EXTRA -connect-host $2"; shift 2 ;;
    --bind) EXTRA="$EXTRA -bind $2"; shift 2 ;;
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
# 固定文件清单，不从标记或目录内容读取待删除的路径。
FILES=("$DIR/kaze-node" "$DIR/env" "$DIR/kaze-node.json" "$DIR/kaze-node.json.tmp")
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
unit_record() { local digest; digest=$(sha256sum < "$UNIT") || return 1; printf 'kaze-node-v1 %s %s\n' "$NAME" "${digest%% *}"; }
managed=0
if exists "$DIR" || exists "$UNIT"; then
  [[ -d $DIR ]] && trusted "$DIR" || die "安装目录不安全: $DIR"
  for f in "$MARK" "$UNIT"; do
    [[ -f $f ]] && trusted "$f" && [[ $(stat -c %h -- "$f") == 1 ]] || die '未能确认安装归属。旧安装请先备份并手工核对，未做更改。'
  done
  unit_record | cmp -s - "$MARK" || die '安装标记与当前实例或服务文件不匹配，未做更改'
  [[ $(systemctl show --property=FragmentPath --value "$NAME.service") == "$UNIT" ]] || die '生效的服务文件不属于该实例'
  for f in "${FILES[@]}"; do
    if exists "$f"; then
      [[ -f $f ]] && trusted "$f" && [[ $(stat -c %h -- "$f") == 1 ]] || die "实例文件归属异常: $f"
    fi
  done
  managed=1
else
  rc=0; load=$(systemctl show --property=LoadState --value "$NAME.service") || rc=$?
  [[ $load == not-found && ($rc == 0 || $rc == 4) ]] || die '已有同名服务或无法确认该名称可用'
fi

if [ "$UNINSTALL" = "1" ]; then
  if (( ! managed )); then echo "未安装 $NAME，无需卸载"; exit 0; fi
  systemctl disable --now "$NAME.service" || die '停用服务失败，未删除文件'
  rm -f -- "$UNIT" "${FILES[@]}" "$MARK"
  rmdir --ignore-fail-on-non-empty -- "$DIR"
  systemctl daemon-reload
  [[ ! -d $DIR ]] || printf '已保留未列入清单的文件: %s\n' "$DIR"
  echo "已卸载 $NAME"
  exit 0
fi

[ -n "$PANEL" ] && [ -n "$TOKEN" ] || { echo "用法: install.sh -u 面板地址 -t 对接令牌"; exit 1; }

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
mv -fT -- "$download" "$DIR/kaze-node"
trap - EXIT

# 令牌放在只有 root 可读的环境文件里,不出现在进程命令行中
cat > "$DIR/env" <<EOT
KAZE_PANEL=$PANEL
KAZE_TOKEN=$TOKEN
KAZE_STATE=$DIR
EOT

cat > "$UNIT" <<EOT
[Unit]
Description=Kaze node ($NAME)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$DIR/env
ExecStart=$DIR/kaze-node$EXTRA
Restart=always
RestartSec=3
LimitNOFILE=1048576
TasksMax=infinity

[Install]
WantedBy=multi-user.target
EOT
chmod 644 "$UNIT"
unit_record > "$MARK"

if [ "${OPTIMIZE:-0}" = "1" ]; then
  cat > /etc/sysctl.d/99-kaze.conf <<EOT
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
