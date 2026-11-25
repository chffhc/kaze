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
case "$NAME" in *[!a-zA-Z0-9_-]*) echo "名称只能包含字母、数字、- 和 _"; exit 1 ;; esac

DIR="/opt/$NAME"
UNIT="/etc/systemd/system/$NAME.service"

if [ "$UNINSTALL" = "1" ]; then
  systemctl disable --now "$NAME" 2>/dev/null || true
  rm -f "$UNIT"
  rm -rf "$DIR"
  systemctl daemon-reload
  echo "已卸载 $NAME"
  exit 0
fi

[ -n "$PANEL" ] && [ -n "$TOKEN" ] || { echo "用法: install.sh -u 面板地址 -t 对接令牌"; exit 1; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "不支持的架构: $(uname -m)"; exit 1 ;;
esac

mkdir -p "$DIR"
chmod 700 "$DIR"
echo "下载节点端 ($ARCH) ..."
curl -fL --retry 3 "$PANEL/dl/kaze-node-linux-$ARCH" -o "$DIR/kaze-node.new"
chmod +x "$DIR/kaze-node.new"
"$DIR/kaze-node.new" -v >/dev/null || { echo "下载的文件无法运行"; exit 1; }
mv -f "$DIR/kaze-node.new" "$DIR/kaze-node"

# 令牌放在只有 root 可读的环境文件里,不出现在进程命令行中
umask 077
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
