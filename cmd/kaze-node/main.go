// kaze-node 是 Kaze 的节点端:入口与出口共用同一个程序,角色由对接令牌所属的设备组决定。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"kaze/internal/node"
	"kaze/internal/proto"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var o node.Options
	ver := flag.Bool("v", false, "显示版本")
	flag.StringVar(&o.PanelURL, "u", env("KAZE_PANEL", ""), "面板地址,如 https://panel.example.com")
	flag.StringVar(&o.Token, "t", env("KAZE_TOKEN", ""), "设备组对接令牌")
	flag.StringVar(&o.UID, "uid", env("KAZE_UID", ""), "节点实例 ID(同一台机器多开时手动指定,默认自动生成)")
	flag.StringVar(&o.StateDir, "state", env("KAZE_STATE", "."), "状态目录(保存实例 ID 与最近一次配置)")
	flag.StringVar(&o.Bind, "bind", env("KAZE_BIND", ""), "监听绑定的本机地址,默认全部")
	flag.StringVar(&o.ConnectHost, "connect-host", env("KAZE_CONNECT_HOST", ""), "出口:入口连接本机时使用的地址(专线内网 IP 等),默认用面板看到的公网 IP")
	flag.IntVar(&o.TunnelPort, "port", 0, "出口:隧道监听端口,默认由面板指定或随机")
	flag.StringVar(&o.Iface, "iface", env("KAZE_IFACE", ""), "探针统计的网卡,逗号分隔,默认自动选择")
	flag.StringVar(&o.ConfigFile, "c", "", "独立模式:从本地 JSON 配置运行,不连接面板")
	flag.BoolVar(&o.Insecure, "insecure", false, "连接面板时跳过 TLS 证书校验(仅调试用)")
	flag.Parse()
	if *ver {
		fmt.Println("kaze-node", proto.Version)
		return
	}
	log.SetFlags(log.LstdFlags)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("kaze-node %s 启动", proto.Version)
	if err := node.Run(ctx, o); err != nil {
		log.Fatal(err)
	}
}
