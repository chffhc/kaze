// kaze-panel 是 Kaze 的面板端:提供 API、Web 界面,并管理所有节点。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"kaze/internal/panel"
	"kaze/internal/proto"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	var o panel.Options
	ver := flag.Bool("v", false, "显示版本")
	flag.StringVar(&o.Listen, "listen", env("KAZE_LISTEN", ":8080"), "监听地址")
	flag.StringVar(&o.DataDir, "data", env("KAZE_DATA", "./data"), "数据目录")
	flag.StringVar(&o.DistDir, "dist", env("KAZE_DIST", "./dist"), "节点端二进制目录(供一键对接脚本下载)")
	flag.StringVar(&o.TLSCert, "tls-cert", env("KAZE_TLS_CERT", ""), "TLS 证书文件(不填则监听 HTTP,建议前置 Caddy/Nginx 提供 HTTPS)")
	flag.StringVar(&o.TLSKey, "tls-key", env("KAZE_TLS_KEY", ""), "TLS 私钥文件")
	flag.StringVar(&o.ProxyCIDRs, "proxy-cidrs", env("KAZE_PROXY_CIDRS", ""), "可信反向代理 CIDR，逗号分隔，默认仅本机回环")
	flag.BoolVar(&o.TrustProxy, "trust-proxy", env("KAZE_TRUST_PROXY", "") == "1", "信任反向代理的 X-Forwarded-For / X-Forwarded-Proto(仅在面板位于反向代理之后时开启)")
	flag.StringVar(&o.AdminUser, "admin-user", env("KAZE_ADMIN_USER", "admin"), "首次启动时创建的管理员用户名")
	flag.StringVar(&o.AdminPass, "admin-pass", env("KAZE_ADMIN_PASS", ""), "首次启动时的管理员密码(不填则随机生成并打印)")
	flag.Parse()
	if *ver {
		fmt.Println("kaze-panel", proto.Version)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("kaze-panel %s 启动", proto.Version)
	if err := panel.Run(ctx, o); err != nil {
		log.Fatal(err)
	}
}
