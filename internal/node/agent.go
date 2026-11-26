// Package node 是节点端:连接面板、应用下发的配置、上报流量与探针数据。
//
// 设计要点:
//   - 配置为"完整快照 + 本地收敛":未变化的规则不重启,连接不受影响;
//   - 与面板失联不影响已有规则,最近一次配置会落盘,节点重启后即使面板不可达也能恢复转发;
//   - 流量上报带序号与确认,未确认的增量会在重连后重发。
package node

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	mrand "math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"kaze/internal/proto"
	"kaze/internal/relay"
)

// Options 是节点端的启动参数。
type Options struct {
	PanelURL    string // 面板地址,如 https://panel.example.com
	Token       string // 设备组对接令牌(决定本节点是入口还是出口)
	UID         string // 节点实例 ID;为空则自动生成并持久化(同机多开时需手动指定)
	StateDir    string // 状态目录
	Bind        string // 入站监听绑定的地址,默认全部
	ConnectHost string // 出口:入口连接本机使用的地址(专线内网 IP 等)
	TunnelPort  int    // 出口:隧道监听端口
	RevPort     int    // 入口:反向隧道监听端口(出口主动连入);0 表示不开启
	Iface       string // 探针统计的网卡,逗号分隔;为空自动选择
	ConfigFile  string // 独立模式:从本地 JSON 读取 NodeConfig,不连接面板
	Insecure    bool   // 连接面板时跳过证书校验(仅调试)
}

type state struct {
	UID        string            `json:"uid"`
	TunnelPort int               `json:"tunnel_port,omitempty"`
	LastConfig *proto.NodeConfig `json:"last_config,omitempty"`
}

// Agent 是节点端主体。
type Agent struct {
	opt      Options
	hostname string
	state    state
	stateMu  sync.Mutex

	clockOff atomic.Int64 // 面板时间 - 本地时间(纳秒)
	in       *inbound
	out      *outbound
	role     atomic.Value // string
	cfgVer   atomic.Int64

	sendCh  chan []byte
	pending *proto.Report
	seq     int64
	metrics *metricsCollector
}

// now 返回与面板校准后的时间,供隧道鉴权使用,避免节点系统时间不准导致鉴权失败。
func (a *Agent) now() time.Time { return time.Now().Add(time.Duration(a.clockOff.Load())) }

func (a *Agent) getRole() string {
	s, _ := a.role.Load().(string)
	return s
}

func (a *Agent) statePath() string { return filepath.Join(a.opt.StateDir, "kaze-node.json") }

func (a *Agent) loadState() {
	if b, err := os.ReadFile(a.statePath()); err == nil {
		json.Unmarshal(b, &a.state)
	}
	if a.opt.UID != "" {
		a.state.UID = a.opt.UID
	}
	if a.state.UID == "" {
		b := make([]byte, 12)
		rand.Read(b)
		a.state.UID = hex.EncodeToString(b)
		a.saveState()
	}
}

func (a *Agent) saveState() {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	b, _ := json.Marshal(&a.state)
	os.MkdirAll(a.opt.StateDir, 0o700)
	tmp := a.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		os.Rename(tmp, a.statePath())
	}
}

// Run 运行节点端直到 ctx 结束。
func Run(ctx context.Context, opt Options) error {
	if opt.StateDir == "" {
		opt.StateDir = "."
	}
	a := &Agent{opt: opt, sendCh: make(chan []byte, 64), seq: time.Now().UnixMilli()}
	a.hostname, _ = os.Hostname()
	a.loadState()
	a.in, a.out = newInbound(a), newOutbound(a)
	a.metrics = newMetricsCollector(opt.Iface)
	defer a.in.stopAll()
	defer a.out.stopAll()

	if opt.ConfigFile != "" {
		b, err := os.ReadFile(opt.ConfigFile)
		if err != nil {
			return err
		}
		var cfg proto.NodeConfig
		if err := json.Unmarshal(b, &cfg); err != nil {
			return err
		}
		if err := a.applyConfig(&cfg, false); err != nil {
			return err
		}
		log.Printf("独立模式运行,角色: %s", cfg.Role)
		<-ctx.Done()
		return nil
	}
	if opt.PanelURL == "" || opt.Token == "" {
		return errors.New("必须指定面板地址 (-u) 和对接令牌 (-t)")
	}
	// 先用上次落盘的配置恢复转发,再去连面板。
	if c := a.state.LastConfig; c != nil {
		if err := a.applyConfig(c, false); err == nil {
			log.Printf("已用本地缓存的配置恢复转发 (版本 %d)", c.Version)
		}
	}
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.session(ctx)
		if ctx.Err() != nil {
			break
		}
		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		}
		log.Printf("与面板的连接断开: %v;%v 后重连(现有规则不受影响)", err, backoff)
		select {
		case <-ctx.Done():
		case <-time.After(backoff + time.Duration(mrand.Int64N(int64(backoff/2)+1))):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	return nil
}

func (a *Agent) applyConfig(cfg *proto.NodeConfig, persist bool) error {
	if cfg.Now > 0 {
		a.clockOff.Store(int64(time.UnixMilli(cfg.Now).Sub(time.Now())))
	}
	a.role.Store(cfg.Role)
	var err error
	switch cfg.Role {
	case proto.RoleIn:
		if cfg.Inbound == nil {
			cfg.Inbound = &proto.InboundConfig{}
		}
		a.out.stopAll()
		a.in.apply(cfg.Inbound)
	case proto.RoleOut:
		if cfg.Outbound == nil {
			return errors.New("出口配置为空")
		}
		a.in.stopAll()
		err = a.out.apply(cfg.Outbound, cfg.GroupID)
	default:
		return errors.New("未知的节点角色: " + cfg.Role)
	}
	a.cfgVer.Store(cfg.Version)
	if persist && err == nil {
		a.state.LastConfig = cfg
		a.saveState()
	}
	return err
}

func (a *Agent) send(t string, v any) {
	select {
	case a.sendCh <- proto.Pack(t, v):
	default: // 发送队列满(连接卡住):丢弃,探针/状态类消息下个周期会再发
	}
}

func (a *Agent) sendStatus(applyErr error) {
	st := proto.Status{ConfigVersion: a.cfgVer.Load()}
	if a.getRole() == proto.RoleIn {
		st.RuleErrors = a.in.ruleErrors()
	} else {
		st.TunnelPort = a.out.listenPort()
		if applyErr != nil {
			st.RuleErrors = map[int64]string{0: applyErr.Error()}
		}
	}
	a.send(proto.TStatus, st)
}

// session 维持一次与面板的控制连接。
func (a *Agent) session(ctx context.Context) error {
	u, err := url.Parse(strings.TrimRight(a.opt.PanelURL, "/") + "/api/node/ws")
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "https", "wss":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}
	d := *websocket.DefaultDialer
	d.HandshakeTimeout = 15 * time.Second
	if a.opt.Insecure {
		d.TLSClientConfig = insecureTLS()
	}
	hdr := http.Header{"Authorization": {"Bearer " + a.opt.Token}}
	ws, resp, err := d.DialContext(ctx, u.String(), hdr)
	if err != nil {
		if resp != nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				return errors.New("对接令牌无效(设备组可能已删除或令牌已重置)")
			}
		}
		return err
	}
	defer ws.Close()
	ws.SetReadLimit(64 << 20)

	// 清空上一个连接遗留的待发消息
	for len(a.sendCh) > 0 {
		<-a.sendCh
	}
	a.send(proto.THello, proto.Hello{
		UID: a.state.UID, Hostname: a.hostname, Version: proto.Version,
		OS: runtime.GOOS, Arch: runtime.GOARCH,
		ConnectHost: a.opt.ConnectHost, TunnelPort: a.opt.TunnelPort, RevPort: a.opt.RevPort,
	})
	log.Printf("已连接面板 %s", a.opt.PanelURL)

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	acks := make(chan int64, 4)
	intervalCh := make(chan int, 1)

	// 写协程:控制消息 + 周期性的探针与流量上报
	go func() {
		defer ws.Close()
		metricsT := time.NewTicker(5 * time.Second)
		defer metricsT.Stop()
		retryT := time.NewTicker(30 * time.Second)
		defer retryT.Stop()
		interval := 10
		reportT := time.NewTicker(time.Duration(interval) * time.Second)
		defer reportT.Stop()
		ping := time.NewTicker(20 * time.Second)
		defer ping.Stop()
		write := func(mt int, b []byte) bool {
			ws.SetWriteDeadline(time.Now().Add(15 * time.Second))
			return ws.WriteMessage(mt, b) == nil
		}
		for {
			select {
			case <-sctx.Done():
				return
			case b := <-a.sendCh:
				if !write(websocket.TextMessage, b) {
					return
				}
			case <-ping.C:
				if !write(websocket.PingMessage, nil) {
					return
				}
			case <-metricsT.C:
				m := a.metrics.sample()
				m.TCPConns, m.UDPSess = relay.ActiveTCP.Load(), relay.ActiveUDP.Load()
				m.Goroutine = runtime.NumGoroutine()
				if a.getRole() == proto.RoleIn {
					m.RevTotal, m.RevUp = a.in.reverseStatus()
				} else {
					m.RevTotal, m.RevUp = a.out.reverseStatus()
				}
				if !write(websocket.TextMessage, proto.Pack(proto.TMetrics, m)) {
					return
				}
			case n := <-intervalCh:
				if n > 0 && n != interval {
					interval = n
					reportT.Reset(time.Duration(n) * time.Second)
				}
			case seq := <-acks:
				if a.pending != nil && a.pending.Seq == seq {
					a.pending = nil
				}
			case <-reportT.C:
				if a.getRole() != proto.RoleIn {
					continue
				}
				if a.pending == nil {
					if items := a.in.collect(); len(items) > 0 {
						a.seq++
						a.pending = &proto.Report{Seq: a.seq, Items: items}
					}
				}
				if a.pending != nil && !write(websocket.TextMessage, proto.Pack(proto.TReport, a.pending)) {
					return
				}
			case <-retryT.C:
				if a.getRole() == proto.RoleIn && a.in.retryFailed() {
					a.sendStatus(nil)
				}
			}
		}
	}()

	ws.SetPongHandler(func(string) error {
		ws.SetReadDeadline(time.Now().Add(70 * time.Second))
		return nil
	})
	for {
		ws.SetReadDeadline(time.Now().Add(70 * time.Second))
		_, data, err := ws.ReadMessage()
		if err != nil {
			return err
		}
		var m proto.Msg
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		switch m.T {
		case proto.TConfig:
			var cfg proto.NodeConfig
			if err := json.Unmarshal(m.D, &cfg); err != nil {
				log.Printf("配置解析失败: %v", err)
				continue
			}
			err := a.applyConfig(&cfg, true)
			if err != nil {
				log.Printf("应用配置失败: %v", err)
			}
			select {
			case intervalCh <- cfg.ReportInterval:
			default:
			}
			a.sendStatus(err)
		case proto.TAck:
			var ack proto.Ack
			if json.Unmarshal(m.D, &ack) == nil {
				select {
				case acks <- ack.Seq:
				case <-sctx.Done():
				}
			}
		case proto.TDiag:
			var dg proto.Diag
			if json.Unmarshal(m.D, &dg) == nil {
				go func() {
					res := proto.DiagResult{ID: dg.ID}
					if a.getRole() == proto.RoleIn {
						res.Hops = a.in.diag(dg.RuleID)
					} else {
						res.Hops = a.out.diag(dg.RuleID)
					}
					a.send(proto.TDiagResult, res)
				}()
			}
		}
	}
}
