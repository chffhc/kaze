package panel

import (
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"kaze/internal/proto"
)

// Options 是面板的启动参数。
type Options struct {
	Listen     string // 监听地址,如 :8080
	DataDir    string // 数据目录(SQLite 数据库)
	DistDir    string // 节点端二进制所在目录,供一键对接脚本下载
	TLSCert    string // 可选:直接提供 HTTPS
	TLSKey     string
	ProxyCIDRs string
	TrustProxy bool   // 信任反向代理传来的 X-Forwarded-For / X-Forwarded-Proto
	AdminUser  string // 首次启动时创建的管理员
	AdminPass  string
}

// Server 是面板服务。
type Server struct {
	proxies  []netip.Prefix
	opt      Options
	db       *sql.DB
	reads    *sql.DB
	hub      *Hub
	secret   []byte
	setMu    sync.RWMutex
	settings map[string]string
	limiter  *ipLimiter
	// ruleMu 串行化规则的创建、修改与删除:端口和 SNI 的占用检查要和随后的写入保持一致。
	ruleMu sync.Mutex
}

func (s *Server) reader() *sql.DB {
	if s.reads != nil {
		return s.reads
	}
	return s.db
}

// H 是 JSON 对象的简写。
type H = map[string]any

// Run 启动面板并阻塞到 ctx 结束。
func Run(ctx context.Context, opt Options) error {
	db, err := openDB(opt.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	reads, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(opt.DataDir, "kaze.db"))+"?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(8000)")
	if err != nil {
		return err
	}
	defer reads.Close()
	db.SetMaxOpenConns(1)
	reads.SetMaxOpenConns(8)
	s := &Server{opt: opt, db: db, reads: reads, settings: map[string]string{}, limiter: newIPLimiter()}
	if opt.TrustProxy {
		for _, value := range strings.Split(opt.ProxyCIDRs, ",") {
			if strings.TrimSpace(value) == "" {
				continue
			}
			network, err := netip.ParsePrefix(strings.TrimSpace(value))
			if err != nil {
				return fmt.Errorf("无效的可信代理网段 %q: %w", value, err)
			}
			s.proxies = append(s.proxies, network)
		}
	}
	if err := s.loadSettings(); err != nil {
		return err
	}
	if err := s.bootstrap(); err != nil {
		return err
	}
	s.hub = newHub(s)
	go s.hub.run(ctx)
	go s.jobs(ctx)

	hs := &http.Server{
		Addr:              opt.Listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 15 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	}()
	log.Printf("面板已启动,监听 %s", opt.Listen)
	if opt.TLSCert != "" && opt.TLSKey != "" {
		err = hs.ListenAndServeTLS(opt.TLSCert, opt.TLSKey)
	} else {
		err = hs.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// bootstrap 生成签名密钥,并在没有任何用户时创建管理员。
func (s *Server) bootstrap() error {
	sec := s.setting("secret", "")
	if sec == "" {
		b := make([]byte, 32)
		rand.Read(b)
		sec = hex.EncodeToString(b)
		if err := s.setSetting("secret", sec); err != nil {
			return err
		}
	}
	s.secret, _ = hex.DecodeString(sec)
	var n int
	if err := s.reader().QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		user, pass := s.opt.AdminUser, s.opt.AdminPass
		if user == "" {
			user = "admin"
		}
		generated := pass == ""
		if generated {
			pass = randString(14)
		}
		if _, err := s.db.Exec(`INSERT INTO users(username,password,role,created_at) VALUES(?,?,'admin',?)`,
			user, hashPassword(pass), now()); err != nil {
			return err
		}
		if generated {
			log.Printf("==============================================================")
			log.Printf("  已创建管理员账号   用户名: %s   密码: %s", user, pass)
			log.Printf("  该密码只显示这一次,请登录后立即修改。")
			log.Printf("==============================================================")
			// 同时写到数据目录,方便以服务方式启动时找回
			os.WriteFile(filepath.Join(s.opt.DataDir, "admin-initial-password.txt"),
				[]byte(fmt.Sprintf("用户名: %s\n密码: %s\n登录并修改密码后请删除本文件。\n", user, pass)), 0o600)
		} else {
			log.Printf("已创建管理员账号 %s", user)
		}
	}
	return nil
}

const randAlphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"

func randString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = randAlphabet[int(b[i])%len(randAlphabet)]
	}
	return string(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- 密码与登录令牌 ----

const pbkdf2Iter = 200_000

func hashPassword(pw string) string {
	salt := make([]byte, 16)
	rand.Read(salt)
	dk, _ := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	return fmt.Sprintf("pbkdf2$%d$%s$%s", pbkdf2Iter, hex.EncodeToString(salt), hex.EncodeToString(dk))
}

func checkPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	iter, _ := strconv.Atoi(parts[1])
	salt, _ := hex.DecodeString(parts[2])
	want, _ := hex.DecodeString(parts[3])
	if iter <= 0 || len(want) == 0 {
		return false
	}
	dk, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(dk, want) == 1
}

const tokenTTL = 7 * 24 * time.Hour

func (s *Server) sign(payload string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) issueToken(u *User) string {
	payload := fmt.Sprintf("%d.%d.%d", u.ID, time.Now().Add(tokenTTL).Unix(), u.tokenVer)
	return payload + "." + s.sign(payload)
}

func (s *Server) parseToken(tok string) (*User, error) {
	i := strings.LastIndexByte(tok, '.')
	if i < 0 || !hmac.Equal([]byte(s.sign(tok[:i])), []byte(tok[i+1:])) {
		return nil, errors.New("登录已失效")
	}
	var uid, exp, ver int64
	if _, err := fmt.Sscanf(tok[:i], "%d.%d.%d", &uid, &exp, &ver); err != nil || exp < now() {
		return nil, errors.New("登录已过期")
	}
	u, err := getUser(s.reader(), uid)
	if err != nil || u.tokenVer != ver {
		return nil, errors.New("登录已失效")
	}
	if u.Banned {
		return nil, errors.New("账号已被封禁")
	}
	return u, nil
}

// ---- HTTP 辅助 ----

func (s *Server) json(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) ok(w http.ResponseWriter, v any) { s.json(w, http.StatusOK, v) }

func (s *Server) fail(w http.ResponseWriter, code int, msg string) {
	s.json(w, code, H{"error": msg})
}

// dbErr 把数据库错误转成响应;sql.ErrNoRows 视为 404。
func (s *Server) dbErr(w http.ResponseWriter, err error) {
	if errors.Is(err, sql.ErrNoRows) {
		s.fail(w, http.StatusNotFound, "记录不存在")
		return
	}
	log.Printf("数据库错误: %v", err)
	s.fail(w, http.StatusInternalServerError, "服务器内部错误")
}

func bind(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	if err := dec.Decode(v); err != nil {
		return errors.New("请求格式错误")
	}
	return nil
}

func pathID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func (s *Server) trustedProxy(r *http.Request) bool {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	return err == nil && s.trustedProxyAddr(peer.Addr())
}

func (s *Server) trustedProxyAddr(addr netip.Addr) bool {
	if !s.opt.TrustProxy || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if len(s.proxies) == 0 {
		return addr.IsLoopback()
	}
	for _, p := range s.proxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) clientIP(r *http.Request) string {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	addr := peer.Addr().Unmap()
	lines := r.Header.Values("X-Forwarded-For")
	for i := len(lines) - 1; i >= 0 && s.trustedProxyAddr(addr); i-- {
		line := lines[i]
		for s.trustedProxyAddr(addr) {
			comma := strings.LastIndexByte(line, ',')
			next, err := netip.ParseAddr(strings.TrimSpace(line[comma+1:]))
			if err != nil || next.Zone() != "" {
				return addr.String()
			}
			addr = next.Unmap()
			if comma == -1 {
				break
			}
			line = line[:comma]
		}
	}
	return addr.String()
}

// baseURL 返回面板的对外地址:优先用设置里的 panel_url,否则从请求推断。
func (s *Server) baseURL(r *http.Request) string {
	if v := s.setting("panel_url", ""); v != "" {
		return strings.TrimRight(v, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if s.trustedProxy(r) {
		if v := r.Header.Get("X-Forwarded-Proto"); v == "http" || v == "https" {
			scheme = v
		}
	}
	return scheme + "://" + r.Host
}

func validBaseURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	if value := u.Port(); value != "" {
		port, err := strconv.Atoi(value)
		if err != nil || port < 1 || port > 65535 {
			return false
		}
	}
	for _, c := range raw {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(":/[]_.~%+-", c)) {
			return false
		}
	}
	return true
}

type handler func(w http.ResponseWriter, r *http.Request, u *User)

func (s *Server) auth(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			s.fail(w, http.StatusUnauthorized, "未登录")
			return
		}
		u, err := s.parseToken(tok)
		if err != nil {
			s.fail(w, http.StatusUnauthorized, err.Error())
			return
		}
		if r.Method != http.MethodGet && !u.IsAdmin() && !s.limiter.allow("u:"+strconv.FormatInt(u.ID, 10), 30, 10*time.Second) {
			s.fail(w, http.StatusTooManyRequests, "操作过于频繁,请稍后再试")
			return
		}
		next(w, r, u)
	}
}

func (s *Server) admin(next handler) http.HandlerFunc {
	return s.auth(func(w http.ResponseWriter, r *http.Request, u *User) {
		if !u.IsAdmin() {
			s.fail(w, http.StatusForbidden, "需要管理员权限")
			return
		}
		next(w, r, u)
	})
}

// ipLimiter 是按 key 的固定窗口限流器(登录、注册、用户写操作)。
type ipLimiter struct {
	nextCleanup time.Time
	mu          sync.Mutex
	m           map[string]*window
}

type window struct {
	until time.Time
	n     int
}

func newIPLimiter() *ipLimiter { return &ipLimiter{m: make(map[string]*window)} }

func (l *ipLimiter) allow(key string, limit int, per time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := time.Now()
	if !t.Before(l.nextCleanup) {
		l.nextCleanup = t.Add(time.Minute) // 防止被大量来源撑爆
		for k, w := range l.m {
			if !t.Before(w.until) {
				delete(l.m, k)
			}
		}
	}
	w := l.m[key]
	if w == nil && len(l.m) >= 50000 {
		return false
	}
	if w == nil || !t.Before(w.until) {
		l.m[key] = &window{until: t.Add(per), n: 1}
		return true
	}
	w.n++
	return w.n <= limit
}

// gzipMiddleware 压缩静态资源与 JSON 响应(WebSocket 升级请求除外)。
func gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") || r.Header.Get("Upgrade") != "" ||
			strings.HasPrefix(r.URL.Path, "/dl/") {
			next.ServeHTTP(w, r)
			return
		}
		gz := gzip.NewWriter(w)
		defer gz.Close()
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Add("Vary", "Accept-Encoding")
		w.Header().Del("Content-Length")
		next.ServeHTTP(&gzipWriter{ResponseWriter: w, gz: gz}, r)
	})
}

type gzipWriter struct {
	http.ResponseWriter
	gz *gzip.Writer
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	g.Header().Del("Content-Length")
	return g.gz.Write(b)
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// 公共
	mux.HandleFunc("GET /api/site", s.handleSite)
	mux.HandleFunc("POST /api/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/auth/register", s.handleRegister)

	// 用户
	mux.HandleFunc("GET /api/me", s.auth(s.handleMe))
	mux.HandleFunc("POST /api/me/password", s.auth(s.handlePassword))
	mux.HandleFunc("POST /api/me/auto_renew", s.auth(s.handleAutoRenew))
	mux.HandleFunc("GET /api/overview", s.auth(s.handleOverview))
	mux.HandleFunc("GET /api/groups", s.auth(s.handleGroups))
	mux.HandleFunc("GET /api/status", s.auth(s.handleNodeStatus))
	mux.HandleFunc("GET /api/rules", s.auth(s.handleRuleList))
	mux.HandleFunc("POST /api/rules", s.auth(s.handleRuleCreate))
	mux.HandleFunc("POST /api/rules/batch", s.auth(s.handleRuleBatch))
	mux.HandleFunc("PUT /api/rules/{id}", s.auth(s.handleRuleUpdate))
	mux.HandleFunc("DELETE /api/rules/{id}", s.auth(s.handleRuleDelete))
	mux.HandleFunc("POST /api/rules/{id}/pause", s.auth(s.handleRulePause))
	mux.HandleFunc("POST /api/rules/{id}/diag", s.auth(s.handleRuleDiag))

	// 商城
	mux.HandleFunc("GET /api/plans", s.auth(s.handlePlans))
	mux.HandleFunc("POST /api/plans/{id}/buy", s.auth(s.handleBuy))
	mux.HandleFunc("GET /api/orders", s.auth(s.handleOrders))
	mux.HandleFunc("POST /api/redeem", s.auth(s.handleRedeem))
	mux.HandleFunc("POST /api/recharge", s.auth(s.handleRecharge))
	mux.HandleFunc("/api/pay/epay/notify", s.handleEpayNotify)
	mux.HandleFunc("GET /api/pay/epay/return", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/#/shop", http.StatusFound)
	})

	// 管理
	mux.HandleFunc("GET /api/admin/stats", s.admin(s.handleAdminStats))
	mux.HandleFunc("GET /api/admin/users", s.admin(s.handleAdminUsers))
	mux.HandleFunc("POST /api/admin/users", s.admin(s.handleAdminUserCreate))
	mux.HandleFunc("PUT /api/admin/users/{id}", s.admin(s.handleAdminUserUpdate))
	mux.HandleFunc("DELETE /api/admin/users/{id}", s.admin(s.handleAdminUserDelete))
	mux.HandleFunc("GET /api/admin/groups/{id}", s.admin(s.handleAdminGroupDetails))
	mux.HandleFunc("GET /api/admin/groups", s.admin(s.handleAdminGroups))
	mux.HandleFunc("POST /api/admin/groups", s.admin(s.handleAdminGroupCreate))
	mux.HandleFunc("PUT /api/admin/groups/{id}", s.admin(s.handleAdminGroupUpdate))
	mux.HandleFunc("DELETE /api/admin/groups/{id}", s.admin(s.handleAdminGroupDelete))
	mux.HandleFunc("POST /api/admin/groups/{id}/reset_token", s.admin(s.handleAdminGroupResetToken))
	mux.HandleFunc("GET /api/admin/nodes", s.admin(s.handleAdminNodes))
	mux.HandleFunc("DELETE /api/admin/nodes/{id}", s.admin(s.handleAdminNodeDelete))
	mux.HandleFunc("GET /api/admin/plans", s.admin(s.handleAdminPlans))
	mux.HandleFunc("POST /api/admin/plans", s.admin(s.handleAdminPlanSave))
	mux.HandleFunc("PUT /api/admin/plans/{id}", s.admin(s.handleAdminPlanSave))
	mux.HandleFunc("DELETE /api/admin/plans/{id}", s.admin(s.handleAdminPlanDelete))
	mux.HandleFunc("GET /api/admin/orders", s.admin(s.handleAdminOrders))
	mux.HandleFunc("GET /api/admin/codes", s.admin(s.handleAdminCodes))
	mux.HandleFunc("POST /api/admin/codes", s.admin(s.handleAdminCodeCreate))
	mux.HandleFunc("DELETE /api/admin/codes/{id}", s.admin(s.handleAdminCodeDelete))
	mux.HandleFunc("GET /api/admin/settings", s.admin(s.handleAdminSettings))
	mux.HandleFunc("PUT /api/admin/settings", s.admin(s.handleAdminSettingsSave))

	// 节点
	mux.HandleFunc("GET /api/node/ws", s.hub.serveWS)
	mux.HandleFunc("GET /install.sh", s.handleInstallScript)
	mux.HandleFunc("GET /dl/{file}", s.handleDownload)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		s.fail(w, http.StatusNotFound, "接口不存在")
	})
	mux.Handle("/", webHandler())
	return gzipMiddleware(mux)
}

func (s *Server) handleSite(w http.ResponseWriter, r *http.Request) {
	s.ok(w, H{
		"site_name":      s.setting("site_name", "Kaze"),
		"allow_register": s.setting("allow_register", "1") == "1",
		"version":        proto.Version,
		"pay_enabled":    s.setting("epay_url", "") != "",
		"pay_types":      strings.Split(s.setting("epay_types", "alipay,wxpay"), ","),
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow("login:"+s.clientIP(r), 10, time.Minute) {
		s.fail(w, http.StatusTooManyRequests, "尝试次数过多,请一分钟后再试")
		return
	}
	var in struct{ Username, Password string }
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	u, err := scanUser(s.reader().QueryRow(`SELECT `+userCols+` FROM users u WHERE u.username=?`, strings.TrimSpace(in.Username)))
	if err != nil || !checkPassword(u.password, in.Password) {
		s.fail(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	if u.Banned {
		s.fail(w, http.StatusForbidden, "账号已被封禁")
		return
	}
	s.ok(w, H{"token": s.issueToken(u), "user": u})
}

func validUsername(s string) bool {
	if len(s) < 3 || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '@') {
			return false
		}
	}
	return true
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if s.setting("allow_register", "1") != "1" {
		s.fail(w, http.StatusForbidden, "本站未开放注册")
		return
	}
	if !s.limiter.allow("reg:"+s.clientIP(r), 5, 10*time.Minute) {
		s.fail(w, http.StatusTooManyRequests, "注册过于频繁,请稍后再试")
		return
	}
	var in struct{ Username, Password string }
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if !validUsername(in.Username) {
		s.fail(w, 400, "用户名需为 3-32 位字母、数字或 _ - . @")
		return
	}
	if len(in.Password) < 8 {
		s.fail(w, 400, "密码至少 8 位")
		return
	}
	res, err := s.db.Exec(`INSERT INTO users(username,password,role,created_at) VALUES(?,?,'user',?)`,
		in.Username, hashPassword(in.Password), now())
	if err != nil {
		s.fail(w, http.StatusConflict, "用户名已被占用")
		return
	}
	id, _ := res.LastInsertId()
	u, err := getUser(s.reader(), id)
	if err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, H{"token": s.issueToken(u), "user": u})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, u *User) { s.ok(w, u) }

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	if !checkPassword(u.password, in.Old) {
		s.fail(w, 400, "原密码不正确")
		return
	}
	if len(in.New) < 8 {
		s.fail(w, 400, "新密码至少 8 位")
		return
	}
	if _, err := s.db.Exec(`UPDATE users SET password=?, token_ver=token_ver+1 WHERE id=?`, hashPassword(in.New), u.ID); err != nil {
		s.dbErr(w, err)
		return
	}
	u.tokenVer++
	s.ok(w, H{"token": s.issueToken(u)})
}

func (s *Server) handleAutoRenew(w http.ResponseWriter, r *http.Request, u *User) {
	var in struct {
		Enabled bool `json:"enabled"`
	}
	if err := bind(r, &in); err != nil {
		s.fail(w, 400, err.Error())
		return
	}
	if _, err := s.db.Exec(`UPDATE users SET auto_renew=? WHERE id=?`, in.Enabled, u.ID); err != nil {
		s.dbErr(w, err)
		return
	}
	s.ok(w, H{"ok": true})
}
