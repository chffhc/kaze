package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// http 伪装传输层。
//
// 连接的开头是一次看起来普通的 HTTP/1.1 请求与响应,请求头和响应头里都没有
// Upgrade / Switching Protocols 之类的字样;头部之后,两个方向都是加密的记录流:
//
//	入口 -> 出口   GET <path> HTTP/1.1 … Cookie: sid=<令牌>
//	出口 -> 入口   HTTP/1.1 200 OK … ETag: "<服务端随机数>"
//	之后           两个方向各自的记录流
//
//	令牌  = base64url( flags(1) | 时间戳毫秒(8) | 随机数(16) | HMAC(32) ),取代其它传输层的连接前导帧
//	记录  = 密文长度(2,大端) | AES-256-GCM(明文);长度同时作为附加数据参与认证
//	密钥  = HMAC(k, 方向 | 令牌头 | 服务端随机数),两个方向各一把
//
// 入口要读到响应头、拿到服务端随机数之后才能发数据(建连多一次往返;开启多路复用时只在建立
// 复用连接时付出一次)。这样做是为了让两个方向的密钥都含有出口这一次给出的随机数:
// 被动截获的请求和数据换一条连接、换一台出口重放,出口解不开,也就不会把旧数据再转发一遍。
//
// 明文为空的记录表示发送方正常结束(相当于 TLS 的 close_notify);没有收到它连接就断开,
// 读取方得到 io.ErrUnexpectedEOF,据此区分"对端写完了"和"连接被掐断"。
//
// 这只是外观上的伪装:头部之后的字节流不是合法的 HTTP 报文体,两端之间必须是直连的 TCP,
// 不能经过 CDN 或会解析 HTTP 的反向代理。
const (
	httpTokenHead = 1 + 8 + 16 // flags | 时间戳 | 随机数
	httpTokenLen  = httpTokenHead + sha256.Size
	httpMaxPlain  = 16 * 1024 // 单条记录的明文上限
	httpRecTag    = 16
	httpHeadLimit = 8 * 1024 // 请求头 / 响应头的总长度上限
	httpUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

var (
	errHTTPMalformed = errors.New("不是合法的 HTTP 报文头")
	errHTTPRecord    = errors.New("http 隧道记录校验失败")
)

func httpMAC(k *Keys, label string, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, k.http)
	m.Write([]byte(label))
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// newHTTPToken 生成请求头里的鉴权令牌,同时返回令牌头(会话密钥由它派生)。
func newHTTPToken(k *Keys, flags byte, now time.Time) (token string, head []byte) {
	return newHandshakeToken(k, flags, now, "auth")
}
func newHandshakeToken(k *Keys, flags byte, now time.Time, label string) (token string, head []byte) {
	b := make([]byte, httpTokenHead, httpTokenLen)
	b[0] = flags
	binary.BigEndian.PutUint64(b[1:], uint64(now.UnixMilli()))
	rand.Read(b[9:])
	b = append(b, httpMAC(k, label, b)...)
	return base64.RawURLEncoding.EncodeToString(b), b[:httpTokenHead:httpTokenHead]
}

// verifyHTTPToken 校验令牌:HMAC、时间窗、随机数不重复。
func verifyHTTPToken(token string, k *Keys, now time.Time, rc *replayCache) (flags byte, head []byte, err error) {
	return verifyHandshakeToken(token, k, now, rc, "auth")
}
func verifyHandshakeToken(token string, k *Keys, now time.Time, rc *replayCache, label string) (flags byte, head []byte, err error) {
	b, derr := base64.RawURLEncoding.DecodeString(token)
	if derr != nil || len(b) != httpTokenLen {
		return 0, nil, errAuth
	}
	head = b[:httpTokenHead:httpTokenHead]
	if !hmac.Equal(b[httpTokenHead:], httpMAC(k, label, head)) {
		return 0, nil, errAuth
	}
	ts := time.UnixMilli(int64(binary.BigEndian.Uint64(b[1:9])))
	if d := now.Sub(ts); d > authWindow || d < -authWindow {
		return 0, nil, errClock
	}
	var nonce [16]byte
	copy(nonce[:], b[9:httpTokenHead])
	if !rc.check(nonce, now) {
		return 0, nil, errReplay
	}
	return b[0], head, nil
}

func newGCM(key []byte) cipher.AEAD {
	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // 密钥固定为 32 字节,不会出错
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		panic(err)
	}
	return a
}

func httpRequest(host, path, token string) []byte {
	return []byte("GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: " + httpUserAgent + "\r\n" +
		"Accept: */*\r\n" +
		"Accept-Encoding: identity\r\n" +
		"Cookie: sid=" + token + "\r\n" +
		"Connection: keep-alive\r\n\r\n")
}

func httpResponse(snonce []byte, now time.Time) []byte {
	return []byte("HTTP/1.1 200 OK\r\n" +
		"Server: nginx\r\n" +
		"Date: " + now.UTC().Format(http.TimeFormat) + "\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Cache-Control: no-store\r\n" +
		"ETag: \"" + base64.RawURLEncoding.EncodeToString(snonce) + "\"\r\n" +
		"Connection: close\r\n\r\n")
}

// httpReject 生成拒绝响应。令牌不对、路径不对的请求都得到一个普通的 404,和未知来源的探测看到的一样。
func httpReject(code int, now time.Time) []byte {
	text := fmt.Sprintf("%d %s", code, http.StatusText(code))
	body := "<html>\r\n<head><title>" + text + "</title></head>\r\n<body>\r\n<center><h1>" + text +
		"</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	return []byte("HTTP/1.1 " + text + "\r\n" +
		"Server: nginx\r\n" +
		"Date: " + now.UTC().Format(http.TimeFormat) + "\r\n" +
		"Content-Type: text/html\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"Connection: close\r\n\r\n" + body)
}

// readHTTPHead 读取一个 HTTP 报文头:返回首行和头字段(字段名转小写)。
func readHTTPHead(br *bufio.Reader) (first string, hdr map[string]string, err error) {
	total := 0
	for i := 0; ; i++ {
		line, err := br.ReadSlice('\n')
		if err != nil {
			if err == bufio.ErrBufferFull {
				err = errHTTPMalformed
			}
			return "", nil, err
		}
		if total += len(line); total > httpHeadLimit || i > 64 {
			return "", nil, errHTTPMalformed
		}
		s := strings.TrimRight(string(line), "\r\n")
		if i == 0 {
			if s == "" {
				return "", nil, errHTTPMalformed
			}
			first, hdr = s, make(map[string]string, 8)
			continue
		}
		if s == "" {
			return first, hdr, nil
		}
		k, v, ok := strings.Cut(s, ":")
		if !ok {
			return "", nil, errHTTPMalformed
		}
		hdr[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
}

// cookieValue 从 Cookie 头里取出指定名字的值。
func cookieValue(cookie, name string) string {
	for _, part := range strings.Split(cookie, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == name {
			return v
		}
	}
	return ""
}

var (
	httpRdPool = sync.Pool{New: func() any { b := make([]byte, httpMaxPlain+httpRecTag); return &b }}
	httpWrPool = sync.Pool{New: func() any { b := make([]byte, 0, 2*(2+httpMaxPlain+httpRecTag)); return &b }}
)

// httpConn 是头部交换之后的加密记录流。读、写各自只允许一个协程(与 TLS 连接的用法相同)。
type httpConn struct {
	net.Conn // 底层 TCP 连接
	br       *bufio.Reader

	wmu     sync.Mutex
	seal    cipher.AEAD
	wctr    uint64
	wclosed bool

	open  cipher.AEAD
	rctr  uint64
	hdr   [2]byte
	hdrN  int
	need  int     // 当前记录的密文长度;0 表示还在读记录头
	have  int     // 当前记录已读到的密文字节数
	body  *[]byte // 池化缓冲,只在一条记录读取、消费期间持有
	plain []byte  // 已解密但还没交给调用方的明文
	rerr  error
}

func newHTTPConn(raw net.Conn, br *bufio.Reader, k *Keys, head, snonce []byte, client bool) *httpConn {
	c2s, s2c := newGCM(httpMAC(k, "c2s", head, snonce)), newGCM(httpMAC(k, "s2c", head, snonce))
	if client {
		return &httpConn{Conn: raw, br: br, seal: c2s, open: s2c}
	}
	return &httpConn{Conn: raw, br: br, seal: s2c, open: c2s}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func (c *httpConn) releaseBody() {
	if c.body != nil {
		httpRdPool.Put(c.body)
		c.body = nil
	}
	c.plain = nil
}

func (c *httpConn) Read(p []byte) (int, error) {
	for {
		if len(c.plain) > 0 {
			n := copy(p, c.plain)
			if c.plain = c.plain[n:]; len(c.plain) == 0 {
				c.releaseBody()
			}
			return n, nil
		}
		if c.rerr != nil {
			return 0, c.rerr
		}
		if len(p) == 0 {
			return 0, nil
		}
		if err := c.readRecord(); err != nil {
			if isTimeout(err) {
				return 0, err // 读超时可以重试:已读到的半条记录保留在状态里
			}
			c.releaseBody()
			c.rerr = err
			return 0, err
		}
	}
}

// readRecord 读入并解密一条记录。被读超时打断时保留进度,下次调用接着读。
func (c *httpConn) readRecord() error {
	if c.need == 0 {
		for c.hdrN < 2 {
			n, err := c.br.Read(c.hdr[c.hdrN:])
			if c.hdrN += n; err != nil && c.hdrN < 2 {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF // 没收到结束记录就断开了
				}
				return err
			}
		}
		n := int(binary.BigEndian.Uint16(c.hdr[:]))
		if n < httpRecTag || n > httpMaxPlain+httpRecTag {
			return errHTTPRecord
		}
		c.need, c.have = n, 0
		c.body = httpRdPool.Get().(*[]byte)
	}
	buf := (*c.body)[:c.need]
	for c.have < c.need {
		n, err := c.br.Read(buf[c.have:])
		if c.have += n; err != nil && c.have < c.need {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return err
		}
	}
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], c.rctr)
	c.rctr++
	pt, err := c.open.Open(buf[:0], nonce[:], buf, c.hdr[:])
	c.need, c.hdrN = 0, 0
	if err != nil {
		return errHTTPRecord
	}
	if len(pt) == 0 {
		return io.EOF // 结束记录:对端正常写完
	}
	c.plain = pt
	return nil
}

func (c *httpConn) appendRecord(out, pt []byte) []byte {
	n := len(pt) + httpRecTag
	hdr := [2]byte{byte(n >> 8), byte(n)}
	out = append(out, hdr[:]...)
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], c.wctr)
	c.wctr++
	return c.seal.Seal(out, nonce[:], pt, hdr[:])
}

func (c *httpConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wclosed {
		return 0, io.ErrClosedPipe
	}
	bp := httpWrPool.Get().(*[]byte)
	defer httpWrPool.Put(bp)
	done := 0
	for done < len(p) {
		// 一次系统调用里尽量多放几条记录
		out, n := (*bp)[:0], 0
		for done+n < len(p) {
			k := min(len(p)-done-n, httpMaxPlain)
			if cap(out)-len(out) < 2+k+httpRecTag {
				break
			}
			out = c.appendRecord(out, p[done+n:done+n+k])
			n += k
		}
		if _, err := c.Conn.Write(out); err != nil {
			return done, err
		}
		done += n
	}
	return done, nil
}

// CloseWrite 发送结束记录并关闭底层连接的写方向(半关闭)。
// 直接 Close 而不先 CloseWrite 表示异常中止:对端会读到 io.ErrUnexpectedEOF。
func (c *httpConn) CloseWrite() error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if c.wclosed {
		return nil
	}
	c.wclosed = true
	var b [2 + httpRecTag]byte
	c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := c.Conn.Write(c.appendRecord(b[:0], nil))
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	return err
}

// dialHTTP 在已建立的 TCP 连接上完成伪装握手:发出请求,读到出口的 200 响应后返回加密连接。
// 握手受 ctx 的期限约束,没有期限时最多等 handshakeTimeout。失败时不关闭 raw,由调用方处理。
func dialHTTP(ctx context.Context, raw net.Conn, k *Keys, host, path string, flags byte, now time.Time) (net.Conn, error) {
	deadline := time.Now().Add(handshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	raw.SetDeadline(deadline)
	token, head := newHTTPToken(k, flags, now)
	if _, err := raw.Write(httpRequest(host, path, token)); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(raw, 4096)
	first, hdr, err := readHTTPHead(br)
	if err != nil {
		return nil, fmt.Errorf("读取出口的响应头失败: %w", err)
	}
	if first != "HTTP/1.1 200 OK" {
		return nil, errors.New("出口拒绝了隧道连接(密钥、路径不一致或时钟偏差过大): " + first)
	}
	snonce, err := base64.RawURLEncoding.DecodeString(strings.Trim(hdr["etag"], `"`))
	if err != nil || len(snonce) != 16+sha256.Size || !hmac.Equal(snonce[16:], httpMAC(k, "server-confirm", head, snonce[:16])) {
		return nil, errors.New("出口的响应头不完整")
	}
	raw.SetDeadline(time.Time{})
	return newHTTPConn(raw, br, k, head, snonce[:16], true), nil
}

// acceptHTTP 在出口侧处理一条新连接:读请求头、校验令牌、写响应头,返回加密连接与令牌里的 flags。
// 校验不通过时按普通 Web 服务器的样子回一个错误页,返回的 err 说明原因。
func acceptHTTP(raw net.Conn, k *Keys, path string, now time.Time, rc *replayCache) (net.Conn, byte, error) {
	raw.SetDeadline(time.Now().Add(handshakeTimeout))
	br := bufio.NewReaderSize(raw, 4096)
	first, hdr, err := readHTTPHead(br)
	if err != nil {
		if err == errHTTPMalformed {
			raw.Write(httpReject(http.StatusBadRequest, now))
		}
		return nil, 0, err
	}
	// 首行形如 "GET /path HTTP/1.1"
	f := strings.Fields(first)
	if len(f) != 3 || !strings.HasPrefix(f[2], "HTTP/1.") {
		raw.Write(httpReject(http.StatusBadRequest, now))
		return nil, 0, errHTTPMalformed
	}
	if f[2] == "HTTP/1.1" && hdr["host"] == "" {
		raw.Write(httpReject(http.StatusBadRequest, now))
		return nil, 0, errHTTPMalformed
	}
	target, _, _ := strings.Cut(f[1], "?")
	token := cookieValue(hdr["cookie"], "sid")
	if f[0] != http.MethodGet || target != path || token == "" {
		reply := httpReject(http.StatusNotFound, now)
		if f[0] == http.MethodHead {
			reply = reply[:bytes.Index(reply, []byte("\r\n\r\n"))+4]
		}
		raw.Write(reply)
		return nil, 0, errors.New("不是隧道请求")
	}
	flags, head, err := verifyHTTPToken(token, k, now, rc)
	if err != nil {
		raw.Write(httpReject(http.StatusNotFound, now))
		return nil, 0, err
	}
	var snonce [16]byte
	rand.Read(snonce[:])
	if _, err := raw.Write(httpResponse(append(snonce[:], httpMAC(k, "server-confirm", head, snonce[:])...), now)); err != nil {
		return nil, 0, err
	}
	raw.SetDeadline(time.Time{})
	return newHTTPConn(raw, br, k, head, snonce[:], false), flags, nil
}
