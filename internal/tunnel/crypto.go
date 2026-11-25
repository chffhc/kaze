package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"sync/atomic"
	"time"
)

// UDPOverhead 是原生 UDP 通道每个报文的额外字节数:nonce(12) + 规则号(4) + GCM tag(16)。
const UDPOverhead = 12 + 4 + 16

// UDPCipher 负责原生 UDP 通道的加解密(AES-256-GCM)。
// 两个方向使用不同的密钥;nonce = 进程启动时随机的 6 字节前缀 + 6 字节计数器。
type UDPCipher struct {
	seal, open cipher.AEAD
	prefix     [6]byte
	ctr        atomic.Uint64
}

// NewUDPCipher 创建加解密器;client=true 表示入口侧。
func NewUDPCipher(k *Keys, client bool) *UDPCipher {
	mk := func(key []byte) cipher.AEAD {
		blk, _ := aes.NewCipher(key)
		a, _ := cipher.NewGCM(blk)
		return a
	}
	c := &UDPCipher{}
	if client {
		c.seal, c.open = mk(k.udpC2S), mk(k.udpS2C)
	} else {
		c.seal, c.open = mk(k.udpS2C), mk(k.udpC2S)
	}
	rand.Read(c.prefix[:])
	return c
}

// Seal 把 规则号|payload 加密追加到 dst。
func (c *UDPCipher) Seal(dst []byte, ruleID uint32, payload []byte) []byte {
	var nonce [12]byte
	copy(nonce[:6], c.prefix[:])
	n := c.ctr.Add(1)
	nonce[6], nonce[7] = byte(n>>40), byte(n>>32)
	binary.BigEndian.PutUint32(nonce[8:], uint32(n))
	var rid [4]byte
	binary.BigEndian.PutUint32(rid[:], ruleID)
	dst = append(dst, nonce[:]...)
	// 规则号作为明文的前 4 字节一并加密
	start := len(dst)
	dst = append(dst, rid[:]...)
	dst = append(dst, payload...)
	out := c.seal.Seal(dst[:start], nonce[:], dst[start:], nil)
	return out
}

// Open 解密一个报文,返回规则号与 payload(payload 复用 pkt 的底层存储)。
func (c *UDPCipher) Open(pkt []byte) (ruleID uint32, payload []byte, ok bool) {
	if len(pkt) < UDPOverhead {
		return 0, nil, false
	}
	pt, err := c.open.Open(pkt[12:12], pkt[:12], pkt[12:], nil)
	if err != nil || len(pt) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(pt), pt[4:], true
}

// GenerateCert 生成出口组使用的自签名证书(ECDSA P-256,有效期 10 年)。
// 入口不走 CA 校验,而是固定校验证书的 SHA-256 指纹(pin)。
func GenerateCert(commonName string) (certPEM, keyPEM, pin string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if commonName == "" {
		commonName = "localhost"
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{commonName},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return
	}
	kb, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return
	}
	sum := sha256.Sum256(der)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}))
	return certPEM, keyPEM, hex.EncodeToString(sum[:]), nil
}
