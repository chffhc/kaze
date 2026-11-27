package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"time"
)

// GenerateCert 生成自签名证书(ECDSA P-256,有效期 10 年)。names 依次写入证书的 DNS 名称,
// 第一个同时作为 CommonName。隧道两端不走 CA 校验,而是固定校验证书的 SHA-256 指纹(pin)。
func GenerateCert(names ...string) (certPEM, keyPEM, pin string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	var dns []string
	for _, n := range names {
		if n != "" {
			dns = append(dns, n)
		}
	}
	if len(dns) == 0 {
		dns = []string{"localhost"}
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dns[0]},
		DNSNames:     dns,
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
