package relay

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

var ppV2Sig = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// ProxyHeader 生成 PROXY protocol 头(ver = 1 或 2),用于向目标传递客户端真实地址。
func ProxyHeader(ver int, src, dst netip.AddrPort) []byte {
	sa, da := src.Addr().Unmap(), dst.Addr().Unmap()
	if !sa.IsValid() || !da.IsValid() {
		if ver == 1 {
			return []byte("PROXY UNKNOWN\r\n")
		}
		return append(append([]byte{}, ppV2Sig...), 0x20, 0x00, 0x00, 0x00) // LOCAL
	}
	v4 := sa.Is4() && da.Is4()
	if !v4 { // 地址族不一致时统一成 IPv6
		sa = netip.AddrFrom16(sa.As16())
		da = netip.AddrFrom16(da.As16())
	}
	if ver == 1 {
		fam := "TCP6"
		if v4 {
			fam = "TCP4"
		}
		return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", fam, sa, da, src.Port(), dst.Port()))
	}
	b := append(make([]byte, 0, 64), ppV2Sig...)
	b = append(b, 0x21) // v2, PROXY
	if v4 {
		b = append(b, 0x11, 0, 12)
		s4, d4 := sa.As4(), da.As4()
		b = append(b, s4[:]...)
		b = append(b, d4[:]...)
	} else {
		b = append(b, 0x21, 0, 36)
		s6, d6 := sa.As16(), da.As16()
		b = append(b, s6[:]...)
		b = append(b, d6[:]...)
	}
	b = binary.BigEndian.AppendUint16(b, src.Port())
	b = binary.BigEndian.AppendUint16(b, dst.Port())
	return b
}
