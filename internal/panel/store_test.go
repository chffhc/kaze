package panel

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kaze/internal/proto"
)

// testdata/v1.0.0.db 是由 1.0.0 的面板和节点实际跑出来的数据库(scripts/e2e_upgrade.py 的第三个参数另存的),
// 里面的密钥、证书和口令都只属于那次测试。它有 4 条规则(编号 1、2、5、6),自增计数停在 7。
func copyFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile(filepath.Join("testdata", "v1.0.0.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "kaze.db"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func scalar[T any](t *testing.T, db *sql.DB, q string, args ...any) T {
	t.Helper()
	var v T
	if err := db.QueryRow(q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return v
}

func insertTestRule(db *sql.DB, inGroup int64, port int, mode string) (int64, error) {
	res, err := db.Exec(`INSERT INTO rules(user_id,in_group,listen_port,created_at,updated_at,tls_mode) VALUES(1,?,?,0,0,?)`, inGroup, port, mode)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// 端口唯一性:普通规则、独占端口的 TLS 规则、母规则互斥;子规则可以共用母规则的端口。
func checkPortIndex(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := insertTestRule(db, 900, 443, proto.TLSModeParent); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", proto.TLSModeAlone, proto.TLSModeParent} {
		if _, err := insertTestRule(db, 900, 443, mode); err == nil {
			t.Fatalf("模式 %q 不应能占用已有规则的端口", mode)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := insertTestRule(db, 900, 443, proto.TLSModeChild); err != nil {
			t.Fatalf("子规则应当可以共用端口: %v", err)
		}
	}
	if _, err := insertTestRule(db, 901, 443, ""); err != nil {
		t.Fatalf("不同入口组的同一个端口互不影响: %v", err)
	}
}

func TestFreshDatabase(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if v := scalar[int](t, db, `PRAGMA user_version`); v != schemaVersion {
		t.Fatalf("user_version = %d", v)
	}
	if _, err := os.Stat(filepath.Join(dir, "kaze.db.v1.bak")); err == nil {
		t.Fatal("全新安装不应产生迁移备份")
	}
	if n := scalar[int](t, db, `SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name='rev_port'`); n != 1 {
		t.Fatal("nodes 表缺少 rev_port")
	}
	checkPortIndex(t, db)
	db.Close()
	// 再次打开:什么都不做
	db2, err := openDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if n := scalar[int](t, db2, `SELECT COUNT(*) FROM rules`); n != 5 {
		t.Fatalf("重新打开后规则数 = %d", n)
	}
}

func TestMigrateFromV1(t *testing.T) {
	dir := copyFixture(t)
	db, err := openDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if v := scalar[int](t, db, `PRAGMA user_version`); v != schemaVersion {
		t.Fatalf("user_version = %d", v)
	}
	// 备份是迁移之前的样子
	bak, err := sql.Open("sqlite", "file:"+filepath.ToSlash(filepath.Join(dir, "kaze.db.v1.bak"))+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer bak.Close()
	if v := scalar[int](t, bak, `PRAGMA user_version`); v != 0 {
		t.Fatalf("备份的 user_version = %d", v)
	}
	if ddl := scalar[string](t, bak, `SELECT sql FROM sqlite_master WHERE name='rules'`); !strings.Contains(ddl, "UNIQUE(in_group, listen_port)") {
		t.Fatal("备份应当保留旧的表结构")
	}

	// 规则逐条对照
	type row struct {
		id                                  int64
		name, proto, targets, lb            string
		user, in, out, port, up, down, crea int64
		paused                              bool
	}
	load := func(d *sql.DB) []row {
		rows, err := d.Query(`SELECT id,name,proto,targets,lb,user_id,in_group,out_group,listen_port,traffic_up,traffic_down,created_at,paused FROM rules ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.name, &r.proto, &r.targets, &r.lb, &r.user, &r.in, &r.out, &r.port, &r.up, &r.down, &r.crea, &r.paused); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		return out
	}
	before, after := load(bak), load(db)
	if len(before) != 4 || len(after) != 4 {
		t.Fatalf("规则数: 迁移前 %d,迁移后 %d", len(before), len(after))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Fatalf("规则 #%d 在迁移后变了:\n 前 %+v\n 后 %+v", before[i].id, before[i], after[i])
		}
	}
	if after[0].up == 0 || !after[3].paused {
		t.Fatalf("样本数据不符合预期: %+v", after)
	}
	// 新列有默认值,经 scanRule 读出来是"普通规则"
	r, err := getRule(db, after[0].id)
	if err != nil {
		t.Fatal(err)
	}
	if r.TLSMode != "" || len(r.TLS.SNI) != 0 || r.TLS.OriginTLS || r.tlsInbound() != nil || r.originTLS() != nil {
		t.Fatalf("旧规则应当是普通规则: %+v", r)
	}

	// 规则号不能复用:样本里 #7 已被删除,新规则必须从 8 开始
	id, err := insertTestRule(db, 1, 23999, "")
	if err != nil {
		t.Fatal(err)
	}
	if id != 8 {
		t.Fatalf("新规则的编号 = %d,应为 8", id)
	}
	// 旧的表级唯一约束换成了"子规则除外"的索引
	if _, err := insertTestRule(db, after[0].in, int(after[0].port), ""); err == nil {
		t.Fatal("迁移后仍应禁止两条普通规则占用同一个端口")
	}
	checkPortIndex(t, db)

	// 其它表原样保留,nodes 多了 rev_port
	for table, want := range map[string]int{"users": 2, "device_groups": 3, "nodes": 2, "plans": 1, "orders": 2, "redeem_codes": 2} {
		if n := scalar[int](t, db, `SELECT COUNT(*) FROM `+table); n != want {
			t.Errorf("%s: %d 行,应为 %d", table, n, want)
		}
	}
	nodes, err := listNodes(db, "")
	if err != nil || len(nodes) != 2 || nodes[0].RevPort != 0 || nodes[0].UID == "" {
		t.Fatalf("节点读取失败: %v %+v", err, nodes)
	}
	groups, err := listGroups(db)
	if err != nil || len(groups) != 3 {
		t.Fatal(err)
	}
	for _, g := range groups {
		if g.Type == proto.RoleOut && (len(g.Config.TunnelKey) != 64 || g.Config.CertPin == "" || g.Config.Fingerprint != "") {
			t.Errorf("出口组 %s 的配置没有完整保留: %+v", g.Name, g.Config)
		}
	}
	db.Close()

	// 第二次打开不再迁移,备份保持不动
	st, _ := os.Stat(filepath.Join(dir, "kaze.db.v1.bak"))
	db2, err := openDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	st2, _ := os.Stat(filepath.Join(dir, "kaze.db.v1.bak"))
	if !st.ModTime().Equal(st2.ModTime()) || st.Size() != st2.Size() {
		t.Fatal("再次启动不应改动备份")
	}
	if n := scalar[int](t, db2, `SELECT COUNT(*) FROM rules`); n != 4+1+5 {
		t.Fatalf("重新打开后规则数 = %d", n)
	}
}

// 数据库来自更新的版本时拒绝启动,而不是带着看不懂的结构往下跑。
func TestRefuseNewerDatabase(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if db, err := openDB(dir); err == nil {
		db.Close()
		t.Fatal("应当拒绝打开结构版本更新的数据库")
	} else if !strings.Contains(err.Error(), "更新版本") {
		t.Fatalf("错误信息应当说明原因: %v", err)
	}
}

func TestMatchGroupList(t *testing.T) {
	for _, c := range []struct {
		list []int64
		id   int64
		want bool
	}{
		{nil, 3, false},
		{[]int64{3, 4}, 3, true},
		{[]int64{3, 4}, 5, false},
		{[]int64{0}, 5, true},       // 0 = 全部
		{[]int64{0, 3, 4}, 5, true}, // 全部,3 和 4 除外
		{[]int64{0, 3, 4}, 3, false},
		{[]int64{3, 0}, 3, false}, // 顺序无关
	} {
		if got := matchGroupList(c.list, c.id); got != c.want {
			t.Errorf("matchGroupList(%v, %d) = %v", c.list, c.id, got)
		}
	}
}

func TestChainHopsResolution(t *testing.T) {
	gs := groupSet{
		1:  {ID: 1, Type: proto.RoleIn},
		2:  {ID: 2, Type: proto.RoleOut},
		3:  {ID: 3, Type: proto.RoleOut},
		4:  {ID: 4, Type: proto.RoleOut},
		10: {ID: 10, Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2, 3, 4}}},
		11: {ID: 11, Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2, 99}}}, // 途经的组已被删除
		12: {ID: 12, Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2}}},
		13: {ID: 13, Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2, 10}}}, // 链里套链
	}
	if hops, chain, ok := gs.hops(0); !ok || hops != nil || chain != nil {
		t.Fatal("直接转发没有出口")
	}
	if hops, chain, ok := gs.hops(3); !ok || len(hops) != 1 || hops[0].ID != 3 || chain != nil {
		t.Fatal("普通出口组就是一跳")
	}
	hops, chain, ok := gs.hops(10)
	if !ok || chain == nil || chain.ID != 10 || len(hops) != 3 || hops[0].ID != 2 || hops[2].ID != 4 {
		t.Fatalf("链式出口解析有误: %v %v %v", hops, chain, ok)
	}
	for _, bad := range []int64{1, 11, 12, 13, 404} {
		if _, _, ok := gs.hops(bad); ok {
			t.Errorf("出口 #%d 不应可用", bad)
		}
	}
	if nextHopKey(7, true) == nextHopKey(7, false) || chainFirstHopKey(7) == 7 {
		t.Fatal("隧道键应当区分不同的变体")
	}
}

func TestNormalizeGroup(t *testing.T) {
	gs := groupSet{2: {ID: 2, Type: proto.RoleOut}, 3: {ID: 3, Type: proto.RoleOut}, 5: {ID: 5, Type: proto.RoleIn}}

	// 出口组:生成密钥与证书,清掉与出口无关的字段
	out := groupInput{Name: "出口", Type: proto.RoleOut, Ratio: 1, Config: GroupConfig{
		Transport: "http", Fingerprint: "Chrome", PortRange: "1-2", ReverseGroups: []int64{1}, ChainHops: []int64{2, 3}}}
	if err := normalizeGroup(&out, nil, gs); err != nil {
		t.Fatal(err)
	}
	c := out.Config
	if len(c.TunnelKey) != 64 || c.CertPin == "" || c.Fingerprint != "chrome" || c.WSPath != "/" || c.PortRange != "" || c.ReverseGroups != nil || c.ChainHops != nil {
		t.Fatalf("出口组规范化结果不对: %+v", c)
	}
	// 编辑时不传密钥材料:沿用原来的
	old := &Group{ID: 9, Type: proto.RoleOut, Config: c}
	edit := groupInput{Name: "出口", Type: proto.RoleOut, Ratio: 1, Config: GroupConfig{Transport: "wss", Mux: false}}
	if err := normalizeGroup(&edit, old, gs); err != nil {
		t.Fatal(err)
	}
	if edit.Config.TunnelKey != c.TunnelKey || edit.Config.CertPin != c.CertPin || !edit.Config.Mux {
		t.Fatal("编辑出口组应沿用密钥与证书,且 WebSocket 强制复用")
	}

	// 入口组:开了反向隧道才生成证书,之后保持不变
	in := groupInput{Name: "入口", Type: proto.RoleIn, Ratio: 1, Config: GroupConfig{TunnelKey: "x", Transport: "tls"}}
	if err := normalizeGroup(&in, nil, gs); err != nil {
		t.Fatal(err)
	}
	if in.Config.RevCertPEM != "" || in.Config.PortRange != "10000-60000" || in.Config.TunnelKey != "" || in.Config.Transport != "" || in.Config.ReverseConns != 2 {
		t.Fatalf("入口组规范化结果不对: %+v", in.Config)
	}
	in.Config.ReverseGroups = []int64{2, 2, 0}
	if err := normalizeGroup(&in, &Group{Type: proto.RoleIn, Config: in.Config}, gs); err != nil {
		t.Fatal(err)
	}
	pin := in.Config.RevCertPin
	if len(pin) != 64 || len(in.Config.ReverseGroups) != 2 {
		t.Fatalf("开启反向隧道后应生成证书并去重名单: %+v", in.Config.ReverseGroups)
	}
	again := groupInput{Name: "入口", Type: proto.RoleIn, Ratio: 1, Config: GroupConfig{ReverseGroups: []int64{2}}}
	if err := normalizeGroup(&again, &Group{Type: proto.RoleIn, Config: in.Config}, gs); err != nil || again.Config.RevCertPin != pin {
		t.Fatal("再次保存不应更换反向隧道证书")
	}

	for name, bad := range map[string]groupInput{
		"类型不存在":     {Name: "x", Type: "relay"},
		"名称为空":      {Name: " ", Type: proto.RoleIn},
		"倍率为负":      {Name: "x", Type: proto.RoleIn, Ratio: -1},
		"传输层不存在":    {Name: "x", Type: proto.RoleOut, Config: GroupConfig{Transport: "quic"}},
		"指纹不存在":     {Name: "x", Type: proto.RoleOut, Config: GroupConfig{Fingerprint: "netscape"}},
		"路径不合法":     {Name: "x", Type: proto.RoleOut, Config: GroupConfig{WSPath: "no-slash"}},
		"CDN 缺地址":   {Name: "x", Type: proto.RoleOut, Config: GroupConfig{CDN: true}},
		"端口范围不合法":   {Name: "x", Type: proto.RoleIn, Config: GroupConfig{PortRange: "9-1"}},
		"TLS 策略越界":  {Name: "x", Type: proto.RoleIn, Config: GroupConfig{TLSInboundPolicy: 3}},
		"屏蔽又强制 TLS": {Name: "x", Type: proto.RoleIn, Config: GroupConfig{TLSInboundPolicy: 2, BlockedProtocols: []string{"tls"}}},
		"链只有一跳":     {Name: "x", Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2}}},
		"链有四跳":      {Name: "x", Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2, 3, 2, 3}}},
		"链里重复":      {Name: "x", Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2, 2}}},
		"链经过入口组":    {Name: "x", Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2, 5}}},
		"链经过不存在的组":  {Name: "x", Type: proto.RoleChain, Config: GroupConfig{ChainHops: []int64{2, 77}}},
	} {
		if err := normalizeGroup(&bad, nil, gs); err == nil {
			t.Errorf("%s: 应当被拒绝", name)
		}
	}
	if err := normalizeGroup(&groupInput{Name: "x", Type: proto.RoleChain}, &Group{Type: proto.RoleOut}, gs); err == nil {
		t.Error("设备组类型不应可以更改")
	}
	chain := groupInput{Name: "链", Type: proto.RoleChain, Ratio: 2, Config: GroupConfig{ChainHops: []int64{3, 2}, ChainMux: true, Transport: "tls"}}
	if err := normalizeGroup(&chain, nil, gs); err != nil || chain.Config.Transport != "" || !chain.Config.ChainMux || chain.Config.TunnelKey != "" {
		t.Fatalf("链式出口规范化结果不对: %v %+v", err, chain.Config)
	}
}

func TestRuleTLSHelpers(t *testing.T) {
	if got, err := normalizeSNI([]string{" A.Example.com ", "a.example.com", "", "b.test"}); err != nil || len(got) != 2 || got[0] != "a.example.com" {
		t.Fatalf("normalizeSNI: %v %v", got, err)
	}
	for _, bad := range []string{"localhost", "1.2.3.4", "*.example.com", "exa mple.com", "-a.com"} {
		if _, err := normalizeSNI([]string{bad}); err == nil {
			t.Errorf("SNI %q 应当被拒绝", bad)
		}
	}
	if got, err := normalizeALPN([]string{"h2", " http/1.1", "h2"}); err != nil || len(got) != 2 {
		t.Fatalf("normalizeALPN: %v %v", got, err)
	}
	if _, err := normalizeALPN([]string{"bad proto"}); err == nil {
		t.Error("带空格的 ALPN 应当被拒绝")
	}

	// 私钥不出接口;回源 TLS 只对会转发的 TLS 规则生效
	r := &Rule{TLSMode: proto.TLSModeAlone, TLS: RuleTLS{SNI: []string{"a.test"}, KeyPEM: "secret", CertPEM: "cert", OriginTLS: true, OriginSNI: "o.test"}}
	if in := r.tlsInbound(); in == nil || in.KeyPEM != "secret" || in.Mode != proto.TLSModeAlone {
		t.Fatal("下发给节点的配置应带私钥")
	}
	if o := r.originTLS(); o == nil || o.SNI != "o.test" {
		t.Fatal("originTLS 有误")
	}
	if r.redact(); r.TLS.KeyPEM != "" || !r.TLS.HasKey || r.TLS.CertPEM != "cert" {
		t.Fatal("redact 应去掉私钥并标记已保存")
	}
	if (&Rule{TLSMode: proto.TLSModeParent, TLS: RuleTLS{OriginTLS: true}}).originTLS() != nil || (&Rule{TLS: RuleTLS{OriginTLS: true}}).originTLS() != nil {
		t.Fatal("母规则和普通规则没有回源 TLS")
	}

	// 编辑时不重新填私钥:证书没变就沿用,变了就必须重填
	ig := &Group{Config: GroupConfig{AllowedHosts: []string{".ok.test"}, BlockedHosts: []string{".bad.ok.test"}}}
	old := &Rule{TLS: RuleTLS{CertPEM: "CERT", KeyPEM: "KEY"}}
	nr := &Rule{TLSMode: proto.TLSModeChild}
	if err := prepareTLS(nr, &RuleTLS{SNI: []string{"a.ok.test"}, CertPEM: " CERT\n"}, ig, old); err != nil || nr.TLS.KeyPEM != "KEY" {
		t.Fatalf("证书未变时应沿用私钥: %v", err)
	}
	if err := prepareTLS(nr, &RuleTLS{SNI: []string{"a.ok.test"}, CertPEM: "OTHER"}, ig, old); err == nil {
		t.Fatal("换了证书却没给私钥,应当报错")
	}
	if err := prepareTLS(nr, &RuleTLS{SNI: []string{"a.ok.test"}, CertPEM: "x", KeyPEM: "y"}, ig, nil); err == nil {
		t.Fatal("不成对的证书与私钥应当报错")
	}
	for name, sni := range map[string][]string{"不在白名单": {"a.other.test"}, "在黑名单": {"x.bad.ok.test"}, "子规则没有 SNI": {}} {
		if err := prepareTLS(&Rule{TLSMode: proto.TLSModeChild}, &RuleTLS{SNI: sni}, ig, nil); err == nil {
			t.Errorf("%s: 应当被拒绝", name)
		}
	}
	// 母规则:忽略 SNI / ALPN / 回源设置
	pr := &Rule{TLSMode: proto.TLSModeParent}
	if err := prepareTLS(pr, &RuleTLS{SNI: []string{"whatever"}, ALPN: []string{"h2"}, OriginTLS: true}, ig, nil); err != nil || len(pr.TLS.SNI) != 0 || len(pr.TLS.ALPN) != 0 || pr.TLS.OriginTLS {
		t.Fatalf("母规则不应保留转发相关的 TLS 设置: %v %+v", err, pr.TLS)
	}
}

// 密钥材料:不带(或原样带回)= 沿用;明确清空 = 重新生成。
func TestKeyMaterialRotation(t *testing.T) {
	gs := groupSet{}
	mk := groupInput{Name: "出口", Type: proto.RoleOut, Ratio: 1, Config: GroupConfig{Transport: "tls"}}
	if err := normalizeGroup(&mk, nil, gs); err != nil {
		t.Fatal(err)
	}
	old := &Group{ID: 1, Type: proto.RoleOut, Config: mk.Config}
	save := func(body string) GroupConfig {
		t.Helper()
		var in groupInput
		if err := json.Unmarshal([]byte(body), &in); err != nil {
			t.Fatal(err)
		}
		in.Name, in.Type, in.Ratio = "出口", proto.RoleOut, 1
		if err := normalizeGroup(&in, keyMaterialBase(old, []byte(body)), gs); err != nil {
			t.Fatal(err)
		}
		return in.Config
	}
	full, _ := json.Marshal(map[string]any{"config": old.Config})
	for name, body := range map[string]string{"不带密钥材料": `{"config":{"transport":"tls"}}`, "原样带回": string(full)} {
		if c := save(body); c.TunnelKey != old.Config.TunnelKey || c.CertPin != old.Config.CertPin || c.KeyPEM != old.Config.KeyPEM {
			t.Errorf("%s: 应当沿用原有的密钥与证书", name)
		}
	}
	if c := save(`{"config":{"transport":"tls","tunnel_key":""}}`); c.TunnelKey == old.Config.TunnelKey || len(c.TunnelKey) != 64 || c.CertPin != old.Config.CertPin {
		t.Error("清空 tunnel_key 应当只更换隧道密钥")
	}
	c := save(`{"config":{"transport":"tls","cert_pem":" ","key_pem":"` + strings.ReplaceAll(old.Config.KeyPEM, "\n", `\n`) + `"}}`)
	if c.CertPin != old.Config.CertPin {
		t.Error("cert_pem 不是空字符串时不算清空")
	}
	c = save(`{"config":{"transport":"tls","cert_pem":"","key_pem":"` + strings.ReplaceAll(old.Config.KeyPEM, "\n", `\n`) + `"}}`)
	if c.CertPin == old.Config.CertPin || c.KeyPEM == old.Config.KeyPEM || c.TunnelKey != old.Config.TunnelKey {
		t.Error("清空 cert_pem 应当更换证书和私钥,保留隧道密钥")
	}
	// 入口组的反向隧道证书
	in := groupInput{Name: "入口", Type: proto.RoleIn, Ratio: 1, Config: GroupConfig{ReverseGroups: []int64{0}}}
	if err := normalizeGroup(&in, nil, gs); err != nil {
		t.Fatal(err)
	}
	oldIn := &Group{ID: 2, Type: proto.RoleIn, Config: in.Config}
	again := groupInput{Name: "入口", Type: proto.RoleIn, Ratio: 1, Config: GroupConfig{ReverseGroups: []int64{0}}}
	if err := normalizeGroup(&again, keyMaterialBase(oldIn, []byte(`{"config":{"rev_cert_pem":""}}`)), gs); err != nil || again.Config.RevCertPin == oldIn.Config.RevCertPin || again.Config.RevCertPin == "" {
		t.Errorf("清空 rev_cert_pem 应当更换反向隧道证书: %v", err)
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		v, min string
		want   bool
	}{
		{"1.1.0", "1.1.0", true}, {"1.0.0", "1.1.0", false}, {"1.0.9", "1.1.0", false}, {"1.2.0", "1.1.0", true},
		{"2.0.0", "1.1.0", true}, {"1.10.0", "1.9.0", true}, {"1.1", "1.1.0", true}, {"", "1.1.0", false}, {"dev", "1.1.0", false},
	} {
		if got := versionAtLeast(c.v, c.min); got != c.want {
			t.Errorf("versionAtLeast(%q, %q) = %v", c.v, c.min, got)
		}
	}
}

// 1.0 的节点端不认识新字段:用到新功能的规则不能下发给它,否则会被当成普通规则来跑。
func TestForLegacyNode(t *testing.T) {
	in := &proto.InboundConfig{
		Rules: []proto.Rule{
			{ID: 1, ListenPort: 1000, Targets: []string{"a:1"}},
			{ID: 2, ListenPort: 443, TLS: &proto.TLSInbound{Mode: proto.TLSModeParent}},
			{ID: 3, ListenPort: 443, Targets: []string{"a:1"}, TLS: &proto.TLSInbound{Mode: proto.TLSModeChild, SNI: []string{"x.test"}}},
			{ID: 4, ListenPort: 1001, OutGroup: 7},
			{ID: 5, ListenPort: 1002, OutGroup: 8},
			{ID: 6, ListenPort: 1003, OutGroup: -8, UDPStream: true},
		},
		Tunnels: map[int64]*proto.TunnelSpec{
			7:  {GroupID: 7, Transport: "http"},
			8:  {GroupID: 8, Transport: "tls", Fingerprint: "chrome"},
			-8: {GroupID: 8, Transport: "tls"},
		},
		Reverse:           &proto.ReverseListen{CertPEM: "c"},
		TLSRejectEmptySNI: true,
	}
	out := &proto.OutboundConfig{
		Transport: "tls",
		Rules: []proto.OutRule{
			{ID: 10, Targets: []string{"a:1"}},
			{ID: 11, Next: 17},
			{ID: 12, Targets: []string{"a:1"}, OriginTLS: &proto.OriginTLS{}},
		},
		Tunnels: map[int64]*proto.TunnelSpec{17: {GroupID: 8}},
		Reverse: []proto.ReverseSpec{{Endpoint: "1.2.3.4:5"}},
	}
	li, lo, skipped := forLegacyNode(in, out, "1.0.0")
	ids := func() (got []int64) {
		for _, r := range li.Rules {
			got = append(got, r.ID)
		}
		for _, r := range lo.Rules {
			got = append(got, r.ID)
		}
		return
	}()
	if want := []int64{1, 5, 6, 10}; len(ids) != len(want) || ids[0] != 1 || ids[1] != 5 || ids[2] != 6 || ids[3] != 10 {
		t.Fatalf("保留的规则 = %v,应为 %v", ids, want)
	}
	for _, id := range []int64{2, 3, 4, 11, 12} {
		if !strings.Contains(skipped[id], "1.0.0") || !strings.Contains(skipped[id], proto.Version) {
			t.Errorf("规则 %d 应当说明被跳过的原因: %q", id, skipped[id])
		}
	}
	if len(skipped) != 5 || li.Tunnels[7] != nil || li.Tunnels[8] == nil || li.Reverse != nil || li.TLSRejectEmptySNI || lo.Tunnels != nil || lo.Reverse != nil {
		t.Fatalf("裁剪结果不对: skipped=%v in=%+v out=%+v", skipped, li, lo)
	}
	// 原配置不能被改动:同组里的新节点还要用它
	if len(in.Rules) != 6 || in.Tunnels[7] == nil || in.Reverse == nil || len(out.Rules) != 3 || out.Tunnels == nil {
		t.Fatal("forLegacyNode 修改了原配置")
	}
	if _, _, sk := forLegacyNode(&proto.InboundConfig{Rules: []proto.Rule{{ID: 1}}}, nil, "1.0.0"); sk != nil {
		t.Fatal("没有被跳过的规则时应返回 nil")
	}
}

// 没有开反向端口的入口机器:同一份组配置里的反向隧道要换成正向连接,而且不能改动共享的原配置。
func TestWithoutReverse(t *testing.T) {
	plain := &proto.InboundConfig{Tunnels: map[int64]*proto.TunnelSpec{1: {GroupID: 1, Endpoints: []string{"1.1.1.1:1"}}}}
	if withoutReverse(plain) != plain {
		t.Fatal("没有用到反向隧道时应原样返回")
	}
	in := &proto.InboundConfig{
		Rules:   []proto.Rule{{ID: 1, OutGroup: 1}},
		Reverse: &proto.ReverseListen{CertPEM: "c", Groups: map[int64]string{1: "k"}},
		Tunnels: map[int64]*proto.TunnelSpec{
			1: {GroupID: 1, Endpoints: []string{"1.1.1.1:1"}, Reverse: true, Fallback: &proto.TunnelSpec{GroupID: 2, Reverse: true}},
			3: {GroupID: 3, Endpoints: []string{"3.3.3.3:3"}},
		},
	}
	out := withoutReverse(in)
	if out == in || out.Reverse != nil || out.Tunnels[1].Reverse || out.Tunnels[1].Fallback.Reverse || len(out.Rules) != 1 {
		t.Fatalf("反向设置没有去干净: %+v", out.Tunnels[1])
	}
	if out.Tunnels[1].Endpoints[0] != "1.1.1.1:1" || out.Tunnels[3] != in.Tunnels[3] {
		t.Fatal("正向地址应当保留,无关的隧道不必复制")
	}
	if in.Reverse == nil || !in.Tunnels[1].Reverse || !in.Tunnels[1].Fallback.Reverse {
		t.Fatal("withoutReverse 修改了原配置")
	}
}
