#!/usr/bin/env python3
"""Kaze 端到端自测(1.1 新增功能):HTTP 伪装传输层、TLS 握手指纹、反向隧道、链式出口、TLS 入站与 SNI 分流。

在本机起 面板 + 1 个入口节点 + 4 个出口节点 + 2 个压测目标,全部经面板接口配置,用真实流量验证。

用法: python3 scripts/e2e_features.py <二进制目录>
"""
import json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kzlib import Env

env = Env(18081, "kaze-e2e-feat-")
api, check, wait, bench = env.api, env.check, env.wait, env.bench
TARGET, TLS_TARGET, REV_PORT = 19100, 19101, 22900
plain, secure = f"127.0.0.1:{TARGET}", f"127.0.0.1:{TLS_TARGET}"


def main():
    env.spawn("target", env.exe("kaze-bench"), "server", "-l", plain)
    env.spawn("target-tls", env.exe("kaze-bench"), "server", "-l", secure, "-tls")
    env.spawn("panel", env.exe("kaze-panel"), "-listen", "127.0.0.1:18081", "-data", os.path.join(env.work, "data"),
              "-dist", env.bin, "-admin-pass", "admin-e2e-pass")
    wait(lambda: api("GET", "/api/site"), what="面板启动")
    admin = api("POST", "/api/auth/login", {"username": "admin", "password": "admin-e2e-pass"})["token"]

    def group(name, typ, ratio=1.0, public=True, **config):
        return api("POST", "/api/admin/groups", {"name": name, "type": typ, "ratio": ratio, "public": public, "config": config}, admin)

    def groups():
        return {g["id"]: g for g in api("GET", "/api/admin/groups", token=admin)}

    def nodes():
        return api("GET", "/api/admin/nodes", token=admin)

    print("[1] 设备组:四种出口、一条链、一个接受反向隧道的入口")
    g_http = group("HTTP 伪装出口", "out", 0.5, transport="http", ws_path="/api/v2/sync", allow_private=True)
    g_fp = group("Chrome 指纹出口", "out", 0.5, transport="tls", fingerprint="chrome", allow_private=True)
    g_wss = group("WSS 出口", "out", 0.5, transport="wss", fingerprint="firefox", allow_private=True)
    g_rev = group("内网出口", "out", 2.0, transport="tls", allow_private=True)
    chain = group("三跳线路", "chain", 3.0, chain_hops=[g_http["id"], g_fp["id"], g_wss["id"]], chain_mux=False)
    g_in = group("入口", "in", 1.0, port_range="22000-22100,22440-22449", allow_private=True,
                 reverse_groups=[g_rev["id"]], reverse_sni="edge.example.com")
    check("出口组保存了传输层与指纹设置", g_http["config"]["transport"] == "http" and g_fp["config"]["fingerprint"] == "chrome")
    check("链式出口没有对接命令", chain["install_cmd"] == "" and chain["config"]["chain_hops"] == [g_http["id"], g_fp["id"], g_wss["id"]])
    check("入口组自动生成了反向隧道证书", len(g_in["config"]["rev_cert_pin"]) == 64 and "BEGIN CERTIFICATE" in g_in["config"]["rev_cert_pem"])
    for bad, why in (
        ({"name": "x", "type": "chain", "config": {"chain_hops": [g_http["id"]]}}, "只有一跳"),
        ({"name": "x", "type": "chain", "config": {"chain_hops": [g_http["id"], g_http["id"]]}}, "同一个组出现两次"),
        ({"name": "x", "type": "chain", "config": {"chain_hops": [g_http["id"], g_in["id"]]}}, "把入口组当成一跳"),
        ({"name": "x", "type": "chain", "config": {"chain_hops": [g_http["id"], chain["id"]]}}, "链里套链"),
        ({"name": "x", "type": "out", "config": {"transport": "tls", "fingerprint": "netscape"}}, "不存在的指纹"),
        ({"name": "x", "type": "out", "config": {"transport": "quic"}}, "不存在的传输层"),
        ({"name": "x", "type": "in", "config": {"tls_inbound_policy": 1, "blocked_protocols": ["tls"]}}, "又屏蔽 TLS 又只许 TLS"),
    ):
        api("POST", "/api/admin/groups", bad, admin, expect=400)
    check("不合法的设备组配置被拒绝", True, "(7 种)")
    api("DELETE", f"/api/admin/groups/{g_fp['id']}?force=1", token=admin, expect=400)
    check("被链式出口使用的出口组不能删除", g_fp["id"] in groups())

    print("[2] 节点对接")
    env.node("node-in", g_in["token"], "-rev-port", str(REV_PORT))
    for name, g in (("node-http", g_http), ("node-fp", g_fp), ("node-wss", g_wss)):
        env.node(name, g["token"])
    # 内网出口:它上报的"入口连我用的地址"是一个连不上的地址(127.0.0.9 上没有监听),只有反向隧道走得通
    env.node("node-rev", g_rev["token"], connect_host="127.0.0.9")
    wait(lambda: sum(1 for n in nodes() if n["online"]) == 5, what="5 个节点上线")
    wait(lambda: all(n["tunnel_port"] for n in nodes() if n["group_id"] != g_in["id"]), what="出口上报隧道端口")
    n_in = next(n for n in nodes() if n["group_id"] == g_in["id"])
    check("入口上报了反向隧道端口", n_in["rev_port"] == REV_PORT and not n_in["outdated"])
    env.node("node-chain", chain["token"])
    time.sleep(1.5)
    check("链式出口的令牌不能对接节点", "对接令牌无效" in env.log("node-chain") and len(nodes()) == 5)
    env.stop("node-chain")

    def rev_status(gid):
        m = next(n for n in nodes() if n["group_id"] == gid).get("metrics") or {}
        return m.get("rev_up", 0), m.get("rev_total", 0)

    wait(lambda: rev_status(g_in["id"]) == (1, 1) and rev_status(g_rev["id"]) == (1, 1), 30, "反向隧道建立")
    check("反向隧道已建立(两端探针均为 1/1)", True)

    print("[3] 用户与规则")
    api("POST", "/api/admin/plans", {"name": "标准版", "price": 0, "traffic": 10 * 2**40, "days": 30, "max_rules": 30}, admin)
    plan = api("GET", "/api/admin/plans", token=admin)[0]
    user = api("POST", "/api/auth/register", {"username": "alice", "password": "alice-pass-1"})["token"]
    api("POST", f"/api/plans/{plan['id']}/buy", token=user)
    uid = api("GET", "/api/me", token=user)["id"]

    def rule(name, out, token=user, expect=200, **extra):
        body = {"name": name, "in_group": g_in["id"], "out_group": out, "targets": [plain], **extra}
        return api("POST", "/api/rules", body, token, expect)

    def my_rules():
        return {x["id"]: x for x in api("GET", "/api/rules", token=user)}

    # 端口都明确指定:22440-22449 这一段留给后面的 TLS 入站规则
    r_http = rule("HTTP 伪装", g_http["id"], listen_port=22001)
    r_fp = rule("Chrome 指纹", g_fp["id"], listen_port=22002)
    r_rev = rule("反向隧道", g_rev["id"], listen_port=22003)
    r_chain = rule("三跳", chain["id"], listen_port=22004)
    plain_rules = (r_http, r_fp, r_rev, r_chain)
    for r in plain_rules:
        wait(lambda: env.port_open(r["listen_port"]), what=f"规则 {r['name']} 同步")
    time.sleep(0.8)
    for r in plain_rules:
        check(f"TCP 转发 [{r['name']}]", wait(lambda: env.echo(r["listen_port"]), 10, "TCP 回显"))
        check(f"UDP 转发 [{r['name']}]", env.udp_echo(r["listen_port"]))
    check("规则状态全部正常", all(x["status"] == "ok" for x in my_rules().values()), str({x["name"]: x["status"] for x in my_rules().values()}))

    print("[4] 链路诊断")
    hops = api("POST", f"/api/rules/{r_rev['id']}/diag", token=admin)["hops"]
    check("反向隧道规则:入口报告的是出口拨入的连接", "反向隧道" in hops[0]["to"] and not any(h.get("error") for h in hops),
          json.dumps(hops, ensure_ascii=False))
    hops = api("POST", f"/api/rules/{r_chain['id']}/diag", token=admin)["hops"]
    order = [h["from"].split()[0] for h in hops]
    check("链式出口:按 入口 → 第 1 跳 → 第 2 跳 → 第 3 跳 的顺序给出每一段",
          order == ["入口", "出口", "出口", "出口"] and hops[-1]["to"] == "目标 " + plain and not any(h.get("error") for h in hops),
          json.dumps(hops, ensure_ascii=False))
    hops = api("POST", f"/api/rules/{r_chain['id']}/diag", token=user)["hops"]
    check("普通用户看不到出口节点的地址", all("127.0.0.1" not in h["to"] or h["to"].startswith("目标") for h in hops))

    print("[5] 伪装的样子:直接探测 HTTP 伪装出口的隧道端口")
    import socket
    port = next(n for n in nodes() if n["group_id"] == g_http["id"])["tunnel_port"]
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.sendall(b"GET /api/v2/sync HTTP/1.1\r\nHost: example.com\r\n\r\n")
    s.settimeout(3)
    resp = s.recv(4096).decode(errors="replace")
    s.close()
    check("没有密钥的探测只得到一个普通的 404", resp.startswith("HTTP/1.1 404 Not Found\r\nServer: nginx") and "upgrade" not in resp.lower())

    print("[6] TLS 入站")
    t_alone = rule("TLS 独占端口", g_http["id"], tls_mode="tls", listen_port=22440,
                   tls={"sni": ["App.Example.com"], "alpn": ["h2", "http/1.1"]})
    check("SNI 被规范成小写,协议固定为 TCP", t_alone["tls"]["sni"] == ["app.example.com"] and t_alone["proto"] == "tcp")
    t_origin = rule("TLS 入站 + 回源 TLS", 0, tls_mode="tls", listen_port=22441, targets=[secure],
                    tls={"alpn": ["h2", "http/1.1"], "origin_tls": True})
    t_chain = rule("TLS 入站经三跳后回源 TLS", chain["id"], tls_mode="tls", listen_port=22442, targets=[secure],
                   tls={"alpn": ["http/1.1"], "origin_tls": True, "origin_sni": "bench.local"})
    for r in (t_alone, t_origin, t_chain):
        wait(lambda: env.port_open(r["listen_port"]), what=f"规则 {r['name']} 同步")
    time.sleep(0.8)
    ok, proto = env.tls_echo(22440, "app.example.com", ["h2", "http/1.1"])
    check("TLS 入站:握手、ALPN 协商、解密后经隧道转发", ok and proto == "h2", f"(ALPN={proto})")
    check("SNI 不符的握手被拒绝", not env.tls_echo(22440, "other.example.com", ["h2"])[0])
    check("ALPN 没有交集的握手被拒绝", not env.tls_echo(22440, "app.example.com", ["spdy/3"])[0])
    check("明文连接到不了目标", not env.echo(22440, 100))
    ok, proto = env.tls_echo(22441, "anything.test", ["http/1.1"])
    check("回源 TLS(入口直出):目标是 TLS 服务", ok and proto == "http/1.1")
    ok, proto = env.tls_echo(22442, "x.test", ["http/1.1"])
    check("TLS 入站 → 三跳 → 回源 TLS", ok and proto == "http/1.1")

    print("[7] SNI 分流:多条规则共用一个 TLS 端口")
    rule("越权", 0, tls_mode="parent", listen_port=22443, expect=400)
    check("普通用户不能创建共享 TLS 端口", True)
    rule("没有母规则", 0, tls_mode="child", listen_port=22443, tls={"sni": ["a.split.test"]}, expect=400)
    parent = api("POST", "/api/rules", {"in_group": g_in["id"], "tls_mode": "parent", "listen_port": 22443}, admin)
    check("管理员创建共享 TLS 端口(不需要目标)", parent["tls_mode"] == "parent" and parent["targets"] == [] and parent["name"] == "共享 TLS 端口 22443")
    view = next(g for g in api("GET", "/api/groups", token=user) if g["id"] == g_in["id"])
    check("用户能看到可挂载的共享端口", [p["port"] for p in view["tls_ports"]] == [22443])
    c_a = rule("", 0, tls_mode="child", tls={"sni": ["a.split.test"]})  # 端口留空:组里只有一个共享端口
    c_b = rule("子规则 B", chain["id"], tls_mode="child", listen_port=22443, tls={"sni": ["b.split.test", "b2.split.test"]})
    check("子规则挂到共享端口上,名称默认取 SNI", c_a["listen_port"] == 22443 and c_a["name"] == "a.split.test")
    rule("重复", 0, tls_mode="child", listen_port=22443, tls={"sni": ["B2.split.test"]}, expect=400)
    rule("没写 SNI", 0, tls_mode="child", listen_port=22443, tls={"sni": []}, expect=400)
    rule("端口不对", 0, tls_mode="child", listen_port=22440, tls={"sni": ["c.split.test"]}, expect=400)
    rule("抢端口", 0, listen_port=22443, expect=400)
    check("重复的 SNI、缺 SNI、挂错端口、占用共享端口都被拒绝", True)
    wait(lambda: env.port_open(22443), what="共享 TLS 端口同步")
    time.sleep(1.0)

    def traffic(rid):
        x = my_rules()[rid]
        return x["traffic_up"] + x["traffic_down"]

    check("SNI a → 子规则 A(直出)", wait(lambda: env.tls_echo(22443, "a.split.test")[0], 10, "子规则 A"))
    check("SNI b2 → 子规则 B(经三跳)", env.tls_echo(22443, "b2.split.test")[0])
    check("没有登记的 SNI 握手失败", not env.tls_echo(22443, "nobody.split.test")[0])
    wait(lambda: traffic(c_a["id"]) > 300_000 and traffic(c_b["id"]) > 300_000, 30, "子规则流量上报")
    check("流量分别记在两条子规则上", True, f"(A {traffic(c_a['id'])} 字节, B {traffic(c_b['id'])} 字节)")
    api("DELETE", f"/api/rules/{parent['id']}", token=admin, expect=409)
    check("还有子规则时不能删除共享端口", True)
    # 共享端口换端口号:子规则跟着走
    api("PUT", f"/api/rules/{parent['id']}", {"in_group": g_in["id"], "tls_mode": "parent", "listen_port": 22444}, admin)
    check("共享端口换端口号,子规则跟着迁移", my_rules()[c_a["id"]]["listen_port"] == 22444 and my_rules()[c_b["id"]]["listen_port"] == 22444)
    wait(lambda: env.port_open(22444) and not env.port_open(22443), what="新端口生效")
    check("新端口上按 SNI 分流正常", wait(lambda: env.tls_echo(22444, "b.split.test")[0], 10, "迁移后的子规则"))
    api("POST", f"/api/rules/{parent['id']}/pause", {"paused": True}, admin)
    wait(lambda: not env.port_open(22444), what="暂停共享端口")
    st = my_rules()[c_a["id"]]
    check("共享端口暂停后,子规则显示为不可用并说明原因", st["status"] == "offline" and "22444" in st["error"], f"({st['error']})")
    api("POST", f"/api/rules/{parent['id']}/pause", {"paused": False}, admin)
    wait(lambda: env.port_open(22444), what="恢复共享端口")

    print("[8] 入口组的 TLS 入站策略")
    def set_in(**changes):
        g = groups()[g_in["id"]]
        cfg = {**g["config"], **changes}
        api("PUT", f"/api/admin/groups/{g_in['id']}", {"name": g["name"], "type": "in", "ratio": g["ratio"], "public": True, "config": cfg}, admin)

    set_in(tls_inbound_policy=2, allowed_hosts=[".split.test"])
    rule("普通规则", 0, expect=400)
    rule("独占端口", 0, tls_mode="tls", expect=400)
    rule("白名单之外", 0, tls_mode="child", listen_port=22444, tls={"sni": ["x.other.test"]}, expect=400)
    c_c = rule("白名单之内", 0, tls_mode="child", listen_port=22444, tls={"sni": ["c.split.test"]})
    check("策略 2:用户只能建子规则,且 SNI 必须在白名单内", c_c["tls_mode"] == "child")
    check("原有规则与反向隧道证书不受设备组修改影响", groups()[g_in["id"]]["config"]["rev_cert_pin"] == g_in["config"]["rev_cert_pin"]
          and wait(lambda: env.tls_echo(22444, "c.split.test")[0], 10, "新子规则"))
    set_in(tls_inbound_policy=0, allowed_hosts=[])

    print("[9] 计费:链式出口只按自己的倍率")
    time.sleep(11)
    before_user = api("GET", "/api/me", token=user)["traffic_used"]
    before_rule = traffic(r_chain["id"])
    before_groups = {gid: g["traffic"] for gid, g in groups().items()}
    bench("tcp", "-a", f"127.0.0.1:{r_chain['listen_port']}", "-c", "2", "-d", "2s")
    wait(lambda: traffic(r_chain["id"]) > before_rule + 1_000_000, 30, "链式规则流量上报")
    time.sleep(11)
    raw = traffic(r_chain["id"]) - before_rule
    billed = api("GET", "/api/me", token=user)["traffic_used"] - before_user
    want = raw * (1.0 + 3.0)  # 入口 1.0 + 链式出口 3.0;三个出口组各自的 0.5 不参与
    check("用户扣除 = 实际流量 ×(入口倍率 + 链式出口倍率)", abs(billed - want) <= max(want * 0.001, 64), f"(实际 {raw/1e6:.0f} MB, 计费 {billed/1e6:.0f} MB)")
    after_groups = {gid: g["traffic"] for gid, g in groups().items()}
    grew = {gid: after_groups[gid] - before_groups[gid] for gid in after_groups}
    check("途经的每个出口组都记上了这笔流量", all(grew[g["id"]] == raw for g in (g_http, g_fp, g_wss, chain, g_in)) and grew[g_rev["id"]] == 0)

    print("[10] 反向隧道:入口移出名单后断开,加回来自动恢复")
    set_in(reverse_groups=[])
    wait(lambda: rev_status(g_rev["id"])[1] == 0, 30, "出口停止拨入")
    check("移出名单后,出口不再拨入,入口改走正向地址(此处连不上)", not env.echo(r_rev["listen_port"], 100))
    set_in(reverse_groups=[0])  # 0 = 全部出口组
    wait(lambda: rev_status(g_in["id"]) == (4, 4), 40, "全部出口组接入反向隧道")
    check("名单写成 [0]:四个出口组全部反向接入", env.echo(r_rev["listen_port"]) and env.echo(r_http["listen_port"]) and env.echo(r_chain["listen_port"]))
    set_in(reverse_groups=[g_rev["id"]])
    wait(lambda: rev_status(g_in["id"]) == (1, 1), 40, "恢复为只有内网出口反向接入")
    check("改回指定名单后其余出口恢复正向连接", wait(lambda: env.echo(r_http["listen_port"]), 10, "正向隧道") and env.echo(r_rev["listen_port"]))

    print("[11] 压测(本机回环,2 核,仅供横向对比)")
    def line(label, *args):
        print(f"   [{label}] ", bench(*args))
    # 再建一条各跳之间开启复用的链,和不复用的对比
    chain_mux = group("三跳线路(各跳复用)", "chain", 3.0, chain_hops=[g_http["id"], g_fp["id"], g_wss["id"]], chain_mux=True)
    r_chain_mux = rule("三跳(各跳复用)", chain_mux["id"], listen_port=22005)
    t_direct = rule("TLS 入站直出", 0, tls_mode="tls", listen_port=22445)
    wait(lambda: env.port_open(22005) and env.port_open(22445), what="压测用的规则同步")
    check("各跳复用的链式出口可用", wait(lambda: env.echo(22005), 10, "三跳(各跳复用)"))
    bench_rules = plain_rules + (r_chain_mux,)
    line("基准:直连目标", "tcp", "-a", plain, "-c", "4", "-d", "3s")
    for r in bench_rules:
        line(r["name"], "tcp", "-a", f"127.0.0.1:{r['listen_port']}", "-c", "4", "-d", "3s")
    line("TLS 入站,直出", "tcp", "-a", "127.0.0.1:22445", "-tls", "-c", "4", "-d", "3s")
    line("TLS 入站 + HTTP 伪装隧道", "tcp", "-a", "127.0.0.1:22440", "-tls", "-sni", "app.example.com", "-alpn", "h2", "-c", "4", "-d", "3s")
    line("TLS 入站,直出 + 回源 TLS", "tcp", "-a", "127.0.0.1:22441", "-tls", "-alpn", "http/1.1", "-c", "4", "-d", "3s")
    line("基准:直连目标", "conn", "-a", plain, "-c", "16", "-d", "3s")
    for r in bench_rules:
        line(r["name"], "conn", "-a", f"127.0.0.1:{r['listen_port']}", "-c", "16", "-d", "3s")
    line("TLS 入站,直出", "conn", "-a", "127.0.0.1:22445", "-tls", "-c", "16", "-d", "3s")
    line("TLS 子规则(SNI 分流,直出)", "conn", "-a", "127.0.0.1:22444", "-tls", "-sni", "a.split.test", "-c", "16", "-d", "3s")

    print("[12] 故障转移组")
    def set_out(g, **changes):
        cur = groups()[g["id"]]
        api("PUT", f"/api/admin/groups/{g['id']}", {"name": cur["name"], "type": "out", "ratio": cur["ratio"], "public": True,
                                                    "config": {**cur["config"], **changes}}, admin)

    set_out(g_fp, failover_group=g_wss["id"])
    check("修改出口组不会更换它的密钥和证书", groups()[g_fp["id"]]["config"]["cert_pin"] == g_fp["config"]["cert_pin"]
          and groups()[g_fp["id"]]["config"]["tunnel_key"] == g_fp["config"]["tunnel_key"])
    time.sleep(1.5)
    # 新建规则后马上让主出口宕机:备用组必须已经拿到这条规则
    r_fo = rule("故障转移", g_fp["id"], listen_port=22006)
    wait(lambda: env.port_open(22006), what="规则同步")
    check("主出口正常时走主出口", wait(lambda: env.echo(22006), 10, "回显"))
    env.stop("node-fp")
    check("主出口宕机后,刚建的规则立即由故障转移组接手", wait(lambda: env.echo(22006), 8, "故障转移") and env.echo(22006) and env.udp_echo(22006))
    check("链式出口不使用故障转移组:中间一跳宕机时整条链不通", not env.echo(r_chain["listen_port"], 1000))
    env.node("node-fp", g_fp["token"])
    wait(lambda: sum(1 for n in nodes() if n["online"]) == 5, 30, "主出口恢复")
    check("主出口恢复后链式出口恢复", wait(lambda: env.echo(r_chain["listen_port"], 1000), 45, "链式出口恢复") and env.echo(22006))

    print("[13] 面板重启后一切恢复")
    env.stop("panel")
    check("面板停机期间:反向隧道、链式出口、SNI 分流都不中断",
          env.echo(r_rev["listen_port"], 1000) and env.echo(r_chain["listen_port"], 1000) and env.tls_echo(22444, "a.split.test", n=1000)[0])
    env.spawn("panel", env.exe("kaze-panel"), "-listen", "127.0.0.1:18081", "-data", os.path.join(env.work, "data"), "-dist", env.bin)
    wait(lambda: api("GET", "/api/site"), what="面板重启")
    wait(lambda: sum(1 for n in nodes() if n["online"]) == 5, 60, "节点重连")
    wait(lambda: rev_status(g_in["id"]) == (1, 1), 30, "探针恢复")
    check("节点重连后规则状态全部正常", all(x["status"] == "ok" for x in my_rules().values()),
          str({x["name"]: x["status"] for x in my_rules().values() if x["status"] != "ok"}))
    api("DELETE", f"/api/admin/users/{uid}", token=admin)
    wait(lambda: not env.port_open(r_http["listen_port"]), what="删除用户后规则下线")
    check("删除用户后,他的规则(含子规则)全部下线,共享端口仍在", not env.tls_echo(22444, "a.split.test")[0] and env.port_open(22444))


env.run(main)
