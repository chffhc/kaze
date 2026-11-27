#!/usr/bin/env python3
"""Kaze 升级自测:用 1.0.0 的面板和节点建出真实数据,再原地换成新版本,确认数据、转发和计费都接得上。

    1. 旧面板 + 旧节点:建组、对接、建规则(中间删掉几条,制造规则号空洞)、跑流量
    2. 停掉旧面板,换新面板接管同一个数据目录(旧节点保持运行)
    3. 检查:数据库已迁移并留了备份;规则、用量原样保留;旧节点重连后照常转发、照常计费
    4. 换新节点(沿用原状态目录):转发恢复,新功能可用

用法: python3 scripts/e2e_upgrade.py <新版二进制目录> <1.0.0 二进制目录> [把迁移前的数据库另存到这个路径]
旧版二进制可以这样得到:  git worktree add /tmp/kaze-v1 v1.0.0 && (cd /tmp/kaze-v1 && go build -o /tmp/kaze-v1-bin/ ./cmd/...)
"""
import os, shutil, sqlite3, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kzlib import Env

if len(sys.argv) < 3:
    sys.exit(__doc__)
OLD = os.path.abspath(sys.argv[2])
SAVE_DB = sys.argv[3] if len(sys.argv) > 3 else ""
env = Env(18082, "kaze-e2e-upg-")
api, check, wait = env.api, env.check, env.wait
TARGET = 19200
plain, secure = f"127.0.0.1:{TARGET}", f"127.0.0.1:{TARGET + 1}"
data = os.path.join(env.work, "data")


def old(name):
    return os.path.join(OLD, name)


def panel(exe):
    return env.spawn("panel", exe, "-listen", "127.0.0.1:18082", "-data", data, "-dist", env.bin, "-admin-pass", "admin-e2e-pass")


def node(name, exe, token):
    return env.spawn(name, exe, "-u", env.panel, "-t", token, "-state", os.path.join(env.work, name),
                     "-bind", "127.0.0.1", "-connect-host", "127.0.0.1")


def main():
    env.spawn("target", env.exe("kaze-bench"), "server", "-l", plain)
    env.spawn("target-tls", env.exe("kaze-bench"), "server", "-l", secure, "-tls")

    print("[1] 1.0.0:建立数据")
    panel(old("kaze-panel"))
    wait(lambda: api("GET", "/api/site"), what="旧面板启动")
    check("旧面板是 1.0.0", api("GET", "/api/site")["version"] == "1.0.0")
    admin = api("POST", "/api/auth/login", {"username": "admin", "password": "admin-e2e-pass"})["token"]
    g_in = api("POST", "/api/admin/groups", {"name": "入口", "type": "in", "ratio": 1.5,
               "config": {"port_range": "23000-23100", "allow_private": True, "blocked_hosts": [".blocked.test"]}}, admin)
    g_out = api("POST", "/api/admin/groups", {"name": "出口", "type": "out", "ratio": 0.5,
                "config": {"transport": "tls", "mux": True, "allow_private": True}}, admin)
    g_ws = api("POST", "/api/admin/groups", {"name": "WS 出口", "type": "out", "ratio": 1.0, "public": False,
               "config": {"transport": "ws", "allow_private": True, "failover_group": g_out["id"]}}, admin)
    node("node-in", old("kaze-node"), g_in["token"])
    node("node-out", old("kaze-node"), g_out["token"])
    nodes = lambda: api("GET", "/api/admin/nodes", token=admin)
    wait(lambda: sum(1 for n in nodes() if n["online"]) == 2 and any(n["tunnel_port"] for n in nodes()), what="旧节点上线")
    api("POST", "/api/admin/plans", {"name": "标准版", "price": 1000, "traffic": 10 * 2**40, "days": 30, "max_rules": 20,
        "groups": [g_ws["id"]]}, admin)
    plan = api("GET", "/api/admin/plans", token=admin)[0]
    user = api("POST", "/api/auth/register", {"username": "alice", "password": "alice-pass-1"})["token"]
    code = api("POST", "/api/admin/codes", {"type": "balance", "amount": 2500, "count": 2}, admin)["codes"]
    api("POST", "/api/redeem", {"code": code[0]}, user)
    api("POST", f"/api/plans/{plan['id']}/buy", token=user)

    def rule(name, out, port, **extra):
        return api("POST", "/api/rules", {"name": name, "in_group": g_in["id"], "out_group": out, "listen_port": port,
                                          "targets": [plain], **extra}, user)

    r1 = rule("直出", 0, 23001, proxy_protocol=0, lb="failover")
    tmp = [rule(f"临时 {i}", 0, 23010 + i) for i in range(3)]
    r2 = rule("隧道", g_out["id"], 23002, speed_limit=0, proto="tcp")
    r3 = rule("暂停的", g_out["id"], 23003)
    api("POST", f"/api/rules/{r3['id']}/pause", {"paused": True}, user)
    for t in tmp[1:]:  # 删掉中间的两条,让规则号出现空洞
        api("DELETE", f"/api/rules/{t['id']}", token=user)
    last = rule("最后一条", 0, 23004)
    api("DELETE", f"/api/rules/{last['id']}", token=user)  # 规则号最大的一条被删:迁移后新规则不能复用这个号
    for r in (r1, r2):
        wait(lambda: env.port_open(r["listen_port"]), what=f"规则 {r['name']} 同步")
    time.sleep(0.5)
    check("旧版本转发正常", wait(lambda: env.echo(r1["listen_port"]) and env.echo(r2["listen_port"]), 10, "回显"))
    time.sleep(11.5)
    before = {x["id"]: x for x in api("GET", "/api/rules", token=user)}
    me_before = api("GET", "/api/me", token=user)
    check("旧版本已记下流量", before[r1["id"]]["traffic_down"] > 0 and before[r2["id"]]["traffic_down"] > 0 and me_before["traffic_used"] > 0,
          f"(规则 {sorted(before)}, 已用 {me_before['traffic_used']} 字节)")

    print("[2] 换上新面板(旧节点不动)")
    env.stop("panel")
    if SAVE_DB:
        # 另存一份迁移前的数据库(合并掉 WAL),给 internal/panel 的迁移单元测试当样本
        if os.path.exists(SAVE_DB):
            os.remove(SAVE_DB)
        con = sqlite3.connect(os.path.join(data, "kaze.db"))
        con.execute("VACUUM INTO ?", (SAVE_DB,))
        con.close()
        print("   已另存迁移前的数据库:", SAVE_DB)
    panel(env.exe("kaze-panel"))
    wait(lambda: api("GET", "/api/site"), what="新面板启动")
    site = api("GET", "/api/site")
    check("新面板已启动", site["version"] != "1.0.0", f"(版本 {site['version']})")
    check("迁移前自动留了备份", os.path.exists(os.path.join(data, "kaze.db.v1.bak")) and "数据库结构已升级" in env.log("panel"))
    con = sqlite3.connect(os.path.join(data, "kaze.db.v1.bak"))
    check("备份是迁移前的完整数据", con.execute("SELECT COUNT(*) FROM rules").fetchone()[0] == len(before)
          and con.execute("PRAGMA user_version").fetchone()[0] == 0)
    con.close()

    check("原来的登录令牌仍然有效", api("GET", "/api/me", token=user)["username"] == "alice")
    after = {x["id"]: x for x in api("GET", "/api/rules", token=user)}
    keys = ("name", "in_group", "out_group", "listen_port", "proto", "targets", "lb", "proxy_protocol", "paused", "created_at")
    check("规则原样保留", sorted(after) == sorted(before) and all(after[i][k] == before[i][k] for i in before for k in keys))
    check("旧规则都是普通规则(没有 TLS 入站设置)", all(x["tls_mode"] == "" and x["tls"]["sni"] == [] for x in after.values()))
    check("规则流量与用户用量没有丢", all(after[i]["traffic_down"] >= before[i]["traffic_down"] for i in before)
          and api("GET", "/api/me", token=user)["traffic_used"] >= me_before["traffic_used"])
    me = api("GET", "/api/me", token=user)
    check("套餐、余额、到期时间原样保留", all(me[k] == me_before[k] for k in ("plan_id", "balance", "expire_at", "traffic_quota", "max_rules")))
    gs = {g["id"]: api("GET", f"/api/admin/groups/{g['id']}", token=admin) for g in api("GET", "/api/admin/groups", token=admin)}
    check("设备组配置原样保留(密钥、证书、故障转移组、黑名单)",
          gs[g_out["id"]]["config"]["tunnel_key"] == g_out["config"]["tunnel_key"]
          and gs[g_out["id"]]["config"]["cert_pin"] == g_out["config"]["cert_pin"]
          and gs[g_ws["id"]]["config"]["failover_group"] == g_out["id"] and gs[g_ws["id"]]["public"] is False
          and gs[g_in["id"]]["config"]["blocked_hosts"] == [".blocked.test"] and gs[g_in["id"]]["token"] == g_in["token"])
    check("订单与兑换码原样保留", len(api("GET", "/api/orders", token=user)) == 2
          and sum(1 for c in api("GET", "/api/admin/codes", token=admin) if c["used_by"]) == 1)

    new_rule = rule("升级后新建", 0, 23005)
    check("新规则不会复用已删除规则的编号", new_rule["id"] > last["id"], f"(删除前最大 {last['id']}, 新规则 {new_rule['id']})")
    api("POST", "/api/rules", {"in_group": g_in["id"], "listen_port": 23001, "targets": [plain]}, user, expect=400)
    check("端口占用检查仍然有效", True)

    print("[3] 旧节点接上新面板")
    wait(lambda: sum(1 for n in nodes() if n["online"]) == 2, 60, "旧节点重连")
    check("旧节点被标记为需要升级", all(n["outdated"] and n["version"] == "1.0.0" for n in nodes()))
    wait(lambda: env.port_open(23005), what="新规则同步到旧节点")
    check("旧节点照常转发(直出、隧道、新建的规则)", env.echo(23001) and env.echo(23002) and env.echo(23005))
    mid = {x["id"]: x for x in api("GET", "/api/rules", token=user)}
    wait(lambda: {x["id"]: x for x in api("GET", "/api/rules", token=user)}[r2["id"]]["traffic_down"] > mid[r2["id"]]["traffic_down"],
         30, "旧节点流量上报")
    check("旧节点的流量上报照常入账", True)
    check("旧节点上规则状态正常", all(x["status"] in ("ok", "paused") for x in api("GET", "/api/rules", token=user)))

    # 管理员升级后第一次打开设备组点"保存"(界面会把整份配置原样带回):不应让出口重启隧道、打断现有连接
    def resave(g):
        cur = api("GET", f"/api/admin/groups/{g['id']}", token=admin)
        body = {k: cur[k] for k in ("name", "type", "ratio", "public", "sort", "note", "config")}
        api("PUT", f"/api/admin/groups/{g['id']}", body, admin)
        return api("GET", f"/api/admin/groups/{g['id']}", token=admin)

    long_conn = env.hold(23002)
    saved = resave(g_out)
    resave(g_in)
    time.sleep(2.5)
    check("原样保存设备组:密钥、证书一字不差,隧道上的长连接不受影响",
          saved["config"]["tunnel_key"] == g_out["config"]["tunnel_key"] and saved["config"]["cert_pem"] == g_out["config"]["cert_pem"]
          and saved["config"]["key_pem"] == g_out["config"]["key_pem"] and env.alive(long_conn)
          and env.log("node-out").count("隧道已监听") == 1)
    long_conn.close()

    # 旧节点不认识新字段。新功能的规则不能下发给它:TLS 入站规则到了旧入口上会变成一个明文转发的端口。
    rules_now = lambda: {x["id"]: x for x in api("GET", "/api/rules", token=user)}
    t_new = api("POST", "/api/rules", {"name": "升级前建的 TLS 入站", "in_group": g_in["id"], "out_group": 0, "listen_port": 23060,
                                       "targets": [plain], "tls_mode": "tls"}, user)
    o_new = api("POST", "/api/rules", {"name": "升级前建的回源 TLS", "in_group": g_in["id"], "out_group": g_out["id"], "listen_port": 23061,
                                       "targets": [secure], "tls_mode": "tls", "tls": {"origin_tls": True}}, user)
    time.sleep(3)
    st = rules_now()[t_new["id"]]
    check("新功能的规则不会下发到旧节点", not env.port_open(23060) and not env.port_open(23061))
    check("规则状态说明了原因和解决办法", st["status"] == "error" and "1.0.0" in st["error"] and "升级" in st["error"], f"({st['error']})")
    check("其余规则不受影响", env.echo(23001) and env.echo(23002))

    print("[4] 换上新节点")
    env.stop("node-in")
    node("node-in", env.exe("kaze-node"), g_in["token"])
    wait(lambda: env.port_open(23060) and env.port_open(23061), 60, "入口升级后 TLS 入站规则生效")
    check("入口升级后,直出的 TLS 入站规则立即可用", wait(lambda: env.tls_echo(23060)[0], 10, "TLS 回显"))
    st = rules_now()[o_new["id"]]
    check("出口还没升级:依赖它的规则继续报错,不会带着错误的行为去转发",
          st["status"] == "error" and "回源 TLS" in st["error"] and not env.tls_echo(23061)[0], f"({st['error']})")
    check("新入口与旧出口之间的原有隧道规则照常工作", env.echo(23002))
    env.stop("node-out")
    node("node-out", env.exe("kaze-node"), g_out["token"])
    wait(lambda: sum(1 for n in nodes() if n["online"] and not n["outdated"]) == 2, 60, "新节点上线")
    check("新节点沿用原来的身份,没有多出机器", len(nodes()) == 2)
    check("新节点转发正常", wait(lambda: env.echo(23001) and env.echo(23002), 15, "回显"))
    check("出口也升级后,回源 TLS 的规则恢复正常", wait(lambda: env.tls_echo(23061)[0], 15, "回源 TLS")
          and rules_now()[o_new["id"]]["status"] == "ok")
    g_http = api("POST", "/api/admin/groups", {"name": "新出口", "type": "out", "config": {"transport": "http", "allow_private": True}}, admin)
    node("node-http", env.exe("kaze-node"), g_http["token"])
    wait(lambda: sum(1 for n in nodes() if n["online"]) == 3 and all(n["tunnel_port"] for n in nodes() if n["group_id"] != g_in["id"]), what="新出口上线")
    chain = api("POST", "/api/admin/groups", {"name": "两跳", "type": "chain", "ratio": 2, "config": {"chain_hops": [g_out["id"], g_http["id"]]}}, admin)
    api("POST", "/api/rules", {"name": "TLS 入站经两跳", "in_group": g_in["id"], "out_group": chain["id"], "listen_port": 23050,
                               "targets": [plain], "tls_mode": "tls", "tls": {"sni": ["up.example.com"]}}, user)
    wait(lambda: env.port_open(23050), what="新功能规则同步")
    check("升级后的环境里新功能可用(TLS 入站 + 链式出口,其中一跳是升级前就有的出口组)",
          wait(lambda: env.tls_echo(23050, "up.example.com")[0], 15, "TLS 回显"))

    print("[5] 再重启一次新面板:不应重复迁移")
    env.stop("panel")
    mtime = os.path.getmtime(os.path.join(data, "kaze.db.v1.bak"))
    panel(env.exe("kaze-panel"))
    wait(lambda: api("GET", "/api/site"), what="面板重启")
    check("第二次启动不再迁移,备份没有被覆盖", env.log("panel").count("数据库结构已升级") == 1
          and os.path.getmtime(os.path.join(data, "kaze.db.v1.bak")) == mtime)
    check("规则数量不变", len(api("GET", "/api/rules", token=user)) == len(before) + 4)


env.run(main)
