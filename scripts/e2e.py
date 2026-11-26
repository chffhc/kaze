#!/usr/bin/env python3
"""Kaze 端到端自测:在本机起 面板 + 入口节点 + 出口节点 + 压测目标,
走一遍 建组 -> 对接 -> 套餐/兑换码 -> 建规则 -> 转发 -> 计费 -> 限额停机 的完整流程。

用法: python3 scripts/e2e.py <二进制目录>     (目录里需要有 kaze-panel / kaze-node / kaze-bench)
"""
import json, os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kzlib import Env

env = Env(18080)
BIN, PANEL, TARGET = env.bin, env.panel, 19000
spawn, api, check, wait, bench = env.spawn, env.api, env.check, env.wait, env.bench
port_open, echo, udp_echo = env.port_open, env.echo, env.udp_echo


def main():
    spawn("target", os.path.join(BIN, "kaze-bench"), "server", "-l", f"127.0.0.1:{TARGET}")
    spawn("panel", os.path.join(BIN, "kaze-panel"), "-listen", "127.0.0.1:18080", "-data", os.path.join(env.work, "data"),
          "-dist", BIN, "-admin-pass", "admin-e2e-pass")
    wait(lambda: api("GET", "/api/site"), what="面板启动")

    print("[1] 登录与基础配置")
    admin = api("POST", "/api/auth/login", {"username": "admin", "password": "admin-e2e-pass"})["token"]
    api("POST", "/api/auth/login", {"username": "admin", "password": "wrong"}, expect=401)
    check("管理员登录", bool(admin))
    gin = api("POST", "/api/admin/groups", {"name": "上海入口", "type": "in", "ratio": 1.5,
              "config": {"port_range": "20000-20100", "allow_private": True}}, admin)
    gout = api("POST", "/api/admin/groups", {"name": "香港出口", "type": "out", "ratio": 0.5,
               "config": {"transport": "tls", "mux": True, "allow_private": True}}, admin)
    gws = api("POST", "/api/admin/groups", {"name": "WS 出口", "type": "out", "ratio": 1,
              "config": {"transport": "ws", "allow_private": True, "udp_over_tcp": True, "ws_path": "/kz"}}, admin)
    check("创建设备组", gin["id"] and gout["id"] and "install.sh" in gin["install_cmd"])
    check("出口组自动生成密钥与证书", len(gout["config"]["tunnel_key"]) == 64 and len(gout["config"]["cert_pin"]) == 64)

    print("[2] 节点对接")
    for name, g in (("in", gin), ("out", gout), ("ws", gws)):
        spawn("node-" + name, os.path.join(BIN, "kaze-node"), "-u", PANEL, "-t", g["token"],
              "-state", os.path.join(env.work, "node-" + name), "-bind", "127.0.0.1", "-connect-host", "127.0.0.1")
    wait(lambda: sum(1 for n in api("GET", "/api/admin/nodes", token=admin) if n["online"]) == 3, what="节点上线")
    wait(lambda: all(n["tunnel_port"] for n in api("GET", "/api/admin/nodes", token=admin) if n["group_id"] != gin["id"]),
         what="出口上报隧道端口")
    check("三个节点全部在线,出口已上报隧道端口", True)
    spawn("node-bad", os.path.join(BIN, "kaze-node"), "-u", PANEL, "-t", "deadbeef", "-state", os.path.join(env.work, "bad"))

    print("[3] 用户、套餐与兑换码")
    plan = None
    api("POST", "/api/admin/plans", {"name": "标准版", "price": 1000, "traffic": 10 * 2**40, "days": 30,
        "max_rules": 5, "speed_limit": 0}, admin)
    plan = api("GET", "/api/admin/plans", token=admin)[0]
    reg = api("POST", "/api/auth/register", {"username": "alice", "password": "alice-pass-1"})
    user = reg["token"]
    api("POST", "/api/rules", {"in_group": gin["id"], "targets": [f"127.0.0.1:{TARGET}"]}, user, expect=400)
    check("未购买套餐的用户不能建规则", True)
    api("POST", f"/api/plans/{plan['id']}/buy", token=user, expect=400)
    check("余额不足不能购买", True)
    codes = api("POST", "/api/admin/codes", {"type": "balance", "amount": 1500, "count": 1}, admin)["codes"]
    api("POST", "/api/redeem", {"code": codes[0]}, user)
    api("POST", "/api/redeem", {"code": codes[0]}, user, expect=400)
    me = api("POST", f"/api/plans/{plan['id']}/buy", token=user)
    check("兑换码充值并购买套餐", me["balance"] == 500 and me["traffic_quota"] == 10 * 2**40 and me["expire_at"] > time.time())
    api("GET", "/api/admin/users", token=user, expect=403)
    check("普通用户无法访问管理接口", True)

    print("[4] 转发规则")
    r1 = api("POST", "/api/rules", {"name": "直出", "in_group": gin["id"], "out_group": 0,
             "targets": [f"127.0.0.1:{TARGET}"]}, user)
    r2 = api("POST", "/api/rules", {"name": "TLS 隧道", "in_group": gin["id"], "out_group": gout["id"],
             "targets": [f"127.0.0.1:{TARGET}"], "proto": "tcp+udp"}, user)
    r3 = api("POST", "/api/rules", {"name": "WS 隧道", "in_group": gin["id"], "out_group": gws["id"],
             "targets": [f"127.0.0.1:{TARGET}"], "listen_port": 20050}, user)
    check("自动分配端口落在端口范围内", 20000 <= r1["listen_port"] <= 20100 and r3["listen_port"] == 20050)
    api("POST", "/api/rules", {"in_group": gin["id"], "targets": ["127.0.0.1:1"], "listen_port": 20050}, user, expect=400)
    api("POST", "/api/rules", {"in_group": gin["id"], "targets": ["127.0.0.1:1"], "listen_port": 80}, user, expect=400)
    check("端口冲突与越界被拒绝", True)
    for r in (r1, r2, r3):
        wait(lambda: port_open(r["listen_port"]), what=f"规则 {r['name']} 同步")
    time.sleep(0.5)
    for r in (r1, r2, r3):
        check(f"TCP 转发 [{r['name']}]", wait(lambda: echo(r["listen_port"]), 10, "TCP 回显"))
        check(f"UDP 转发 [{r['name']}]", udp_echo(r["listen_port"]))
    hops = api("POST", f"/api/rules/{r2['id']}/diag", token=admin)["hops"]
    check("链路诊断", len(hops) >= 2 and all(not h.get("error") for h in hops), json.dumps(hops, ensure_ascii=False))

    print("[5] 压测(本机回环,仅供横向对比)")
    print("   基准(直连目标):", bench("tcp", "-a", f"127.0.0.1:{TARGET}", "-c", "4", "-d", "3s"))
    for r in (r1, r2, r3):
        print(f"   [{r['name']}] ", bench("tcp", "-a", f"127.0.0.1:{r['listen_port']}", "-c", "4", "-d", "3s"))
    print("   基准(直连目标):", bench("conn", "-a", f"127.0.0.1:{TARGET}", "-c", "16", "-d", "3s"))
    for r in (r1, r2, r3):
        print(f"   [{r['name']}] ", bench("conn", "-a", f"127.0.0.1:{r['listen_port']}", "-c", "16", "-d", "3s"))
    for r in (r1, r2):
        print(f"   [{r['name']}] ", bench("udp", "-a", f"127.0.0.1:{r['listen_port']}", "-c", "2", "-d", "3s"))

    print("[6] 流量统计与计费")
    def traffic():
        rules = {x["id"]: x for x in api("GET", "/api/rules", token=user)}
        return rules, api("GET", "/api/me", token=user)
    rules, me = wait(lambda: (lambda t: t if all(t[0][r["id"]]["traffic_down"] > 1e6 for r in (r1, r2, r3)) else None)(traffic()),
                     30, "流量上报")
    time.sleep(11)  # 等最后一个上报周期落库
    rules, me = traffic()
    raw = {r["id"]: rules[r["id"]]["traffic_up"] + rules[r["id"]]["traffic_down"] for r in (r1, r2, r3)}
    # 计费 = 直出 ×1.5 + TLS 隧道 ×(1.5+0.5) + WS 隧道 ×(1.5+1)
    want = raw[r1["id"]] * 1.5 + raw[r2["id"]] * 2.0 + raw[r3["id"]] * 2.5
    check("按倍率计费", abs(me["traffic_used"] - want) <= max(want * 0.001, 64),
          f"(实际 {sum(raw.values())/1e6:.0f} MB, 计费 {me['traffic_used']/1e6:.0f} MB)")
    check("规则状态正常", all(x["status"] == "ok" for x in rules.values()))

    print("[7] 限额与规则生命周期")
    uid = me["id"]
    api("PUT", f"/api/admin/users/{uid}", {"traffic_quota": 1}, admin)
    wait(lambda: not port_open(r1["listen_port"]), what="流量用尽后规则下线")
    check("流量用尽后规则自动下线", True)
    api("PUT", f"/api/admin/users/{uid}", {"traffic_quota": 10 * 2**40}, admin)
    wait(lambda: port_open(r1["listen_port"]), what="恢复额度后规则上线")
    check("恢复额度后规则自动恢复", echo(r1["listen_port"], 1000))
    api("POST", f"/api/rules/{r1['id']}/pause", {"paused": True}, user)
    wait(lambda: not port_open(r1["listen_port"]), what="暂停规则")
    api("DELETE", f"/api/rules/{r2['id']}", token=user)
    wait(lambda: not port_open(r2["listen_port"]), what="删除规则")
    check("暂停 / 删除规则即时生效", True)
    api("PUT", f"/api/admin/users/{uid}", {"speed_limit": 8}, admin)  # 8 Mbps
    wait(lambda: port_open(r3["listen_port"]), what="限速变更后规则重启")
    time.sleep(0.5)
    out = bench("tcp", "-a", f"127.0.0.1:{r3['listen_port']}", "-c", "2", "-d", "4s")
    mbs = float(out.split("(")[-1].split(" MB/s")[0])
    check("用户级限速 8 Mbps", 0.5 <= mbs <= 1.6, f"(实测 {mbs*8:.1f} Mbps)")

    print("[8] 面板重启后节点自动重连")
    env.stop("panel")
    check("面板停机期间转发不中断", echo(r3["listen_port"], 1000))
    spawn("panel", os.path.join(BIN, "kaze-panel"), "-listen", "127.0.0.1:18080", "-data", os.path.join(env.work, "data"), "-dist", BIN)
    wait(lambda: api("GET", "/api/site"), what="面板重启")
    wait(lambda: sum(1 for n in api("GET", "/api/admin/nodes", token=admin) if n["online"]) == 3, 60, "节点重连")
    check("节点已自动重连", True)


env.run(main)
