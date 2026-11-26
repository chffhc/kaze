"""端到端自测脚本共用的辅助代码:起进程、调面板接口、发流量、收尾清理。"""
import json, os, shutil, socket, ssl, subprocess, sys, tempfile, time, urllib.error, urllib.request


class Env:
    def __init__(self, panel_port, prefix="kaze-e2e-"):
        self.bin = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "dist")
        self.panel = f"http://127.0.0.1:{panel_port}"
        self.work = tempfile.mkdtemp(prefix=prefix)
        self.procs = {}
        self.passed = 0

    # ---- 进程 ----
    def exe(self, name):
        return os.path.join(self.bin, name)

    def spawn(self, name, *args):
        log = open(os.path.join(self.work, name + ".log"), "a")
        p = subprocess.Popen(list(args), stdout=log, stderr=subprocess.STDOUT)
        self.procs[name] = p
        return p

    def stop(self, name):
        p = self.procs.pop(name)
        p.terminate()
        p.wait()

    def log(self, name):
        try:
            return open(os.path.join(self.work, name + ".log"), errors="replace").read()
        except OSError:
            return ""

    def node(self, name, token, *extra, connect_host="127.0.0.1"):
        """以对接令牌启动一个节点端(全部绑定在本机回环上)。connect_host 是它告诉面板的"对端连我用这个地址"。"""
        return self.spawn(name, self.exe("kaze-node"), "-u", self.panel, "-t", token, "-state", os.path.join(self.work, name),
                          "-bind", "127.0.0.1", "-connect-host", connect_host, *extra)

    # ---- 面板接口 ----
    def api(self, method, path, body=None, token=None, expect=200):
        req = urllib.request.Request(self.panel + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                code, data = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, data = e.code, e.read()
        out = json.loads(data) if data else None
        if code != expect:
            raise AssertionError(f"{method} {path} -> {code} {out} (期望 {expect})")
        return out

    # ---- 断言与等待 ----
    def check(self, name, cond, detail=""):
        if not cond:
            raise AssertionError(f"✗ {name} {detail}")
        self.passed += 1
        print(f"  ✓ {name} {detail}")

    def wait(self, cond, timeout=15, what=""):
        end = time.time() + timeout
        while time.time() < end:
            try:
                v = cond()
                if v:
                    return v
            except Exception:
                pass
            time.sleep(0.3)
        raise AssertionError("等待超时: " + what)

    # ---- 流量 ----
    @staticmethod
    def port_open(port):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            return False

    @staticmethod
    def _roundtrip(s, n):
        """配合 kaze-bench server 的回显模式:先发一个 'E',之后发什么回什么。"""
        s.settimeout(10)
        payload = b"E" + os.urandom(n)
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(65536)
            if not chunk:
                break
            got += chunk
        s.close()
        return got == payload

    def echo(self, port, n=200_000):
        """经规则端口做一次 TCP 回显;连不上、被重置或数据不一致都算失败。"""
        try:
            return self._roundtrip(socket.create_connection(("127.0.0.1", port), timeout=5), n)
        except OSError:
            return False

    @staticmethod
    def hold(port):
        """经规则端口建立一条长连接并保持(用来检查某个操作会不会打断已有连接)。"""
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.settimeout(5)
        s.sendall(b"E")
        if s.recv(1) != b"E":
            raise AssertionError("长连接建立失败")
        return s

    @staticmethod
    def alive(s):
        """长连接是否还通:发一段数据并原样读回。"""
        msg = os.urandom(64)
        try:
            s.sendall(msg)
            got = b""
            while len(got) < len(msg):
                chunk = s.recv(256)
                if not chunk:
                    return False
                got += chunk
            return got == msg
        except OSError:
            return False

    def tls_echo(self, port, sni=None, alpn=None, n=200_000):
        """以 TLS 连接入口(不校验证书)并做一次回显。返回 (是否成功, 协商出的 ALPN);握手被拒绝时返回 (False, 原因)。"""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        if alpn:
            ctx.set_alpn_protocols(alpn)
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        raw.settimeout(5)
        try:
            s = ctx.wrap_socket(raw, server_hostname=sni)
        except (ssl.SSLError, OSError) as e:
            raw.close()
            return False, str(e)
        proto = s.selected_alpn_protocol()
        try:
            return self._roundtrip(s, n), proto
        except (ssl.SSLError, OSError) as e:
            return False, str(e)

    @staticmethod
    def udp_echo(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        for _ in range(8):
            msg = os.urandom(600)
            s.sendto(msg, ("127.0.0.1", port))
            try:
                if s.recv(4096) == msg:
                    return True
            except socket.timeout:
                pass
        return False

    def bench(self, *args):
        return subprocess.run([self.exe("kaze-bench"), *args], capture_output=True, text=True, timeout=120).stdout.strip()

    # ---- 收尾 ----
    def scan_logs(self):
        """各进程的日志里不应出现崩溃或数据竞争(用 go build -race 编出来的二进制跑时,竞争会写在这里)。"""
        for name in sorted(os.listdir(self.work)):
            if not name.endswith(".log"):
                continue
            text = open(os.path.join(self.work, name), errors="replace").read()
            for mark in ("DATA RACE", "panic:", "fatal error:", "goroutine "):
                if mark in text:
                    i = text.index(mark)
                    raise AssertionError(f"{name} 里出现了 {mark!r}:\n" + text[max(0, i - 200):i + 1500])
        self.check("各进程日志里没有崩溃或数据竞争", True)

    def run(self, main):
        """运行 main,失败时打印各进程日志的末尾;无论成败都停掉所有进程并清理工作目录。"""
        try:
            main()
            self.scan_logs()
            print(f"\n全部通过: {self.passed} 项检查")
            code = 0
        except Exception as e:
            print("\n失败:", e)
            for name in sorted(os.listdir(self.work)):
                if name.endswith(".log") and not name.startswith("target"):
                    print(f"--- {name} (末尾) ---")
                    print("".join(open(os.path.join(self.work, name), errors="replace").readlines()[-12:]))
            code = 1
        finally:
            for p in self.procs.values():
                try:
                    p.terminate()
                except Exception:
                    pass
            time.sleep(0.5)
            shutil.rmtree(self.work, ignore_errors=True)
        sys.exit(code)
