#!/usr/bin/env python3
"""Fix 3 acceptance. Run only on the patched tree:

    python3 scripts/test-rule-revocation.py --patched

Builds from source with a local Go toolchain/module cache (no downloads).
No existing panel, node, database, binary or endpoint is accepted as input.
"""
import argparse
from contextlib import ExitStack
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HOST = '127.0.0.1'


class Failure(Exception):
    """Only fixture-authored, credential-free messages go to stdout/stderr."""


def require(ok, msg):
    if not ok:
        raise Failure(msg)


def until(label, check, seconds=8):
    end = time.monotonic() + seconds
    while True:
        if check():
            return
        if time.monotonic() >= end:
            raise Failure('timed out: ' + label)
        time.sleep(0.1)


def reserve(stack):
    s = stack.enter_context(socket.socket())
    s.bind((HOST, 0))
    return s, s.getsockname()[1]


def stop(p):
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()


def connect(port):
    return socket.create_connection((HOST, port), timeout=2)


def exchange(s):
    # E selects echo mode on the first exchange with kaze-bench.
    payload = b'E' + secrets.token_bytes(31)
    s.sendall(payload)
    got = bytearray()
    while len(got) < len(payload):
        part = s.recv(len(payload) - len(got))
        require(part, 'unexpected EOF on a permitted stream')
        got.extend(part)
    require(got == payload, 'incorrect echo on a permitted stream')


def fresh(port):
    with connect(port) as s:
        exchange(s)


def refused(port):
    try:
        with connect(port):
            return False
    except ConnectionRefusedError:
        return True


def closed(s):
    # At the barrier all earlier echoes were drained. Silence is not EOF.
    try:
        require(s.recv(1) == b'', 'unexpected data on the revoked stream')
    except (ConnectionResetError, ConnectionAbortedError):
        pass
    except TimeoutError:
        raise Failure('revoked stream did not close') from None


def rule_ids(work, node, section):
    state = work / node / 'kaze-node.json'
    if not state.exists():
        return None
    cfg = json.loads(state.read_bytes()).get('last_config', {}).get(section)
    return None if cfg is None else {r['id'] for r in cfg['rules']}


def scenario(bins, work, stack, fallback):
    route = 'fallback' if fallback else 'primary'
    work.mkdir()
    password = secrets.token_urlsafe(24)
    panel_sock, panel = reserve(stack)
    target_sock, target = reserve(stack)
    slots = [reserve(stack) for _ in range(3)]

    def spawn(binary, *args, **env):
        p = subprocess.Popen([bins / binary, *args], cwd=work,
                             env={'HOME': str(work), 'TMPDIR': str(work), **env},
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        stack.callback(stop, p)
        return p

    def api(method, path, body=None, token=None):
        conn = HTTPConnection(HOST, panel, timeout=5)  # no proxy or redirect handling
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        try:
            conn.request(method, '/api/' + path, json.dumps(body) if body is not None else None,
                         headers)
            res = conn.getresponse()
            require(res.status == 200, f'{method} {path}: HTTP {res.status}')
            return json.loads(res.read())
        finally:
            conn.close()

    panel_sock.close()
    proc = spawn('kaze-panel', '-listen', f'{HOST}:{panel}', '-data', 'db', '-dist', str(bins),
                 KAZE_ADMIN_PASS=password)

    def ready():
        require(proc.poll() is None, 'temporary panel exited')
        try:
            return api('GET', 'site')
        except ConnectionRefusedError:
            return False

    until('panel readiness', ready)
    admin = api('POST', 'auth/login', {'username': 'admin', 'password': password})['token']
    target_sock.close()
    spawn('kaze-bench', 'server', '-l', f'{HOST}:{target}')

    def group(name, role, **cfg):
        return api('POST', 'admin/groups', {'name': name, 'type': role, 'public': False,
                   'config': {'allow_private': True, **cfg}}, admin)

    ingress = group('ingress', 'in', port_range='1024-65535')
    backup = group('backup', 'out', transport='tcp')
    primary = group('primary', 'out', transport='tcp', failover_group=backup['id'])
    # Exactly one exit runs: a successful tunneled echo cannot take the other route.
    for name, g in [('ingress', ingress), ('exit', backup if fallback else primary)]:
        spawn('kaze-node', '-u', f'http://{HOST}:{panel}', '-state', name, '-bind', HOST,
              '-connect-host', HOST, KAZE_TOKEN=g['token'])

    def nodes_ready():
        nodes = api('GET', 'admin/nodes', token=admin)
        return {n['group_id'] for n in nodes if n['online'] and
                (n['group_id'] == ingress['id'] or n['tunnel_port'])} == {
                    ingress['id'], (backup if fallback else primary)['id']}

    until('private local nodes online', nodes_ready, seconds=20)
    grants = [g['id'] for g in (ingress, primary, backup)]

    def provision(name):
        plan = {'name': name, 'groups': grants, 'price': 0, 'days': 1,
                'max_rules': 3, 'traffic': 1 << 30}
        api('POST', 'admin/plans', plan, admin)
        pid = next(p['id'] for p in api('GET', 'admin/plans', token=admin) if p['name'] == name)
        user = api('POST', 'auth/register', {'username': name, 'password': secrets.token_urlsafe(24)})['token']
        api('POST', f'plans/{pid}/buy', token=user)
        return user, pid, plan

    alice, aid, plan_a = provision('alice')
    bob, _, _ = provision('bob')
    rules = []
    for (port_sock, port), owner in zip(slots, [alice, alice, bob]):
        port_sock.close()
        rules.append(api('POST', 'rules', {'in_group': ingress['id'], 'out_group': primary['id'],
                         'proto': 'tcp', 'listen_port': port, 'targets': [f'{HOST}:{target}']}, owner))
    a, paused, b = [r['id'] for r in rules]
    ap, pp, bp = [r['listen_port'] for r in rules]

    def applied(expected):
        for node, section in [('ingress', 'inbound'), ('exit', 'outbound')]:
            until(f'{route}: {node} applied expected rule IDs',
                  lambda: rule_ids(work, node, section) == expected)

    def update(granted):
        api('PUT', f'admin/plans/{aid}', {**plan_a, 'groups': granted}, admin)
        for user, want in [(alice, granted), (bob, grants)]:
            require({g['id'] for g in api('GET', 'groups', token=user)} == set(want),
                    'incorrect effective grants after plan edit')

    def saved():
        require({r['id']: r['paused'] for r in api('GET', 'rules', token=alice)} ==
                {a: False, paused: True}, 'saved A rules or manual pause changed')

    applied({a, paused, b})
    fresh(pp)  # prove this rule worked before its owner paused it
    api('POST', f'rules/{paused}/pause', {'paused': True}, alice)
    applied({a, b})
    require(refused(pp), 'manually paused listener still open')
    sa, sb = (stack.enter_context(connect(p)) for p in (ap, bp))
    exchange(sa)
    exchange(sb)

    removed = primary['id'] if fallback else ingress['id']
    update([gid for gid in grants if gid != removed])
    applied({b})
    closed(sa)
    require(refused(ap) and refused(pp), 'revoked or paused listener still open')
    saved()
    exchange(sb)  # the original B stream, not a replacement
    fresh(bp)

    update(grants)
    applied({a, b})
    fresh(ap)
    require(refused(pp), 'restoration reopened the manually paused listener')
    saved()
    exchange(sb)
    fresh(bp)
    print(f'PASS {route}: A closed/refused then restored; manual pause preserved; B continuous')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--patched', action='store_true', required=True,
                        help='confirm fix 3 is present in this source tree')
    parser.parse_args()
    hub = (ROOT / 'internal/panel/hub.go').read_text()
    require('loadRulePolicy' in hub, 'patched panel config generation not found; no services started')
    with tempfile.TemporaryDirectory(prefix='kaze-rule-grants-') as tmp:
        root = Path(tmp)
        bins = root / 'bin'
        bins.mkdir()
        env = {**os.environ, 'GOENV': 'off', 'GOWORK': 'off', 'GOTOOLCHAIN': 'local',
               'GOPROXY': 'off', 'GONOPROXY': 'none', 'GOSUMDB': 'off', 'GOFLAGS': '',
               'GOVCS': '*:off', 'GOTELEMETRY': 'off', 'CGO_ENABLED': '0'}
        result = subprocess.run(['go', 'build', '-mod=readonly', '-o', str(bins), './cmd/kaze-panel',
                                 './cmd/kaze-node', './cmd/kaze-bench'], cwd=ROOT, env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=240)
        require(result.returncode == 0, 'offline build failed (check Go version, cache and patched sources)')
        for fallback in (False, True):
            with ExitStack() as stack:
                scenario(bins, root / ('fallback' if fallback else 'primary'), stack, fallback)


if __name__ == '__main__':
    try:
        main()
    except Failure as e:
        sys.exit('FAIL: ' + str(e))
    except Exception as e:
        # Third-party exceptions can include response bodies or credentials.
        sys.exit('FAIL: fixture error (' + type(e).__name__ + ')')
