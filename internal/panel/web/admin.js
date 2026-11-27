// Kaze 面板前端:管理端页面与应用启动。

// ---- 总览 ----
const AdminDashPage = {
  setup() {
    const s = ref(null), unit = ref('hour');
    poll(() => run(async () => { s.value = await api('GET', '/api/admin/stats'); }), 15000);
    return { s, unit, fmt };
  },
  template: `
  <div v-if="s">
    <div class="page-head"><div><h1>全站总览</h1><p class="sub">面板版本 {{ s.version }}</p></div></div>
    <div class="panel">
      <dl class="stats" style="margin:0">
        <div class="fact"><dt>在线节点</dt><dd>{{ s.nodes_online }}<small> / {{ s.nodes }} 台</small></dd></div>
        <div class="fact"><dt>用户 / 规则</dt><dd>{{ s.users }}<small> 人 / {{ s.rules }} 条</small></dd></div>
        <div v-if="s.unattributed_count" class="fact"><dt>近 62 天未归属流量</dt><dd>{{ fmt.bytes(s.unattributed_bytes) }}<small> / {{ s.unattributed_count }} 条</small></dd></div>
        <div class="fact"><dt>充值(今日 / 本月)</dt><dd>{{ fmt.money(s.recharge_today) }}<small> / {{ fmt.money(s.recharge_month) }}</small></dd></div>
        <div class="fact"><dt>套餐销售(今日 / 本月)</dt><dd>{{ fmt.money(s.sales_today) }}<small> / {{ fmt.money(s.sales_month) }}</small></dd></div>
      </dl>
    </div>
    <div class="panel">
      <div class="panel-head">
        <h2>全站流量</h2>
        <div class="actions">
          <div class="legend"><span><i style="background:var(--teal)"></i>下行</span><span><i style="background:var(--amber)"></i>上行</span></div>
          <div class="seg"><button type="button" :class="{on: unit === 'hour'}" @click="unit = 'hour'">24 小时</button><button type="button" :class="{on: unit === 'day'}" @click="unit = 'day'">30 天</button></div>
        </div>
      </div>
      <div class="panel-body"><traffic-chart :points="unit === 'hour' ? s.hourly : s.daily" :unit="unit"></traffic-chart></div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>近 24 小时用量排行</h2><span class="sub">按计费流量</span></div>
      <div class="empty" v-if="!s.top_users.length">近 24 小时没有流量。</div>
      <table v-else><tbody><tr v-for="(t, i) in s.top_users" :key="t.username">
        <td style="width:48px" class="num dim">{{ i + 1 }}</td><td>{{ t.username }}</td><td class="r num">{{ fmt.bytes(t.billed) }}</td>
      </tr></tbody></table>
    </div>
  </div>`,
};

// ---- 用户 ----
const AdminUsersPage = {
  setup() {
    const users = ref(null), plans = ref([]), q = ref(''), form = ref(null);
    const load = () => run(async () => { users.value = await api('GET', '/api/admin/users' + (q.value ? '?q=' + encodeURIComponent(q.value) : '')); });
    onMounted(() => { load(); run(async () => { plans.value = await api('GET', '/api/admin/plans'); }); });
    function open(u) {
      form.value = u ? {
        id: u.id, username: u.username, password: '', role: u.role, balance: u.balance / 100, plan_id: u.plan_id,
        quota_gb: fmt.gb(u.traffic_quota), used_gb: fmt.gb(u.traffic_used), expire: fmt.toLocalInput(u.expire_at),
        max_rules: u.max_rules, speed_limit: u.speed_limit, conn_limit: u.conn_limit, ip_limit: u.ip_limit, banned: u.banned, note: u.note || '',
      } : { id: 0, username: '', password: '', role: 'user', balance: 0, plan_id: 0, quota_gb: 0, used_gb: 0, expire: '',
        max_rules: 0, speed_limit: 0, conn_limit: 0, ip_limit: 0, banned: false, note: '' };
    }
    // 选择套餐时把套餐的额度填进表单(仍可再手动调整)
    function applyPlan() {
      const p = plans.value.find(x => x.id === form.value.plan_id);
      if (!p) return;
      const f = form.value;
      f.quota_gb = fmt.gb(p.traffic); f.max_rules = p.max_rules; f.speed_limit = p.speed_limit; f.conn_limit = p.conn_limit; f.ip_limit = p.ip_limit;
      f.expire = p.days ? fmt.toLocalInput(Math.floor(Date.now() / 1000) + p.days * 86400) : '';
    }
    async function save() {
      const f = form.value;
      const body = {
        username: f.username, role: f.role, balance: Math.round(Number(f.balance) * 100), plan_id: Number(f.plan_id),
        traffic_quota: Math.round(Number(f.quota_gb) * 1073741824), traffic_used: Math.round(Number(f.used_gb) * 1073741824),
        expire_at: fmt.fromLocalInput(f.expire), max_rules: Number(f.max_rules) || 0, speed_limit: Number(f.speed_limit) || 0,
        conn_limit: Number(f.conn_limit) || 0, ip_limit: Number(f.ip_limit) || 0, banned: f.banned, note: f.note,
      };
      if (f.password) body.password = f.password;
      const ok = await run(() => f.id ? api('PUT', '/api/admin/users/' + f.id, body) : api('POST', '/api/admin/users', body), f.id ? '用户已保存' : '用户已创建');
      if (ok) { form.value = null; load(); }
    }
    async function remove(u) {
      if (!confirm('删除用户"' + u.username + '"?其 ' + u.rule_count + ' 条规则会一并删除,无法恢复。')) return;
      if (await run(() => api('DELETE', '/api/admin/users/' + u.id), '用户已删除')) load();
    }
    const state = u => {
      if (u.banned) return ['已封禁', 'bad'];
      if (u.role === 'admin') return ['管理员', 'ok'];
      if (!u.traffic_quota) return ['未开通', ''];
      if (u.expire_at && u.expire_at <= Date.now() / 1000) return ['已到期', 'warn'];
      if (u.traffic_used >= u.traffic_quota) return ['流量用尽', 'warn'];
      return ['正常', 'ok'];
    };
    return { users, plans, q, form, load, open, applyPlan, save, remove, state, fmt, store };
  },
  template: `
  <div>
    <div class="page-head"><div><h1>用户</h1></div>
      <div class="actions">
        <form @submit.prevent="load" style="display:flex;gap:8px"><input type="text" v-model.trim="q" placeholder="搜索用户名或备注" aria-label="搜索用户" style="width:220px"><button class="btn">搜索</button></form>
        <button class="btn primary" @click="open(null)">新建用户</button>
      </div>
    </div>
    <div class="panel">
      <div class="empty" v-if="users && !users.length">没有找到用户。</div>
      <div class="scroll-x" v-else-if="users">
        <table>
          <thead><tr><th>用户</th><th>套餐</th><th class="r">已用 / 配额</th><th>到期</th><th class="r">余额</th><th class="r">规则</th><th>状态</th><th></th></tr></thead>
          <tbody><tr v-for="u in users" :key="u.id">
            <td><b>{{ u.username }}</b><div class="sub" v-if="u.note">{{ u.note }}</div></td>
            <td>{{ u.plan_name || '-' }}</td>
            <td class="r num">{{ fmt.bytes(u.traffic_used) }} / {{ fmt.bytes(u.traffic_quota) }}</td>
            <td class="num">{{ u.expire_at ? fmt.date(u.expire_at) : '不限期' }}</td>
            <td class="r num">{{ fmt.money(u.balance) }}</td>
            <td class="r num">{{ u.rule_count }}<span class="dim" v-if="u.role !== 'admin'"> / {{ u.max_rules }}</span></td>
            <td><span class="tag" :class="state(u)[1]">{{ state(u)[0] }}</span></td>
            <td class="ops"><button class="link" @click="open(u)">编辑</button><button class="link danger" v-if="u.id !== store.user.id" @click="remove(u)">删除</button></td>
          </tr></tbody>
        </table>
      </div>
    </div>
    <modal v-if="form" :title="form.id ? '编辑用户' : '新建用户'" @close="form = null">
      <form id="user-form" @submit.prevent="save" autocomplete="off">
        <div class="grid2">
          <div class="field"><label>用户名</label><input type="text" v-model.trim="form.username" required></div>
          <div class="field"><label>密码</label><input type="password" v-model="form.password" autocomplete="new-password" :required="!form.id" :placeholder="form.id ? '留空则不修改' : '至少 8 位'"></div>
        </div>
        <div class="grid2">
          <div class="field"><label>套餐</label><select v-model.number="form.plan_id" @change="applyPlan"><option :value="0">无(手动设置额度)</option><option v-for="p in plans" :key="p.id" :value="p.id">{{ p.name }}</option></select>
            <div class="hint">选择套餐会把下面的额度填成套餐的值</div></div>
          <div class="field"><label>到期时间</label><input type="datetime-local" v-model="form.expire"><div class="hint">留空表示不限期</div></div>
        </div>
        <div class="grid3">
          <div class="field"><label>流量配额 (GB)</label><input type="number" min="0" step="0.01" v-model="form.quota_gb"></div>
          <div class="field"><label>已用流量 (GB)</label><input type="number" min="0" step="0.01" v-model="form.used_gb"></div>
          <div class="field"><label>规则数上限</label><input type="number" min="0" v-model="form.max_rules"></div>
        </div>
        <div class="grid3">
          <div class="field"><label>限速 (Mbps)</label><input type="number" min="0" v-model="form.speed_limit"></div>
          <div class="field"><label>连接数</label><input type="number" min="0" v-model="form.conn_limit"></div>
          <div class="field"><label>来源 IP 数</label><input type="number" min="0" v-model="form.ip_limit"></div>
        </div>
        <div class="grid2">
          <div class="field"><label>余额(元)</label><input type="number" step="0.01" v-model="form.balance"></div>
          <div class="field"><label>角色</label><select v-model="form.role"><option value="user">普通用户</option><option value="admin">管理员</option></select></div>
        </div>
        <div class="field"><label>备注</label><input type="text" v-model="form.note"></div>
        <label class="check"><input type="checkbox" v-model="form.banned">封禁该用户(无法登录,规则全部停用)</label>
      </form>
      <template #foot><button class="btn" @click="form = null">取消</button><button class="btn primary" form="user-form">{{ form.id ? '保存用户' : '创建用户' }}</button></template>
    </modal>
  </div>`,
};

// ---- 设备组与节点 ----
const fingerprints = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', '360', 'qq'];
const groupTypeText = { in: '入口组', out: '出口组', chain: '链式出口' };

function blankGroup(type) {
  const config = {
    in: { display_host: '', port_range: '10000-60000', direct_mode: 0, allowed_out: [], blocked_protocols: [], blocked_hosts: [], allowed_hosts: [],
      disable_udp: false, max_fail: 3, fail_timeout: 30, allow_private: false,
      tls_inbound_policy: 0, tls_reject_empty_sni: false, reverse_groups: [], reverse_sni: '', reverse_conns: 2 },
    out: { transport: 'tls', mux: true, mux_conns: 4, tunnel_port: 0, connect_host: '', connect_port: 0, sni: '', ws_host: '', ws_path: '/',
      cdn: false, cdn_tls: true, udp_over_tcp: false, failover_group: 0, fingerprint: '', allow_private: false, max_fail: 3, fail_timeout: 30 },
    chain: { chain_hops: [], chain_mux: false },
  }[type];
  return { id: 0, name: '', type, ratio: 1, public: true, sort: 0, note: '', advanced: false, json: '', config,
    blockedHostsText: '', allowedHostsText: '', revMode: 'none', revPick: [], hop1: 0, hop2: 0, hop3: 0 };
}

const AdminGroupsPage = {
  setup() {
    const groups = ref(null), nodes = ref([]), form = ref(null), install = ref(null);
    const load = () => run(async () => { [groups.value, nodes.value] = await Promise.all([api('GET', '/api/admin/groups'), api('GET', '/api/admin/nodes')]); });
    poll(load, 8000);
    const byType = t => (groups.value || []).filter(g => g.type === t);
    const ins = computed(() => byType('in')), outs = computed(() => byType('out')), chains = computed(() => byType('chain'));
    const gname = id => { const g = (groups.value || []).find(x => x.id === id); return g ? g.name : '#' + id; };
    const sections = computed(() => [
      { type: 'in', list: ins.value, empty: '入口是用户连接的机器,先建一个入口组再对接机器。' },
      { type: 'out', list: outs.value, empty: '出口负责连接转发目标。只做直接转发时可以不建出口组。' },
      { type: 'chain', list: chains.value, empty: '把 2 到 3 个出口组串成一条线路,用户选它作为出口时,流量依次经过每一跳。' },
    ]);

    // 表单里的派生字段 <-> config
    function fillDerived(f) {
      const c = f.config;
      if (f.type === 'in') {
        for (const k of ['allowed_out', 'blocked_protocols', 'blocked_hosts', 'allowed_hosts', 'reverse_groups']) c[k] = c[k] || [];
        f.blockedHostsText = c.blocked_hosts.join('\n');
        f.allowedHostsText = c.allowed_hosts.join('\n');
        // 反向隧道名单:含 0 表示"全部出口组",其余 ID 是例外
        const all = c.reverse_groups.includes(0);
        f.revPick = c.reverse_groups.filter(x => x !== 0);
        f.revMode = all ? 'all' : f.revPick.length ? 'some' : 'none';
      } else if (f.type === 'chain') {
        const h = c.chain_hops || [];
        f.hop1 = h[0] || 0; f.hop2 = h[1] || 0; f.hop3 = h[2] || 0;
      }
    }
    function syncConfig() {
      const f = form.value, c = f.config;
      if (f.type === 'in') {
        c.blocked_hosts = lines(f.blockedHostsText);
        c.allowed_hosts = lines(f.allowedHostsText);
        c.reverse_groups = f.revMode === 'none' ? [] : f.revMode === 'all' ? [0].concat(f.revPick) : f.revPick.slice();
        for (const k of ['max_fail', 'fail_timeout', 'direct_mode', 'tls_inbound_policy', 'reverse_conns']) c[k] = Number(c[k]) || 0;
      } else if (f.type === 'out') {
        for (const k of ['max_fail', 'fail_timeout', 'mux_conns', 'tunnel_port', 'connect_port', 'failover_group']) c[k] = Number(c[k]) || 0;
      } else {
        c.chain_hops = [f.hop1, f.hop2, f.hop3].map(Number).filter(Boolean);
      }
    }
    function open(g, type) {
      const f = blankGroup(g ? g.type : type);
      if (g) {
        Object.assign(f, { id: g.id, name: g.name, ratio: g.ratio, public: g.public, sort: g.sort, note: g.note });
        f.config = Object.assign(f.config, JSON.parse(JSON.stringify(g.config)));
      }
      fillDerived(f);
      form.value = f;
    }
    function toggleAdvanced() {
      const f = form.value;
      if (!f.advanced) { syncConfig(); f.json = JSON.stringify(f.config, null, 2); f.advanced = true; return; }
      try { f.config = Object.assign(blankGroup(f.type).config, JSON.parse(f.json)); } catch (e) { toast('JSON 格式有误: ' + e.message, true); return; }
      fillDerived(f);
      f.advanced = false;
    }
    async function save() {
      const f = form.value;
      let config;
      if (f.advanced) { try { config = JSON.parse(f.json); } catch (e) { toast('JSON 格式有误: ' + e.message, true); return; } }
      else { syncConfig(); config = f.config; }
      const body = { name: f.name, type: f.type, ratio: Number(f.ratio), public: f.public, sort: Number(f.sort) || 0, note: f.note, config };
      const label = groupTypeText[f.type];
      const res = await run(() => f.id ? api('PUT', '/api/admin/groups/' + f.id, body) : api('POST', '/api/admin/groups', body),
        f.id ? label + '已保存' : f.type === 'chain' ? '链式出口已创建' : null);
      if (!res) return;
      form.value = null;
      await load();
      if (!f.id && f.type !== 'chain') install.value = res; // 新建后直接展示对接命令
    }
    async function remove(g) {
      const tip = g.type === 'chain' ? '删除链式出口"' + g.name + '"?' : '删除设备组"' + g.name + '"?已对接的机器会被断开。';
      if (!confirm(tip)) return;
      try { await api('DELETE', '/api/admin/groups/' + g.id); }
      catch (e) {
        if (e.status !== 409) { toast(e.message, true); return; }
        if (!confirm(e.message + '。继续删除?')) return;
        if (!await run(() => api('DELETE', '/api/admin/groups/' + g.id + '?force=1'))) return;
      }
      toast(groupTypeText[g.type] + '已删除'); load();
    }
    async function resetToken() {
      if (!confirm('重置后,已对接的机器会全部断开,需要用新命令重新对接。继续?')) return;
      const r = await run(() => api('POST', '/api/admin/groups/' + install.value.id + '/reset_token'), '令牌已重置');
      if (r) { install.value = Object.assign({}, install.value, r); load(); }
    }
    async function removeNode(n) {
      if (!confirm('从列表中移除机器"' + (n.hostname || n.uid) + '"?')) return;
      if (await run(() => api('DELETE', '/api/admin/nodes/' + n.id), '机器已移除')) load();
    }
    const directText = ['可选', '禁止直接转发', '只允许直接转发'];
    const tlsPolicyText = ['', '用户只能建 TLS 入站', '用户只能建 TLS 子规则'];
    const usesTLS = c => c.cdn ? c.cdn_tls : (c.transport === 'tls' || c.transport === 'wss');
    const forcedMux = c => c.cdn || c.transport === 'ws' || c.transport === 'wss';
    const nodeAddr = n => {
      const host = n.connect_host || n.ip;
      if (n.tunnel_port) return host + ':' + n.tunnel_port;
      if (n.rev_port) return host + ':' + n.rev_port + '(反向)';
      return '-';
    };
    const gtype = id => { const g = (groups.value || []).find(x => x.id === id); return g ? g.type : ''; };
    return { groups, nodes, ins, outs, chains, sections, gname, gtype, form, install, open, toggleAdvanced, save, remove, resetToken, removeNode,
      fmt, copyText, directText, tlsPolicyText, usesTLS, forcedMux, nodeAddr, fingerprints, groupTypeText };
  },
  template: `
  <div>
    <div class="page-head"><div><h1>设备组</h1><p class="sub">入口组里的机器共用一套规则;出口组里的机器之间自动均衡负载和故障转移;链式出口把几个出口组串成一条线路。</p></div>
      <div class="actions"><button class="btn" @click="open(null, 'chain')" :disabled="outs.length < 2" :title="outs.length < 2 ? '至少需要两个出口组' : ''">新建链式出口</button>
        <button class="btn" @click="open(null, 'out')">新建出口组</button><button class="btn primary" @click="open(null, 'in')">新建入口组</button></div></div>

    <div class="panel" v-for="sec in sections" :key="sec.type">
      <div class="panel-head"><h2>{{ groupTypeText[sec.type] }}</h2></div>
      <div class="empty" v-if="groups && !sec.list.length"><b>还没有{{ groupTypeText[sec.type] }}</b>{{ sec.empty }}</div>
      <div class="scroll-x" v-else>
        <table>
          <thead><tr><th>名称</th><th class="r">倍率</th><th>{{ sec.type === 'chain' ? '状态' : '机器' }}</th><th class="r">规则</th><th class="r">累计流量</th>
            <th>{{ sec.type === 'in' ? '端口 / 入站' : sec.type === 'out' ? '隧道' : '线路' }}</th><th>可见</th><th></th></tr></thead>
          <tbody><tr v-for="g in sec.list" :key="g.id">
            <td><b>{{ g.name }}</b> <span class="dim num">#{{ g.id }}</span><div class="sub" v-if="g.note">{{ g.note }}</div></td>
            <td class="r num">{{ g.ratio }}x</td>
            <td v-if="sec.type === 'chain'"><span class="dot" :class="g.online ? 'on' : 'off'"></span>{{ g.online ? '每一跳都在线' : '有一跳不在线' }}</td>
            <td v-else><span class="dot" :class="g.online ? 'on' : 'off'"></span><span class="num">{{ g.online }} / {{ g.node_count }}</span> 在线</td>
            <td class="r num">{{ g.rule_count }}</td>
            <td class="r num">{{ fmt.bytes(g.traffic) }}</td>
            <td v-if="sec.type === 'in'"><span class="num">{{ g.config.port_range }}</span><span class="sub">,{{ directText[g.config.direct_mode || 0] }}</span>
              <div class="sub" v-if="g.config.tls_inbound_policy || (g.config.reverse_groups || []).length">
                <span class="tag" v-if="g.config.tls_inbound_policy">{{ tlsPolicyText[g.config.tls_inbound_policy] }}</span>
                <span class="tag" v-if="(g.config.reverse_groups || []).length">接受反向隧道</span></div></td>
            <td v-else-if="sec.type === 'out'">{{ g.config.cdn ? 'ws 经 CDN' : g.config.transport }}<span class="sub">{{ g.config.mux ? ',复用' : '' }}{{ g.config.fingerprint && usesTLS(g.config) ? ',' + g.config.fingerprint + ' 指纹' : '' }}{{ g.config.failover_group ? ',备用 ' + gname(g.config.failover_group) : '' }}</span></td>
            <td v-else><div class="route"><template v-for="(h, i) in g.config.chain_hops" :key="h"><span class="wire" v-if="i"></span><span class="hop">{{ gname(h) }}</span></template></div></td>
            <td><span class="tag" :class="g.public ? 'ok' : ''">{{ g.public ? '所有用户' : '仅授权套餐' }}</span></td>
            <td class="ops"><button class="link" v-if="sec.type !== 'chain'" @click="install = g">对接</button><button class="link" @click="open(g)">编辑</button><button class="link danger" @click="remove(g)">删除</button></td>
          </tr></tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-head"><h2>已对接的机器</h2></div>
      <div class="empty" v-if="!nodes.length">还没有机器对接。点设备组右侧的"对接",把命令复制到机器上运行。</div>
      <div class="scroll-x" v-else>
        <table>
          <thead><tr><th>机器</th><th>设备组</th><th>IP</th><th>对端连接地址</th><th>系统</th><th>版本</th><th>最后在线</th><th></th></tr></thead>
          <tbody><tr v-for="n in nodes" :key="n.id">
            <td><span class="dot" :class="n.online ? 'on' : 'off'"></span>{{ n.hostname || n.uid }}
              <span class="tag" :class="n.metrics.rev_up < n.metrics.rev_total ? 'warn' : 'ok'" v-if="n.online && n.metrics && n.metrics.rev_total"
                :title="gtype(n.group_id) === 'in' ? '已有出口接入的出口组数 / 允许接入的出口组数' : '已连上的入口机器数 / 需要连入的入口机器数'">反向隧道 {{ n.metrics.rev_up || 0 }}/{{ n.metrics.rev_total }}</span>
              <div class="rule-err" v-if="n.error">{{ n.error }}</div></td>
            <td>{{ gname(n.group_id) }}</td><td class="num">{{ n.ip }}</td>
            <td class="num">{{ nodeAddr(n) }}</td>
            <td>{{ n.os }}/{{ n.arch }}</td>
            <td class="num">{{ n.version }} <span class="tag warn" v-if="n.outdated" title="节点端比面板旧,用到新功能的规则不会下发到这台机器。重新运行对接命令即可升级。">需升级</span></td>
            <td>{{ n.online ? '在线' : fmt.time(n.last_seen) }}</td>
            <td class="ops"><button class="link danger" v-if="!n.online" @click="removeNode(n)">移除</button></td>
          </tr></tbody>
        </table>
      </div>
    </div>

    <modal v-if="install" :title="'对接机器到 ' + install.name" wide @close="install = null">
      <p style="margin-bottom:10px">在要对接的 Linux 机器上以 root 运行下面的命令。多台机器对接同一个组时,运行同一条命令即可。</p>
      <pre class="cmd">{{ install.install_cmd }}</pre>
      <p class="sub" style="margin-top:10px" v-if="install.type === 'out'">出口默认用机器的公网 IP 和随机端口供入口连接。要指定时在命令末尾加 <code>--port 端口</code> 或 <code>--connect-host 内网IP</code>。</p>
      <p class="sub" style="margin-top:10px" v-else>要让内网里的出口主动连进来(反向隧道),在命令末尾加 <code>--rev-port 端口</code>,并在这个入口组的设置里选好哪些出口组走反向隧道。</p>
      <p class="sub" style="margin-top:6px">命令里包含对接令牌,拿到它的人可以把机器接入这个组,请勿外传。</p>
      <template #foot><button class="btn danger" @click="resetToken">重置令牌</button><button class="btn primary" @click="copyText(install.install_cmd)">复制命令</button></template>
    </modal>

    <modal v-if="form" :title="(form.id ? '编辑' : '新建') + groupTypeText[form.type]" wide @close="form = null">
      <form id="group-form" @submit.prevent="save">
        <div class="grid3">
          <div class="field"><label>名称</label><input type="text" v-model.trim="form.name" required maxlength="64"></div>
          <div class="field"><label>流量倍率</label><input type="number" min="0" step="0.01" v-model="form.ratio">
            <div class="hint" v-if="form.type === 'chain'">计费只用这个倍率,不累加各跳的倍率</div></div>
          <div class="field"><label>排序</label><input type="number" v-model="form.sort"></div>
        </div>
        <div class="field"><label>说明(用户可见)</label><input type="text" v-model="form.note"></div>
        <label class="check"><input type="checkbox" v-model="form.public">对所有用户开放(取消后只有套餐授权的用户可用)</label>

        <template v-if="!form.advanced && form.type === 'chain'">
          <div class="grid3">
            <div class="field"><label>第 1 跳</label><select v-model.number="form.hop1" required><option :value="0" disabled>选择出口组</option><option v-for="o in outs" :key="o.id" :value="o.id" :disabled="o.id === form.hop2 || o.id === form.hop3">{{ o.name }}</option></select></div>
            <div class="field"><label>第 2 跳</label><select v-model.number="form.hop2" required><option :value="0" disabled>选择出口组</option><option v-for="o in outs" :key="o.id" :value="o.id" :disabled="o.id === form.hop1 || o.id === form.hop3">{{ o.name }}</option></select></div>
            <div class="field"><label>第 3 跳</label><select v-model.number="form.hop3"><option :value="0">不使用</option><option v-for="o in outs" :key="o.id" :value="o.id" :disabled="o.id === form.hop1 || o.id === form.hop2">{{ o.name }}</option></select></div>
          </div>
          <p class="hint" style="margin:-6px 0 14px">流量从入口进来后依次经过每一跳,由最后一跳连接转发目标。每一跳用下一跳出口组自己的隧道设置。</p>
          <label class="check"><input type="checkbox" v-model="form.config.chain_mux">各跳之间使用多路复用(入口到第 1 跳按第 1 跳出口组自己的设置)</label>
          <p class="hint">链式出口上 UDP 一律封装在隧道里传输;各跳的故障转移组不生效。</p>
        </template>

        <template v-if="!form.advanced && form.type === 'in'">
          <div class="grid2">
            <div class="field"><label>展示给用户的入口地址</label><input type="text" v-model.trim="form.config.display_host" placeholder="留空则显示机器 IP"></div>
            <div class="field"><label>用户可用端口</label><input type="text" v-model.trim="form.config.port_range" placeholder="10000-60000,443"></div>
          </div>
          <div class="grid2">
            <div class="field"><label>直接转发</label><select v-model.number="form.config.direct_mode"><option :value="0">可选(用户可直出,也可选出口)</option><option :value="1">禁止(必须经出口)</option><option :value="2">只允许直接转发(专线)</option></select></div>
            <div class="field"><label>入站屏蔽协议</label>
              <div style="display:flex;gap:16px;height:36px;align-items:center">
                <label class="check" style="margin:0" v-for="p in ['http', 'tls', 'socks']" :key="p"><input type="checkbox" :value="p" v-model="form.config.blocked_protocols">{{ p.toUpperCase() }}</label>
              </div></div>
          </div>
          <div class="field" v-if="outs.length"><label>限制可用出口(不勾选表示不限制)</label>
            <div style="display:flex;gap:16px;flex-wrap:wrap"><label class="check" style="margin:0" v-for="o in outs.concat(chains)" :key="o.id"><input type="checkbox" :value="o.id" v-model="form.config.allowed_out">{{ o.name }}</label></div></div>
          <details class="more" :open="form.config.tls_inbound_policy > 0 || form.config.tls_reject_empty_sni">
            <summary>TLS 入站</summary>
            <div class="field"><label>用户可以创建的规则</label>
              <select v-model.number="form.config.tls_inbound_policy"><option :value="0">不限制(普通转发和 TLS 入站都可以)</option><option :value="1">只能建 TLS 入站规则</option><option :value="2">只能建 TLS 子规则(挂在管理员的共享 TLS 端口下)</option></select>
              <div class="hint">共享 TLS 端口由管理员在"转发规则"页新建规则时,把入站方式选成"共享 TLS 端口"来创建。配了下面的域名白名单后,子规则的 SNI 必须在白名单内。</div></div>
            <label class="check"><input type="checkbox" v-model="form.config.tls_reject_empty_sni">拒绝不带 SNI 的 TLS 握手(挡掉按 IP 扫描的探测)</label>
          </details>
          <details class="more" :open="form.revMode !== 'none'">
            <summary>反向隧道(出口在内网时使用)</summary>
            <div class="grid2">
              <div class="field"><label>哪些出口组主动连进来</label>
                <select v-model="form.revMode"><option value="none">不使用</option><option value="some">指定的出口组</option><option value="all">全部出口组</option></select></div>
              <div class="field" v-if="form.revMode !== 'none'"><label>每台出口到每台入口的连接数</label><input type="number" min="1" max="16" v-model="form.config.reverse_conns"></div>
            </div>
            <div class="field" v-if="form.revMode !== 'none' && outs.length"><label>{{ form.revMode === 'all' ? '以下出口组除外' : '走反向隧道的出口组' }}</label>
              <div style="display:flex;gap:16px;flex-wrap:wrap"><label class="check" style="margin:0" v-for="o in outs" :key="o.id"><input type="checkbox" :value="o.id" v-model="form.revPick">{{ o.name }}</label></div></div>
            <div class="field" v-if="form.revMode !== 'none'"><label>出口拨入时使用的 TLS SNI</label><input type="text" v-model.trim="form.config.reverse_sni" placeholder="留空自动生成">
              <div class="hint">只有用 <code>--rev-port 端口</code> 对接的入口机器会接受反向连接,其余机器仍按正向隧道连接出口。反向隧道固定使用 TLS 和多路复用,UDP 封装在隧道里。</div></div>
          </details>
          <details class="more">
            <summary>域名黑白名单、UDP 与故障转移</summary>
            <div class="grid2">
              <div class="field"><label>域名黑名单(SNI / Host 后缀)</label><textarea class="code" rows="3" v-model="form.blockedHostsText" placeholder=".example.com"></textarea></div>
              <div class="field"><label>域名白名单</label><textarea class="code" rows="3" v-model="form.allowedHostsText"></textarea><div class="hint">填了白名单后,只放行能识别出域名且命中的连接</div></div>
            </div>
            <div class="grid2">
              <div class="field"><label>连续失败几次后摘除</label><input type="number" min="1" v-model="form.config.max_fail"></div>
              <div class="field"><label>摘除时长(秒)</label><input type="number" min="1" v-model="form.config.fail_timeout"></div>
            </div>
            <label class="check"><input type="checkbox" v-model="form.config.disable_udp">禁用 UDP 转发</label>
            <label class="check"><input type="checkbox" v-model="form.config.allow_private">允许直接转发到内网 / 本机地址(专线或自用时开启)</label>
          </details>
        </template>

        <template v-if="!form.advanced && form.type === 'out'">
          <div class="grid3">
            <div class="field"><label>隧道传输层</label><select v-model="form.config.transport" :disabled="form.config.cdn">
              <option value="tls">TLS(推荐)</option><option value="wss">WebSocket + TLS</option><option value="http">HTTP 伪装</option>
              <option value="ws">WebSocket(明文头)</option><option value="tcp">TCP(不加密,仅专线)</option></select></div>
            <div class="field"><label>TLS 握手指纹</label><select v-model="form.config.fingerprint" :disabled="!usesTLS(form.config)">
              <option value="">不伪装(Go 默认)</option><option v-for="fp in fingerprints" :key="fp" :value="fp">{{ fp }}</option></select></div>
            <div class="field"><label>TLS SNI</label><input type="text" v-model.trim="form.config.sni" placeholder="留空自动生成" :disabled="!usesTLS(form.config)"></div>
          </div>
          <p class="hint" style="margin:-6px 0 14px" v-if="form.config.transport === 'http' && !form.config.cdn">连接开头是一次普通的 HTTP 请求和响应(不带 Upgrade 头),之后是加密数据流。两端之间必须直连,不能经过 CDN 或反向代理。</p>
          <p class="hint" style="margin:-6px 0 14px" v-else-if="form.config.fingerprint && usesTLS(form.config)">入口连接出口时,TLS ClientHello 模拟 {{ form.config.fingerprint }} 浏览器。反向隧道里由出口拨号时同样生效。</p>
          <div class="grid2">
            <label class="check" style="margin-top:28px"><input type="checkbox" v-model="form.config.mux" :disabled="forcedMux(form.config)">多路复用(新连接免握手,延迟更低)</label>
            <div class="field"><label>每台出口的复用连接数</label><input type="number" min="1" max="32" v-model="form.config.mux_conns"></div>
          </div>
          <label class="check"><input type="checkbox" v-model="form.config.udp_over_tcp">UDP 走隧道(UDP over TCP)。不勾选时走同端口的原生 UDP 加密通道</label>
          <div class="grid2">
            <div class="field"><label>故障转移组</label><select v-model.number="form.config.failover_group"><option :value="0">无</option><option v-for="o in outs.filter(x => x.id !== form.id)" :key="o.id" :value="o.id">{{ o.name }}</option></select>
              <div class="hint">本组机器全部故障时,新连接改走这个组</div></div>
            <div class="field"><label>隧道监听端口</label><input type="number" min="0" max="65535" v-model="form.config.tunnel_port"><div class="hint">0 = 每台机器自动选择</div></div>
          </div>
          <details class="more" :open="form.config.cdn || !!form.config.connect_host || ['ws', 'wss', 'http'].includes(form.config.transport)">
            <summary>连接地址、请求路径与 CDN</summary>
            <div class="grid2">
              <div class="field"><label>入口连接出口用的地址</label><input type="text" v-model.trim="form.config.connect_host" placeholder="留空用每台机器的公网 IP"></div>
              <div class="field"><label>入口连接出口用的端口</label><input type="number" min="0" max="65535" v-model="form.config.connect_port"><div class="hint">0 = 机器上报的监听端口</div></div>
            </div>
            <div class="grid2">
              <div class="field"><label>Host 头(WebSocket / HTTP 伪装)</label><input type="text" v-model.trim="form.config.ws_host" placeholder="留空用连接地址"></div>
              <div class="field"><label>请求路径(WebSocket / HTTP 伪装)</label><input type="text" v-model.trim="form.config.ws_path"></div>
            </div>
            <label class="check"><input type="checkbox" v-model="form.config.cdn">经 CDN 中转(出口监听明文 WebSocket 供 CDN 回源,上面的地址填 CDN 域名或优选 IP)</label>
            <label class="check" v-if="form.config.cdn"><input type="checkbox" v-model="form.config.cdn_tls">入口到 CDN 使用 HTTPS</label>
            <label class="check"><input type="checkbox" v-model="form.config.allow_private">允许转发到内网 / 本机地址</label>
          </details>
        </template>

        <div class="field" v-if="form.advanced"><label>设备组配置 (JSON)</label>
          <textarea class="code" rows="16" v-model="form.json" spellcheck="false"></textarea>
          <div class="hint" v-if="form.type === 'out'">包含隧道密钥与证书。清空 tunnel_key 或 cert_pem 后保存会重新生成,已对接的机器会自动同步。</div>
          <div class="hint" v-else-if="form.type === 'in'">reverse_groups 里写 [0] 表示全部出口组,[0, 3, 4] 表示除 3、4 以外的全部。清空 rev_cert_pem 后保存会重新生成反向隧道证书。</div></div>
      </form>
      <template #foot>
        <button class="btn" style="margin-right:auto" @click="toggleAdvanced">{{ form.advanced ? '返回表单' : '高级编辑' }}</button>
        <button class="btn" @click="form = null">取消</button><button class="btn primary" form="group-form">{{ form.id ? '保存' + groupTypeText[form.type] : '创建' + groupTypeText[form.type] }}</button>
      </template>
    </modal>
  </div>`,
};

// ---- 套餐 ----
const AdminPlansPage = {
  setup() {
    const plans = ref(null), groups = ref([]), form = ref(null);
    const load = () => run(async () => { plans.value = await api('GET', '/api/admin/plans'); });
    onMounted(() => { load(); run(async () => { groups.value = (await api('GET', '/api/admin/groups')).filter(g => !g.public); }); });
    function open(p) {
      form.value = p ? Object.assign({}, p, { price_yuan: p.price / 100, traffic_gb: fmt.gb(p.traffic), groups: (p.groups || []).slice() })
        : { id: 0, name: '', description: '', price_yuan: 10, traffic_gb: 100, days: 30, max_rules: 10, speed_limit: 0, conn_limit: 0, ip_limit: 0, groups: [], hidden: false, sort: 0 };
    }
    async function save() {
      const f = form.value;
      const body = { name: f.name, description: f.description, price: Math.round(Number(f.price_yuan) * 100), traffic: Math.round(Number(f.traffic_gb) * 1073741824),
        days: Number(f.days) || 0, max_rules: Number(f.max_rules) || 0, speed_limit: Number(f.speed_limit) || 0, conn_limit: Number(f.conn_limit) || 0,
        ip_limit: Number(f.ip_limit) || 0, groups: f.groups, hidden: f.hidden, sort: Number(f.sort) || 0 };
      if (await run(() => f.id ? api('PUT', '/api/admin/plans/' + f.id, body) : api('POST', '/api/admin/plans', body), f.id ? '套餐已保存' : '套餐已创建')) { form.value = null; load(); }
    }
    async function remove(p) {
      if (!confirm('删除套餐"' + p.name + '"?已购买的用户不受影响,但无法再自动续费。')) return;
      if (await run(() => api('DELETE', '/api/admin/plans/' + p.id), '套餐已删除')) load();
    }
    return { plans, groups, form, open, save, remove, fmt };
  },
  template: `
  <div>
    <div class="page-head"><div><h1>套餐</h1></div><div class="actions"><button class="btn primary" @click="open(null)">新建套餐</button></div></div>
    <div class="panel">
      <div class="empty" v-if="plans && !plans.length"><b>还没有套餐</b>用户需要购买套餐(或由你手动设置额度)后才能创建规则。</div>
      <div class="scroll-x" v-else-if="plans">
        <table>
          <thead><tr><th>套餐</th><th class="r">价格</th><th class="r">流量</th><th class="r">时长</th><th class="r">规则数</th><th class="r">限速</th><th>状态</th><th></th></tr></thead>
          <tbody><tr v-for="p in plans" :key="p.id">
            <td><b>{{ p.name }}</b><div class="sub" v-if="p.description">{{ p.description }}</div></td>
            <td class="r num">{{ fmt.money(p.price) }}</td><td class="r num">{{ fmt.bytes(p.traffic) }}</td>
            <td class="r num">{{ p.days ? p.days + ' 天' : '不限期' }}</td><td class="r num">{{ p.max_rules }}</td>
            <td class="r num">{{ fmt.limit(p.speed_limit, 'Mbps') }}</td>
            <td><span class="tag" :class="p.hidden ? '' : 'ok'">{{ p.hidden ? '已下架' : '在售' }}</span></td>
            <td class="ops"><button class="link" @click="open(p)">编辑</button><button class="link danger" @click="remove(p)">删除</button></td>
          </tr></tbody>
        </table>
      </div>
    </div>
    <modal v-if="form" :title="form.id ? '编辑套餐' : '新建套餐'" @close="form = null">
      <form id="plan-form" @submit.prevent="save">
        <div class="grid2">
          <div class="field"><label>名称</label><input type="text" v-model.trim="form.name" required></div>
          <div class="field"><label>价格(元)</label><input type="number" min="0" step="0.01" v-model="form.price_yuan"></div>
        </div>
        <div class="field"><label>说明</label><input type="text" v-model="form.description"></div>
        <div class="grid3">
          <div class="field"><label>流量 (GB)</label><input type="number" min="0" step="0.01" v-model="form.traffic_gb"></div>
          <div class="field"><label>时长(天)</label><input type="number" min="0" v-model="form.days"><div class="hint">0 = 不限期</div></div>
          <div class="field"><label>规则数上限</label><input type="number" min="0" v-model="form.max_rules"></div>
        </div>
        <div class="grid3">
          <div class="field"><label>限速 (Mbps)</label><input type="number" min="0" v-model="form.speed_limit"></div>
          <div class="field"><label>连接数</label><input type="number" min="0" v-model="form.conn_limit"></div>
          <div class="field"><label>来源 IP 数</label><input type="number" min="0" v-model="form.ip_limit"></div>
        </div>
        <div class="field" v-if="groups.length"><label>额外授权的非公开设备组</label>
          <div style="display:flex;gap:16px;flex-wrap:wrap"><label class="check" style="margin:0" v-for="g in groups" :key="g.id"><input type="checkbox" :value="g.id" v-model="form.groups">{{ g.name }}</label></div></div>
        <div class="grid2">
          <div class="field"><label>排序</label><input type="number" v-model="form.sort"></div>
          <label class="check" style="margin-top:28px"><input type="checkbox" v-model="form.hidden">下架(不在商城显示)</label>
        </div>
      </form>
      <template #foot><button class="btn" @click="form = null">取消</button><button class="btn primary" form="plan-form">{{ form.id ? '保存套餐' : '创建套餐' }}</button></template>
    </modal>
  </div>`,
};

// ---- 订单 ----
const AdminOrdersPage = {
  setup() {
    const orders = ref(null);
    onMounted(() => run(async () => { orders.value = await api('GET', '/api/admin/orders'); }));
    return { orders, fmt, orderType, orderStatus };
  },
  template: `
  <div>
    <div class="page-head"><div><h1>订单</h1><p class="sub">最近 500 笔</p></div></div>
    <div class="panel">
      <div class="empty" v-if="orders && !orders.length">还没有订单。</div>
      <div class="scroll-x" v-else-if="orders">
        <table>
          <thead><tr><th>时间</th><th>用户</th><th>类型</th><th>说明</th><th class="r">金额</th><th>方式</th><th>状态</th><th>订单号</th></tr></thead>
          <tbody><tr v-for="o in orders" :key="o.id">
            <td class="num">{{ fmt.time(o.created_at) }}</td><td>{{ o.username || '#' + o.user_id }}</td><td>{{ orderType[o.type] || o.type }}</td><td>{{ o.note }}</td>
            <td class="r num">{{ fmt.money(o.amount) }}</td><td>{{ o.pay_method }}</td>
            <td><span class="tag" :class="o.status === 'paid' ? 'ok' : ''">{{ orderStatus[o.status] || o.status }}</span></td>
            <td class="num dim">{{ o.order_no }}</td>
          </tr></tbody>
        </table>
      </div>
    </div>
  </div>`,
};

// ---- 兑换码 ----
const AdminCodesPage = {
  setup() {
    const codes = ref(null), plans = ref([]), form = ref(null), made = ref(null);
    const load = () => run(async () => { codes.value = await api('GET', '/api/admin/codes'); });
    onMounted(() => { load(); run(async () => { plans.value = await api('GET', '/api/admin/plans'); }); });
    const pname = id => { const p = plans.value.find(x => x.id === id); return p ? p.name : '套餐 #' + id; };
    function open() { form.value = { type: 'balance', amount_yuan: 10, plan_id: plans.value.length ? plans.value[0].id : 0, count: 10, note: '' }; }
    async function save() {
      const f = form.value;
      const r = await run(() => api('POST', '/api/admin/codes', { type: f.type, amount: Math.round(Number(f.amount_yuan) * 100), plan_id: Number(f.plan_id), count: Number(f.count), note: f.note }));
      if (r) { form.value = null; made.value = r.codes.join('\n'); load(); }
    }
    async function remove(c) {
      if (!confirm('删除兑换码 ' + c.code + '?')) return;
      if (await run(() => api('DELETE', '/api/admin/codes/' + c.id), '兑换码已删除')) load();
    }
    return { codes, plans, form, made, pname, open, save, remove, fmt, copyText };
  },
  template: `
  <div>
    <div class="page-head"><div><h1>兑换码</h1></div><div class="actions"><button class="btn primary" @click="open">生成兑换码</button></div></div>
    <div class="panel">
      <div class="empty" v-if="codes && !codes.length"><b>还没有兑换码</b>兑换码可以给用户充值余额,或直接开通一个套餐。</div>
      <div class="scroll-x" v-else-if="codes">
        <table>
          <thead><tr><th>兑换码</th><th>内容</th><th>备注</th><th>状态</th><th>生成时间</th><th></th></tr></thead>
          <tbody><tr v-for="c in codes" :key="c.id">
            <td><button class="link muted num" style="padding:0" title="复制" @click="copyText(c.code)">{{ c.code }}</button></td>
            <td>{{ c.type === 'plan' ? pname(c.plan_id) : '余额 ' + fmt.money(c.amount) }}</td><td>{{ c.note }}</td>
            <td><span class="tag" :class="c.used_by ? '' : 'ok'">{{ c.used_by ? (c.used_name || '用户 #' + c.used_by) + ' 于 ' + fmt.time(c.used_at) + ' 使用' : '未使用' }}</span></td>
            <td class="num">{{ fmt.time(c.created_at) }}</td>
            <td class="ops"><button class="link danger" @click="remove(c)">删除</button></td>
          </tr></tbody>
        </table>
      </div>
    </div>
    <modal v-if="form" title="生成兑换码" @close="form = null">
      <form id="code-form" @submit.prevent="save">
        <div class="grid2">
          <div class="field"><label>类型</label><select v-model="form.type"><option value="balance">充值余额</option><option value="plan" :disabled="!plans.length">开通套餐</option></select></div>
          <div class="field" v-if="form.type === 'balance'"><label>面额(元)</label><input type="number" min="0.01" step="0.01" v-model="form.amount_yuan"></div>
          <div class="field" v-else><label>套餐</label><select v-model.number="form.plan_id"><option v-for="p in plans" :key="p.id" :value="p.id">{{ p.name }}</option></select></div>
        </div>
        <div class="grid2">
          <div class="field"><label>数量</label><input type="number" min="1" max="500" v-model="form.count"></div>
          <div class="field"><label>备注</label><input type="text" v-model="form.note"></div>
        </div>
      </form>
      <template #foot><button class="btn" @click="form = null">取消</button><button class="btn primary" form="code-form">生成兑换码</button></template>
    </modal>
    <modal v-if="made" title="兑换码已生成" @close="made = null">
      <textarea class="code" rows="10" readonly :value="made"></textarea>
      <template #foot><button class="btn primary" @click="copyText(made)">复制全部</button></template>
    </modal>
  </div>`,
};

// ---- 站点设置 ----
const AdminSettingsPage = {
  setup() {
    const f = ref(null);
    onMounted(() => run(async () => {
      const s = await api('GET', '/api/admin/settings');
      f.value = Object.assign({}, s, { allow: s.allow_register === '1', epay_key: '', min_yuan: (Number(s.recharge_min) || 100) / 100 });
    }));
    async function save() {
      const v = f.value;
      const body = { site_name: v.site_name, allow_register: v.allow ? '1' : '0', announcement: v.announcement, panel_url: v.panel_url,
        epay_url: v.epay_url, epay_pid: v.epay_pid, epay_key: v.epay_key, epay_types: v.epay_types, recharge_min: String(Math.round(Number(v.min_yuan) * 100)) };
      if (await run(() => api('PUT', '/api/admin/settings', body), '设置已保存')) {
        if (v.epay_key) { v.epay_key_set = true; v.epay_key = ''; }
        store.site = await api('GET', '/api/site');
        document.title = store.site.site_name;
      }
    }
    return { f, save };
  },
  template: `
  <div v-if="f">
    <div class="page-head"><div><h1>站点设置</h1></div></div>
    <form @submit.prevent="save" style="max-width:720px">
      <div class="panel"><div class="panel-head"><h2>基本</h2></div><div class="panel-body">
        <div class="grid2">
          <div class="field"><label>站点名称</label><input type="text" v-model.trim="f.site_name" placeholder="Kaze"></div>
          <div class="field"><label>面板对外地址</label><input type="text" v-model.trim="f.panel_url" placeholder="https://panel.example.com"><div class="hint">用于生成对接命令和支付回调地址。留空则按当前访问地址推断。</div></div>
        </div>
        <div class="field"><label>公告(显示在用户概览页)</label><textarea rows="3" v-model="f.announcement"></textarea></div>
        <label class="check"><input type="checkbox" v-model="f.allow">开放注册</label>
      </div></div>
      <div class="panel"><div class="panel-head"><h2>在线支付(易支付)</h2></div><div class="panel-body">
        <div class="field"><label>网关地址</label><input type="text" v-model.trim="f.epay_url" placeholder="https://pay.example.com"><div class="hint">不带 /submit.php。留空则关闭在线充值,用户仍可使用兑换码。</div></div>
        <div class="grid2">
          <div class="field"><label>商户 ID (PID)</label><input type="text" v-model.trim="f.epay_pid"></div>
          <div class="field"><label>商户密钥</label><input type="password" v-model="f.epay_key" autocomplete="new-password" :placeholder="f.epay_key_set ? '已设置,留空则不修改' : ''"></div>
        </div>
        <div class="grid2">
          <div class="field"><label>支付通道</label><input type="text" v-model.trim="f.epay_types" placeholder="alipay,wxpay"><div class="hint">用英文逗号分隔</div></div>
          <div class="field"><label>最低充值金额(元)</label><input type="number" min="0.01" step="0.01" v-model="f.min_yuan"></div>
        </div>
      </div></div>
      <button class="btn primary">保存设置</button>
    </form>
  </div>`,
};

Object.assign(pages, {
  '/admin': AdminDashPage, '/admin/users': AdminUsersPage, '/admin/groups': AdminGroupsPage,
  '/admin/rules': { components: { RulesPage }, template: '<rules-page all></rules-page>' },
  '/admin/plans': AdminPlansPage, '/admin/orders': AdminOrdersPage, '/admin/codes': AdminCodesPage, '/admin/settings': AdminSettingsPage,
});
const adminNav = [['/admin', '全站总览'], ['/admin/users', '用户'], ['/admin/groups', '设备组'], ['/admin/rules', '全部规则'],
  ['/admin/plans', '套餐'], ['/admin/orders', '订单'], ['/admin/codes', '兑换码'], ['/admin/settings', '站点设置']];

// ---- 应用 ----
const App = {
  setup() {
    const ready = ref(false);
    window.addEventListener('hashchange', () => { store.route = location.hash.slice(1) || '/'; window.scrollTo(0, 0); });
    onMounted(async () => {
      try { store.site = await api('GET', '/api/site'); document.title = store.site.site_name; } catch (e) { /* 用默认值 */ }
      if (store.token) { try { await refreshUser(); } catch (e) { /* 令牌失效,回到登录页 */ } }
      ready.value = true;
    });
    const page = computed(() => {
      const r = store.route;
      if (r.startsWith('/admin') && !(store.user && store.user.role === 'admin')) return pages['/'];
      return pages[r] || pages['/'];
    });
    return { ready, store, page, userNav, adminNav, logout };
  },
  template: `
  <div class="toasts" aria-live="polite"><div v-for="t in store.toasts" :key="t.id" class="toast" :class="{err: t.err}">{{ t.msg }}</div></div>
  <template v-if="ready">
    <login-page v-if="!store.user"></login-page>
    <div class="shell" v-else>
      <aside class="side">
        <a class="brand" href="#/"><logo></logo>{{ store.site.site_name }}</a>
        <nav aria-label="主导航">
          <a v-for="n in userNav" :key="n[0]" :href="'#' + n[0]" :class="{on: store.route === n[0]}">{{ n[1] }}</a>
          <template v-if="store.user.role === 'admin'">
            <div class="nav-sep">管理</div>
            <a v-for="n in adminNav" :key="n[0]" :href="'#' + n[0]" :class="{on: store.route === n[0]}">{{ n[1] }}</a>
          </template>
        </nav>
        <div class="side-foot"><span :title="store.user.username">{{ store.user.username }}</span><button type="button" @click="logout">退出登录</button></div>
      </aside>
      <main><component :is="page" :key="store.route"></component></main>
    </div>
  </template>`,
};

const app = createApp(App);
app.component('modal', Modal);
app.component('traffic-chart', TrafficChart);
app.component('route-line', RouteLine);
app.component('login-page', LoginPage);
app.component('rules-page', RulesPage);
app.component('logo', Logo);
app.mount('#app');
