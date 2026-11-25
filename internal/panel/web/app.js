// Kaze 面板前端:公共部分与用户端页面。管理端页面在 admin.js。
// 不依赖构建工具:Vue 3 全局版 + 模板字符串,随面板二进制一起内嵌分发。
const { createApp, reactive, ref, computed, onMounted, onUnmounted, watch } = Vue;

const store = reactive({
  site: { site_name: 'Kaze', allow_register: true, pay_enabled: false, pay_types: [] },
  user: null,
  token: localStorage.getItem('kaze_token') || '',
  toasts: [],
  route: location.hash.slice(1) || '/',
});

function toast(msg, err) {
  const t = { id: Math.random(), msg, err };
  store.toasts.push(t);
  setTimeout(() => { store.toasts = store.toasts.filter(x => x !== t); }, err ? 5000 : 2600);
}

function setToken(tok) {
  store.token = tok || '';
  if (tok) localStorage.setItem('kaze_token', tok); else localStorage.removeItem('kaze_token');
}

function logout() { setToken(''); store.user = null; }

async function api(method, path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (store.token) headers.Authorization = 'Bearer ' + store.token;
  let res;
  try {
    res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch (e) {
    throw new Error('无法连接面板,请检查网络');
  }
  let data = null;
  try { data = await res.json(); } catch (e) { /* 空响应 */ }
  if (res.status === 401 && !path.startsWith('/api/auth/')) { logout(); throw new Error((data && data.error) || '登录已失效,请重新登录'); }
  if (!res.ok) { const err = new Error((data && data.error) || ('请求失败 (' + res.status + ')')); err.status = res.status; throw err; }
  return data;
}

// run 执行一个异步操作,失败时弹出错误提示。
async function run(fn, okMsg) {
  try { const v = await fn(); if (okMsg) toast(okMsg); return v === undefined ? true : v; }
  catch (e) { toast(e.message, true); return false; }
}

async function refreshUser() { store.user = await api('GET', '/api/me'); }

// ---- 格式化 ----
const fmt = {
  bytes(n) {
    n = Number(n) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(n >= 100 ? 1 : 2)) + ' ' + u[i];
  },
  rate(bytesPerSec) {
    let n = (Number(bytesPerSec) || 0) * 8;
    const u = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    let i = 0;
    while (n >= 1000 && i < u.length - 1) { n /= 1000; i++; }
    return (i === 0 ? Math.round(n) : n.toFixed(n >= 100 ? 0 : 1)) + ' ' + u[i];
  },
  money(cents) { return '¥' + ((Number(cents) || 0) / 100).toFixed(2); },
  time(ts) {
    if (!ts) return '-';
    const d = new Date(ts * 1000), p = x => String(x).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes());
  },
  date(ts) { return ts ? fmt.time(ts).slice(0, 10) : '-'; },
  dur(sec) {
    sec = Math.max(0, Math.floor(sec));
    const d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
    if (d) return d + ' 天 ' + h + ' 小时';
    if (h) return h + ' 小时 ' + m + ' 分';
    return m + ' 分钟';
  },
  limit(v, unit) { return v ? v + ' ' + unit : '不限'; },
  gb(bytes) { return +((Number(bytes) || 0) / 1073741824).toFixed(2); },
  toLocalInput(ts) {
    if (!ts) return '';
    const d = new Date(ts * 1000), p = x => String(x).padStart(2, '0');
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
  },
  fromLocalInput(s) { return s ? Math.floor(new Date(s).getTime() / 1000) : 0; },
};
const lines = s => String(s || '').split('\n').map(x => x.trim()).filter(Boolean);
const statusText = { ok: '运行中', paused: '已暂停', inactive: '已停用', offline: '节点离线', error: '同步失败' };
const statusTag = { ok: 'ok', paused: '', inactive: 'warn', offline: 'warn', error: 'bad' };
const orderType = { plan: '购买套餐', renew: '自动续费', recharge: '余额充值', redeem: '兑换码', admin: '管理员调整' };
const orderStatus = { paid: '已完成', pending: '待支付', cancelled: '已取消' };
const lbText = { round_robin: '轮询', random: '随机', least_conn: '最小连接数', ip_hash: '按来源 IP', failover: '主备(仅故障时切换)' };

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); }
  catch (e) {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select();
    document.execCommand('copy'); ta.remove();
  }
  toast('已复制');
}

// poll 在组件存活期间按间隔重复执行 fn(页面隐藏时暂停)。
function poll(fn, ms) {
  let timer;
  onMounted(() => { fn(); timer = setInterval(() => { if (!document.hidden) fn(); }, ms); });
  onUnmounted(() => clearInterval(timer));
}

// ---- 通用组件 ----
const Modal = {
  props: { title: String, wide: Boolean },
  emits: ['close'],
  setup(props, { emit }) {
    const onKey = e => { if (e.key === 'Escape') emit('close'); };
    onMounted(() => document.addEventListener('keydown', onKey));
    onUnmounted(() => document.removeEventListener('keydown', onKey));
    return {};
  },
  template: `
  <div class="mask" @mousedown.self="$emit('close')">
    <div class="modal" :class="{wide}" role="dialog" aria-modal="true">
      <div class="modal-head"><h2>{{ title }}</h2><button type="button" aria-label="关闭" @click="$emit('close')">×</button></div>
      <div class="modal-body"><slot></slot></div>
      <div class="modal-foot" v-if="$slots.foot"><slot name="foot"></slot></div>
    </div>
  </div>`,
};

// 流量柱状图:上行(橙)叠在下行(青)之上。
const TrafficChart = {
  props: { points: { type: Array, default: () => [] }, unit: { type: String, default: 'hour' } },
  setup(props) {
    const W = 720, H = 190, L = 6, R = 6, T = 18, B = 22;
    const view = computed(() => {
      const pts = props.points || [];
      const max = Math.max(1, ...pts.map(p => p.up + p.down));
      const bw = (W - L - R) / Math.max(1, pts.length);
      const step = props.unit === 'hour' ? 4 : 5;
      const bars = pts.map((p, i) => {
        const hd = (H - T - B) * p.down / max, hu = (H - T - B) * p.up / max;
        const d = new Date(p.t * 1000);
        const label = props.unit === 'hour' ? String(d.getHours()).padStart(2, '0') + ':00' : (d.getMonth() + 1) + '/' + d.getDate();
        return {
          x: L + i * bw + bw * 0.16, w: bw * 0.68,
          yd: H - B - hd, hd, yu: H - B - hd - hu, hu,
          label, showLabel: (pts.length - 1 - i) % step === 0, cx: L + i * bw + bw / 2,
          tip: label + '  下行 ' + fmt.bytes(p.down) + ' / 上行 ' + fmt.bytes(p.up),
        };
      });
      const sum = pts.reduce((a, p) => a + p.up + p.down, 0);
      return { bars, max, sum };
    });
    return { view, W, H, B, T, fmt };
  },
  template: `
  <div>
    <svg class="chart" :viewBox="'0 0 ' + W + ' ' + H" preserveAspectRatio="none" role="img" :aria-label="'流量图,合计 ' + fmt.bytes(view.sum)">
      <line :x1="0" :x2="W" :y1="T" :y2="T"></line>
      <line :x1="0" :x2="W" :y1="H - B" :y2="H - B"></line>
      <text x="6" :y="T - 5">{{ fmt.bytes(view.max) }}</text>
      <g v-for="b in view.bars" :key="b.cx">
        <title>{{ b.tip }}</title>
        <rect class="down" :x="b.x" :y="b.yd" :width="b.w" :height="b.hd" rx="1.5"></rect>
        <rect class="up" :x="b.x" :y="b.yu" :width="b.w" :height="b.hu" rx="1.5"></rect>
        <text v-if="b.showLabel" :x="b.cx" :y="H - 6" text-anchor="middle">{{ b.label }}</text>
      </g>
    </svg>
  </div>`,
};

// 规则的线路表示:入口 → 出口 → 目标
const RouteLine = {
  props: { rule: Object, groups: Object },
  setup(props) {
    const name = id => (props.groups[id] && props.groups[id].name) || ('#' + id);
    return { name };
  },
  template: `
  <div class="route" :class="rule.status">
    <span class="hop">{{ name(rule.in_group) }}<b>:{{ rule.listen_port }}</b></span>
    <template v-if="rule.out_group"><span class="wire"></span><span class="hop">{{ name(rule.out_group) }}</span></template>
    <span class="wire"></span>
    <span class="hop tgt">{{ rule.targets[0] }}<em v-if="rule.targets.length > 1">等 {{ rule.targets.length }} 个</em></span>
  </div>`,
};

// ---- 登录 / 注册 ----
const LoginPage = {
  setup() {
    const mode = ref('login');
    const f = reactive({ username: '', password: '' });
    const busy = ref(false);
    async function submit() {
      busy.value = true;
      await run(async () => {
        const r = await api('POST', '/api/auth/' + mode.value, f);
        setToken(r.token);
        store.user = r.user;
        location.hash = '#/';
      });
      busy.value = false;
    }
    return { mode, f, busy, submit, store };
  },
  template: `
  <div class="login">
    <div class="login-art">
      <div>
        <a class="brand" style="padding:0;margin-bottom:48px" href="#/"><logo></logo>{{ store.site.site_name }}</a>
        <h1>把端口交给入口,把线路交给出口</h1>
        <p>建一条规则,选好入口和出口,流量就沿着加密隧道送到目标。用量、限速和到期时间都在这里管。</p>
      </div>
      <svg class="flow" viewBox="0 0 600 360" preserveAspectRatio="none" aria-hidden="true">
        <path d="M-10 300 C 140 300, 180 120, 330 120 S 520 40, 620 40" stroke="#4fd0c8"/>
        <path d="M-10 330 C 160 330, 220 200, 360 200 S 540 150, 620 150" stroke="#e9861f" style="animation-duration:3.1s"/>
        <path d="M-10 250 C 120 250, 160 60, 300 60 S 500 250, 620 250" stroke="#7fa3ad" style="animation-duration:3.8s"/>
      </svg>
    </div>
    <div class="login-form">
      <form @submit.prevent="submit">
        <h2>{{ mode === 'login' ? '登录' : '注册账号' }}</h2>
        <div class="field"><label for="lu">用户名</label><input id="lu" type="text" v-model.trim="f.username" autocomplete="username" required></div>
        <div class="field"><label for="lp">密码</label><input id="lp" type="password" v-model="f.password" :autocomplete="mode === 'login' ? 'current-password' : 'new-password'" required>
          <div class="hint" v-if="mode === 'register'">至少 8 位</div></div>
        <button class="btn primary" :disabled="busy">{{ mode === 'login' ? '登录' : '注册并登录' }}</button>
        <div class="switch" v-if="store.site.allow_register">
          <template v-if="mode === 'login'">还没有账号?<button type="button" class="link" @click="mode = 'register'">注册</button></template>
          <template v-else>已有账号?<button type="button" class="link" @click="mode = 'login'">登录</button></template>
        </div>
      </form>
    </div>
  </div>`,
};

// ---- 概览 ----
const OverviewPage = {
  setup() {
    const data = ref(null);
    const unit = ref('hour');
    poll(() => run(async () => { data.value = await api('GET', '/api/overview'); store.user = data.value.user; }), 15000);
    const u = computed(() => data.value ? data.value.user : store.user);
    const pct = computed(() => u.value.traffic_quota ? Math.min(100, 100 * u.value.traffic_used / u.value.traffic_quota) : 0);
    const state = computed(() => {
      const x = u.value, now = Date.now() / 1000;
      if (x.role === 'admin') return { ok: true, text: '管理员账号不受套餐限制' };
      if (!x.traffic_quota) return { ok: false, text: '还没有套餐,购买后才能创建转发规则', shop: true };
      if (x.expire_at && x.expire_at <= now) return { ok: false, text: '套餐已于 ' + fmt.time(x.expire_at) + ' 到期,规则已停用', shop: true };
      if (x.traffic_used >= x.traffic_quota) return { ok: false, text: '本期流量已用完,规则已停用', shop: true };
      return { ok: true, text: (x.plan_name || '自定义额度') + (x.expire_at ? ',' + fmt.date(x.expire_at) + ' 到期(还剩 ' + fmt.dur(x.expire_at - now) + ')' : ',长期有效') };
    });
    return { data, unit, u, pct, state, fmt };
  },
  template: `
  <div v-if="data">
    <div class="page-head"><div><h1>概览</h1></div></div>
    <div class="notice" v-if="data.announcement">{{ data.announcement }}</div>
    <div class="panel">
      <div class="usage">
        <div class="usage-main">
          <div class="sub">本期已用流量</div>
          <div class="usage-fig">{{ fmt.bytes(u.traffic_used) }}<small v-if="u.traffic_quota">/ {{ fmt.bytes(u.traffic_quota) }}</small></div>
          <div class="gauge" :class="{warn: pct >= 80 && pct < 100, bad: pct >= 100}" v-if="u.traffic_quota"><i :style="{width: pct + '%'}"></i></div>
          <p class="sub" style="margin-top:10px">{{ state.text }} <a v-if="state.shop" href="#/shop">去商城</a></p>
        </div>
        <dl class="facts" style="margin:0">
          <div class="fact"><dt>余额</dt><dd>{{ fmt.money(u.balance) }}</dd></div>
          <div class="fact"><dt>转发规则</dt><dd>{{ u.rule_count }}<small v-if="u.role !== 'admin'"> / {{ u.max_rules }} 条</small></dd></div>
          <div class="fact"><dt>限速</dt><dd>{{ u.speed_limit || '不限' }}<small v-if="u.speed_limit"> Mbps</small></dd></div>
          <div class="fact"><dt>连接数 / IP 数</dt><dd>{{ u.conn_limit || '不限' }}<small> / {{ u.ip_limit || '不限' }}</small></dd></div>
        </dl>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head">
        <h2>流量走势</h2>
        <div class="actions">
          <div class="legend"><span><i style="background:var(--teal)"></i>下行</span><span><i style="background:var(--amber)"></i>上行</span></div>
          <div class="seg"><button type="button" :class="{on: unit === 'hour'}" @click="unit = 'hour'">24 小时</button><button type="button" :class="{on: unit === 'day'}" @click="unit = 'day'">30 天</button></div>
        </div>
      </div>
      <div class="panel-body"><traffic-chart :points="unit === 'hour' ? data.hourly : data.daily" :unit="unit"></traffic-chart></div>
    </div>
  </div>`,
};

// ---- 转发规则 ----
function blankRule() {
  return { id: 0, name: '', in_group: 0, out_group: 0, listen_port: '', proto: 'tcp+udp', targetsText: '', lb: 'round_robin',
    proxy_protocol: 0, speed_limit: 0, conn_limit: 0, ip_limit: 0 };
}

const RulesPage = {
  props: { all: Boolean },
  setup(props) {
    const rules = ref(null), groups = ref([]);
    const form = ref(null), batch = ref(null), diag = ref(null);
    const gmap = computed(() => Object.fromEntries(groups.value.map(g => [g.id, g])));
    const inGroups = computed(() => groups.value.filter(g => g.type === 'in'));
    const outGroups = computed(() => groups.value.filter(g => g.type === 'out'));
    const load = () => run(async () => { rules.value = await api('GET', '/api/rules' + (props.all ? '?all=1' : '')); });
    onMounted(() => run(async () => { groups.value = await api('GET', '/api/groups'); }));
    poll(load, 10000);

    // 某个入口组下可选的出口(受"限制出口"与直出策略约束)
    function outsFor(inId) {
      const g = gmap.value[inId];
      if (!g) return [];
      if (g.direct_mode === 2) return [];
      const allow = g.allowed_out || [];
      return outGroups.value.filter(o => !allow.length || allow.includes(o.id));
    }
    const canDirect = inId => { const g = gmap.value[inId]; return !g || g.direct_mode !== 1 || store.user.role === 'admin'; };
    const entry = r => { const g = gmap.value[r.in_group]; return g && g.hosts && g.hosts.length ? g.hosts[0] + ':' + r.listen_port : ''; };

    function openNew() {
      const f = blankRule();
      if (inGroups.value.length) f.in_group = inGroups.value[0].id;
      if (!canDirect(f.in_group)) { const o = outsFor(f.in_group); f.out_group = o.length ? o[0].id : 0; }
      form.value = f;
    }
    function openEdit(r) { form.value = Object.assign(blankRule(), r, { targetsText: r.targets.join('\n'), listen_port: r.listen_port }); }
    function onInChange() {
      const f = form.value, outs = outsFor(f.in_group);
      if (f.out_group && !outs.find(o => o.id === f.out_group)) f.out_group = 0;
      if (!f.out_group && !canDirect(f.in_group)) f.out_group = outs.length ? outs[0].id : 0;
    }
    async function save() {
      const f = form.value;
      const body = { name: f.name, in_group: f.in_group, out_group: f.out_group, listen_port: Number(f.listen_port) || 0, proto: f.proto,
        targets: lines(f.targetsText), lb: f.lb, proxy_protocol: Number(f.proxy_protocol), speed_limit: Number(f.speed_limit) || 0,
        conn_limit: Number(f.conn_limit) || 0, ip_limit: Number(f.ip_limit) || 0 };
      const ok = await run(() => f.id ? api('PUT', '/api/rules/' + f.id, body) : api('POST', '/api/rules', body), f.id ? '规则已保存' : '规则已创建');
      if (ok) { form.value = null; load(); if (!props.all) refreshUser().catch(() => {}); }
    }
    async function togglePause(r) {
      if (await run(() => api('POST', '/api/rules/' + r.id + '/pause', { paused: !r.paused }), r.paused ? '规则已恢复' : '规则已暂停')) load();
    }
    async function remove(r) {
      if (!confirm('删除规则"' + r.name + '"?端口 ' + r.listen_port + ' 会立即停止转发。')) return;
      if (await run(() => api('DELETE', '/api/rules/' + r.id), '规则已删除')) { load(); if (!props.all) refreshUser().catch(() => {}); }
    }
    async function runDiag(r) {
      diag.value = { rule: r, hops: null };
      const res = await run(() => api('POST', '/api/rules/' + r.id + '/diag'));
      if (diag.value && diag.value.rule === r) diag.value.hops = res ? res.hops : [];
    }
    function openBatch() { batch.value = { in_group: inGroups.value.length ? inGroups.value[0].id : 0, out_group: 0, proto: 'tcp+udp', text: '' }; }
    async function saveBatch() {
      const res = await run(() => api('POST', '/api/rules/batch', batch.value));
      if (res) { toast('已导入 ' + res.created + ' 条规则'); batch.value = null; load(); refreshUser().catch(() => {}); }
    }
    return { rules, groups, gmap, inGroups, outGroups, form, batch, diag, outsFor, canDirect, entry, openNew, openEdit, onInChange, save,
      togglePause, remove, runDiag, openBatch, saveBatch, fmt, statusText, statusTag, lbText, copyText, store };
  },
  template: `
  <div>
    <div class="page-head">
      <div><h1>{{ all ? '全部规则' : '转发规则' }}</h1><p class="sub" v-if="!all && store.user.role !== 'admin'">已用 {{ store.user.rule_count }} / {{ store.user.max_rules }} 条</p></div>
      <div class="actions" v-if="!all"><button class="btn" @click="openBatch">批量导入</button><button class="btn primary" @click="openNew">新建规则</button></div>
    </div>
    <div class="panel">
      <div class="empty" v-if="rules && !rules.length"><b>还没有转发规则</b>{{ all ? '用户创建规则后会出现在这里。' : '新建一条规则,选择入口和目标地址即可开始转发。' }}</div>
      <div class="scroll-x" v-else-if="rules">
        <table class="stack-sm">
          <thead><tr><th>规则</th><th>线路</th><th class="r">上行 / 下行</th><th>状态</th><th></th></tr></thead>
          <tbody>
            <tr v-for="r in rules" :key="r.id">
              <td><div class="rule-name">{{ r.name }}</div>
                <div class="sub"><template v-if="all">{{ r.username }}</template>
                  <button v-else-if="entry(r)" class="link muted num" style="padding:0" title="复制入口地址" @click="copyText(entry(r))">{{ entry(r) }}</button>
                  <span class="dim proto">{{ r.proto.toUpperCase() }}</span></div></td>
              <td><route-line :rule="r" :groups="gmap"></route-line><div class="rule-err" v-if="r.error">{{ r.error }}</div></td>
              <td class="r num updown"><div>{{ fmt.bytes(r.traffic_up) }}</div><div>{{ fmt.bytes(r.traffic_down) }}</div></td>
              <td><span class="tag" :class="statusTag[r.status]">{{ statusText[r.status] }}</span></td>
              <td class="ops">
                <button class="link" @click="runDiag(r)">诊断</button>
                <button class="link" @click="togglePause(r)">{{ r.paused ? '恢复' : '暂停' }}</button>
                <button class="link" @click="openEdit(r)">编辑</button>
                <button class="link danger" @click="remove(r)">删除</button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <modal v-if="form" :title="form.id ? '编辑规则' : '新建规则'" @close="form = null">
      <form id="rule-form" @submit.prevent="save">
        <div class="field"><label>名称</label><input type="text" v-model.trim="form.name" maxlength="64" placeholder="留空则按端口自动命名"></div>
        <div class="grid2">
          <div class="field"><label>入口</label>
            <select v-model.number="form.in_group" @change="onInChange">
              <option v-for="g in inGroups" :key="g.id" :value="g.id">{{ g.name }}({{ g.ratio }}x)</option>
            </select>
            <div class="hint" v-if="gmap[form.in_group]">可用端口 {{ gmap[form.in_group].port_range }}</div></div>
          <div class="field"><label>出口</label>
            <select v-model.number="form.out_group">
              <option v-if="canDirect(form.in_group)" :value="0">直接转发(不经出口)</option>
              <option v-for="g in outsFor(form.in_group)" :key="g.id" :value="g.id">{{ g.name }}({{ g.ratio }}x,{{ g.transport }})</option>
            </select>
            <div class="hint">计费倍率为入口与出口之和</div></div>
        </div>
        <div class="grid2">
          <div class="field"><label>监听端口</label><input type="number" v-model="form.listen_port" min="0" max="65535" placeholder="留空自动分配"></div>
          <div class="field"><label>协议</label>
            <select v-model="form.proto"><option value="tcp+udp">TCP + UDP</option><option value="tcp">仅 TCP</option><option value="udp">仅 UDP</option></select></div>
        </div>
        <div class="field"><label>转发目标</label>
          <textarea class="code" rows="3" v-model="form.targetsText" placeholder="example.com:443" required></textarea>
          <div class="hint">每行一个 主机:端口。填多个时按下面的策略做负载均衡。</div></div>
        <details class="more" :open="form.lb !== 'round_robin' || form.proxy_protocol || form.speed_limit || form.conn_limit || form.ip_limit">
          <summary>负载均衡、PROXY protocol 与限制</summary>
          <div class="grid2">
            <div class="field"><label>多目标策略</label><select v-model="form.lb"><option v-for="(t, k) in lbText" :key="k" :value="k">{{ t }}</option></select></div>
            <div class="field"><label>PROXY protocol</label><select v-model.number="form.proxy_protocol"><option :value="0">关闭</option><option :value="1">v1</option><option :value="2">v2</option></select>
              <div class="hint">向目标传递访客真实 IP,目标需支持</div></div>
          </div>
          <div class="grid3">
            <div class="field"><label>限速 (Mbps)</label><input type="number" min="0" v-model="form.speed_limit"></div>
            <div class="field"><label>连接数</label><input type="number" min="0" v-model="form.conn_limit"></div>
            <div class="field"><label>来源 IP 数</label><input type="number" min="0" v-model="form.ip_limit"></div>
          </div>
          <div class="hint">填 0 表示不限。规则级限制与账号级限制同时生效。</div>
        </details>
      </form>
      <template #foot><button class="btn" @click="form = null">取消</button><button class="btn primary" form="rule-form">{{ form.id ? '保存规则' : '创建规则' }}</button></template>
    </modal>

    <modal v-if="batch" title="批量导入规则" @close="batch = null">
      <div class="grid2">
        <div class="field"><label>入口</label><select v-model.number="batch.in_group"><option v-for="g in inGroups" :key="g.id" :value="g.id">{{ g.name }}</option></select></div>
        <div class="field"><label>出口</label><select v-model.number="batch.out_group"><option :value="0">直接转发(不经出口)</option><option v-for="g in outsFor(batch.in_group)" :key="g.id" :value="g.id">{{ g.name }}</option></select></div>
      </div>
      <div class="field"><label>规则列表</label>
        <textarea class="code" rows="8" v-model="batch.text" placeholder="名称#监听端口#目标地址#目标端口&#10;游戏服##203.0.113.8#25565"></textarea>
        <div class="hint">每行一条,监听端口留空则自动分配。任意一行有误时整批都不会导入。</div></div>
      <template #foot><button class="btn" @click="batch = null">取消</button><button class="btn primary" @click="saveBatch">导入规则</button></template>
    </modal>

    <modal v-if="diag" :title="'链路诊断:' + diag.rule.name" @close="diag = null">
      <p class="sub" v-if="!diag.hops">正在让各节点测量到下一跳的 TCP 建连耗时…</p>
      <table v-else-if="diag.hops.length">
        <thead><tr><th>从</th><th>到</th><th class="r">建连耗时</th></tr></thead>
        <tbody><tr v-for="(h, i) in diag.hops" :key="i">
          <td>{{ h.from }}</td><td>{{ h.to }}</td>
          <td class="r"><span v-if="h.error" class="tag bad" style="white-space:normal">{{ h.error }}</span><span v-else class="num">{{ h.ms.toFixed(1) }} ms</span></td>
        </tr></tbody>
      </table>
      <p class="sub" v-else>没有拿到诊断结果,入口或出口节点可能不在线。</p>
    </modal>
  </div>`,
};

// ---- 节点状态(探针)----
const StatusPage = {
  setup() {
    const groups = ref(null);
    poll(() => run(async () => { groups.value = await api('GET', '/api/status'); }), 5000);
    const pct = (a, b) => b ? Math.min(100, 100 * a / b) : 0;
    return { groups, pct, fmt, now: () => Date.now() / 1000 };
  },
  template: `
  <div>
    <div class="page-head"><div><h1>节点状态</h1><p class="sub">每 5 秒刷新一次</p></div></div>
    <div class="panel" v-if="groups && !groups.length"><div class="empty"><b>暂时没有可用的节点</b>管理员添加设备组并对接机器后,状态会显示在这里。</div></div>
    <div class="panel" v-for="g in groups" :key="g.id">
      <div class="panel-head"><h2>{{ g.name }} <span class="tag">{{ g.type === 'in' ? '入口' : '出口' }}</span></h2></div>
      <div class="empty" v-if="!g.nodes.length">这个设备组还没有对接机器。</div>
      <div class="scroll-x" v-else>
        <table>
          <thead><tr><th>机器</th><th>CPU</th><th>内存</th><th class="r">负载</th><th class="r">上传 / 下载</th><th class="r">连接</th><th class="r">在线时长</th><th>版本</th></tr></thead>
          <tbody>
            <tr v-for="n in g.nodes" :key="n.id">
              <td><span class="dot" :class="n.online ? 'on' : 'off'"></span>{{ n.hostname || '未命名' }}<span class="sub num" v-if="n.ip"> {{ n.ip }}</span>
                <div class="rule-err" v-if="n.error">{{ n.error }}</div></td>
              <template v-if="n.online && n.metrics">
                <td><span class="meter" :class="{hot: n.metrics.cpu > 80}"><i :style="{width: n.metrics.cpu + '%'}"></i></span><span class="num">{{ n.metrics.cpu.toFixed(0) }}%</span></td>
                <td><span class="meter" :class="{hot: pct(n.metrics.mem_used, n.metrics.mem_total) > 85}"><i :style="{width: pct(n.metrics.mem_used, n.metrics.mem_total) + '%'}"></i></span><span class="num">{{ fmt.bytes(n.metrics.mem_used) }}</span></td>
                <td class="r num">{{ n.metrics.load1.toFixed(2) }}</td>
                <td class="r num">{{ fmt.rate(n.metrics.tx_rate) }} / {{ fmt.rate(n.metrics.rx_rate) }}</td>
                <td class="r num">{{ n.metrics.tcp_conns }}<span class="dim" v-if="n.metrics.udp_sess"> + {{ n.metrics.udp_sess }} UDP</span></td>
                <td class="r">{{ fmt.dur(n.metrics.uptime) }}</td>
              </template>
              <td v-else colspan="6" class="dim">{{ n.online ? '等待上报…' : '离线,最后在线 ' + fmt.time(n.last_seen) }}</td>
              <td class="num">{{ n.version }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>`,
};

// ---- 商城 ----
const ShopPage = {
  setup() {
    const plans = ref([]), orders = ref([]);
    const code = ref(''), recharge = ref(null);
    const load = () => run(async () => {
      [plans.value, orders.value] = await Promise.all([api('GET', '/api/plans'), api('GET', '/api/orders')]);
      await refreshUser();
    });
    onMounted(load);
    async function buy(p) {
      const renew = store.user.plan_id === p.id && store.user.expire_at > Date.now() / 1000;
      const tip = renew ? '续费后到期时间顺延 ' + p.days + ' 天,已用流量清零。' : '新套餐立即生效,已用流量清零' + (store.user.plan_id ? ',原套餐剩余时长不保留。' : '。');
      if (!confirm('用余额 ' + fmt.money(p.price) + ' 购买"' + p.name + '"?\n' + tip)) return;
      if (await run(() => api('POST', '/api/plans/' + p.id + '/buy'), '已购买 ' + p.name)) load();
    }
    async function redeem() {
      if (!code.value.trim()) return;
      const r = await run(() => api('POST', '/api/redeem', { code: code.value.trim() }));
      if (r) { toast(r.message); code.value = ''; load(); }
    }
    function openRecharge() { recharge.value = { amount: 50, method: (store.site.pay_types || [])[0] || 'alipay' }; }
    async function pay() {
      const r = await run(() => api('POST', '/api/recharge', { amount: Number(recharge.value.amount), method: recharge.value.method }));
      if (r) location.href = r.url;
    }
    async function setRenew(e) {
      const enabled = e.target.checked;
      if (await run(() => api('POST', '/api/me/auto_renew', { enabled }), enabled ? '已开启自动续费' : '已关闭自动续费')) store.user.auto_renew = enabled;
      else e.target.checked = !enabled;
    }
    const payName = { alipay: '支付宝', wxpay: '微信支付', qqpay: 'QQ 钱包', usdt: 'USDT' };
    return { plans, orders, code, recharge, buy, redeem, openRecharge, pay, setRenew, fmt, store, orderType, orderStatus, payName };
  },
  template: `
  <div>
    <div class="page-head"><div><h1>商城</h1></div></div>
    <div class="panel">
      <div class="panel-body" style="display:flex;gap:28px;flex-wrap:wrap;align-items:flex-end">
        <div><div class="sub">余额</div><div class="usage-fig" style="font-size:34px">{{ fmt.money(store.user.balance) }}</div></div>
        <button class="btn primary" v-if="store.site.pay_enabled" @click="openRecharge">充值</button>
        <form style="display:flex;gap:8px;flex:1;min-width:260px;max-width:420px" @submit.prevent="redeem">
          <input type="text" v-model="code" placeholder="输入兑换码" aria-label="兑换码">
          <button class="btn">兑换</button>
        </form>
        <label class="check" style="margin:0 0 6px"><input type="checkbox" :checked="store.user.auto_renew" @change="setRenew">到期时用余额自动续费</label>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>套餐</h2><span class="sub" v-if="store.user.plan_name">当前:{{ store.user.plan_name }}</span></div>
      <div class="empty" v-if="!plans.length"><b>暂时没有在售套餐</b>请联系管理员开通。</div>
      <div class="scroll-x" v-else>
        <table>
          <thead><tr><th>套餐</th><th class="r">流量</th><th class="r">时长</th><th class="r">规则数</th><th class="r">限速</th><th class="r">价格</th><th></th></tr></thead>
          <tbody>
            <tr v-for="p in plans" :key="p.id">
              <td><div class="plan-name">{{ p.name }} <span class="tag ok" v-if="store.user.plan_id === p.id">使用中</span></div><div class="sub" v-if="p.description">{{ p.description }}</div></td>
              <td class="r num">{{ fmt.bytes(p.traffic) }}</td>
              <td class="r num">{{ p.days ? p.days + ' 天' : '不限期' }}</td>
              <td class="r num">{{ p.max_rules }}</td>
              <td class="r num">{{ fmt.limit(p.speed_limit, 'Mbps') }}</td>
              <td class="r"><span class="price">{{ fmt.money(p.price) }}</span></td>
              <td class="ops"><button class="btn sm primary" @click="buy(p)">{{ store.user.plan_id === p.id ? '续费' : '购买' }}</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head"><h2>订单记录</h2></div>
      <div class="empty" v-if="!orders.length">还没有订单。</div>
      <div class="scroll-x" v-else>
        <table>
          <thead><tr><th>时间</th><th>类型</th><th>说明</th><th class="r">金额</th><th>状态</th><th>订单号</th></tr></thead>
          <tbody><tr v-for="o in orders" :key="o.id">
            <td class="num">{{ fmt.time(o.created_at) }}</td><td>{{ orderType[o.type] || o.type }}</td><td>{{ o.note }}</td>
            <td class="r num">{{ fmt.money(o.amount) }}</td>
            <td><span class="tag" :class="o.status === 'paid' ? 'ok' : ''">{{ orderStatus[o.status] || o.status }}</span></td>
            <td class="num dim">{{ o.order_no }}</td>
          </tr></tbody>
        </table>
      </div>
    </div>
    <modal v-if="recharge" title="余额充值" @close="recharge = null">
      <div class="field"><label>金额(元)</label><input type="number" min="1" step="0.01" v-model="recharge.amount"></div>
      <div class="field"><label>支付方式</label><select v-model="recharge.method"><option v-for="t in store.site.pay_types" :key="t" :value="t">{{ payName[t] || t }}</option></select></div>
      <p class="sub">点击后会跳转到支付页面,支付完成后余额自动到账。</p>
      <template #foot><button class="btn" @click="recharge = null">取消</button><button class="btn primary" @click="pay">去支付</button></template>
    </modal>
  </div>`,
};

// ---- 账号 ----
const AccountPage = {
  setup() {
    const f = reactive({ old: '', new: '', again: '' });
    async function save() {
      if (f.new !== f.again) { toast('两次输入的新密码不一致', true); return; }
      const r = await run(() => api('POST', '/api/me/password', { old: f.old, new: f.new }));
      if (r) { setToken(r.token); f.old = f.new = f.again = ''; toast('密码已修改,其他设备上的登录已失效'); }
    }
    return { f, save, store, fmt };
  },
  template: `
  <div>
    <div class="page-head"><div><h1>账号</h1><p class="sub">{{ store.user.username }},注册于 {{ fmt.date(store.user.created_at) }}</p></div></div>
    <div class="panel" style="max-width:460px">
      <div class="panel-head"><h2>修改密码</h2></div>
      <form class="panel-body" @submit.prevent="save">
        <div class="field"><label>当前密码</label><input type="password" v-model="f.old" autocomplete="current-password" required></div>
        <div class="field"><label>新密码</label><input type="password" v-model="f.new" autocomplete="new-password" minlength="8" required><div class="hint">至少 8 位</div></div>
        <div class="field"><label>再输入一次新密码</label><input type="password" v-model="f.again" autocomplete="new-password" required></div>
        <button class="btn primary">修改密码</button>
      </form>
    </div>
  </div>`,
};

const Logo = { template: `<svg viewBox="0 0 32 32" aria-hidden="true"><path d="M4 11h15a3.2 3.2 0 1 0-3.2-3.2M4 16.5h23M4 22h17a3.2 3.2 0 1 1-3.2 3.2" fill="none" stroke="#4fd0c8" stroke-width="2.4" stroke-linecap="round"/></svg>` };

const pages = {
  '/': OverviewPage, '/rules': RulesPage, '/status': StatusPage, '/shop': ShopPage, '/account': AccountPage,
};
const userNav = [['/', '概览'], ['/rules', '转发规则'], ['/status', '节点状态'], ['/shop', '商城'], ['/account', '账号']];
