// Kaze 界面交互自测:用无头浏览器真的在表单里点选、填写、保存,再用接口核对落库的结果。
// 只起面板,不起节点——这里验证的是"界面提交的内容对不对",转发本身由 e2e*.py 覆盖。
//
// 用法(在仓库根目录):
//   npm i --no-save playwright-core && npx playwright-core install chromium-headless-shell
//   node scripts/ui_flow.mjs <二进制目录>      (目录里需要有 kaze-panel)
import { chromium } from 'playwright-core';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
const BIN = path.resolve(process.argv[2] || 'dist');
const W = fs.mkdtempSync(path.join(os.tmpdir(), 'kaze-ui-')), P = 'http://127.0.0.1:18091';
const procs = [];
const sp = (name, cmd, args) => { const fd = fs.openSync(`${W}/${name}.log`, 'w'); const p = spawn(cmd, args, { stdio: ['ignore', fd, fd] }); procs.push(p); return p; };
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function api(m, path, body, tok) {
  const r = await fetch(P + path, { method: m, headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const d = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`${m} ${path} ${r.status} ${JSON.stringify(d)}`);
  return d;
}
let passed = 0;
const check = (name, cond, detail = '') => { if (!cond) throw new Error('✗ ' + name + ' ' + detail); passed++; console.log('  ✓ ' + name); };
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
let code = 0;
try {
  sp('panel', `${BIN}/kaze-panel`, ['-listen', '127.0.0.1:18091', '-data', `${W}/data`, '-dist', BIN, '-admin-pass', 'admin-ui-pass']);
  for (let i = 0; i < 50; i++) { try { await api('GET', '/api/site'); break; } catch { await sleep(200); } }
  const adm = (await api('POST', '/api/auth/login', { username: 'admin', password: 'admin-ui-pass' })).token;
  const grp = (name, type, config) => api('POST', '/api/admin/groups', { name, type, ratio: 1, config }, adm);
  const gout = await grp('香港出口', 'out', { transport: 'tls', fingerprint: 'chrome' });
  const ghttp = await grp('东京出口', 'out', { transport: 'http', ws_path: '/api/v2/sync', ws_host: 'cdn.example.com' });
  const gus = await grp('洛杉矶出口', 'out', { transport: 'wss' });
  const gin = await grp('上海入口', 'in', { port_range: '21000-21100,8443,9443', reverse_groups: [gus.id], blocked_hosts: ['.blocked.test'] });
  await api('POST', '/api/admin/plans', { name: '标准版', price: 0, traffic: 2 ** 40, days: 30, max_rules: 20 }, adm);
  const plan = (await api('GET', '/api/admin/plans', null, adm))[0];
  const alice = (await api('POST', '/api/auth/register', { username: 'alice', password: 'alice-pass-1' })).token;
  await api('POST', `/api/plans/${plan.id}/buy`, null, alice);
  await api('POST', '/api/rules', { in_group: gin.id, tls_mode: 'parent', listen_port: 8443 }, adm);
  const site = await api('POST', '/api/rules', { name: '网站', in_group: gin.id, out_group: ghttp.id, listen_port: 9443, targets: ['10.0.0.1:443', '10.0.0.2:443'], lb: 'failover',
    proxy_protocol: 2, tls_mode: 'tls', tls: { sni: ['www.example.com'], alpn: ['h2', 'http/1.1'], origin_tls: true, origin_sni: 'origin.internal', origin_verify: true } }, alice);
  const groups = async () => Object.fromEntries(await Promise.all((await api('GET', '/api/admin/groups', null, adm)).map(async g => [g.id, await api('GET', '/api/admin/groups/' + g.id, null, adm)])));
  const rules = async () => await api('GET', '/api/rules', null, alice);

  const browser = await chromium.launch();
  const errors = [];
  async function session(tok) {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 1400 } });
    const page = await ctx.newPage();
    // 故意提交不合法内容时,浏览器会把接口的 4xx 响应记成一条 "Failed to load resource",那不算界面出错
    page.on('console', m => { if ((m.type() === 'error' || m.type() === 'warning') && !m.text().includes('Failed to load resource')) errors.push(`${m.type()}: ${m.text()}`); });
    page.on('pageerror', e => errors.push(`pageerror: ${e.message}`));
    page.on('dialog', d => d.accept());
    await page.goto(P + '/');
    await page.evaluate(t => localStorage.setItem('kaze_token', t), tok);
    return page;
  }
  const field = (page, form, label) => page.locator(`${form} .field`, { has: page.locator('label', { hasText: new RegExp('^' + label) }) });
  const saved = async page => { await page.waitForSelector('.modal', { state: 'detached', timeout: 5000 }); await page.waitForTimeout(300); };

  console.log('[用户] 转发规则表单');
  let page = await session(alice);
  await page.goto(P + '/#/rules'); await page.reload(); await page.waitForSelector('text=新建规则');
  // 1. 新建 TLS 子规则
  await page.click('text=新建规则');
  await field(page, '#rule-form', '入站方式').locator('select').selectOption('child');
  check('选择子规则后,共享端口自动选中唯一的那个', await field(page, '#rule-form', '共享 TLS 端口').locator('select').inputValue() === '8443');
  check('子规则表单里没有协议选择(TLS 只有 TCP)', await field(page, '#rule-form', '协议').count() === 0);
  await field(page, '#rule-form', 'SNI').locator('input').fill('Shop.Example.com, pay.example.com');
  await field(page, '#rule-form', '转发目标').locator('textarea').fill('10.0.0.9:8080');
  await page.click('button:has-text("创建规则")'); await saved(page);
  let r = (await rules()).find(x => x.tls_mode === 'child');
  check('子规则按表单内容保存', r && r.listen_port === 8443 && eq(r.tls.sni, ['shop.example.com', 'pay.example.com']) && r.name === 'shop.example.com' && r.proto === 'tcp' && eq(r.targets, ['10.0.0.9:8080']), JSON.stringify(r));
  // 2. 不合法的输入:错误提示留在表单里,不关闭
  await page.click('text=新建规则');
  await field(page, '#rule-form', '入站方式').locator('select').selectOption('child');
  await field(page, '#rule-form', 'SNI').locator('input').fill('pay.example.com');
  await field(page, '#rule-form', '转发目标').locator('textarea').fill('10.0.0.9:8080');
  await page.click('button:has-text("创建规则")');
  await page.waitForSelector('.toast.err');
  check('SNI 冲突时给出提示并保留表单', (await page.textContent('.toast.err')).includes('pay.example.com') && await page.locator('.modal').count() === 1);
  await page.click('.modal-head button'); await page.waitForTimeout(200);   // 提示还在的时候也要能点到关闭按钮
  check('提示不挡住弹窗的关闭按钮', await page.locator('.modal').count() === 0);
  await page.waitForTimeout(5600);
  check('提示过几秒自动消失', await page.locator('.toast').count() === 0);
  // 3. 编辑已有的 TLS 规则:只改名字,其它设置都要原样带回
  await page.click('tr:has-text("网站") >> text=编辑');
  check('编辑时表单回填了 TLS 设置', await field(page, '#rule-form', 'SNI').locator('input').inputValue() === 'www.example.com'
    && await field(page, '#rule-form', 'ALPN').locator('input').inputValue() === 'h2, http/1.1'
    && await field(page, '#rule-form', '目标的 SNI').locator('input[type=text]').inputValue() === 'origin.internal'
    && await field(page, '#rule-form', '目标的 SNI').locator('input[type=checkbox]').isChecked()
    && await field(page, '#rule-form', '监听端口').locator('input').inputValue() === '9443');
  await field(page, '#rule-form', '名称').locator('input').fill('网站 v2');
  await page.click('button:has-text("保存规则")'); await saved(page);
  r = (await rules()).find(x => x.id === site.id);
  const keep = x => [x.in_group, x.out_group, x.listen_port, x.proto, x.targets, x.lb, x.proxy_protocol, x.tls_mode, x.tls];
  check('只改名称:TLS 设置、目标、均衡策略、PROXY protocol 原样保留', r.name === '网站 v2' && eq(keep(r), keep(site)), JSON.stringify(r));
  // 4. 从 TLS 入站改成普通转发:TLS 设置被清掉,端口保留
  await page.click('tr:has-text("网站 v2") >> text=编辑');
  await field(page, '#rule-form', '入站方式').locator('select').selectOption('');
  await page.click('button:has-text("保存规则")'); await saved(page);
  r = (await rules()).find(x => x.id === site.id);
  check('改成普通转发后不再带 TLS 设置', r.tls_mode === '' && eq(r.tls.sni, []) && !r.tls.origin_tls && r.listen_port === 9443, JSON.stringify(r));
  await page.context().close();

  console.log('[管理员] 设备组表单');
  page = await session(adm);
  await page.goto(P + '/#/admin/groups'); await page.reload(); await page.waitForSelector('text=新建链式出口');
  // 5. 新建链式出口
  await page.click('text=新建链式出口');
  await field(page, '#group-form', '名称').locator('input').fill('三跳测试');
  await field(page, '#group-form', '第 1 跳').locator('select').selectOption(String(gout.id));
  await field(page, '#group-form', '第 2 跳').locator('select').selectOption(String(ghttp.id));
  await field(page, '#group-form', '第 3 跳').locator('select').selectOption(String(gus.id));
  await page.click('button:has-text("创建链式出口")'); await saved(page);
  let gs = await groups();
  const chain = Object.values(gs).find(g => g.type === 'chain');
  check('链式出口按所选顺序保存', chain && chain.name === '三跳测试' && eq(chain.config.chain_hops, [gout.id, ghttp.id, gus.id]) && chain.config.chain_mux === false, JSON.stringify(chain && chain.config));
  check('新建链式出口后不弹出对接命令', await page.locator('.modal').count() === 0);
  // 6. 编辑链式出口:去掉第 3 跳,打开各跳复用
  await page.click('tr:has-text("三跳测试") >> text=编辑');
  await field(page, '#group-form', '第 3 跳').locator('select').selectOption('0');
  await page.locator('#group-form label.check', { hasText: '各跳之间使用多路复用' }).locator('input').check();
  await page.click('button:has-text("保存链式出口")'); await saved(page);
  gs = await groups();
  check('编辑链式出口生效', eq(gs[chain.id].config.chain_hops, [gout.id, ghttp.id]) && gs[chain.id].config.chain_mux === true);
  // 7. 入口组:反向隧道改成"全部出口组",原来勾选的那个变成例外
  await page.click('tr:has-text("上海入口") >> text=编辑');
  await field(page, '#group-form', '哪些出口组主动连进来').locator('select').selectOption('all');
  await field(page, '#group-form', '每台出口到每台入口的连接数').locator('input').fill('3');
  await page.locator('#group-form summary', { hasText: 'TLS 入站' }).click();
  await field(page, '#group-form', '用户可以创建的规则').locator('select').selectOption('1');
  await page.click('button:has-text("保存入口组")'); await saved(page);
  gs = await groups();
  let c = gs[gin.id].config;
  check('入口组的反向隧道与 TLS 策略按表单保存', eq(c.reverse_groups, [0, gus.id]) && c.reverse_conns === 3 && c.tls_inbound_policy === 1, JSON.stringify(c.reverse_groups));
  check('保存入口组不改动其它设置和反向隧道证书', c.rev_cert_pin === gin.config.rev_cert_pin && c.rev_key_pem === gin.config.rev_key_pem && c.port_range === '21000-21100,8443,9443' && eq(c.blocked_hosts, ['.blocked.test']));
  // 8. 出口组:换指纹
  await page.click('tr:has-text("香港出口") >> text=编辑');
  await field(page, '#group-form', 'TLS 握手指纹').locator('select').selectOption('safari');
  await page.click('button:has-text("保存出口组")'); await saved(page);
  gs = await groups(); c = gs[gout.id].config;
  check('出口组换指纹后,密钥和证书一字不差', c.fingerprint === 'safari' && c.tunnel_key === gout.config.tunnel_key && c.cert_pem === gout.config.cert_pem && c.key_pem === gout.config.key_pem);
  // 9. 出口组:进出一次"高级编辑"再保存,配置不应有任何变化
  await page.click('tr:has-text("东京出口") >> text=编辑');
  check('HTTP 伪装下指纹与 SNI 不可选', await field(page, '#group-form', 'TLS 握手指纹').locator('select').isDisabled() && await field(page, '#group-form', 'TLS SNI').locator('input').isDisabled());
  await page.click('button:has-text("高级编辑")');
  const json = await page.locator('#group-form textarea.code').inputValue();
  check('高级编辑里是完整的 JSON 配置', JSON.parse(json).transport === 'http' && JSON.parse(json).tunnel_key === ghttp.config.tunnel_key);
  await page.click('button:has-text("返回表单")');
  await page.click('button:has-text("保存出口组")'); await saved(page);
  gs = await groups();
  check('进出高级编辑后保存,配置没有变化', eq(gs[ghttp.id].config, ghttp.config), JSON.stringify(gs[ghttp.id].config));
  // 10. 高级编辑里清空隧道密钥:重新生成
  await page.click('tr:has-text("东京出口") >> text=编辑');
  await page.click('button:has-text("高级编辑")');
  const edited = JSON.parse(await page.locator('#group-form textarea.code').inputValue());
  edited.tunnel_key = '';
  await page.locator('#group-form textarea.code').fill(JSON.stringify(edited, null, 2));
  await page.click('button:has-text("保存出口组")'); await saved(page);
  gs = await groups(); c = gs[ghttp.id].config;
  check('清空 tunnel_key 后保存:换了新密钥,证书不变', c.tunnel_key.length === 64 && c.tunnel_key !== ghttp.config.tunnel_key && c.cert_pin === ghttp.config.cert_pin);
  // 11. 被链式出口使用的出口组删不掉
  await page.click('tr:has-text("香港出口") >> text=删除');
  await page.waitForSelector('.toast.err');
  check('删除被链式出口使用的出口组时给出原因', (await page.textContent('.toast.err')).includes('三跳测试') && (await groups())[gout.id] !== undefined);
  await page.context().close();
  await browser.close();
  check('整个过程没有脚本错误或 Vue 警告', errors.length === 0, errors.join('\n'));
  console.log(`\n全部通过: ${passed} 项检查`);
} catch (e) { console.error('\n失败:', String(e.stack || e).slice(0, 1800)); code = 1; }
for (const p of procs) p.kill();
fs.rmSync(W, { recursive: true, force: true });
process.exit(code);
