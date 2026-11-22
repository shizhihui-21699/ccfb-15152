import { chromium } from '@playwright/test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { spawn, type ChildProcess } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const tsx = resolve(root, 'node_modules/.bin/tsx');
const entry = resolve(root, 'src/server/main.ts');
const port = 7799;

function start(mode: string, dir: string): ChildProcess {
  const child = spawn(tsx, [entry], {
    cwd: root,
    env: { ...process.env, SWGUARD_MODE: mode, SWGUARD_PORT: String(port), SWGUARD_DATA_DIR: dir },
    stdio: 'inherit',
  });
  return child;
}
async function waitUp() {
  for (let i = 0; i < 60; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/__swguard/health`);
      if (r.ok) return;
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('server start timeout');
}

const profile = await mkdtemp(resolve(tmpdir(), 'swfull-'));
const browser = await chromium.launchPersistentContext(profile, { headless: true, serviceWorkers: 'allow' });
const page = browser.pages()[0] ?? (await browser.newPage());
page.on('console', (m) => console.log('[console]', m.type(), m.text()));
page.on('pageerror', (e) => console.log('[pageerror]', e.message));

async function state(label: string) {
  const s = await page.evaluate(async () => ({
    controller: navigator.serviceWorker.controller?.scriptURL ?? null,
    regs: (await navigator.serviceWorker.getRegistrations()).map((r) => ({
      scope: r.scope,
      active: r.active?.scriptURL ?? null,
      state: r.active?.state ?? null,
    })),
    caches: await caches.keys(),
    evil: (window as any).__EVIL_SW_WAS_HERE__ === true,
  }));
  console.log(`\n=== ${label} ===`);
  console.log(JSON.stringify(s, null, 2));
}

// 1) infected
let srv = start('infected', '/tmp/swfull/infected');
await waitUp();
await page.goto(`http://127.0.0.1:${port}/infected`);
await page.click('#btn-infect');
await page.waitForTimeout(2500);
await state('感染后');

// 2) remediating（kill-first 两阶段应急）
srv.kill('SIGTERM');
await new Promise((r) => srv.once('exit', r));
srv = start('remediating', '/tmp/swfull/remediating');
await waitUp();

await page.goto(`http://127.0.0.1:${port}/?swguard-no-reload`);
await page.waitForTimeout(1500);
await state('修复后首次导航（恶意SW仍驻留）');

// 3) force update via CDP
const cdp = await browser.newCDPSession(page);
await cdp.send('ServiceWorker.enable');
const upd = await cdp.send('ServiceWorker.updateRegistration', { scopeURL: `http://127.0.0.1:${port}/` });
console.log('CDP update result:', upd);

// 分多个时间点观察 kill SW 激活与自注销
for (let i = 1; i <= 8; i++) {
  await page.waitForTimeout(1000);
  const s = await page.evaluate(async () => ({
    controller: navigator.serviceWorker.controller?.scriptURL ?? null,
    regs: (await navigator.serviceWorker.getRegistrations()).length,
    caches: await caches.keys(),
  }));
  console.log(`kill后 t+${i}s`, JSON.stringify(s));
  console.log('  workers:', browser.serviceWorkers().map((w) => w.url()));
}
await state('强制更新后（期待 kill SW 已自注销、evil 缓存被删）');

// 4) 二次部署 clean
srv.kill('SIGTERM');
await new Promise((r) => srv.once('exit', r));
srv = start('clean', '/tmp/swfull/clean');
await waitUp();
await page.goto(`http://127.0.0.1:${port}/?swguard-no-reload`);
await page.waitForTimeout(5000);
await state('clean 二次部署后（期待合法 SW 恢复）');

const inc = await (await fetch(`http://127.0.0.1:${port}/__swguard/incidents`)).json();
console.log('\n=== 服务端事件 ===');
console.log(JSON.stringify({ scriptRequests: inc.scriptRequests, incidents: inc.incidents, beaconCount: inc.beaconReports.length }, null, 2));

srv.kill('SIGTERM');
await browser.close();
await rm(profile, { recursive: true, force: true });
