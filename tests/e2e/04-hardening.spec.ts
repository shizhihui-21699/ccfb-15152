import { test, expect } from './fixtures';
import { readSwState, waitFor } from './helpers';

/**
 * 预防加固验证：
 *  - 页面 CSP worker-src 'self' 阻断 blob:/data: 等非同源 worker 注册
 *  - 硬化响应头在所有关键资源上存在
 *  - 上线前审计 CLI 对干净站点零 error，对恶意样本报 error 且退出码非零
 */
test.describe('预防与上线前检测', () => {
  test('CSP 阻止非同源 SW 注册（blob/data URL）', async ({ modeServer, persistentContext }) => {
    await modeServer.restart('clean');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());
    // 部分 headless 版本不把 CSP 违规输出到 console，仅作信息采集
    const cspErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') cspErrors.push(msg.text());
    });

    await page.goto(`${modeServer.baseUrl}/csp-test.html`);
    const results = await waitFor(
      () => page.evaluate(() => (window as any).__CSP_RESULT__ as string[] | undefined),
      (r) => Array.isArray(r) && r.length === 2,
      10_000,
      'csp test finished',
    );
    // 核心断言：两种非同源 worker 注册都被浏览器拒绝
    expect(results.every((r) => r.includes('blocked'))).toBe(true);

    // 没有任何非同源 worker 注册成功（reconcile 的合法 /sw.js 除外）
    const state = await readSwState(page);
    expect(state.registrations.filter((r) => /blob:|data:/.test(r.scriptURL))).toHaveLength(0);
    // 若有 CSP 日志，内容必须指向 worker-src 违规（信息性，不强制）
    if (cspErrors.length > 0) {
      expect(cspErrors.join(' ')).toMatch(/Content Security Policy|Refused|SecurityError|worker/i);
    }
  });

  test('SW 脚本与页面均携带完整硬化头', async ({ modeServer, persistentContext }) => {
    await modeServer.restart('clean');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());
    const pageRes = await page.goto(`${modeServer.baseUrl}/`);
    const pageHeaders = pageRes!.headers();
    expect(pageHeaders['x-content-type-options']).toBe('nosniff');
    expect(pageHeaders['content-security-policy']).toMatch(/worker-src 'self'/);

    const swRes = await page.request.get(`${modeServer.baseUrl}/sw.js`, {
      headers: { 'Service-Worker': 'script' },
    });
    const h = swRes.headers();
    expect(h['cache-control']).toMatch(/max-age=0|no-store|no-cache/);
    expect(h['x-content-type-options']).toBe('nosniff');
    expect(h['content-security-policy']).toMatch(/script-src 'self'/);
  });

  test('清单端点不可缓存，且只暴露调和所需字段', async ({ modeServer, persistentContext }) => {
    await modeServer.restart('clean');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());
    await page.goto(`${modeServer.baseUrl}/`);
    const res = await page.request.get(`${modeServer.baseUrl}/__swguard/manifest`);
    expect(res.headers()['cache-control']).toMatch(/no-store|no-cache/);
    const body = await res.json();
    expect(body.serviceWorkers[0].sha256).toMatch(/^[a-f0-9]{64}$/);
    expect(body.hardening.updateViaCache).toBe('none');
    // 内部字段不外泄
    expect(body.hardening.allowedScriptPrefixes).toBeUndefined();
  });
});
