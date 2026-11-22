import { test, expect } from './fixtures';
import { readSwState, waitForController, waitForRegistrationCount, waitFor, forceUpdate } from './helpers';

/**
 * 基线：干净站点 + 合法 SW。
 * 验证正常注册、离线缓存建立、硬化响应头，以及 reconcile 的重新注册能力。
 */
test.describe('干净基线：合法 SW 的正常生命周期', () => {
  test.beforeAll(async () => {
    // fixture 默认 infected，基线用例显式切回 clean
  });

  test('合法 SW 注册、接管并建立离线缓存，响应头满足硬化要求', async ({ modeServer, persistentContext }) => {
    await modeServer.restart('clean');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());

    const response = await page.goto(`${modeServer.baseUrl}/`);
    expect(response?.status()).toBe(200);

    // 页面硬化头：worker-src 'self' 必须存在
    const pageCsp = response?.headers()['content-security-policy'] ?? '';
    expect(pageCsp).toMatch(/worker-src[^;]*'self'/);

    // SW 脚本硬化头
    const swResponse = await page.request.get(`${modeServer.baseUrl}/sw.js`, {
      headers: { 'Service-Worker': 'script' },
    });
    const swHeaders = swResponse.headers();
    expect(swHeaders['content-type']).toContain('javascript');
    expect(swHeaders['x-content-type-options']).toBe('nosniff');
    expect(swHeaders['cache-control']).toMatch(/max-age=0|no-store|no-cache/);
    expect(swHeaders['content-security-policy']).toBeTruthy();

    // reconcile 自动注册合法 SW 并接管
    await waitForController(page, (url) => url?.endsWith('/sw.js') ?? false);
    const state = await readSwState(page);
    expect(state.controller).toContain('/sw.js');
    expect(state.registrations).toHaveLength(1);
    expect(state.evilMarker).toBe(false);

    // 合法离线缓存建立（app-v 前缀）
    await waitFor(
      () => readSwState(page),
      (s) => s.caches.some((n) => n.startsWith('app-v')),
      10_000,
      'app-v cache created',
    );
  });

  test('离线页面缓存可在「断网」语义下命中（离线功能基线）', async ({ modeServer, persistentContext }) => {
    await modeServer.restart('clean');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());
    await page.goto(`${modeServer.baseUrl}/`);
    await waitForController(page, (url) => url?.endsWith('/sw.js') ?? false);

    // 等待离线壳缓存
    await waitFor(
      async () => page.evaluate(async () => (await caches.keys()).some((n) => n.startsWith('app-v'))),
      (v) => v === true,
      10_000,
      'shell cached',
    );
    const offlineHit = await page.evaluate(async () => Boolean(await caches.match('/offline.html')));
    expect(offlineHit).toBe(true);
  });

  test('全部注销后 reconcile 在下一次加载时自动恢复合法注册', async ({ modeServer, persistentContext }) => {
    await modeServer.restart('clean');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());
    await page.goto(`${modeServer.baseUrl}/`);
    await waitForController(page, (url) => url?.endsWith('/sw.js') ?? false);

    await page.evaluate(async () => {
      const regs = await navigator.serviceWorker.getRegistrations();
      await Promise.all(regs.map((r) => r.unregister()));
    });
    await waitForRegistrationCount(page, 0);

    // 重新加载页面，reconcile 发现无注册后自动装回
    await page.reload();
    await waitForRegistrationCount(page, 1);
    await waitForController(page, (url) => url?.endsWith('/sw.js') ?? false);
    await forceUpdate(page);
  });
});
