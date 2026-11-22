import { test, expect } from './fixtures';
import { readSwState, waitFor, fetchIncidents, forceUpdate } from './helpers';

/**
 * 发现与取证：
 *  - 浏览器内部 SW 请求带 Service-Worker: script 头，服务端据此建立完整脚本清单
 *  - 页面 beacon 上报注册现状，与服务端日志交叉验证
 *  - 恶意 SW 可伪造健康检查响应，但伪造不了浏览器内部更新通道
 */
test.describe('发现与取证', () => {
  test('服务端通过 Service-Worker 请求头识别全部 SW 脚本拉取', async ({ modeServer, persistentContext }) => {
    await modeServer.restart('clean');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());
    await page.goto(`${modeServer.baseUrl}/`);
    await waitFor(
      () => readSwState(page),
      (s) => s.registrations.length === 1,
      10_000,
      'registered',
    );
    await forceUpdate(page);
    await page.waitForTimeout(1000);

    const incidents = await fetchIncidents(modeServer.baseUrl);
    const swRequests = incidents.scriptRequests as Array<{
      url: string;
      serviceWorkerHeader: string | null;
      known: boolean;
    }>;
    expect(swRequests.length).toBeGreaterThan(0);
    for (const req of swRequests) {
      expect(req.serviceWorkerHeader).toBe('script'); // 浏览器内部通道的固定标记
    }
    expect(swRequests.some((r) => r.url === '/sw.js' && r.known)).toBe(true);
  });

  test('页面 beacon 上报注册与缓存现状，服务端记录并复核', async ({ modeServer, persistentContext }) => {
    await modeServer.restart('clean');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());
    await page.goto(`${modeServer.baseUrl}/`);
    // 先等 reconcile 完成注册（startup beacon 在注册枚举之后发出）
    await waitFor(
      () => readSwState(page),
      (s) => s.registrations.length === 1,
      10_000,
      'registered before beacon',
    );
    // 首次注册的 SW 会 skipWaiting+claim 夺权，可能中断夺权前发出的 beacon。
    // 重新加载后控制器稳定，reconcile 重跑并可靠发出 startup beacon。
    await page.reload();
    await waitFor(
      () => fetchIncidents(modeServer.baseUrl),
      (data: any) => (data.beaconReports?.length ?? 0) >= 1,
      15_000,
      'beacon received',
    );

    const incidents = await fetchIncidents(modeServer.baseUrl);
    const reports = incidents.beaconReports as Array<{ reason: string; scriptURL: string; cacheNames: string[] }>;
    const startup = reports.find((r) => r.reason === 'startup');
    expect(startup).toBeDefined();
    expect(startup!.scriptURL).toContain('/sw.js');
  });

  test('恶意 SW 能伪造健康检查，但通过浏览器内部通道获取的源站真相不受影响', async ({
    modeServer,
    persistentContext,
  }) => {
    await modeServer.restart('infected');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());
    await page.goto(`${modeServer.baseUrl}/infected`);
    await page.click('#btn-infect');
    await waitFor(
      () => readSwState(page),
      (s) => s.registrations[0]?.state === 'activated',
      10_000,
      'evil active',
    );
    await page.goto(`${modeServer.baseUrl}/`);
    await page.waitForTimeout(800);

    // 页面内 fetch 被恶意 SW 拦截，返回伪造健康值
    const forged = await page.evaluate(async () => (await fetch('/__swguard/health')).json());
    expect(forged.forged).toBe(true);

    // Playwright 的 request 上下文走真实网络（不经页面 SW），拿到的是源站真实响应
    const real = await page.request.get(`${modeServer.baseUrl}/__swguard/health`);
    const realBody = await real.json();
    expect(realBody.source).toBe('origin');
    expect(realBody.forged).toBeUndefined();
  });
});
