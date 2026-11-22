import { test, expect } from './fixtures';
import {
  readSwState,
  waitForController,
  waitForRegistrationCount,
  waitFor,
  forceUpdate,
  fetchIncidents,
  cdpForceUpdate,
} from './helpers';

/**
 * 核心对抗链（真实应急的两阶段部署）：
 *  阶段0  infected  —— 访客注册到被篡改的恶意 SW，被投毒、管理 API 被改写
 *  阶段1  remediating（kill-first）—— 浏览器内部更新通道下发 kill SW：
 *          夺权 → 精准删除恶意缓存（app-v 受保护）→ 自注销
 *  阶段2  clean（二次部署）—— reconcile 按清单重新注册合法 SW，离线功能恢复
 */
test.describe('完整感染-清除链', () => {
  test('恶意 SW 驻留后，kill SW 经不可拦截的更新通道完成清除且不破坏离线缓存', async ({
    modeServer,
    persistentContext,
  }) => {
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());

    // ---- 阶段 -1：先建立干净基线（真实受害者本来就有合法 SW 与离线缓存）----
    await modeServer.restart('clean');
    await page.goto(`${modeServer.baseUrl}/?swguard-no-reload`);
    await waitForController(page, (url) => url?.endsWith('/sw.js') ?? false);
    await waitFor(
      () => readSwState(page),
      (s) => s.caches.some((n) => n.startsWith('app-v')),
      10_000,
      'legit offline cache established',
    );

    // ---- 阶段 0：感染窗口期，访客在 /infected 注册到被篡改的 SW ----
    await modeServer.restart('infected');
    await page.goto(`${modeServer.baseUrl}/infected`);
    await page.click('#btn-infect');
    // 必须等到 activated（而非仅 controller 变化）：installing 阶段的 SW 还不能拦截导航
    await waitFor(
      () => readSwState(page),
      (s) => s.registrations[0]?.state === 'activated' && (s.controller ?? '').endsWith('/sw.js'),
      10_000,
      'evil sw activated',
    );

    // ---- 恶意 SW 持续投毒：导航响应被改写，DOM 里出现攻击载荷标签 ----
    await page.goto(`${modeServer.baseUrl}/?swguard-no-reload`);
    // 确认当前激活的确实是恶意字节，而不是被更新节流回退的合法 SW
    const activeWorker = persistentContext.serviceWorkers()[0];
    if (activeWorker) {
      await waitFor(
        () => activeWorker.evaluate(() => Boolean((globalThis as Record<string, unknown>).__SWGUARD_EVIL__)),
        (v) => v === true,
        8000,
        'evil bytes active',
      );
    }
    await waitFor(
      () => readSwState(page),
      (s) => s.hasInjectedPayload && s.caches.includes('evil-cache-v1'),
      10_000,
      'evil injection + evil cache',
    );
    // 记录合法离线缓存（供 kill 后比对「未被误伤」）
    const offlineBeforeKill = await page.evaluate(async () => Boolean(await caches.match('/offline.html')));
    expect(offlineBeforeKill).toBe(true);

    // 模拟恶意页面投毒：改写页面侧 SW 管理 API，让页面的清除代码「看不见」注册
    await page.evaluate(() => {
      const orig = navigator.serviceWorker.getRegistrations.bind(navigator.serviceWorker);
      navigator.serviceWorker.getRegistrations = () =>
        orig().then((list) => list.filter((r) => !/evil|sw\.js/.test(r.active?.scriptURL ?? '')));
    });
    const hidden = await page.evaluate(() => navigator.serviceWorker.getRegistrations());
    expect(hidden).toHaveLength(0); // 页面侧视图已被污染

    // ---- 阶段 1：应急 kill-first 部署 ----
    await modeServer.restart('remediating');

    // 浏览器可能在导航时自行完成更新检查，也可能需要显式触发，两条路都覆盖。
    // 关键点：更新请求走浏览器内部网络栈，页面 API 被投毒也拦不住它的响应。
    await page.goto(`${modeServer.baseUrl}/?swguard-no-reload`).catch(() => undefined);
    await forceUpdate(page).catch(() => undefined);
    // CDP 是浏览器调试级信道，不经过被污染的页面 JS
    await cdpForceUpdate(persistentContext, page, `${modeServer.baseUrl}/`);

    // kill SW 激活并自注销 → 注册数归零（可能在导航时已完成，也可能在 update 后完成）
    await waitForRegistrationCount(page, 0, 25_000);

    // 恶意缓存已被 kill SW 精准删除
    await waitFor(
      () => readSwState(page),
      (s) => !s.caches.includes('evil-cache-v1'),
      10_000,
      'evil cache purged',
    );

    // 受保护的合法离线缓存仍在（离线功能不受影响的关键证据）
    const offlinePreserved = await page.evaluate(async () => Boolean(await caches.match('/offline.html')));
    expect(offlinePreserved).toBe(true);

    // 服务端事件流：kill-first 窗口对已知脚本也下发了 kill，且页面上报过 kill 信号
    const incidentsDuringKill = await fetchIncidents(modeServer.baseUrl);
    expect(incidentsDuringKill.incidents.some((i: any) => i.kind === 'remediation-kill')).toBe(true);
    expect(
      (incidentsDuringKill.beaconReports ?? []).some((r: any) => r.reason === 'kill-signal'),
    ).toBe(true);

    // ---- 阶段 2：二次部署切回 clean，reconcile 重新注册合法 SW ----
    await modeServer.restart('clean');
    await page.goto(`${modeServer.baseUrl}/?swguard-no-reload`);
    await waitForRegistrationCount(page, 1, 20_000);
    await waitForController(page, (url) => url?.endsWith('/sw.js') ?? false, 20_000);

    // 投毒消失：新控制器不再改写导航，DOM 中不再有攻击载荷标签
    await waitFor(
      () => readSwState(page),
      (s) => s.hasInjectedPayload === false,
      10_000,
      'injection payload gone',
    );

    // 合法离线缓存仍可命中
    const offlineFinal = await page.evaluate(async () => Boolean(await caches.match('/offline.html')));
    expect(offlineFinal).toBe(true);

    // 全链路事件取证
    const incidents = await fetchIncidents(modeServer.baseUrl);
    const swScriptRequests = incidents.scriptRequests as Array<{ url: string; known: boolean }>;
    expect(swScriptRequests.some((r) => r.url === '/sw.js')).toBe(true);
  });

  test('清单外的隐藏 SW 脚本请求会被服务端识别并直接下发 kill SW', async ({
    modeServer,
    persistentContext,
  }) => {
    await modeServer.restart('clean');
    const page = persistentContext.pages()[0] ?? (await persistentContext.newPage());
    // no-reload 避免 reconcile 的任何自动刷新打断 evaluate
    await page.goto(`${modeServer.baseUrl}/?swguard-no-reload`);
    await waitForRegistrationCount(page, 1);
    const before = (await readSwState(page)).registrations.length;

    // 攻击者在 /uploads/ 下放了一个 SW 并注册（scope /uploads/）。
    // 该 URL 不在清单内，服务端对浏览器内部 SW 请求直接返回 kill SW。
    // kill SW 会立即自注销，因此不增加长期注册数。
    await page.evaluate(
      (baseUrl) => navigator.serviceWorker.register(`${baseUrl}/uploads/backdoor.js`).catch((e) => ({ error: e.message })),
      modeServer.baseUrl,
    );

    // 等服务端收到这条清单外 SW 脚本请求
    await waitFor(
      () => fetchIncidents(modeServer.baseUrl),
      (data: any) =>
        (data.scriptRequests ?? []).some((r: any) => r.url === '/uploads/backdoor.js' && r.known === false),
      15_000,
      'unknown SW request logged',
    );

    // kill SW 自注销后，注册数回到基线（只剩合法的 /sw.js）
    await waitFor(
      () => readSwState(page),
      (s) => s.registrations.length === before,
      15_000,
      'backdoor self-unregistered',
    );

    const incidents = await fetchIncidents(modeServer.baseUrl);
    expect(incidents.incidents.some((i: any) => i.kind === 'unknown-script-request')).toBe(true);
  });
});
