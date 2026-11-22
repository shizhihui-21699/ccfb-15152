import type { BrowserContext, Page } from '@playwright/test';

/** 轮询等待断言成立（SW 生命周期事件时序不确定，避免硬编码 sleep） */
export async function waitFor<T>(fn: () => Promise<T>, check: (v: T) => boolean, timeoutMs = 15_000, label = 'condition'): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  let last: T;
  while (Date.now() < deadline) {
    last = await fn();
    if (check(last)) return last;
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error(`等待超时: ${label}（最后值=${JSON.stringify(last)}）`);
}

export interface SwState {
  registrations: Array<{ scope: string; scriptURL: string; state: string }>;
  controller: string | null;
  caches: string[];
  evilMarker: boolean;
  hasInjectedPayload: boolean;
}

/** 在页面内读取 SW / 缓存 / 污染标记的完整状态 */
export async function readSwState(page: Page): Promise<SwState> {
  return page.evaluate(async () => {
    const regs = await navigator.serviceWorker.getRegistrations();
    const cachesList = await caches.keys();
    return {
      registrations: regs.map((r) => ({
        scope: r.scope,
        scriptURL: r.active?.scriptURL ?? r.waiting?.scriptURL ?? r.installing?.scriptURL ?? '(none)',
        state: r.active?.state ?? r.waiting?.state ?? r.installing?.state ?? 'none',
      })),
      controller: navigator.serviceWorker.controller?.scriptURL ?? null,
      caches: cachesList,
      evilMarker: (window as unknown as { __EVIL_SW_WAS_HERE__?: boolean }).__EVIL_SW_WAS_HERE__ === true,
      // 恶意 SW 注入的同源载荷脚本标签（比 window 标记更可靠，导航后仍在 DOM 里）
      hasInjectedPayload: Boolean(document.querySelector('script[data-attacker="1"]')),
    };
  });
}

/** 触发所有注册的更新检查（浏览器内部 fetch，恶意 SW 无法拦截其响应） */
export async function forceUpdate(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const regs = await navigator.serviceWorker.getRegistrations();
    await Promise.all(regs.map((r) => r.update()));
  });
}

export async function unregisterAll(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const regs = await navigator.serviceWorker.getRegistrations();
    await Promise.all(regs.map((r) => r.unregister()));
  });
}

/** 等待控制器脚本 URL 满足条件 */
export async function waitForController(page: Page, predicate: (url: string | null) => boolean, timeoutMs = 15_000): Promise<void> {
  await waitFor(
    () => page.evaluate(() => navigator.serviceWorker.controller?.scriptURL ?? null),
    predicate,
    timeoutMs,
    'controller scriptURL',
  );
}

/** 通过 CDP 强制更新指定 scope 的注册（页面 API 被投毒时的兜底信道） */
export async function cdpForceUpdate(context: BrowserContext, page: Page, scopeURL: string): Promise<void> {
  const session = await context.newCDPSession(page);
  await session.send('ServiceWorker.enable');
  await session.send('ServiceWorker.updateRegistration', { scopeURL }).catch(() => undefined);
}

/** 等待注册数量满足条件 */
export async function waitForRegistrationCount(page: Page, expected: number, timeoutMs = 15_000): Promise<void> {
  await waitFor(
    () => page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length),
    (n) => n === expected,
    timeoutMs,
    `registration count === ${expected}`,
  );
}

export async function fetchIncidents(baseUrl: string): Promise<any> {
  const res = await fetch(`${baseUrl}/__swguard/incidents`);
  return res.json();
}

/** 确认 context 里 SW 进程已被 Playwright 观测到（用于确保注册真正落盘） */
export async function waitForServiceWorker(context: BrowserContext, urlIncludes: string): Promise<void> {
  await waitFor(
    async () => {
      const workers = context.serviceWorkers();
      return workers.some((w) => w.url().includes(urlIncludes));
    },
    (v) => v === true,
    10_000,
    `service worker url includes ${urlIncludes}`,
  );
}
