/**
 * 页面侧 SW 调和库（reconcile）—— 构建后产物为 /reconcile.js，被每个页面引用。
 *
 * 威胁模型前提：页面当前可能正被一个恶意 SW 控制，页面里的部分 Web API 可能已被
 * 投毒页面改写。因此本库遵守三条铁律：
 *  1. 信任根只在服务端清单（/__swguard/manifest），任何 SW 的 postMessage 自报版本都不可信；
 *  2. 「替换恶意 SW 脚本字节」这件事不依赖页面 API —— 浏览器内部的 SW 更新请求
 *     无法被页面/恶意 SW 拦截，服务端下发 kill SW 即可完成夺权（见 kill.js.template）；
 *  3. 本库负责的是：强制触发更新检查、处理 kill 信号、清理页面侧存储、按清单重新注册、
 *     发现并上报异常注册。凡是能被多 scope 绕过的动作，都配合服务端日志交叉验证。
 */

interface ManifestSW {
  scriptUrl: string;
  scope: string;
  version: string;
  sha256: string;
  cachePrefixes: string[];
}

interface Manifest {
  serviceWorkers: ManifestSW[];
  hardening: {
    updateViaCache: 'none' | 'imports' | 'all';
    pageCsp: string;
  };
  kill: {
    purgeStorageKeys: string[];
  };
  beacon: {
    endpoint: string;
    manifestEndpoint: string;
  };
}

interface RegistrationReport {
  scope: string;
  scriptURL: string;
  state: string;
  controllerScriptURL?: string | null;
  cacheNames?: string[];
  reason: 'startup' | 'mismatch' | 'kill-signal' | 'unknown-controller' | 'periodic';
  at: string;
}

type LogFn = (msg: string) => void;

export interface ReconcileOptions {
  /** 清单地址，默认 /__swguard/manifest */
  manifestUrl?: string;
  /** 调试日志出口 */
  log?: LogFn;
  /** 是否在收到 kill 信号后自动 reload（生产环境应为 true） */
  autoReload?: boolean;
}

export class Reconciler {
  private manifest: Manifest | null = null;
  private readonly log: LogFn;
  private readonly autoReload: boolean;
  private readonly manifestUrl: string;
  private killed = false;

  constructor(opts: ReconcileOptions = {}) {
    this.log = opts.log ?? ((m) => console.info('[swguard]', m));
    // 测试页面可用 ?swguard-no-reload 关闭自动刷新，避免与自动化步骤竞争
    this.autoReload =
      opts.autoReload ??
      (typeof location === 'undefined' || !new URLSearchParams(location.search).has('swguard-no-reload'));
    this.manifestUrl = opts.manifestUrl ?? '/__swguard/manifest';
  }

  /** 入口：每次页面加载时执行一次 */
  async run(): Promise<void> {
    this.manifest = await this.fetchManifest();
    this.listenKillSignal();
    await this.reconcile();
  }

  /** 拉取清单。清单走普通 fetch —— 恶意 SW 可能伪造它，所以服务端响应带不可缓存头，
   *  且页面侧只用清单做「应该注册什么」的参照；真正的字节替换仍由浏览器更新通道保证。 */
  private async fetchManifest(): Promise<Manifest> {
    const res = await fetch(this.manifestUrl, {
      cache: 'no-store',
      headers: { accept: 'application/json' },
    });
    if (!res.ok) throw new Error(`清单拉取失败: ${res.status}`);
    return (await res.json()) as Manifest;
  }

  /** 监听 kill SW 夺权后广播的信号。该信号来自 SW 上下文 postMessage，
   *  配合服务端状态共同判断，不单独作为信任依据。 */
  private listenKillSignal(): void {
    navigator.serviceWorker.addEventListener('message', (event) => {
      const data = event.data as { type?: string; deletedCaches?: string[]; purgeStorageKeys?: string[] } | null;
      if (data?.type !== 'swguard:killed') return;
      this.killed = true;
      this.log(`收到 kill 信号，已删缓存: ${(data.deletedCaches ?? []).join(', ') || '无'}`);
      this.purgePageStorage(data.purgeStorageKeys ?? this.manifest?.kill.purgeStorageKeys ?? []);
      this.report({
        scope: this.manifest?.serviceWorkers[0]?.scope ?? '/',
        scriptURL: '(kill-sw)',
        state: 'killed',
        reason: 'kill-signal',
      });
      if (this.autoReload) {
        // reload 后控制器为空，reconcile() 会把清单中的合法 SW 装回去
        setTimeout(() => location.reload(), 300);
      }
    });
  }

  /** 核心调和逻辑 */
  private async reconcile(): Promise<void> {
    if (!('serviceWorker' in navigator)) return;
    const manifest = this.manifest;
    if (!manifest) return;

    const registrations = await this.safeGetRegistrations();
    const expected = new Map(manifest.serviceWorkers.map((sw) => [sw.scope, sw]));
    const cacheNames = await this.safeCacheNames();

    // 1) 上报现状（startup 全量 beacon），服务端据此发现未知 scope / 未知脚本
    for (const reg of registrations) {
      const sw = this.registrationWorker(reg);
      await this.report({
        scope: reg.scope,
        scriptURL: sw?.scriptURL ?? '',
        state: sw?.state ?? 'unknown',
        controllerScriptURL: navigator.serviceWorker.controller?.scriptURL ?? null,
        cacheNames,
        reason: 'startup',
      });
    }

    // 2) 处置清单外注册：页面侧尽力注销，同时强制触发更新让服务端 kill SW 接管。
    //    注意：恶意页面可能改写 getRegistrations 隐藏自己，所以这里的「没发现」
    //    绝不等于「不存在」——服务端日志里的 Service-Worker: script 请求才是完整视图。
    for (const reg of registrations) {
      const sw = this.registrationWorker(reg);
      const scriptPath = sw ? safePathname(sw.scriptURL) : '';
      const known = manifest.serviceWorkers.some((entry) => entry.scriptUrl === scriptPath);
      if (!known) {
        this.log(`发现清单外 SW 注册: ${scriptPath}（scope=${reg.scope}），尝试注销并强制更新`);
        await this.killRegistration(reg);
        await this.report({
          scope: reg.scope,
          scriptURL: scriptPath,
          state: sw?.state ?? 'unknown',
          reason: 'unknown-controller',
        });
      }
    }

    // 3) 控制器异常（没有控制器 / 控制器不是清单内脚本）：触发更新检查。
    //    update() 会发起浏览器内部更新请求，恶意 SW 无法拦截该响应。
    const controller = navigator.serviceWorker.controller;
    if (controller) {
      const controllerPath = safePathname(controller.scriptURL);
      const knownController = manifest.serviceWorkers.some((e) => e.scriptUrl === controllerPath);
      if (!knownController) {
        this.log(`当前控制器 ${controllerPath} 不在清单内，强制 update()`);
        await this.forceUpdateAll(registrations);
      }
    }

    // 4) 确保清单里的合法 SW 都已按规范注册（updateViaCache: 'none'）
    for (const expectedSW of manifest.serviceWorkers) {
      const existing = registrations.find((r) => r.scope === expectedSW.scope);
      if (!existing) {
        this.log(`注册合法 SW: ${expectedSW.scriptUrl}（scope=${expectedSW.scope}）`);
        await navigator.serviceWorker.register(expectedSW.scriptUrl, {
          scope: expectedSW.scope,
          updateViaCache: manifest.hardening.updateViaCache,
        });
      } else {
        // 即使已注册也强制一次更新检查，缩短字节被替换后的收敛时间
        await existing.update().catch((err) => this.log(`update 被阻止（将由浏览器周期更新兜底）: ${String(err)}`));
      }
    }

    // 5) 控制器版本核验：ping 当前控制器，自报版本与清单不一致即视为可疑。
    //    恶意 SW 会伪造 pong，所以这一步只是快速信号，最终以更新通道 + 服务端日志为准。
    await this.verifyControllerVersion();
  }

  private async verifyControllerVersion(): Promise<void> {
    const controller = navigator.serviceWorker.controller;
    if (!controller || !this.manifest) return;
    const expected = this.manifest.serviceWorkers[0];
    if (!expected) return;
    try {
      const reply = (await this.postMessageWithTimeout(
        { type: 'swguard:ping' },
        4000,
      )) as { type?: string; version?: string } | null;
      // kill SW 自报 kill-active；恶意 SW 可能伪造 pong+假版本
      if (reply?.type === 'swguard:kill-active') {
        this.log('控制器自报为 kill SW，等待重新注册流程');
        return;
      }
      if (reply?.type === 'swguard:pong' && reply.version !== expected.version) {
        this.log(`控制器版本 ${reply.version} 与清单 ${expected.version} 不符，上报并强制更新`);
        await this.report({
          scope: expected.scope,
          scriptURL: safePathname(controller.scriptURL),
          state: controller.state,
          reason: 'mismatch',
        });
        navigator.serviceWorker.getRegistration(expected.scope)
          .then((reg) => reg?.update())
          .catch(() => undefined);
      }
    } catch {
      this.log('控制器 ping 超时/无应答（合法 SW 必有应答），上报异常');
      await this.report({
        scope: expected.scope,
        scriptURL: safePathname(controller.scriptURL),
        state: controller.state,
        reason: 'mismatch',
      });
    }
  }

  /** 对一个恶意注册执行「页面侧能做的全部动作」。
   *  unregister 可能被投毒 API 干扰，所以同时调用 update() ——
   *  即使注销被拦，服务端也会在更新通道下发 kill SW 完成夺权。 */
  private async killRegistration(reg: ServiceWorkerRegistration): Promise<void> {
    try {
      const ok = await reg.unregister();
      this.log(`unregister 结果: ${ok}`);
    } catch (err) {
      this.log(`unregister 失败/被拦截: ${String(err)}`);
    }
    try {
      await reg.update();
    } catch (err) {
      this.log(`update 失败: ${String(err)}`);
    }
  }

  private async forceUpdateAll(registrations: ServiceWorkerRegistration[]): Promise<void> {
    await Promise.all(
      registrations.map((reg) => reg.update().catch((err) => this.log(`update 异常: ${String(err)}`))),
    );
  }

  /** 清理页面侧存储（localStorage 等）。CacheStorage 的恶意缓存由 kill SW 在 activate 中删除，
   *  这里只处理 SW 无权按 key 清理的同源存储。 */
  private purgePageStorage(keys: string[]): void {
    for (const key of keys) {
      try {
        localStorage.removeItem(key);
      } catch {
        /* 存储不可用时忽略 */
      }
    }
  }

  private async safeGetRegistrations(): Promise<ServiceWorkerRegistration[]> {
    try {
      return [...(await navigator.serviceWorker.getRegistrations())];
    } catch (err) {
      this.log(`getRegistrations 被拦截或失败: ${String(err)} —— 以服务端日志为准`);
      return [];
    }
  }

  private async safeCacheNames(): Promise<string[]> {
    try {
      return await caches.keys();
    } catch {
      return [];
    }
  }

  private registrationWorker(reg: ServiceWorkerRegistration): ServiceWorker | null {
    return reg.active ?? reg.waiting ?? reg.installing ?? null;
  }

  private postMessageWithTimeout(message: unknown, timeoutMs: number): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        navigator.serviceWorker.removeEventListener('message', onMessage);
        reject(new Error('timeout'));
      }, timeoutMs);
      const onMessage = (event: MessageEvent) => {
        clearTimeout(timer);
        navigator.serviceWorker.removeEventListener('message', onMessage);
        resolve(event.data);
      };
      navigator.serviceWorker.addEventListener('message', onMessage);
      navigator.serviceWorker.controller?.postMessage(message);
    });
  }

  /** 上报到服务端 beacon 端点。服务端对全部字段做不可信处理并与访问日志交叉验证。
   *  带退避重试：SW 首次注册时 skipWaiting+claim 夺权可能中断在途请求。 */
  private async report(partial: Omit<RegistrationReport, 'at'>): Promise<void> {
    if (!this.manifest) return;
    const payload: RegistrationReport = { ...partial, at: new Date().toISOString() };
    const maxAttempts = 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const res = await fetch(this.manifest.beacon.endpoint, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(payload),
          keepalive: true,
          credentials: 'same-origin',
        });
        if (res.ok) return;
        this.log(`beacon 上报返回 ${res.status}，第 ${attempt} 次尝试`);
      } catch (err) {
        this.log(`beacon 上报失败（第 ${attempt} 次）: ${String(err)}`);
      }
      if (attempt < maxAttempts) {
        await new Promise((r) => setTimeout(r, 400 * attempt));
      }
    }
  }
}

function safePathname(url: string): string {
  try {
    return new URL(url, self.location.origin).pathname;
  } catch {
    return url;
  }
}

// 浏览器环境自动启动（测试中也可以手动 new Reconciler()）
declare global {
  interface Window {
    __SWGUARD__?: Reconciler;
  }
}
if (typeof window !== 'undefined' && !window.__SWGUARD__) {
  const reconciler = new Reconciler();
  window.__SWGUARD__ = reconciler;
  // 延迟到 DOM 就绪，避免与业务脚本竞争
  if (document.readyState === 'loading') {
    window.addEventListener('DOMContentLoaded', () => void reconciler.run());
  } else {
    void reconciler.run();
  }
}
