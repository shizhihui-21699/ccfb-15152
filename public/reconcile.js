"use strict";
(() => {
  // src/client/reconcile.ts
  var Reconciler = class {
    manifest = null;
    log;
    autoReload;
    manifestUrl;
    killed = false;
    constructor(opts = {}) {
      this.log = opts.log ?? ((m) => console.info("[swguard]", m));
      this.autoReload = opts.autoReload ?? (typeof location === "undefined" || !new URLSearchParams(location.search).has("swguard-no-reload"));
      this.manifestUrl = opts.manifestUrl ?? "/__swguard/manifest";
    }
    /** 入口：每次页面加载时执行一次 */
    async run() {
      this.manifest = await this.fetchManifest();
      this.listenKillSignal();
      await this.reconcile();
    }
    /** 拉取清单。清单走普通 fetch —— 恶意 SW 可能伪造它，所以服务端响应带不可缓存头，
     *  且页面侧只用清单做「应该注册什么」的参照；真正的字节替换仍由浏览器更新通道保证。 */
    async fetchManifest() {
      const res = await fetch(this.manifestUrl, {
        cache: "no-store",
        headers: { accept: "application/json" }
      });
      if (!res.ok) throw new Error(`\u6E05\u5355\u62C9\u53D6\u5931\u8D25: ${res.status}`);
      return await res.json();
    }
    /** 监听 kill SW 夺权后广播的信号。该信号来自 SW 上下文 postMessage，
     *  配合服务端状态共同判断，不单独作为信任依据。 */
    listenKillSignal() {
      navigator.serviceWorker.addEventListener("message", (event) => {
        const data = event.data;
        if (data?.type !== "swguard:killed") return;
        this.killed = true;
        this.log(`\u6536\u5230 kill \u4FE1\u53F7\uFF0C\u5DF2\u5220\u7F13\u5B58: ${(data.deletedCaches ?? []).join(", ") || "\u65E0"}`);
        this.purgePageStorage(data.purgeStorageKeys ?? this.manifest?.kill.purgeStorageKeys ?? []);
        this.report({
          scope: this.manifest?.serviceWorkers[0]?.scope ?? "/",
          scriptURL: "(kill-sw)",
          state: "killed",
          reason: "kill-signal"
        });
        if (this.autoReload) {
          setTimeout(() => location.reload(), 300);
        }
      });
    }
    /** 核心调和逻辑 */
    async reconcile() {
      if (!("serviceWorker" in navigator)) return;
      const manifest = this.manifest;
      if (!manifest) return;
      const registrations = await this.safeGetRegistrations();
      const expected = new Map(manifest.serviceWorkers.map((sw) => [sw.scope, sw]));
      const cacheNames = await this.safeCacheNames();
      for (const reg of registrations) {
        const sw = this.registrationWorker(reg);
        await this.report({
          scope: reg.scope,
          scriptURL: sw?.scriptURL ?? "",
          state: sw?.state ?? "unknown",
          controllerScriptURL: navigator.serviceWorker.controller?.scriptURL ?? null,
          cacheNames,
          reason: "startup"
        });
      }
      for (const reg of registrations) {
        const sw = this.registrationWorker(reg);
        const scriptPath = sw ? safePathname(sw.scriptURL) : "";
        const known = manifest.serviceWorkers.some((entry) => entry.scriptUrl === scriptPath);
        if (!known) {
          this.log(`\u53D1\u73B0\u6E05\u5355\u5916 SW \u6CE8\u518C: ${scriptPath}\uFF08scope=${reg.scope}\uFF09\uFF0C\u5C1D\u8BD5\u6CE8\u9500\u5E76\u5F3A\u5236\u66F4\u65B0`);
          await this.killRegistration(reg);
          await this.report({
            scope: reg.scope,
            scriptURL: scriptPath,
            state: sw?.state ?? "unknown",
            reason: "unknown-controller"
          });
        }
      }
      const controller = navigator.serviceWorker.controller;
      if (controller) {
        const controllerPath = safePathname(controller.scriptURL);
        const knownController = manifest.serviceWorkers.some((e) => e.scriptUrl === controllerPath);
        if (!knownController) {
          this.log(`\u5F53\u524D\u63A7\u5236\u5668 ${controllerPath} \u4E0D\u5728\u6E05\u5355\u5185\uFF0C\u5F3A\u5236 update()`);
          await this.forceUpdateAll(registrations);
        }
      }
      for (const expectedSW of manifest.serviceWorkers) {
        const existing = registrations.find((r) => r.scope === expectedSW.scope);
        if (!existing) {
          this.log(`\u6CE8\u518C\u5408\u6CD5 SW: ${expectedSW.scriptUrl}\uFF08scope=${expectedSW.scope}\uFF09`);
          await navigator.serviceWorker.register(expectedSW.scriptUrl, {
            scope: expectedSW.scope,
            updateViaCache: manifest.hardening.updateViaCache
          });
        } else {
          await existing.update().catch((err) => this.log(`update \u88AB\u963B\u6B62\uFF08\u5C06\u7531\u6D4F\u89C8\u5668\u5468\u671F\u66F4\u65B0\u515C\u5E95\uFF09: ${String(err)}`));
        }
      }
      await this.verifyControllerVersion();
    }
    async verifyControllerVersion() {
      const controller = navigator.serviceWorker.controller;
      if (!controller || !this.manifest) return;
      const expected = this.manifest.serviceWorkers[0];
      if (!expected) return;
      try {
        const reply = await this.postMessageWithTimeout(
          { type: "swguard:ping" },
          4e3
        );
        if (reply?.type === "swguard:kill-active") {
          this.log("\u63A7\u5236\u5668\u81EA\u62A5\u4E3A kill SW\uFF0C\u7B49\u5F85\u91CD\u65B0\u6CE8\u518C\u6D41\u7A0B");
          return;
        }
        if (reply?.type === "swguard:pong" && reply.version !== expected.version) {
          this.log(`\u63A7\u5236\u5668\u7248\u672C ${reply.version} \u4E0E\u6E05\u5355 ${expected.version} \u4E0D\u7B26\uFF0C\u4E0A\u62A5\u5E76\u5F3A\u5236\u66F4\u65B0`);
          await this.report({
            scope: expected.scope,
            scriptURL: safePathname(controller.scriptURL),
            state: controller.state,
            reason: "mismatch"
          });
          navigator.serviceWorker.getRegistration(expected.scope).then((reg) => reg?.update()).catch(() => void 0);
        }
      } catch {
        this.log("\u63A7\u5236\u5668 ping \u8D85\u65F6/\u65E0\u5E94\u7B54\uFF08\u5408\u6CD5 SW \u5FC5\u6709\u5E94\u7B54\uFF09\uFF0C\u4E0A\u62A5\u5F02\u5E38");
        await this.report({
          scope: expected.scope,
          scriptURL: safePathname(controller.scriptURL),
          state: controller.state,
          reason: "mismatch"
        });
      }
    }
    /** 对一个恶意注册执行「页面侧能做的全部动作」。
     *  unregister 可能被投毒 API 干扰，所以同时调用 update() ——
     *  即使注销被拦，服务端也会在更新通道下发 kill SW 完成夺权。 */
    async killRegistration(reg) {
      try {
        const ok = await reg.unregister();
        this.log(`unregister \u7ED3\u679C: ${ok}`);
      } catch (err) {
        this.log(`unregister \u5931\u8D25/\u88AB\u62E6\u622A: ${String(err)}`);
      }
      try {
        await reg.update();
      } catch (err) {
        this.log(`update \u5931\u8D25: ${String(err)}`);
      }
    }
    async forceUpdateAll(registrations) {
      await Promise.all(
        registrations.map((reg) => reg.update().catch((err) => this.log(`update \u5F02\u5E38: ${String(err)}`)))
      );
    }
    /** 清理页面侧存储（localStorage 等）。CacheStorage 的恶意缓存由 kill SW 在 activate 中删除，
     *  这里只处理 SW 无权按 key 清理的同源存储。 */
    purgePageStorage(keys) {
      for (const key of keys) {
        try {
          localStorage.removeItem(key);
        } catch {
        }
      }
    }
    async safeGetRegistrations() {
      try {
        return [...await navigator.serviceWorker.getRegistrations()];
      } catch (err) {
        this.log(`getRegistrations \u88AB\u62E6\u622A\u6216\u5931\u8D25: ${String(err)} \u2014\u2014 \u4EE5\u670D\u52A1\u7AEF\u65E5\u5FD7\u4E3A\u51C6`);
        return [];
      }
    }
    async safeCacheNames() {
      try {
        return await caches.keys();
      } catch {
        return [];
      }
    }
    registrationWorker(reg) {
      return reg.active ?? reg.waiting ?? reg.installing ?? null;
    }
    postMessageWithTimeout(message, timeoutMs) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          navigator.serviceWorker.removeEventListener("message", onMessage);
          reject(new Error("timeout"));
        }, timeoutMs);
        const onMessage = (event) => {
          clearTimeout(timer);
          navigator.serviceWorker.removeEventListener("message", onMessage);
          resolve(event.data);
        };
        navigator.serviceWorker.addEventListener("message", onMessage);
        navigator.serviceWorker.controller?.postMessage(message);
      });
    }
    /** 上报到服务端 beacon 端点。服务端对全部字段做不可信处理并与访问日志交叉验证。
     *  带退避重试：SW 首次注册时 skipWaiting+claim 夺权可能中断在途请求。 */
    async report(partial) {
      if (!this.manifest) return;
      const payload = { ...partial, at: (/* @__PURE__ */ new Date()).toISOString() };
      const maxAttempts = 3;
      for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
          const res = await fetch(this.manifest.beacon.endpoint, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(payload),
            keepalive: true,
            credentials: "same-origin"
          });
          if (res.ok) return;
          this.log(`beacon \u4E0A\u62A5\u8FD4\u56DE ${res.status}\uFF0C\u7B2C ${attempt} \u6B21\u5C1D\u8BD5`);
        } catch (err) {
          this.log(`beacon \u4E0A\u62A5\u5931\u8D25\uFF08\u7B2C ${attempt} \u6B21\uFF09: ${String(err)}`);
        }
        if (attempt < maxAttempts) {
          await new Promise((r) => setTimeout(r, 400 * attempt));
        }
      }
    }
  };
  function safePathname(url) {
    try {
      return new URL(url, self.location.origin).pathname;
    } catch {
      return url;
    }
  }
  if (typeof window !== "undefined" && !window.__SWGUARD__) {
    const reconciler = new Reconciler();
    window.__SWGUARD__ = reconciler;
    if (document.readyState === "loading") {
      window.addEventListener("DOMContentLoaded", () => void reconciler.run());
    } else {
      void reconciler.run();
    }
  }
})();
//# sourceMappingURL=reconcile.js.map
