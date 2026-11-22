/*
 * 合法的业务 Service Worker（app-v3）。
 * 职责：离线 App Shell 与静态资源缓存。
 * 安全约束：
 *  - 只使用清单登记的缓存名前缀 app-v（清除方案据此区分「正常离线数据」与「恶意缓存」）
 *  - 不使用 importScripts 拉取任何跨源脚本
 *  - fetch 只处理同源 GET，其余直接放行
 */
'use strict';

const VERSION = 'app-v3';
const CACHE = `${VERSION}-shell`; // 名称带 app-v 前缀，属于受保护的合法缓存
const OFFLINE_URLS = ['/offline.html', '/styles.css'];
/**
 * 已知攻击缓存前缀（与 config/sw-manifest.json 的 kill.purgeCachePrefixes 保持一致）。
 * 纵深防御：即便攻击者缓存绕过了 kill SW 阶段，合法 SW 激活时也会兜底清除。
 */
const QUARANTINE_PREFIXES = ['evil-', 'attacker-', 'malware-'];
const QUARANTINE_EXACT = ['evil-cache-v1'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      await cache.addAll(OFFLINE_URLS);
      // 新版本立即接管，缩短「等待中」窗口（恶意版本常卡在 waiting 阻碍替换）
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(
        names
          .filter((name) => {
            // 只清理自己旧版本的缓存 + 已知攻击缓存，绝不动其它前缀
            const ownOld = name.startsWith('app-v') && name !== CACHE;
            const quarantined =
              QUARANTINE_EXACT.includes(name) ||
              QUARANTINE_PREFIXES.some((p) => name.startsWith(p));
            return ownOld || quarantined;
          })
          .map((name) => caches.delete(name)),
      );
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== self.location.origin) return;

  if (req.mode === 'navigate') {
    // 导航请求：网络优先，失败时回退离线页
    event.respondWith(
      fetch(req).catch(() =>
        caches.match('/offline.html').then((res) => res || Response.error()),
      ),
    );
    return;
  }

  // 静态资源：缓存优先，后台刷新
  event.respondWith(
    caches.match(req).then((cached) => {
      const network = fetch(req)
        .then((res) => {
          if (res.ok) {
            const copy = res.clone();
            caches.open(CACHE).then((cache) => cache.put(req, copy));
          }
          return res;
        })
        .catch(() => cached);
      return cached || network;
    }),
  );
});

// 供页面侧 reconcile 做存活/版本探测（kill SW 不会响应这个协议）
self.addEventListener('message', (event) => {
  if (event.data?.type === 'swguard:ping') {
    event.source?.postMessage({
      type: 'swguard:pong',
      version: VERSION,
      cache: CACHE,
    });
  }
});
