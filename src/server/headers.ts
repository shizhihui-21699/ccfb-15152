import type { SiteManifest } from '../core/types.js';

/**
 * 安全响应头集中管理。这些头是「防止将来再被注册恶意 SW」的第一道防线：
 *
 * - Cache-Control: no-store（SW 脚本）：杜绝 HTTP 缓存投毒，保证更新通道拿到源站字节
 * - Content-Security-Policy: worker-src 'self'：页面只能注册同源 worker，
 *   注入的第三方脚本无权注册跨源/eval worker
 * - X-Content-Type-Options: nosniff：防止浏览器把非 JS 响应当成 SW 脚本执行
 * - Clear-Site-Data（仅显式清除端点）：按浏览器支持情况做纵深防御
 */

export function scriptResponseHeaders(manifest: SiteManifest): Record<string, string> {
  return {
    'cache-control': `public, max-age=${manifest.hardening.scriptMaxAgeSeconds}`,
    'content-type': 'application/javascript; charset=utf-8',
    'x-content-type-options': 'nosniff',
    // SW 脚本自身的 CSP（Chrome 支持 worker 脚本 CSP）
    'content-security-policy': manifest.hardening.workerCsp,
    // 禁止被跨源 iframe 嵌入，降低点击劫持 + 注册诱导面
    'x-frame-options': 'DENY',
  };
}

export function pageResponseHeaders(manifest: SiteManifest): Record<string, string> {
  return {
    'content-type': 'text/html; charset=utf-8',
    'x-content-type-options': 'nosniff',
    'content-security-policy': manifest.hardening.pageCsp,
    'x-frame-options': 'DENY',
    'referrer-policy': 'same-origin',
  };
}

export function staticAssetHeaders(manifest: SiteManifest): Record<string, string> {
  return {
    'x-content-type-options': 'nosniff',
    'content-security-policy': manifest.hardening.pageCsp,
  };
}

/** 显式清除端点专用。注意 `"cache"` 会连合法离线缓存一起删，
 *  所以默认只清 executionContexts 和 storage，CacheStorage 的精细清理交给 kill SW。 */
export function clearSiteDataHeaders(includeCache = false): Record<string, string> {
  const directives = ['"executionContexts"', '"storage"'];
  if (includeCache) directives.push('"cache"');
  return {
    'clear-site-data': directives.join(', '),
    'cache-control': 'no-store',
  };
}

export const NO_STORE = 'no-store, no-cache, must-revalidate, proxy-revalidate';
