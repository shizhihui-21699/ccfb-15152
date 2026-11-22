import type { AuditFinding, SiteManifest } from '../core/types.js';
import { sha256Buffer } from '../core/hash.js';

/**
 * 对一个「正在运行的站点」做上线前/线上巡检：
 * 拉取清单内每个 SW 脚本 URL，检查响应头与字节 hash。
 * 这是静态扫描之外的第二道闸：即使源码评审通过，错误的网关/CDN 配置仍会让防线失效。
 */
export interface FetchLike {
  (url: string, init?: { headers?: Record<string, string> }): Promise<{
    status: number;
    headers: Record<string, string>;
    text(): Promise<string>;
  }>;
}

export interface LiveAuditTarget {
  baseUrl: string;
  fetchImpl: FetchLike;
}

export async function auditLiveSwScript(
  target: LiveAuditTarget,
  manifest: SiteManifest,
): Promise<AuditFinding[]> {
  const findings: AuditFinding[] = [];
  for (const entry of manifest.serviceWorkers) {
    const url = `${target.baseUrl}${entry.scriptUrl}`;
    // 显式带上浏览器更新请求的头，尽量还原浏览器内部通道的服务端决策
    const res = await target.fetchImpl(url, { headers: { 'Service-Worker': 'script' } });
    const lowerHeaders = Object.fromEntries(
      Object.entries(res.headers).map(([k, v]) => [k.toLowerCase(), v]),
    );

    if (res.status !== 200) {
      findings.push(error(entry.scriptUrl, 'http-status', `SW 脚本响应状态 ${res.status}`, '保证脚本 URL 稳定可访问'));
      continue;
    }

    // 1) hash 必须与清单一致
    const body = await res.text();
    const actualHash = sha256Buffer(body);
    if (actualHash !== entry.sha256.toLowerCase()) {
      findings.push(
        error(
          entry.scriptUrl,
          'hash-mismatch',
          `线上字节 hash ${actualHash} 与清单 ${entry.sha256} 不一致`,
          '立即排查 CDN 缓存/源站篡改，并在流水线中加入 hash 比对门禁',
        ),
      );
    }

    // 2) 缓存策略：SW 脚本必须 no-store 或 max-age=0
    const cacheControl = lowerHeaders['cache-control'] ?? '';
    const maxAge = /max-age=(\d+)/.exec(cacheControl)?.[1];
    if (!/no-store|no-cache/.test(cacheControl) && (maxAge === undefined || Number(maxAge) > manifest.hardening.scriptMaxAgeSeconds)) {
      findings.push(
        error(
          entry.scriptUrl,
          'cache-poisoning-risk',
          `SW 脚本缓存策略过宽: ${cacheControl || '(缺失)'}`,
          `设置 Cache-Control: no-store 或 max-age=${manifest.hardening.scriptMaxAgeSeconds}`,
        ),
      );
    }

    // 3) MIME 必须是 JS
    const contentType = lowerHeaders['content-type'] ?? '';
    if (!/javascript/.test(contentType)) {
      findings.push(error(entry.scriptUrl, 'mime', `Content-Type 不是 JavaScript: ${contentType}`, '使用 application/javascript; charset=utf-8'));
    }

    // 4) nosniff
    if (lowerHeaders['x-content-type-options'] !== 'nosniff') {
      findings.push(warning(entry.scriptUrl, 'nosniff', '缺少 X-Content-Type-Options: nosniff', '加上该头防止 MIME 混淆'));
    }

    // 5) SW 自身 CSP
    const csp = lowerHeaders['content-security-policy'] ?? '';
    if (!csp) {
      findings.push(warning(entry.scriptUrl, 'worker-csp', 'SW 脚本缺少 CSP', '设置最收紧的 worker CSP（default-src none）'));
    } else if (/(script-src[^;]*(unsafe-eval|https?:))/.test(csp)) {
      findings.push(error(entry.scriptUrl, 'worker-csp-loose', 'SW 的 CSP 允许 unsafe-eval 或远程脚本', '收紧为 script-src self'));
    }
  }

  // 6) 页面 CSP 必须包含 worker-src 'self'
  const pageRes = await target.fetchImpl(`${target.baseUrl}/`);
  const pageHeaders = Object.fromEntries(Object.entries(pageRes.headers).map(([k, v]) => [k.toLowerCase(), v]));
  const pageCsp = pageHeaders['content-security-policy'] ?? '';
  if (!/worker-src\s+[^;]*'self'/.test(pageCsp)) {
    findings.push(
      error(
        '/',
        'page-worker-src',
        "页面 CSP 缺少 worker-src 'self'，第三方注入脚本可注册任意 worker",
        "在页面 CSP 中加入 worker-src 'self'",
      ),
    );
  }
  return findings;
}

function error(target: string, id: string, message: string, remediation: string): AuditFinding {
  return { id, severity: 'error', target, message, remediation };
}
function warning(target: string, id: string, message: string, remediation: string): AuditFinding {
  return { id, severity: 'warning', target, message, remediation };
}
