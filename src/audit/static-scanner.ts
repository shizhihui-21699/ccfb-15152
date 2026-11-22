import { readFile } from 'node:fs/promises';
import type { AuditFinding, Severity } from '../core/types.js';

/**
 * 静态规则引擎：对 SW 脚本源码做启发式扫描。
 * 它不是「证明脚本安全」，而是把历史投毒样本里反复出现的危险模式在上线前拦住，
 * 每条规则都给出修复建议；error 级命中应阻断发布流水线。
 */
export interface StaticRule {
  id: string;
  severity: Severity;
  pattern: RegExp;
  message: string;
  remediation: string;
}

export const STATIC_RULES: StaticRule[] = [
  {
    id: 'sw-eval',
    severity: 'error',
    pattern: /\beval\s*\(|new\s+Function\s*\(/,
    message: 'SW 中使用 eval / new Function，可把任意字符串变成可执行代码',
    remediation: '删除动态求值；数据驱动逻辑改用显式分派表',
  },
  {
    id: 'sw-remote-import',
    severity: 'error',
    pattern: /importScripts\s*\(\s*['"`]https?:\/\//,
    message: 'importScripts 加载跨源脚本，源站一旦失守即可热更新攻击载荷',
    remediation: '只允许同源、清单前缀内的 importScripts，并在 CSP script-src 中限制',
  },
  {
    id: 'sw-cross-origin-fetch-noop',
    severity: 'warning',
    pattern: /fetch\s*\(\s*['"`]https?:\/\//,
    message: 'SW 直接请求跨源 URL，确认是否为业务必需，响应是否会被缓存/再注入页面',
    remediation: '收敛跨源请求清单；禁止把跨源响应放入 CacheStorage 后回灌给页面',
  },
  {
    id: 'sw-page-api-tamper',
    severity: 'error',
    pattern: /navigator\.serviceWorker\.(register|getRegistrations)\s*=/,
    message: '改写 navigator.serviceWorker 管理 API —— 恶意 SW 用于阻止清除的典型手法',
    remediation: '合法代码没有任何理由改写这些 API，删除并重写相关逻辑',
  },
  {
    id: 'sw-inline-injection',
    severity: 'error',
    pattern: /\.replace\s*\(\s*['"`]<\/body>|document\.write|insertAdjacentHTML/,
    message: '存在向 HTML 注入内容的字符串操作，可能被用于导航响应投毒',
    remediation: '禁止在 SW 中改写导航 HTML；如需注入分析脚本，在服务端模板里完成',
  },
  {
    id: 'sw-cache-star',
    severity: 'warning',
    pattern: /caches\.delete\s*\(\s*['"`]\*['"`]\)|cache\.put\s*\(\s*[^,]+,\s*[^)]*\)\s*;\s*\/\/\s*wildcard/i,
    message: '出现通配式缓存操作痕迹，容易把投毒响应长期持久化',
    remediation: '缓存键必须显式枚举，并与清单登记的缓存前缀保持一致',
  },
  {
    id: 'sw-skip-message-guard',
    severity: 'info',
    pattern: /addEventListener\s*\(\s*['"`]message['"`]/,
    message: 'SW 监听 message 事件：确认所有分支都校验了 event.data 结构与来源',
    remediation: '对 postMessage 做 schema 校验，拒绝非预期类型，禁止把消息字段拼进 eval/URL',
  },
  {
    id: 'sw-navigation-rewrite',
    severity: 'warning',
    pattern: /request\.mode\s*===?\s*['"`]navigate['"`][\s\S]{0,400}new\s+Response/,
    message: 'SW 对导航请求构造新 Response，属于高危能力（可返回任意页面）',
    remediation: '导航请求优先网络优先/离线回退模式；若必须改响应，需代码评审 + 快照测试',
  },
  {
    id: 'sw-no-skipwaiting-claim',
    severity: 'info',
    pattern: /skipWaiting|clients\.claim/,
    message: '使用 skipWaiting/claim：确认激活顺序不会让半更新状态接管页面',
    remediation: '在 activate 中先完成缓存迁移再 claim；为更新流程补 E2E 用例',
  },
];

export interface StaticScanResult {
  file: string;
  findings: AuditFinding[];
}

export async function scanServiceWorkerFile(file: string): Promise<StaticScanResult> {
  const source = await readFile(file, 'utf8');
  const findings: AuditFinding[] = [];
  for (const rule of STATIC_RULES) {
    rule.pattern.lastIndex = 0;
    if (rule.pattern.test(source)) {
      findings.push({
        id: rule.id,
        severity: rule.severity,
        target: file,
        message: rule.message,
        remediation: rule.remediation,
      });
    }
  }
  return { file, findings };
}

/** 对 importScripts 做专门的白名单校验（白名单来自清单，不接受页面输入） */
export function checkImportScripts(source: string, allowedPrefixes: string[]): AuditFinding[] {
  const findings: AuditFinding[] = [];
  const re = /importScripts\s*\(([^)]*)\)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(source)) !== null) {
    const args = m[1] ?? '';
    const urlMatches = args.matchAll(/['"`]([^'"`]+)['"`]/g);
    for (const u of urlMatches) {
      const url = u[1] ?? '';
      if (/^https?:\/\//.test(url)) {
        findings.push({
          id: 'import-cross-origin',
          severity: 'error',
          target: url,
          message: `importScripts 跨源地址: ${url}`,
          remediation: '移除跨源 import，或把资源自托管后纳入清单前缀',
        });
      } else if (!allowedPrefixes.some((p) => url.startsWith(p))) {
        findings.push({
          id: 'import-not-allowlisted',
          severity: 'error',
          target: url,
          message: `importScripts 地址 ${url} 不在清单允许前缀内`,
          remediation: `允许前缀: ${allowedPrefixes.join(', ')}`,
        });
      }
    }
  }
  return findings;
}
