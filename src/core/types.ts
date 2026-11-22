/**
 * 全站共享的类型定义。
 * 设计原则：所有「可信判断」都必须能追溯到服务端签发的清单（manifest），
 * 浏览器侧运行时数据（navigator.serviceWorker / postMessage）一律视为不可信输入。
 */

/** 清单中登记的一个合法 Service Worker 脚本 */
export interface ServiceWorkerEntry {
  /** 脚本 URL，必须同源、绝对路径 */
  scriptUrl: string;
  /** 注册 scope */
  scope: string;
  /** 人类可读版本号，仅用于展示与灰度，不参与信任判断 */
  version: string;
  /** 合法脚本的 SHA-256（小写 hex）。运行时由 loader 对磁盘文件计算后回填/校验 */
  sha256: string;
  /** 该 SW 允许创建的 CacheStorage 名称前缀（用于离线功能保留判断） */
  cachePrefixes: string[];
}

export interface HardeningConfig {
  /** 对应 registration.updateViaCache */
  updateViaCache: 'none' | 'imports' | 'all';
  /** SW 脚本响应允许的 max-age */
  scriptMaxAgeSeconds: number;
  /** 允许作为 SW 脚本下发的 URL 前缀；清单外的请求一律视为入侵并下发 kill SW */
  allowedScriptPrefixes: string[];
  /** SW 中 importScripts 允许的同源前缀 */
  allowedImportPrefixes: string[];
  /** SW 脚本响应的 CSP */
  workerCsp: string;
  /** 页面响应的 CSP（worker-src 'self' 是关键防线） */
  pageCsp: string;
}

export interface KillConfig {
  /** kill SW 激活时要删除的缓存名前缀 */
  purgeCachePrefixes: string[];
  /** kill SW 激活时要精确删除的缓存名 */
  purgeExactCacheNames: string[];
  /** 需要清空的同源存储键（localStorage 等，由页面侧 reconcile 执行） */
  purgeStorageKeys: string[];
}

export interface BeaconConfig {
  endpoint: string;
  manifestEndpoint: string;
}

export interface SiteManifest {
  serviceWorkers: ServiceWorkerEntry[];
  hardening: HardeningConfig;
  kill: KillConfig;
  beacon: BeaconConfig;
}

/** 页面侧通过 beacon 上报的一条 SW 注册记录（数据全部不可信，服务端需复核） */
export interface RegistrationReport {
  scope: string;
  scriptURL: string;
  state: string;
  /** 页面侧能拿到的信息（多数浏览器不暴露脚本 hash） */
  controllerScriptURL?: string | null;
  /** CacheStorage 中实际存在的缓存名 */
  cacheNames?: string[];
  /** 触发上报的原因 */
  reason: 'startup' | 'mismatch' | 'kill-signal' | 'unknown-controller' | 'periodic';
  at: string;
}

/** 服务端在 access log 中识别出的 SW 脚本请求 */
export interface ScriptRequestEvent {
  at: string;
  url: string;
  /** 请求头 Service-Worker 的值（script / null） */
  serviceWorkerHeader: string | null;
  userAgent: string;
  /** 是否命中清单白名单 */
  known: boolean;
  /** 命中的清单条目（若有） */
  matchedScript?: string;
}

/** 服务端记录的一次安全事件 */
export interface SecurityIncident {
  id: string;
  at: string;
  kind:
    | 'unknown-script-request'
    | 'registration-report'
    | 'hash-mismatch'
    | 'forbidden-import'
    | 'remediation-kill';
  detail: Record<string, unknown>;
}

/** 审计工具对单个检查项的结论 */
export type Severity = 'error' | 'warning' | 'info';

export interface AuditFinding {
  id: string;
  severity: Severity;
  target: string;
  message: string;
  remediation: string;
}

export interface AuditReport {
  generatedAt: string;
  target: string;
  summary: Record<Severity, number>;
  findings: AuditFinding[];
}
