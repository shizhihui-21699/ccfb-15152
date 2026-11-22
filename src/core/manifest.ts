import { readFile } from 'node:fs/promises';
import { resolve, isAbsolute } from 'node:path';
import type { SiteManifest, ServiceWorkerEntry } from './types.js';
import { sha256File } from './hash.js';

export class ManifestError extends Error {}

/**
 * 加载并校验站点 SW 清单。
 * 清单是整套方案的信任根：只有清单里登记、且磁盘文件 hash 与登记值一致的脚本，
 * 才允许以 SW 脚本身份下发；其它 URL 的 SW 脚本请求一律返回 kill SW。
 *
 * @param manifestPath 清单 JSON 路径
 * @param publicRoot   静态文件根目录，用于计算 SW 脚本磁盘路径并回填 hash
 */
export async function loadManifest(manifestPath: string, publicRoot: string): Promise<SiteManifest> {
  const raw = await readFile(manifestPath, 'utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new ManifestError(`清单不是合法 JSON: ${(e as Error).message}`);
  }
  const manifest = validate(parsed);

  // 对每个登记的 SW 脚本计算实际 hash，与清单值交叉校验。
  // 清单里写 "FILLED_AT_RUNTIME" 表示由 loader 回填（本地演示用），
  // 生产环境应在 CI 中把真实 hash 写死，loader 只做严格比对。
  for (const entry of manifest.serviceWorkers) {
    const diskPath = resolve(publicRoot, '.' + entry.scriptUrl);
    const actual = await sha256File(diskPath);
    if (entry.sha256 === 'FILLED_AT_RUNTIME') {
      entry.sha256 = actual;
    } else if (entry.sha256.toLowerCase() !== actual) {
      throw new ManifestError(
        `SW 脚本 ${entry.scriptUrl} 的 hash 与清单不符：清单=${entry.sha256} 实际=${actual}。` +
          '可能是脚本被篡改或清单过期，拒绝以受信状态启动。',
      );
    }
  }
  return manifest;
}

function validate(value: unknown): SiteManifest {
  if (typeof value !== 'object' || value === null) throw new ManifestError('清单根节点必须是对象');
  const m = value as Partial<SiteManifest>;
  if (!Array.isArray(m.serviceWorkers) || m.serviceWorkers.length === 0) {
    throw new ManifestError('serviceWorkers 必须是非空数组');
  }
  for (const sw of m.serviceWorkers) validateEntry(sw);
  if (!m.hardening || typeof m.hardening !== 'object') throw new ManifestError('缺少 hardening');
  if (m.hardening.updateViaCache !== 'none' && m.hardening.updateViaCache !== 'imports' && m.hardening.updateViaCache !== 'all') {
    throw new ManifestError('hardening.updateViaCache 只能是 none/imports/all');
  }
  if (!Array.isArray(m.hardening.allowedScriptPrefixes) || m.hardening.allowedScriptPrefixes.length === 0) {
    throw new ManifestError('hardening.allowedScriptPrefixes 必须是非空数组');
  }
  if (!m.kill || !Array.isArray(m.kill.purgeCachePrefixes)) throw new ManifestError('缺少 kill.purgeCachePrefixes');
  if (!m.beacon?.endpoint || !m.beacon.manifestEndpoint) throw new ManifestError('缺少 beacon 端点配置');
  return m as SiteManifest;
}

function validateEntry(sw: ServiceWorkerEntry): void {
  if (!sw.scriptUrl?.startsWith('/') || sw.scriptUrl.startsWith('//')) {
    throw new ManifestError('scriptUrl 必须是同源绝对路径');
  }
  if (!sw.scope?.startsWith('/')) throw new ManifestError(`scope 必须是绝对路径: ${sw.scriptUrl}`);
  if (!sw.version) throw new ManifestError(`缺少 version: ${sw.scriptUrl}`);
  if (!/^[a-f0-9]{64}$/i.test(sw.sha256) && sw.sha256 !== 'FILLED_AT_RUNTIME') {
    throw new ManifestError(`sha256 非法: ${sw.scriptUrl}`);
  }
  if (!Array.isArray(sw.cachePrefixes)) throw new ManifestError(`cachePrefixes 必须是数组: ${sw.scriptUrl}`);
}

/** 判断某个脚本 URL 是否在白名单前缀内（白名单本身来自清单，不接受请求参数） */
export function isAllowedScriptUrl(urlPath: string, manifest: SiteManifest): boolean {
  return manifest.hardening.allowedScriptPrefixes.some(
    (prefix) => urlPath === prefix || urlPath.startsWith(prefix),
  );
}

export function findEntry(scriptUrl: string, manifest: SiteManifest): ServiceWorkerEntry | undefined {
  return manifest.serviceWorkers.find((e) => e.scriptUrl === scriptUrl);
}

export function assertSafeRelativePath(urlPath: string): void {
  if (isAbsolute(urlPath) && !urlPath.startsWith('/')) throw new ManifestError('非法路径');
  if (urlPath.includes('..') || urlPath.includes('\0')) throw new ManifestError('路径穿越被拒绝');
}
